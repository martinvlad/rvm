//! Replay protection for [`StreamSession`]: the pin is checked when the
//! descriptor arrives (by the verifier), again when the stream completes and
//! identity is verified, and again at module hand-over, and advanced only by
//! compare-and-set from the value just checked.

use crate::stream_session::{Emit, StreamSession};
use crate::stream_session_types::{SessionError, SessionState};
use rvm_rvf::stream::witness::{binding_of, StreamEvent};
use rvm_rvf::stream::{EpochPin, IdentityStatus, ReplayProtection, StreamError};

impl StreamSession<'_> {
    /// Once the identity is verified: expose the package and pin the
    /// descriptor. A cut, poisoned or refused stream never gets here, so it
    /// never moves a pin.
    pub(crate) fn promote(&mut self, witness: Emit<'_>) -> Result<(), SessionError> {
        if self.state != SessionState::Complete
            || self.identity_status() != Some(IdentityStatus::Verified)
        {
            return Ok(());
        }
        // Re-check the pin now, not when the descriptor arrived: another
        // session may have completed a newer epoch in the meantime. Then
        // advance by compare-and-set from the value just checked; losing the
        // race means re-reading and re-checking.
        let Some(d) = self.admission.verifier().descriptor() else {
            return Ok(());
        };
        let (file_id, signer) = (d.header.file_id, d.header.signer_key_id);
        let new = EpochPin {
            epoch: d.header.epoch,
            descriptor_hash: d.descriptor_hash,
            signer_key_id: signer,
        };
        for _ in 0..4 {
            let cur = match self.pin_check() {
                Ok(c) => c,
                Err(e) => return Err(self.reject_replay(e, witness)),
            };
            let ReplayProtection::Store { store, .. } = self.replay else {
                break;
            };
            if self.pin_recorded || store.advance(&signer, &file_id, cur, new) {
                self.pin_recorded = true;
                break;
            }
        }
        if matches!(self.replay, ReplayProtection::Store { .. }) && !self.pin_recorded {
            return Err(self.reject_replay(StreamError::StaleEpoch, witness));
        }
        if let Some(p) = self.pending_package.take() {
            self.package = Some(p);
        }
        Ok(())
    }

    /// The pin currently on record for this stream's lineage, after checking
    /// that this descriptor is not older than it (or a conflicting twin).
    pub(crate) fn pin_check(&self) -> Result<Option<EpochPin>, StreamError> {
        let Some(d) = self.admission.verifier().descriptor() else {
            return Ok(None);
        };
        let cur = self
            .replay
            .lookup(&d.header.signer_key_id, &d.header.file_id);
        if let Some(p) = cur {
            if d.header.epoch < p.epoch {
                return Err(StreamError::StaleEpoch);
            }
            if d.header.epoch == p.epoch && p.descriptor_hash != d.descriptor_hash {
                return Err(StreamError::EpochConflict);
            }
        }
        Ok(cur)
    }

    pub(crate) fn reject_replay(&mut self, e: StreamError, witness: Emit<'_>) -> SessionError {
        if let (Some(w), Some(b)) = (witness, binding_of(&self.admission)) {
            w(
                &StreamEvent::DescriptorRejected {
                    descriptor_hash: b,
                    reason: e,
                },
                &b,
            );
        }
        let err = SessionError::Replay(e);
        self.fail(err.clone());
        err
    }
}
