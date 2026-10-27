//! Identity confirmation, module hand-over, capability installation and the
//! poison obligation: the parts of [`StreamSession`] that act on a *finished*
//! stream.

use crate::stream_module::VerifiedModule;
use crate::stream_obligation::PoisonObligation;
use crate::stream_session::StreamSession;
use crate::stream_session_types::{PoisonReport, SessionError, SessionState};
use rvm_cap::CapabilityTable;
use rvm_rvf::stream::witness::{binding_of, emit_event, finish_identity_witnessed, StreamEvent};
use rvm_rvf::stream::{AdmissionError, IdentityStatus};
use rvm_rvf::WitnessContext;
use rvm_types::PartitionId;
use rvm_witness::WitnessLog;

/// The `seg_type` of a WASM runtime segment.
const SEG_TYPE_WASM: u8 = rvm_rvf::format::SEG_TYPE_WASM;

impl StreamSession<'_> {
    /// For a stream that completed with an `Unverifiable` identity: re-read the
    /// persisted body in file order and check `SHA-256 == rvf_identity`.
    /// Success makes [`Self::take_module`] available; a mismatch poisons the
    /// session (see [`Self::take_obligation`]).
    ///
    /// # Errors
    ///
    /// [`SessionError::Stream`] with the verifier's refusal.
    pub fn finish_identity(
        &mut self,
        read_at: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<(), SessionError> {
        let r = self
            .admission
            .finish_identity(read_at)
            .map_err(|e| SessionError::Stream(AdmissionError::Stream(e)));
        self.check_poisoned();
        if r.is_ok() {
            self.promote(None)?;
        }
        r
    }

    /// [`Self::finish_identity`], witnessing a mismatch poison.
    ///
    /// # Errors
    ///
    /// As [`Self::finish_identity`].
    pub fn finish_identity_witnessed<const N: usize>(
        &mut self,
        read_at: impl FnMut(u64, &mut [u8]) -> bool,
        log: &WitnessLog<N>,
        ctx: WitnessContext,
    ) -> Result<(), SessionError> {
        let r = finish_identity_witnessed(&mut self.admission, read_at, log, ctx)
            .map_err(|e| SessionError::Stream(AdmissionError::Stream(e)));
        self.check_poisoned();
        if r.is_ok() {
            self.promote(Some(&|ev: &StreamEvent, b: &[u8; 32]| {
                emit_event(ev, b, log, ctx);
            }))?;
        }
        r
    }

    /// [`Self::take_module`], writing a failing witness record if replay
    /// protection refuses the module at hand-over.
    ///
    /// # Errors
    ///
    /// As [`Self::take_module`].
    pub fn take_module_witnessed<const N: usize>(
        &mut self,
        seg_id: u64,
        log: &WitnessLog<N>,
        ctx: WitnessContext,
    ) -> Result<VerifiedModule, SessionError> {
        let r = self.take_module(seg_id);
        if let Err(SessionError::Replay(e)) = &r {
            if let Some(b) = binding_of(&self.admission) {
                emit_event(
                    &StreamEvent::DescriptorRejected {
                        descriptor_hash: b,
                        reason: *e,
                    },
                    &b,
                    log,
                    ctx,
                );
            }
        }
        r
    }

    /// Hand over the validated module of segment `seg_id`.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotComplete`] before the stream completed,
    /// [`SessionError::Unusable`] after a failure or poison,
    /// [`SessionError::IdentityUnverified`] until the identity is verified,
    /// [`SessionError::NoSuchModule`] when that segment carried no validated
    /// WASM module, and [`SessionError::IdentityMismatch`] if the buffered
    /// bytes do not match the verified executable (length and SHA-256).
    pub fn take_module(&mut self, seg_id: u64) -> Result<VerifiedModule, SessionError> {
        match self.state {
            SessionState::Receiving => return Err(SessionError::NotComplete),
            SessionState::Failed | SessionState::Poisoned => return Err(SessionError::Unusable),
            SessionState::Complete => {}
        }
        if self.identity_status() != Some(IdentityStatus::Verified) {
            return Err(SessionError::IdentityUnverified);
        }
        // The pin is re-checked here too: a newer epoch pinned since this
        // session completed makes its module stale.
        self.pin_check().map_err(SessionError::Replay)?;
        let report = self.admission.report().ok_or(SessionError::Unusable)?;
        let executable = *report
            .executables
            .iter()
            .find(|e| e.segment_id == seg_id && e.segment_type == SEG_TYPE_WASM)
            .ok_or(SessionError::NoSuchModule)?;
        let rvf_identity = report.rvf_identity;
        let (bytes, validated) = self
            .ready
            .remove(&seg_id)
            .ok_or(SessionError::NoSuchModule)?;
        if !executable.matches(&bytes) {
            return Err(SessionError::IdentityMismatch);
        }
        let descriptor_hash = self.descriptor_hash().unwrap_or([0; 32]);
        Ok(VerifiedModule::new(
            bytes,
            executable,
            validated,
            rvf_identity,
            descriptor_hash,
            self.session_id,
        ))
    }

    /// Install the package's granted capabilities into `table` and remember
    /// the handles, so that a poisoned session can revoke exactly these.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotComplete`] / [`SessionError::Unusable`] unless the
    /// session is `Complete`, and [`SessionError::Install`] if the table is
    /// full (nothing is left installed).
    pub fn install_capabilities<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        owner: PartitionId,
        epoch: u32,
        first_cap_id: u64,
    ) -> Result<usize, SessionError> {
        match self.state {
            SessionState::Receiving => return Err(SessionError::NotComplete),
            SessionState::Failed | SessionState::Poisoned => return Err(SessionError::Unusable),
            SessionState::Complete => {}
        }
        if self.identity_status() != Some(IdentityStatus::Verified) {
            return Err(SessionError::IdentityUnverified);
        }
        let package = self.package.as_ref().ok_or(SessionError::Unusable)?;
        let handles = package
            .capabilities()
            .install_tracked(table, owner, epoch, first_cap_id)
            .map_err(SessionError::Install)?;
        let n = handles.len();
        self.installed.extend(handles);
        Ok(n)
    }

    /// The obligation a poisoned session leaves, once. `None` while the
    /// session is not poisoned, if the poison happened before a descriptor was
    /// authenticated (nothing was granted or started), or if it was already
    /// taken. Dropping the obligation without discharging it leaves the
    /// session's capabilities and instances live.
    #[must_use]
    pub fn take_obligation(&mut self) -> Option<PoisonObligation> {
        let authenticated = self
            .poison
            .as_ref()
            .is_some_and(PoisonReport::authenticated);
        if self.state != SessionState::Poisoned || self.obligation_issued || !authenticated {
            return None;
        }
        self.obligation_issued = true;
        Some(PoisonObligation {
            session_id: self.session_id,
            handles: core::mem::take(&mut self.installed),
        })
    }
}
