//! The receiver state machine (ADR-353 sections 5 and 6).
//!
//! [`StreamVerifier::push`] takes one complete frame. Nothing is buffered
//! here: a released [`VerifiedChunk`] borrows the frame the caller passed,
//! which was hashed in place. Memory held between calls is the verified
//! descriptor, one small record per segment, and the leaf list of each segment
//! whose chunk table was accepted but is not yet fully verified.
//!
//! ## Fault model
//!
//! * A frame whose size contradicts the signed descriptor, a table whose `n`
//!   is wrong, and a frame shorter than its own header **poison** the stream
//!   immediately ([`StreamError::FrameSizeLie`]).
//! * A duplicate, out-of-order, unknown-segment, unknown-type or
//!   chunk-before-table frame, a hash mismatch, and a chunk whose required
//!   stages are not yet verified are **counted faults**. The stream is
//!   poisoned when the count exceeds the policy `fault_budget`. A refused
//!   frame never advances the expected next chunk.
//! * The identity check runs before the final chunk is released, so a
//!   mismatch releases nothing from that chunk.

use super::commit::chunk_list_hash_flat;
use super::descriptor::{decode_descriptor, VerifiedDescriptor, FLAG_IDENTITY_PRESENT, MAX_STAGES};
use super::error::{StreamError, StreamResult};
use super::events::{Event, IdentityStatus, PoisonInfo, StreamState};
use super::frame::{FRAME_CHUNK, FRAME_CHUNK_TABLE, FRAME_DESCRIPTOR};
use super::ident::IdentityTracker;
use super::StreamPolicy;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

#[derive(Clone)]
pub(super) struct SegState {
    pub(super) n: u32,
    pub(super) next: u32,
    pub(super) leaves: Option<Vec<u8>>,
    pub(super) done: bool,
}

/// Verifies a stream of frames against a signed descriptor.
#[derive(Clone)]
pub struct StreamVerifier<'p> {
    pub(super) policy: StreamPolicy<'p>,
    pub(super) state: StreamState,
    pub(super) desc: Option<VerifiedDescriptor>,
    pub(super) segs: Vec<SegState>,
    pub(super) stage_remaining: [u32; MAX_STAGES as usize],
    pub(super) left: usize,
    pub(super) faults: u32,
    pub(super) verified_bytes: u64,
    pub(super) released_chunks: u64,
    pub(super) table_bytes: u64,
    pub(super) identity: Option<IdentityTracker>,
    pub(super) identity_status: Option<IdentityStatus>,
    pub(super) max_chunk_len: u64,
    pub(super) max_table_payload: u64,
    pub(super) poison_info: Option<PoisonInfo>,
    pub(super) last_fault: Option<PoisonInfo>,
    pub(super) duplicates_ignored: u64,
    pub(super) duplicate_cap: u64,
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

impl<'p> StreamVerifier<'p> {
    /// A verifier waiting for the descriptor frame.
    #[must_use]
    pub fn new(policy: StreamPolicy<'p>) -> Self {
        Self {
            policy,
            state: StreamState::AwaitDescriptor,
            desc: None,
            segs: Vec::new(),
            stage_remaining: [0; MAX_STAGES as usize],
            left: 0,
            faults: 0,
            verified_bytes: 0,
            released_chunks: 0,
            table_bytes: 0,
            identity: None,
            identity_status: None,
            max_chunk_len: 0,
            max_table_payload: 0,
            poison_info: None,
            last_fault: None,
            duplicates_ignored: 0,
            duplicate_cap: 0,
        }
    }

    /// A verifier for a descriptor delivered out of band (a sidecar, or
    /// referenced by hash from a package contract).
    ///
    /// # Errors
    ///
    /// The reason the descriptor was refused.
    pub fn from_descriptor(bytes: &[u8], policy: StreamPolicy<'p>) -> StreamResult<Self> {
        let mut v = Self::new(policy);
        v.install(bytes)?;
        Ok(v)
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> StreamState {
        self.state
    }

    /// Counted faults so far.
    #[must_use]
    pub const fn faults(&self) -> u32 {
        self.faults
    }

    /// Body bytes released so far.
    #[must_use]
    pub const fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// Chunks released so far.
    #[must_use]
    pub const fn released_chunks(&self) -> u64 {
        self.released_chunks
    }

    /// The verified descriptor, once accepted.
    #[must_use]
    pub const fn descriptor(&self) -> Option<&VerifiedDescriptor> {
        self.desc.as_ref()
    }

    /// The identity status recorded at completion.
    #[must_use]
    pub const fn identity_status(&self) -> Option<IdentityStatus> {
        self.identity_status
    }

    /// Where and why the stream was poisoned, once it is.
    #[must_use]
    pub const fn poison_info(&self) -> Option<PoisonInfo> {
        self.poison_info
    }

    /// The most recent counted fault (a refused frame that did not poison the
    /// stream, or the one that did).
    #[must_use]
    pub const fn last_fault(&self) -> Option<PoisonInfo> {
        self.last_fault
    }

    /// Duplicate frames ignored so far.
    #[must_use]
    pub const fn duplicates_ignored(&self) -> u64 {
        self.duplicates_ignored
    }

    /// The next chunk index expected for a segment; `None` when the segment is
    /// unknown or already verified.
    #[must_use]
    pub fn next_chunk(&self, seg_id: u64) -> Option<u32> {
        let s = &self.segs[self.desc.as_ref()?.find(seg_id)?];
        (!s.done).then_some(s.next)
    }

    /// Whether every segment of `stage` is verified.
    #[must_use]
    pub fn stage_verified(&self, stage: u8) -> bool {
        self.desc.is_some()
            && (stage as usize) < self.stage_remaining.len()
            && self.stage_remaining[stage as usize] == 0
    }

    /// Whether a segment is fully verified.
    #[must_use]
    pub fn segment_verified(&self, seg_id: u64) -> bool {
        self.desc
            .as_ref()
            .and_then(|d| d.find(seg_id))
            .is_some_and(|i| self.segs[i].done)
    }

    /// The largest payload a frame of this type may declare. Zero means no
    /// frame of that type is legal right now.
    #[must_use]
    pub const fn frame_payload_limit(&self, frame_type: u8) -> u64 {
        match (frame_type, self.state) {
            (FRAME_DESCRIPTOR, StreamState::AwaitDescriptor) => {
                self.policy.max_descriptor_bytes as u64
            }
            (FRAME_CHUNK, StreamState::Ready | StreamState::Receiving) => self.max_chunk_len,
            (FRAME_CHUNK_TABLE, StreamState::Ready | StreamState::Receiving) => {
                self.max_table_payload
            }
            _ => 0,
        }
    }

    /// Terminal failure from outside the state machine (the frame reader's
    /// size lies). A rejected descriptor stays rejected.
    pub fn poison(&mut self, reason: StreamError) -> StreamError {
        self.poison_at(reason, None, 0)
    }

    pub(crate) fn poison_at(
        &mut self,
        reason: StreamError,
        seg: Option<u64>,
        chunk: u32,
    ) -> StreamError {
        // Terminal states are never turned into `Poisoned` by a late frame or
        // a reader-level size lie: a completed stream stays completed, and the
        // offending bytes are refused with `BadState` by the caller.
        if !matches!(
            self.state,
            StreamState::Rejected(_)
                | StreamState::Complete
                | StreamState::CompleteUnverified
                | StreamState::Suspended
        ) {
            self.force_poison(reason, seg, chunk);
        }
        reason
    }

    /// Poison regardless of state, for the two callers that revoke a stream
    /// that had completed: admission refusing a package, and a failed
    /// `finish_identity`.
    pub(crate) fn force_poison(&mut self, reason: StreamError, seg: Option<u64>, chunk: u32) {
        self.state = StreamState::Poisoned(reason);
        self.identity = None; // joins any identity worker
        if self.poison_info.is_none() {
            self.poison_info = Some(PoisonInfo {
                seg_id: seg,
                chunk_index: chunk,
                reason,
            });
        }
    }

    pub(super) fn fault(
        &mut self,
        reason: StreamError,
        seg: Option<u64>,
        chunk: u32,
    ) -> StreamError {
        self.last_fault = Some(PoisonInfo {
            seg_id: seg,
            chunk_index: chunk,
            reason,
        });
        self.faults += 1;
        if self.faults > self.policy.fault_budget {
            self.poison_at(reason, seg, chunk);
        }
        reason
    }

    /// Input ended before `Complete`: move to `Suspended`.
    pub fn end_of_input(&mut self) -> StreamState {
        if matches!(self.state, StreamState::Receiving | StreamState::Ready) {
            if let Some(t) = &mut self.identity {
                t.release_worker();
            }
            self.state = StreamState::Suspended;
        }
        self.state
    }

    /// Continue after `Suspended`; progress is kept at chunk granularity.
    pub fn resume(&mut self) -> bool {
        if self.state == StreamState::Suspended {
            self.state = StreamState::Receiving;
            true
        } else {
            false
        }
    }

    fn install(&mut self, bytes: &[u8]) -> StreamResult<Event<'static>> {
        let d = match decode_descriptor(bytes, &self.policy) {
            Ok(d) => d,
            Err(e) => {
                self.state = StreamState::Rejected(e);
                return Err(e);
            }
        };
        let h = d.header;
        self.segs.reserve_exact(d.entries.len());
        for e in &d.entries {
            // `n` is derived from the signed stored_len and was proven to fit.
            let n = h.chunk_count(e.stored_len).unwrap_or(1);
            self.segs.push(SegState {
                n,
                next: 0,
                leaves: None,
                done: false,
            });
            self.stage_remaining[e.stage as usize] += 1;
            self.max_chunk_len = self
                .max_chunk_len
                .max(h.chunk_len(e.stored_len, 0).unwrap_or(0));
            if n > 1 {
                self.max_table_payload = self.max_table_payload.max(32 * u64::from(n));
            }
        }
        let total_chunks: u64 = self.segs.iter().map(|s| u64::from(s.n)).sum();
        self.duplicate_cap = self
            .policy
            .max_duplicate_frames
            .unwrap_or(4 * total_chunks + 64);
        self.left = d.entries.len();
        // Stage-ordered delivery (stages not already non-decreasing in body
        // order) is expected to arrive out of file order, which makes the
        // running hash infeasible at once: do not start a worker for it.
        let stages_in_body_order = d.entries.windows(2).all(|w| w[0].stage <= w[1].stage);
        if h.flags & FLAG_IDENTITY_PRESENT != 0 {
            self.identity = Some(IdentityTracker::new(
                h.body_len,
                self.max_chunk_len,
                stages_in_body_order,
            ));
        }
        let ev = Event::DescriptorVerified {
            descriptor_hash: d.descriptor_hash,
            seg_count: h.seg_count,
            body_len: h.body_len,
        };
        self.desc = Some(d);
        self.state = StreamState::Ready;
        Ok(ev)
    }

    /// Accept one complete frame.
    ///
    /// # Errors
    ///
    /// The frame was refused: nothing was released and the expected next chunk
    /// did not advance. Whether the stream survived is in [`Self::state`].
    pub fn push<'a>(&mut self, frame: &'a [u8]) -> StreamResult<Event<'a>> {
        match self.state {
            StreamState::Poisoned(_) => return Err(StreamError::Poisoned),
            StreamState::AwaitDescriptor => {
                if frame.len() < 5 || frame[0] != FRAME_DESCRIPTOR {
                    return Err(self.poison(StreamError::UnexpectedFrame));
                }
                if rd32(frame, 1) as usize != frame.len() - 5 {
                    return Err(self.poison(StreamError::FrameSizeLie));
                }
                return self.install(&frame[5..]);
            }
            StreamState::Ready | StreamState::Receiving => {}
            _ => return Err(StreamError::BadState),
        }
        let result = match frame.first() {
            Some(&FRAME_CHUNK) => self.on_chunk(frame),
            Some(&FRAME_CHUNK_TABLE) => self.on_table(frame),
            Some(&FRAME_DESCRIPTOR) => self.on_descriptor_again(frame),
            _ => Err(self.fault(StreamError::UnexpectedFrame, None, 0)),
        };
        if result.is_ok() && self.state == StreamState::Ready {
            self.state = StreamState::Receiving;
        }
        result
    }

    /// Count an exact repeat of something already verified against the cap.
    pub(super) fn count_duplicate(&mut self, seg_id: u64, chunk_index: u32) -> StreamResult<()> {
        self.duplicates_ignored = self.duplicates_ignored.saturating_add(1);
        if self.duplicates_ignored > self.duplicate_cap {
            return Err(self.poison_at(StreamError::DuplicateFlood, Some(seg_id), chunk_index));
        }
        Ok(())
    }

    /// A descriptor frame after admission: ignored if byte-identical, a
    /// counted fault if it differs.
    fn on_descriptor_again<'a>(&mut self, f: &'a [u8]) -> StreamResult<Event<'a>> {
        if f.len() < 5 || rd32(f, 1) as usize != f.len() - 5 {
            return Err(self.poison(StreamError::FrameSizeLie));
        }
        let same = f.len() - 5 <= self.policy.max_descriptor_bytes
            && super::commit::descriptor_hash(&f[5..])
                == self.desc.as_ref().expect("installed").descriptor_hash;
        if !same {
            return Err(self.fault(StreamError::UnexpectedFrame, None, 0));
        }
        self.count_duplicate(0, 0)?;
        Ok(Event::DuplicateDescriptor)
    }

    fn on_table<'a>(&mut self, f: &'a [u8]) -> StreamResult<Event<'a>> {
        if f.len() < 13 {
            return Err(self.poison(StreamError::FrameSizeLie));
        }
        let (seg_id, n) = (rd64(f, 1), rd32(f, 9));
        if (f.len() - 13) as u64 != 32 * u64::from(n) {
            return Err(self.poison_at(StreamError::FrameSizeLie, Some(seg_id), 0));
        }
        let Some(i) = self.desc.as_ref().and_then(|d| d.find(seg_id)) else {
            return Err(self.fault(StreamError::UnexpectedFrame, Some(seg_id), 0));
        };
        let s = &self.segs[i];
        if s.n <= 1 || s.leaves.is_some() || s.done {
            return Err(self.fault(StreamError::UnexpectedFrame, Some(seg_id), 0));
        }
        if n != s.n {
            return Err(self.poison_at(StreamError::FrameSizeLie, Some(seg_id), 0));
        }
        let (file_id, want) = {
            let d = self.desc.as_ref().expect("descriptor installed");
            (d.header.file_id, d.entries[i].chunk_table_hash)
        };
        if self.table_bytes + (f.len() as u64 - 13) > self.policy.max_table_bytes {
            return Err(self.fault(StreamError::LimitExceeded, Some(seg_id), 0));
        }
        let ok = chunk_list_hash_flat(&file_id, seg_id, &f[13..])
            .is_some_and(|h| bool::from(h.ct_eq(&want)));
        if !ok {
            return Err(self.fault(StreamError::TableHashMismatch, Some(seg_id), 0));
        }
        self.table_bytes += f.len() as u64 - 13;
        self.segs[i].leaves = Some(f[13..].to_vec());
        Ok(Event::TableVerified { seg_id })
    }

    /// For storage-capable consumers that received chunks out of file order:
    /// re-read the persisted body in file order, check **every chunk against
    /// the signed leaf and table commitments** (so the confirming bytes must
    /// equal the streamed bytes) and then check `SHA-256 == rvf_identity`.
    /// `rvf_identity` is itself a signer assertion: this proves the body matches
    /// what the signer committed to, not that the signer's claim names the
    /// package the host meant (that is what `expected_identity` pins). `read_at(offset, buf)` must fill `buf` or
    /// return `false`. Uses a 64 KiB buffer. A mismatch poisons the stream.
    ///
    /// # Errors
    ///
    /// [`StreamError::BadState`] unless the stream completed with an
    /// `Unverifiable` identity, [`StreamError::IdentityMismatch`] on mismatch.
    ///
    /// # Panics
    ///
    /// Never in practice: the descriptor is installed whenever the state is
    /// `Complete`.
    pub fn finish_identity(
        &mut self,
        mut read_at: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> StreamResult<()> {
        if self.state != StreamState::CompleteUnverified
            || self.identity_status != Some(IdentityStatus::Unverifiable)
        {
            return Err(StreamError::BadState);
        }
        let (h, entries) = {
            let d = self.desc.as_ref().expect("descriptor installed");
            (d.header, d.entries.clone())
        };
        let mut body_hash = IdentityTracker::new(h.body_len, 65536, true);
        let mut buf = alloc::vec![0u8; 65536];
        // Re-verify the persisted body against the *signed commitments*, chunk
        // by chunk, while hashing it in file order. Reading is streamed in
        // 64 KiB pieces whatever the chunk size, so memory stays bounded even
        // for the segment-granular profile.
        for (i, e) in entries.iter().enumerate() {
            let n = self.segs[i].n;
            // Finished segments no longer hold their chunk table, so rebuild
            // the leaf list from the persisted bytes (32 bytes per chunk, one
            // segment at a time) and compare it with the signed commitment.
            let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(n as usize);
            for idx in 0..n {
                let len = h.chunk_len(e.stored_len, idx).unwrap_or(0);
                let start = e.body_offset + h.chunk_size().map_or(0, |cs| u64::from(idx) * cs);
                let mut leaf = Sha256::new();
                leaf.update([super::commit::LEAF_TAG]);
                leaf.update(h.file_id);
                leaf.update(e.seg_id.to_le_bytes());
                leaf.update(idx.to_le_bytes());
                leaf.update(len.to_le_bytes());
                let mut done = 0u64;
                while done < len {
                    let k = (len - done).min(buf.len() as u64) as usize;
                    if !read_at(start + done, &mut buf[..k]) {
                        return Err(StreamError::BadState);
                    }
                    leaf.update(&buf[..k]);
                    body_hash.update(&buf[..k]);
                    done += k as u64;
                }
                leaves.push(leaf.finalize().into());
            }
            let got = if n == 1 {
                leaves[0]
            } else {
                super::commit::chunk_list_hash(&h.file_id, e.seg_id, &leaves)
            };
            if !bool::from(got.ct_eq(&e.chunk_table_hash)) {
                // The persisted body is not the one that was streamed.
                self.force_poison(StreamError::ChunkHashMismatch, Some(e.seg_id), 0);
                return Err(StreamError::ChunkHashMismatch);
            }
        }
        let confirmed = body_hash.feasible
            && body_hash
                .digest()
                .is_some_and(|got| bool::from(got.ct_eq(&h.rvf_identity)));
        if !confirmed {
            // Explicit retroactive revocation of an unconfirmed artifact.
            self.force_poison(StreamError::IdentityMismatch, None, 0);
            return Err(StreamError::IdentityMismatch);
        }
        self.identity_status = Some(IdentityStatus::Verified);
        self.state = StreamState::Complete;
        Ok(())
    }
}
