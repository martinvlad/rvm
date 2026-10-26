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

#[derive(Clone)]
pub(super) struct IdentityTracker {
    pub(super) hasher: Sha256,
    pub(super) pos: u64,
    pub(super) feasible: bool,
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
    pub(super) pending_table_bytes: u64,
    pub(super) identity: Option<IdentityTracker>,
    pub(super) identity_status: Option<IdentityStatus>,
    pub(super) max_chunk_len: u64,
    pub(super) max_table_payload: u64,
    pub(super) poison_info: Option<PoisonInfo>,
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
            pending_table_bytes: 0,
            identity: None,
            identity_status: None,
            max_chunk_len: 0,
            max_table_payload: 0,
            poison_info: None,
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
        if !matches!(self.state, StreamState::Rejected(_)) {
            self.state = StreamState::Poisoned(reason);
            if self.poison_info.is_none() {
                self.poison_info = Some(PoisonInfo {
                    seg_id: seg,
                    chunk_index: chunk,
                    reason,
                });
            }
        }
        reason
    }

    pub(super) fn fault(
        &mut self,
        reason: StreamError,
        seg: Option<u64>,
        chunk: u32,
    ) -> StreamError {
        self.faults += 1;
        if self.faults > self.policy.fault_budget {
            self.poison_at(reason, seg, chunk);
        }
        reason
    }

    /// Input ended before `Complete`: move to `Suspended`.
    pub fn end_of_input(&mut self) -> StreamState {
        if matches!(self.state, StreamState::Receiving | StreamState::Ready) {
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
        self.left = d.entries.len();
        if h.flags & FLAG_IDENTITY_PRESENT != 0 {
            self.identity = Some(IdentityTracker {
                hasher: Sha256::new(),
                pos: 0,
                feasible: true,
            });
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
            _ => Err(self.fault(StreamError::UnexpectedFrame, None, 0)),
        };
        if result.is_ok() && self.state == StreamState::Ready {
            self.state = StreamState::Receiving;
        }
        result
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
        let ok = chunk_list_hash_flat(&file_id, seg_id, &f[13..])
            .is_some_and(|h| bool::from(h.ct_eq(&want)));
        if !ok {
            return Err(self.fault(StreamError::TableHashMismatch, Some(seg_id), 0));
        }
        let bytes = f.len() as u64 - 13;
        if self.pending_table_bytes + bytes > self.policy.max_pending_table_bytes {
            return Err(self.poison_at(StreamError::LimitExceeded, Some(seg_id), 0));
        }
        self.pending_table_bytes += bytes;
        self.segs[i].leaves = Some(f[13..].to_vec());
        Ok(Event::TableVerified { seg_id })
    }

    /// For storage-capable consumers that received chunks out of file order:
    /// re-read the persisted body in file order and check
    /// `SHA-256 == rvf_identity`. `read_at(offset, buf)` must fill `buf` or
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
        if self.state != StreamState::Complete
            || self.identity_status != Some(IdentityStatus::Unverifiable)
        {
            return Err(StreamError::BadState);
        }
        let h = self.desc.as_ref().expect("descriptor installed").header;
        let mut hasher = Sha256::new();
        let mut buf = alloc::vec![0u8; 65536];
        let mut pos = 0u64;
        while pos < h.body_len {
            let n = (h.body_len - pos).min(buf.len() as u64) as usize;
            if !read_at(pos, &mut buf[..n]) {
                return Err(StreamError::BadState);
            }
            hasher.update(&buf[..n]);
            pos += n as u64;
        }
        let got: [u8; 32] = hasher.finalize().into();
        if !bool::from(got.ct_eq(&h.rvf_identity)) {
            return Err(self.poison_at(StreamError::IdentityMismatch, None, 0));
        }
        self.identity_status = Some(IdentityStatus::Verified);
        Ok(())
    }
}
