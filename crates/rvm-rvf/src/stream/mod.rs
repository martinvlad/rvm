//! Verified streaming admission of an RVF body (ADR-160, RuVector ADR-353).
//!
//! A signed **stream descriptor** (RVSD) commits to every byte of an unchanged
//! RVF body. [`StreamVerifier`] verifies the descriptor, then releases body
//! bytes as [`VerifiedChunk`]s only after their SHA-256 leaf hash matched the
//! descriptor and every stage named in the segment's `requires_mask` is fully
//! verified. Nothing that fails a hash is ever handed to a consumer.
//!
//! This module restates the RVSD wire format; it does not depend on
//! RuVector's `rvf-wire`. The two implementations are held in step by shared
//! known-answer vectors (`tests/vectors/rvsd-v1-vectors.json`).
//!
//! | Piece | Role |
//! |---|---|
//! | [`decode_descriptor`] | parse and authenticate the descriptor (only parser of unauthenticated bytes) |
//! | [`StreamVerifier`] | the receiver state machine, push-style, one frame at a time |
//! | [`FrameReader`] | reassemble frames from arbitrary byte splits, size-checked before buffering |
//! | [`SegmentChecker`] / [`StreamAdmission`] | the ADR-155 loading rules, applied incrementally to released bytes |
//! | [`witness`] | one witness record per descriptor, segment and poison event |
//!
//! ## Allocation
//!
//! Memory is bounded by the verified descriptor and the receiver policy, never
//! by a size a frame claims: the descriptor (at most
//! [`StreamPolicy::max_descriptor_bytes`], plus a signed-message copy of the
//! same size while it is checked), one small record per segment, and the leaf
//! list of each segment whose chunk table was accepted but which is not yet
//! fully verified (at most [`StreamPolicy::max_pending_table_bytes`]). The
//! verifier never buffers a chunk: a released chunk borrows the caller's frame.

#![allow(clippy::many_single_char_names)]

mod admission;
mod chunk;
mod commit;
mod descriptor;
mod error;
mod events;
mod frame;
mod segment;
mod verifier;
pub mod witness;

#[cfg(any(test, feature = "testkit"))]
pub mod builder;

pub use admission::{AdmissionError, AdmissionEvent, StreamAdmission};
pub use commit::{
    chunk_list_hash, chunk_list_hash_flat, descriptor_hash, leaf_hash, signed_message,
    signer_key_id, verify_descriptor_signature, LEAF_TAG, SIG_DOMAIN, SIG_LEN, TABLE_TAG,
};
pub use descriptor::{
    decode_descriptor, descriptor_len, StreamEntry, StreamHeader, VerifiedDescriptor,
    CHUNK_LOG2_MAX, CHUNK_LOG2_MIN, CHUNK_LOG2_SEGMENT, ENTRY_SIZE, FLAGS_KNOWN, FLAG_CHUNKED,
    FLAG_IDENTITY_PRESENT, FLAG_REQUIRE_COMPLETE_BEFORE_EXEC, HEADER_SIZE, MAGIC, MAX_STAGES,
    SEG_TYPE_ROOT_PAGE, TRAILER_SIZE, VERSION,
};
pub use error::{StreamError, StreamResult};
pub use events::{Event, IdentityStatus, PoisonInfo, StreamState, VerifiedChunk};
pub use frame::{
    chunk_frame, descriptor_frame, table_frame, FrameReader, FrameTarget, FRAME_CHUNK,
    FRAME_CHUNK_TABLE, FRAME_DESCRIPTOR,
};
pub use verifier::StreamVerifier;

use crate::policy::SizePolicy;

/// Epoch pin lookup by `file_id`.
pub type EpochPinFn<'a> = dyn Fn(&[u8; 16]) -> Option<EpochPin> + 'a;

/// The highest accepted `(epoch, descriptor hash)` for one `file_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochPin {
    /// Highest accepted epoch.
    pub epoch: u64,
    /// Hash of the descriptor accepted at that epoch, when known. At an equal
    /// epoch a descriptor with a different hash is a conflict.
    pub descriptor_hash: Option<[u8; 32]>,
}

/// Receiver policy for descriptors and streams.
#[derive(Clone, Copy)]
pub struct StreamPolicy<'a> {
    /// Largest descriptor accepted (default 1 MiB).
    pub max_descriptor_bytes: usize,
    /// Largest `seg_count` (default 16384); also bounded by `size.max_segments`.
    pub max_segments: u32,
    /// Largest `stored_len` of one segment (default 1 GiB).
    pub max_segment_bytes: u64,
    /// Largest declared `uncompressed_len` of one segment (default 4 GiB).
    pub max_uncompressed_len: u64,
    /// Most bytes of accepted-but-unconsumed chunk-table leaves (default 16 MiB).
    pub max_pending_table_bytes: u64,
    /// Most segments whose first chunk arrived but which are not yet fully
    /// received, as far as admission is concerned (default 256).
    pub max_open_segments: usize,
    /// Signed class totals and container cap (ADR-155 section 4). Class totals
    /// are checked against each segment's `stored_len`, which is at least its
    /// payload length, so this prefilter is never looser than [`crate::verify`].
    pub size: SizePolicy,
    /// Trusted Ed25519 public keys, matched by `signer_key_id`.
    pub trusted_keys: &'a [[u8; 32]],
    /// Epoch pin lookup by `file_id`.
    pub epoch_pin: Option<&'a EpochPinFn<'a>>,
    /// Trusted clock in ns; `expires_ns` is enforced only when set.
    pub now_ns: Option<u64>,
    /// Expected `policy_hash`; enforced only when set.
    pub expected_policy_hash: Option<[u8; 32]>,
    /// Counted faults tolerated before the stream is poisoned (default 4).
    pub fault_budget: u32,
}

impl<'a> StreamPolicy<'a> {
    /// The fail-closed defaults, trusting `trusted_keys`.
    #[must_use]
    pub const fn new(trusted_keys: &'a [[u8; 32]]) -> Self {
        Self {
            max_descriptor_bytes: 1 << 20,
            max_segments: 16384,
            max_segment_bytes: 1 << 30,
            max_uncompressed_len: 1 << 32,
            max_pending_table_bytes: 16 << 20,
            max_open_segments: 256,
            size: SizePolicy::FAIL_CLOSED,
            trusted_keys,
            epoch_pin: None,
            now_ns: None,
            expected_policy_hash: None,
            fault_budget: 4,
        }
    }

    /// Upper bound on bytes allocated while decoding a descriptor: the entry
    /// vector, the index vector and the signed-message copy.
    #[must_use]
    pub const fn descriptor_alloc_bound(&self) -> usize {
        4 * self.max_descriptor_bytes + 4096
    }
}

impl core::fmt::Debug for StreamPolicy<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StreamPolicy")
            .field("max_descriptor_bytes", &self.max_descriptor_bytes)
            .field("max_segments", &self.max_segments)
            .field("size", &self.size)
            .field("trusted_keys", &self.trusted_keys.len())
            .field("fault_budget", &self.fault_budget)
            .finish_non_exhaustive()
    }
}
