//! Public vocabulary of the stream verifier: states, identity status, poison
//! information and the events a pushed frame can produce.

use super::error::StreamError;

/// Receiver state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Waiting for the descriptor.
    AwaitDescriptor,
    /// Descriptor verified; no body frame accepted yet.
    Ready,
    /// Body frames are being accepted.
    Receiving,
    /// Input ended early. Resumable at chunk granularity; never `Complete`.
    Suspended,
    /// Every segment verified, the byte count matches and the body's SHA-256
    /// equals the signed `rvf_identity`. Terminal.
    Complete,
    /// Every segment verified and the byte count matches, but the chunks did not
    /// arrive in file order, so the identity is not confirmed. Moves to
    /// `Complete` or `Poisoned` when `finish_identity` runs.
    CompleteUnverified,
    /// The descriptor was refused. Terminal.
    Rejected(StreamError),
    /// A hash, size or fault-budget failure. Terminal: revoke, terminate,
    /// drop derived state.
    Poisoned(StreamError),
}

impl StreamState {
    /// Whether no further frame can ever be accepted.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Rejected(_) | Self::Poisoned(_) | Self::Complete | Self::CompleteUnverified
        )
    }
}

/// Outcome of the whole-body identity check at completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityStatus {
    /// `SHA-256` over the released bytes in file order equals `rvf_identity`.
    Verified,
    /// Chunks did not arrive in file order; the consumer may re-read its
    /// persisted body and call [`super::StreamVerifier::finish_identity`].
    Unverifiable,
    /// The descriptor carries no identity (`identity_present` clear).
    NotPresent,
}

/// Where and why a stream was poisoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoisonInfo {
    /// The segment involved, when the failure had one.
    pub seg_id: Option<u64>,
    /// The chunk index involved (0 when none).
    pub chunk_index: u32,
    /// The reason.
    pub reason: StreamError,
}

/// A chunk whose leaf hash matched and whose required stages are verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedChunk<'a> {
    /// Segment id.
    pub seg_id: u64,
    /// Segment type from the signed table.
    pub seg_type: u8,
    /// Chunk index within the segment.
    pub chunk_index: u32,
    /// Offset of the first byte within the stored segment.
    pub segment_offset: u64,
    /// Offset of the first byte within the body.
    pub body_offset: u64,
    /// The verified bytes.
    pub bytes: &'a [u8],
}

/// Result of accepting one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// The descriptor was accepted.
    DescriptorVerified {
        /// SHA-256 of the signed descriptor.
        descriptor_hash: [u8; 32],
        /// Number of segments.
        seg_count: u32,
        /// Total body bytes.
        body_len: u64,
    },
    /// A chunk table matched its commitment.
    TableVerified {
        /// Segment id.
        seg_id: u64,
    },
    /// A chunk that hashes to an already-verified leaf was repeated. Nothing
    /// was released and no fault was counted; the repeat is counted against
    /// `max_duplicate_frames`.
    Duplicate {
        /// Segment id.
        seg_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// A chunk of an already-finished multi-chunk segment arrived with the
    /// right length, but its chunk table was freed when the segment finished,
    /// so its bytes can no longer be checked. It is counted against the
    /// duplicate budget and is never released or applied.
    Unverified {
        /// Segment id.
        seg_id: u64,
        /// Chunk index.
        chunk_index: u32,
    },
    /// The descriptor frame was repeated byte for byte after admission.
    DuplicateDescriptor,
    /// A chunk was released.
    Chunk {
        /// The released bytes.
        chunk: VerifiedChunk<'a>,
        /// This chunk completed its segment.
        segment_verified: bool,
        /// This chunk completed its stage.
        stage_verified: Option<u8>,
        /// Set when this chunk completed the stream.
        complete: Option<IdentityStatus>,
    },
}
