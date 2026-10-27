//! Typed refusal reasons for the streaming verifier.
//!
//! The numeric codes are RuVector `ErrorCode` values (`0x0802`,
//! `0x0805..=0x0819`, ADR-353) so a refusal means the same thing on both sides
//! of the wire. The reason names match the shared known-answer vectors.

use core::fmt;
use rvm_types::RvmError;

/// Why a descriptor or a frame was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StreamError {
    /// The signer's key id is not in the receiver's trust set.
    UnknownSigner = 0x0802,
    /// The descriptor is shorter than its own header says.
    DescriptorTruncated = 0x0805,
    /// The descriptor magic is not `RVSD`.
    BadMagic = 0x0806,
    /// The descriptor version is not 1.
    UnsupportedVersion = 0x0807,
    /// Unknown flags, algorithms, chunk size or non-zero reserved bytes.
    BadFlags = 0x0808,
    /// A receiver policy limit is exceeded.
    LimitExceeded = 0x0809,
    /// The segment table breaks an invariant.
    TableInvalid = 0x080A,
    /// The descriptor signature does not verify.
    BadSignature = 0x080B,
    /// The descriptor epoch is below the pinned epoch (replay).
    StaleEpoch = 0x080C,
    /// The pinned epoch with different descriptor content.
    EpochConflict = 0x080D,
    /// The descriptor has expired on a trusted clock.
    Expired = 0x080E,
    /// The descriptor `policy_hash` differs from the expected one.
    PolicyMismatch = 0x080F,
    /// A chunk does not match its committed leaf hash.
    ChunkHashMismatch = 0x0810,
    /// A chunk table does not match its committed hash.
    TableHashMismatch = 0x0811,
    /// A duplicate, out-of-order, unknown or malformed frame.
    UnexpectedFrame = 0x0812,
    /// A frame size contradicts the signed descriptor.
    FrameSizeLie = 0x0813,
    /// A chunk arrived before the stages in its `requires_mask` were verified.
    RequirementsUnmet = 0x0814,
    /// `SHA-256(body)` differs from the signed `rvf_identity`.
    IdentityMismatch = 0x0815,
    /// An executable or index segment uses a non-cryptographic checksum.
    WeakChecksum = 0x0816,
    /// The stream is poisoned and accepts nothing.
    Poisoned = 0x0817,
    /// A frame was pushed in a state that cannot accept it.
    BadState = 0x0819,
    /// More duplicate frames than the policy allows.
    DuplicateFlood = 0x081A,
    // ---- RVM-local codes (not in RuVector's `ErrorCode`): 0x0F00.. ----
    /// A released segment is not a well-formed RVF segment (ADR-155 structure).
    SegmentMalformed = 0x0F00,
    /// A segment header contradicts its signed table entry.
    SegmentMismatch = 0x0F01,
    /// Admission needs `rvf_identity` and the descriptor carries none.
    IdentityRequired = 0x0F02,
    /// More segments were open at once than policy allows.
    TooManyOpenSegments = 0x0F03,
    /// The descriptor sets `expires_ns` and the policy has no trusted clock.
    ClockRequired = 0x0F04,
}

impl StreamError {
    /// The RuVector numeric error code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// The reason name used by the shared vectors (`UnknownSigner` or
    /// `Stream<Name>`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::UnknownSigner => "UnknownSigner",
            Self::DescriptorTruncated => "StreamDescriptorTruncated",
            Self::BadMagic => "StreamBadMagic",
            Self::UnsupportedVersion => "StreamUnsupportedVersion",
            Self::BadFlags => "StreamBadFlags",
            Self::LimitExceeded => "StreamLimitExceeded",
            Self::TableInvalid => "StreamTableInvalid",
            Self::BadSignature => "StreamBadSignature",
            Self::StaleEpoch => "StreamStaleEpoch",
            Self::EpochConflict => "StreamEpochConflict",
            Self::Expired => "StreamExpired",
            Self::PolicyMismatch => "StreamPolicyMismatch",
            Self::ChunkHashMismatch => "StreamChunkHashMismatch",
            Self::TableHashMismatch => "StreamTableHashMismatch",
            Self::UnexpectedFrame => "StreamUnexpectedFrame",
            Self::FrameSizeLie => "StreamFrameSizeLie",
            Self::RequirementsUnmet => "StreamRequirementsUnmet",
            Self::IdentityMismatch => "StreamIdentityMismatch",
            Self::WeakChecksum => "StreamWeakChecksum",
            Self::Poisoned => "StreamPoisoned",
            Self::BadState => "StreamBadState",
            Self::DuplicateFlood => "StreamDuplicateFlood",
            Self::SegmentMalformed => "RvmSegmentMalformed",
            Self::SegmentMismatch => "RvmSegmentMismatch",
            Self::IdentityRequired => "RvmIdentityRequired",
            Self::TooManyOpenSegments => "RvmTooManyOpenSegments",
            Self::ClockRequired => "RvmClockRequired",
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (0x{:04x})", self.name(), self.code())
    }
}

impl From<StreamError> for RvmError {
    fn from(e: StreamError) -> Self {
        match e {
            StreamError::LimitExceeded | StreamError::TooManyOpenSegments => {
                RvmError::ResourceLimitExceeded
            }
            StreamError::UnsupportedVersion | StreamError::BadFlags => RvmError::Unsupported,
            _ => RvmError::ProofInvalid,
        }
    }
}

/// Result alias for streaming operations.
pub type StreamResult<T> = core::result::Result<T, StreamError>;
