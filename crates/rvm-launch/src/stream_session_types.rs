//! Vocabulary of [`StreamSession`](crate::StreamSession): its state, events,
//! errors and the report a consumer acts on when a stream is poisoned.

use rvm_rvf::stream::{AdmissionError, PoisonInfo};
use rvm_wasm::ModuleError;

/// Where the session stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Frames are being accepted.
    Receiving,
    /// Every segment verified and the package passed ADR-155 admission.
    Complete,
    /// The stream completed but the package or a module was refused.
    Failed,
    /// The stream is poisoned. Terminal.
    Poisoned,
}

/// Why the session refused something.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// The stream or admission layer refused a frame.
    Stream(AdmissionError),
    /// A streamed module failed validation or exceeded policy.
    Module {
        /// The segment that carried it.
        seg_id: u64,
        /// What the validator said.
        error: ModuleError,
    },
    /// The stream completed but the package did not pass ADR-155 admission.
    PackageRefused,
    /// A module was requested before the stream completed.
    NotComplete,
    /// No validated module exists for that segment.
    NoSuchModule,
    /// The buffered bytes do not match the verified executable identity.
    IdentityMismatch,
    /// The stream completed with an identity that nothing has verified
    /// (stage-ordered delivery): call `finish_identity` first.
    IdentityUnverified,
    /// Installing the package's capabilities failed.
    Install(rvm_rvf::RvfError),
    /// The session failed or was poisoned earlier.
    Unusable,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Stream(e) => write!(f, "{e}"),
            Self::Module { seg_id, error } => write!(f, "module in segment {seg_id}: {error}"),
            Self::PackageRefused => f.write_str("the package did not pass admission"),
            Self::NotComplete => f.write_str("the stream is not complete"),
            Self::NoSuchModule => f.write_str("no validated module for that segment"),
            Self::IdentityMismatch => {
                f.write_str("module bytes do not match the verified executable identity")
            }
            Self::IdentityUnverified => {
                f.write_str("the package identity has not been verified; call finish_identity")
            }
            Self::Install(e) => write!(f, "installing capabilities: {e}"),
            Self::Unusable => f.write_str("the session failed or was poisoned"),
        }
    }
}

impl From<AdmissionError> for SessionError {
    fn from(e: AdmissionError) -> Self {
        Self::Stream(e)
    }
}

/// What a frame did, in terms a transport driver cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The descriptor was accepted.
    Descriptor,
    /// A chunk table was accepted.
    Table,
    /// The descriptor was repeated byte for byte and ignored.
    DuplicateDescriptor,
    /// A repeat of an already-verified chunk was ignored.
    Duplicate {
        /// Its segment.
        seg_id: u64,
    },
    /// A chunk was released.
    Chunk {
        /// Its segment.
        seg_id: u64,
        /// This chunk completed the segment.
        segment_verified: bool,
        /// This chunk completed the stage.
        stage_verified: Option<u8>,
    },
    /// The last chunk arrived and admission passed.
    Complete,
}

/// Why and where a stream was poisoned, for a consumer to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoisonReport {
    /// The descriptor the stream ran under. `None` when the poison happened
    /// before any descriptor was authenticated: such a stream granted nothing
    /// and started nothing, and nothing outside the session is affected.
    pub descriptor_hash: Option<[u8; 32]>,
    /// The segment, chunk and reason.
    pub info: PoisonInfo,
}

impl PoisonReport {
    /// Whether the stream had authenticated its descriptor.
    #[must_use]
    pub const fn authenticated(&self) -> bool {
        self.descriptor_hash.is_some()
    }
}
