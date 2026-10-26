//! A module that is safe to start: verified, validated, complete.

use alloc::vec::Vec;
use rvm_rvf::VerifiedExecutable;
use rvm_wasm::ValidatedModule;

/// A WASM module that has passed every gate on the stream path.
///
/// The only constructor is crate-private and is called by exactly one place,
/// [`StreamSession::take_module`](crate::StreamSession::take_module), which
/// requires that
///
/// 1. the stream is `Complete` and admission built a passing report;
/// 2. the module's segment was `SegmentVerified` (every chunk matched its
///    signed commitment, its signature and content hash held);
/// 3. the incremental validator finished without error under the policy; and
/// 4. the buffered bytes match the verified executable's length and SHA-256.
///
/// [`Instance::start_verified`](crate::Instance::start_verified) takes it by
/// value, so the module is moved, not shared, into the instance's
/// partition-private storage; nothing the transport does to its own buffer
/// afterwards can change it. There is no `Clone`, no public constructor and no
/// way to build one from raw bytes.
///
/// ```compile_fail
/// use rvm_launch::VerifiedModule;
/// // Fields are private and there is no constructor: raw bytes cannot be
/// // promoted to a verified module.
/// let _ = VerifiedModule { bytes: vec![0] };
/// ```
#[derive(Debug)]
pub struct VerifiedModule {
    bytes: Vec<u8>,
    executable: VerifiedExecutable,
    validated: ValidatedModule,
    rvf_identity: [u8; 32],
    descriptor_hash: [u8; 32],
}

impl VerifiedModule {
    pub(crate) fn new(
        bytes: Vec<u8>,
        executable: VerifiedExecutable,
        validated: ValidatedModule,
        rvf_identity: [u8; 32],
        descriptor_hash: [u8; 32],
    ) -> Self {
        Self {
            bytes,
            executable,
            validated,
            rvf_identity,
            descriptor_hash,
        }
    }

    pub(crate) fn into_bytes(self) -> (Vec<u8>, VerifiedExecutable, [u8; 32], [u8; 32]) {
        (
            self.bytes,
            self.executable,
            self.rvf_identity,
            self.descriptor_hash,
        )
    }

    /// The verified module bytes, read-only.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The identity (segment, length, SHA-256) the bytes were bound to.
    #[must_use]
    pub const fn executable(&self) -> &VerifiedExecutable {
        &self.executable
    }

    /// What validation found.
    #[must_use]
    pub const fn validated(&self) -> &ValidatedModule {
        &self.validated
    }

    /// The `rvfIdentity` of the package the module came from.
    #[must_use]
    pub const fn rvf_identity(&self) -> &[u8; 32] {
        &self.rvf_identity
    }

    /// The hash of the signed descriptor the module streamed under.
    #[must_use]
    pub const fn descriptor_hash(&self) -> &[u8; 32] {
        &self.descriptor_hash
    }
}
