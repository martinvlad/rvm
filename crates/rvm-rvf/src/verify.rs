//! Verify-before-load: identity, root manifest, per-segment hashes,
//! signatures, size policy, and capability mapping.
//!
//! Two design points are load-bearing rather than stylistic.
//!
//! **Failure returns a report, not an error.** ADR-284 §1.9 calls for a
//! witness record for *every* verification result, and a refusal is a result.
//! Returning `Err` on the first bad hash would discard exactly the evidence
//! the refusal needs to be auditable. So [`verify`] returns `Ok(report)`
//! whenever the container parses, with `report.ok == false` and a record per
//! check. `Err` is reserved for bytes that are not an RVF at all. Callers who
//! want the failure as an error call [`VerificationReport::into_result`].
//!
//! **Nothing here executes anything.** The only bytes read from an executable
//! segment are read to hash them (ADR-284 §1.7).

use crate::capability::CapabilityMapping;
use crate::container::walk;
use crate::detail::DetailCode;
use crate::error::{RvfError, RvfResult};
use crate::format::SEG_TYPE_META;
use crate::hash::sha256;
use crate::policy::{SizePolicy, SizeViolation};
use crate::report::{
    build_report, facts_from_buffer, Declarations, Delivery, ReportInput, SegmentFacts,
};
use alloc::vec::Vec;

/// Which check a record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CheckKind {
    /// The container's SHA-256 matches the caller's expected identity.
    Identity = 0,
    /// A root manifest segment is present.
    RootManifestPresent = 1,
    /// A segment's payload matches the content hash in its header.
    ContentHash = 2,
    /// An executable segment carries a signature at all.
    ExecutableSigned = 3,
    /// A segment's Ed25519 signature verifies against a trusted key.
    Signature = 4,
    /// The container fits inside the signed size policy.
    SizePolicy = 5,
    /// Declared capability classes map into `rvm-cap`.
    CapabilityMapping = 6,
    /// A package that declares a stream profile was not delivered as a verified
    /// stream, and signed policy does not permit buffered loading.
    StreamProfile = 7,
    /// A stream descriptor was verified or refused (ADR-353 section 5).
    StreamDescriptor = 8,
    /// A stream segment was fully verified chunk by chunk.
    StreamSegment = 9,
    /// A stream was poisoned: a hash, size or fault-budget failure.
    StreamPoisoned = 10,
    /// Every segment of a stream verified and the byte count matched.
    StreamComplete = 11,
    /// A streamed executable module passed or failed incremental validation.
    StreamModule = 12,
    /// A stream frame was refused and counted against the fault budget.
    StreamFault = 13,
}

/// The result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    /// The check passed.
    Pass = 0,
    /// The check failed. Any failure makes the whole report `ok == false`.
    Fail = 1,
    /// The check did not apply, or could not run. A skip never makes a report
    /// fail on its own, and is never treated as a pass.
    Skip = 2,
}

/// One verification result. Every check performed produces exactly one,
/// whether it passed, failed, or was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationRecord {
    /// Which check this records.
    pub check: CheckKind,
    /// Its result.
    pub outcome: Outcome,
    /// Stream position of the segment checked, for per-segment checks.
    pub segment_index: Option<usize>,
    /// Ordinal of the segment checked, for per-segment checks.
    pub segment_id: Option<u64>,
    /// Type discriminator of the segment checked, or 0 for container-level.
    pub segment_type: u8,
    /// Why the check produced this outcome.
    pub detail: DetailCode,
}

/// Identity of executable payload bytes examined during RVF verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedExecutable {
    /// Ordinal assigned by the RVF writer.
    pub segment_id: u64,
    /// RVF segment type discriminator.
    pub segment_type: u8,
    /// Exact executable payload length.
    pub byte_length: u64,
    /// SHA-256 of the executable payload bytes.
    pub sha256: [u8; 32],
}

impl VerifiedExecutable {
    /// Whether `module` is exactly the payload represented by this identity.
    #[must_use]
    pub fn matches(&self, module: &[u8]) -> bool {
        self.byte_length == module.len() as u64 && self.sha256 == sha256(module)
    }
}

/// The full result of verifying one artifact.
///
/// Carries no timestamp: two verifications of the same bytes under the same
/// options produce identical reports, which is what makes a report comparable
/// across backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// SHA-256 of the whole container — the canonical `rvfIdentity`.
    pub rvf_identity: [u8; 32],
    /// Container size in bytes.
    pub byte_length: u64,
    /// True when no record failed.
    pub ok: bool,
    /// How many segments were examined.
    pub segment_count: usize,
    /// Executable payload identities retained for verify-before-load binding.
    /// They become execution-eligible only when [`Self::ok`] is true.
    pub executables: Vec<VerifiedExecutable>,
    /// One record per check performed, in check order.
    pub records: Vec<VerificationRecord>,
    /// The default-deny capability mapping this artifact resolves to.
    ///
    /// When the capability check failed, this is the deny-everything mapping:
    /// a refused artifact grants nothing.
    pub capabilities: CapabilityMapping,
    /// Every size limit the container exceeded.
    pub size_violations: Vec<SizeViolation>,
}

impl VerificationReport {
    /// The failing records.
    #[must_use]
    pub fn failures(&self) -> Vec<&VerificationRecord> {
        self.records
            .iter()
            .filter(|r| r.outcome == Outcome::Fail)
            .collect()
    }

    /// The first failing record for `check`, if any.
    #[must_use]
    pub fn first_failure(&self, check: CheckKind) -> Option<&VerificationRecord> {
        self.records
            .iter()
            .find(|r| r.outcome == Outcome::Fail && r.check == check)
    }

    /// Convert a failed report into the matching error.
    ///
    /// # Errors
    ///
    /// [`RvfError::UnsupportedCapability`] when a declared class is
    /// unrepresentable, and [`RvfError::MalformedFooter`] as the generic
    /// verification failure otherwise. Callers that need to distinguish the
    /// individual failures read [`VerificationReport::failures`] instead;
    /// this is the shorthand for "refuse and say roughly why".
    pub fn into_result(self) -> RvfResult<Self> {
        if self.ok {
            return Ok(self);
        }
        if self.first_failure(CheckKind::CapabilityMapping).is_some() {
            if self.records.iter().any(|record| {
                record.check == CheckKind::CapabilityMapping
                    && record.detail == DetailCode::CapabilityUnknown
            }) {
                return Err(RvfError::UnknownCapability);
            }
            // The specific class is already in the record set; report the
            // first declared class RVM cannot represent.
            let class = crate::capability::CapabilityClass::ALL
                .into_iter()
                .find(|c| !c.is_representable())
                .unwrap_or(crate::capability::CapabilityClass::Clipboard);
            return Err(RvfError::UnsupportedCapability(class));
        }
        Err(RvfError::MalformedFooter)
    }
}

/// How to verify.
///
/// [`VerifyOptions::default`] is the strict posture: unsigned executables are
/// refused, no key is trusted until one is supplied, and the fail-closed size
/// policy applies.
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// Ed25519 public keys whose signatures are accepted. With none supplied,
    /// signature checks are recorded as skipped rather than passed — an
    /// unverifiable signature is never treated as a valid one.
    pub trusted_keys: Vec<[u8; 32]>,
    /// Permit executable segments with no signature. Off by default; exists
    /// for unsigned development builds, which are labeled as such and are not
    /// eligible for distribution.
    pub allow_unsigned_executable: bool,
    /// When set, the container's SHA-256 must equal this value.
    pub expected_identity: Option<[u8; 32]>,
    /// The signed size limits to enforce at parse time.
    pub size_policy: SizePolicy,
    /// Permit the buffered loader to accept a package that declares a stream
    /// profile ([`crate::STREAM_PROFILE_DECLARATION_KEY`]). Off by default:
    /// loading a stream-profiled package from a whole buffer skips the
    /// per-chunk commitments its publisher chose, so it needs explicit,
    /// signed-policy permission (ADR-160 item 7).
    ///
    /// The permission only takes effect together with a pinned
    /// [`Self::expected_identity`]: a stream-profiled package that arrives as an
    /// unpinned buffer is unauthenticated as to what it is.
    pub permit_buffered_stream_profile: bool,
    /// Refuse a whole-buffer package unless [`Self::expected_identity`] pins
    /// it. Set by a host whose policy says packages are stream-delivered (or
    /// that holds a descriptor for this one): the unsigned `META` line that
    /// declares a stream profile can be stripped by anyone who can change the
    /// bytes, and only the pin ties the buffer to the signed descriptor.
    pub require_pinned_identity: bool,
}

impl VerifyOptions {
    /// Strict defaults with the given trusted keys.
    #[must_use]
    pub fn with_trusted_keys(keys: Vec<[u8; 32]>) -> Self {
        Self {
            trusted_keys: keys,
            ..Self::default()
        }
    }

    /// Require the container to hash to `identity`.
    #[must_use]
    pub fn expect_identity(mut self, identity: [u8; 32]) -> Self {
        self.expected_identity = Some(identity);
        self
    }

    /// Use `policy` instead of the fail-closed default.
    #[must_use]
    pub fn with_size_policy(mut self, policy: SizePolicy) -> Self {
        self.size_policy = policy;
        self
    }
}

/// Verify an in-memory RVF container without executing any of it.
///
/// The per-segment facts are read from `data` here; the records and the report
/// are built by the same code the streaming admission uses
/// ([`crate::stream::StreamAdmission`]), so the two paths share one rule set.
///
/// # Errors
///
/// An [`RvfError`] when `data` is not a well-formed container. Verification
/// *failures* are reported in the returned value, not raised.
pub fn verify(data: &[u8], opts: &VerifyOptions) -> RvfResult<VerificationReport> {
    let segments = walk(data)?;
    let facts: Vec<SegmentFacts> = segments
        .iter()
        .map(|seg| facts_from_buffer(data, seg))
        .collect();
    let meta_payloads = segments
        .iter()
        .filter(|s| s.header.seg_type == SEG_TYPE_META && !s.header.is_encrypted())
        .map(|s| s.payload(data))
        .collect();
    Ok(build_report(
        &ReportInput {
            identity: sha256(data),
            container_bytes: data.len() as u64,
            segments: &segments,
            facts: &facts,
            meta: Declarations { meta_payloads },
            delivery: Delivery::Buffered,
        },
        opts,
    ))
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
