//! The one rule set that turns per-segment facts into a [`VerificationReport`].
//!
//! [`crate::verify()`] reads facts from a buffer it holds whole; the streaming
//! admission ([`crate::stream::StreamAdmission`]) accumulates the same facts
//! while released chunks go by. Both then call [`build_report`], so the
//! buffered and the streamed paths cannot disagree about what a record means,
//! which checks run, or in what order.

use crate::capability::{declared_classes_in, has_unknown_class_name_in, map_declared};
use crate::capability::{CapabilityClass, CapabilityMapping};
use crate::container::{root_manifest, ParsedSegment};
use crate::detail::DetailCode;
use crate::format::{
    build_signed_message, decode_signature_footer, ED25519_SIGNATURE_LENGTH, SIGNED_MESSAGE_LEN,
    SIG_ALGO_ED25519,
};
use crate::hash::{sha256, verify_content_hash};
use crate::policy::check as check_sizes;
use crate::verify::{
    CheckKind, Outcome, VerificationRecord, VerificationReport, VerifiedExecutable, VerifyOptions,
};
use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey};

/// What a segment's signature footer turned out to be.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SigFacts {
    /// The header does not set `SIGNED`.
    Unsigned,
    /// `SIGNED` is set but the footer cannot be decoded.
    Malformed,
    /// A decoded footer.
    Decoded {
        /// Signature algorithm.
        algo: u16,
        /// Declared signature length.
        length: u16,
        /// The 64 signature bytes, when the length is 64.
        signature: Option<[u8; 64]>,
        /// The canonical message the signature covers.
        message: [u8; SIGNED_MESSAGE_LEN],
    },
}

/// Everything about one segment that the loading rules look at, apart from
/// its header.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SegmentFacts {
    /// The payload matches the header's content hash.
    pub content_hash_ok: bool,
    /// The signature footer.
    pub sig: SigFacts,
    /// SHA-256 of the payload, kept for executables only.
    pub payload_sha256: Option<[u8; 32]>,
}

/// Facts for a segment of a container held whole in `data`.
pub(crate) fn facts_from_buffer(data: &[u8], seg: &ParsedSegment) -> SegmentFacts {
    let payload = seg.payload(data);
    let sig = if seg.is_signed() {
        match seg
            .footer
            .clone()
            .and_then(|r| decode_signature_footer(&data[r]).ok())
        {
            None => SigFacts::Malformed,
            Some(f) => SigFacts::Decoded {
                algo: f.sig_algo,
                length: f.sig_length,
                signature: <[u8; 64]>::try_from(f.signature).ok(),
                message: build_signed_message(&seg.header, payload),
            },
        }
    } else {
        SigFacts::Unsigned
    };
    SegmentFacts {
        content_hash_ok: verify_content_hash(&seg.header, payload),
        sig,
        payload_sha256: seg.is_executable().then(|| sha256(payload)),
    }
}

/// The plaintext metadata a container's declarations are read from.
pub(crate) struct Declarations<'a> {
    /// Unencrypted `META` payloads, in stream order.
    pub meta_payloads: Vec<&'a [u8]>,
}

/// The declaration key that marks a package as stream-profiled (ADR-160
/// item 7). Any value declares the profile; `required` is the canonical one.
///
/// The declaration cannot carry the descriptor hash: the descriptor commits to
/// the body's hash, so a body that contained the descriptor hash would be
/// circular. The binding to the descriptor is the descriptor's own
/// `rvf_identity`, which covers this very `META` line.
pub const STREAM_PROFILE_DECLARATION_KEY: &str = "rvm.stream_profile";

fn declares_stream_profile<'a>(mut payloads: impl Iterator<Item = &'a [u8]>) -> bool {
    payloads.any(|p| {
        core::str::from_utf8(p).is_ok_and(|text| {
            text.lines().any(|line| {
                line.strip_prefix(STREAM_PROFILE_DECLARATION_KEY)
                    .is_some_and(|rest| rest.starts_with('='))
            })
        })
    })
}

/// How the container was delivered, which decides the stream-profile record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// Whole buffer: a stream-profiled package needs explicit permission.
    Buffered,
    /// Through a verified stream: the profile is satisfied by construction.
    Streamed,
}

/// Inputs of [`build_report`].
pub(crate) struct ReportInput<'a> {
    /// SHA-256 of the whole container.
    pub identity: [u8; 32],
    /// Container size in bytes.
    pub container_bytes: u64,
    /// Segments in stream order (root page excluded).
    pub segments: &'a [ParsedSegment],
    /// Facts, one per segment.
    pub facts: &'a [SegmentFacts],
    /// Plaintext `META` payloads.
    pub meta: Declarations<'a>,
    /// Delivery path.
    pub delivery: Delivery,
}

const fn outcome(passed: bool) -> Outcome {
    if passed {
        Outcome::Pass
    } else {
        Outcome::Fail
    }
}

const fn container_record(
    check: CheckKind,
    outcome: Outcome,
    detail: DetailCode,
) -> VerificationRecord {
    VerificationRecord {
        check,
        outcome,
        segment_index: None,
        segment_id: None,
        segment_type: 0,
        detail,
    }
}

fn segment_record(
    check: CheckKind,
    outcome: Outcome,
    seg: &ParsedSegment,
    detail: DetailCode,
) -> VerificationRecord {
    VerificationRecord {
        check,
        outcome,
        segment_index: Some(seg.index),
        segment_id: Some(seg.header.segment_id),
        segment_type: seg.header.seg_type,
        detail,
    }
}

/// Run every container-level and per-segment check, in the order ADR-284 and
/// ADR-155 fix, and assemble the report.
pub(crate) fn build_report(input: &ReportInput<'_>, opts: &VerifyOptions) -> VerificationReport {
    let mut records = Vec::new();
    let segments = input.segments;

    if let Some(expected) = opts.expected_identity {
        let matches = expected == input.identity;
        records.push(container_record(
            CheckKind::Identity,
            outcome(matches),
            if matches {
                DetailCode::IdentityMatches
            } else {
                DetailCode::IdentityMismatch
            },
        ));
    }

    records.push(root_manifest_record(segments));

    let size_violations = check_sizes(input.container_bytes, segments, &opts.size_policy);
    records.push(container_record(
        CheckKind::SizePolicy,
        outcome(size_violations.is_empty()),
        if size_violations.is_empty() {
            DetailCode::WithinSizePolicy
        } else {
            DetailCode::ExceedsSizePolicy
        },
    ));

    let (capabilities, cap_record) = capability_record(&input.meta);
    records.push(cap_record);

    if declares_stream_profile(input.meta.meta_payloads.iter().copied()) {
        records.push(stream_profile_record(input.delivery, opts));
    }

    for (seg, facts) in segments.iter().zip(input.facts) {
        records.push(segment_record(
            CheckKind::ContentHash,
            outcome(facts.content_hash_ok),
            seg,
            if facts.content_hash_ok {
                DetailCode::ContentHashMatches
            } else {
                DetailCode::ContentHashMismatch
            },
        ));
        if seg.is_executable() {
            records.push(executable_signed_record(seg, opts));
        }
        if seg.is_signed() {
            records.push(signature_record(seg, &facts.sig, opts));
        }
    }

    let ok = !records.iter().any(|r| r.outcome == Outcome::Fail);
    let executables = segments
        .iter()
        .zip(input.facts)
        .filter(|(seg, _)| seg.is_executable())
        .map(|(seg, facts)| VerifiedExecutable {
            segment_id: seg.header.segment_id,
            segment_type: seg.header.seg_type,
            byte_length: seg.header.payload_length,
            sha256: facts.payload_sha256.unwrap_or([0; 32]),
        })
        .collect();
    VerificationReport {
        rvf_identity: input.identity,
        byte_length: input.container_bytes,
        ok,
        segment_count: segments.len(),
        executables,
        records,
        capabilities,
        size_violations,
    }
}

/// ADR-284 1.1: the root manifest is verified before anything else.
fn root_manifest_record(segments: &[ParsedSegment]) -> VerificationRecord {
    match root_manifest(segments) {
        Some(seg) => segment_record(
            CheckKind::RootManifestPresent,
            Outcome::Pass,
            seg,
            DetailCode::RootManifestFound,
        ),
        None => container_record(
            CheckKind::RootManifestPresent,
            Outcome::Fail,
            DetailCode::RootManifestMissing,
        ),
    }
}

fn deny_all() -> CapabilityMapping {
    map_declared(&[]).unwrap_or_else(|_| unreachable!("the empty declaration always maps"))
}

fn capability_record(meta: &Declarations<'_>) -> (CapabilityMapping, VerificationRecord) {
    let payloads = || meta.meta_payloads.iter().copied();
    if has_unknown_class_name_in(payloads()) {
        return (
            deny_all(),
            container_record(
                CheckKind::CapabilityMapping,
                Outcome::Fail,
                DetailCode::CapabilityUnknown,
            ),
        );
    }
    let declared: Vec<CapabilityClass> = declared_classes_in(payloads());
    match map_declared(&declared) {
        Ok(mapping) => (
            mapping,
            container_record(
                CheckKind::CapabilityMapping,
                Outcome::Pass,
                DetailCode::CapabilitiesMapped,
            ),
        ),
        // A refused artifact grants nothing.
        Err(_) => (
            deny_all(),
            container_record(
                CheckKind::CapabilityMapping,
                Outcome::Fail,
                DetailCode::CapabilityUnsupported,
            ),
        ),
    }
}

/// ADR-160 item 7: a package that declares a stream profile is refused by the
/// buffered loader unless signed policy permits it.
fn stream_profile_record(delivery: Delivery, opts: &VerifyOptions) -> VerificationRecord {
    let (outcome, detail) = match delivery {
        Delivery::Streamed => (Outcome::Pass, DetailCode::StreamProfileSatisfied),
        Delivery::Buffered if opts.permit_buffered_stream_profile => {
            (Outcome::Pass, DetailCode::StreamProfilePermitted)
        }
        Delivery::Buffered => (Outcome::Fail, DetailCode::StreamProfileDowngrade),
    };
    container_record(CheckKind::StreamProfile, outcome, detail)
}

fn executable_signed_record(seg: &ParsedSegment, opts: &VerifyOptions) -> VerificationRecord {
    if seg.is_signed() {
        return segment_record(
            CheckKind::ExecutableSigned,
            Outcome::Pass,
            seg,
            DetailCode::ExecutableIsSigned,
        );
    }
    if opts.allow_unsigned_executable {
        return segment_record(
            CheckKind::ExecutableSigned,
            Outcome::Skip,
            seg,
            DetailCode::UnsignedExecutablePermitted,
        );
    }
    segment_record(
        CheckKind::ExecutableSigned,
        Outcome::Fail,
        seg,
        DetailCode::ExecutableIsUnsigned,
    )
}

fn signature_record(
    seg: &ParsedSegment,
    sig: &SigFacts,
    opts: &VerifyOptions,
) -> VerificationRecord {
    let SigFacts::Decoded {
        algo,
        length,
        signature,
        message,
    } = sig
    else {
        return segment_record(
            CheckKind::Signature,
            Outcome::Fail,
            seg,
            DetailCode::FooterMalformed,
        );
    };

    if *algo != SIG_ALGO_ED25519 || *length != ED25519_SIGNATURE_LENGTH {
        return segment_record(
            CheckKind::Signature,
            if seg.is_executable() {
                Outcome::Fail
            } else {
                Outcome::Skip
            },
            seg,
            DetailCode::UnsupportedSignatureAlgorithm,
        );
    }
    if opts.trusted_keys.is_empty() {
        return segment_record(
            CheckKind::Signature,
            if seg.is_executable() && !opts.allow_unsigned_executable {
                Outcome::Fail
            } else {
                Outcome::Skip
            },
            seg,
            DetailCode::NoTrustedKey,
        );
    }

    let verified = signature.is_some_and(|bytes| {
        let signature = Signature::from_bytes(&bytes);
        opts.trusted_keys.iter().any(|raw| {
            VerifyingKey::from_bytes(raw)
                .is_ok_and(|key| key.verify_strict(message, &signature).is_ok())
        })
    });
    segment_record(
        CheckKind::Signature,
        outcome(verified),
        seg,
        if verified {
            DetailCode::SignatureVerifies
        } else {
            DetailCode::SignatureRejected
        },
    )
}
