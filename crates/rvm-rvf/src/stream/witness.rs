//! Witness records for stream events (ADR-160 item 6).
//!
//! Four events are recorded, pass and fail alike, through the same
//! `rvm-rvf` witness path every other verification result uses
//! ([`crate::witness::build_record_with_payload`], the same `CheckKind` in
//! `flags`, the same `ActionKind` mapping, the same artifact binding in
//! `capability_hash`):
//!
//! | Event | Check | Outcome | `target_object_id` | `payload` | `aux` |
//! |---|---|---|---|---|---|
//! | `DescriptorVerified` | `StreamDescriptor` | pass | 0 | descriptor hash\[..8\] | |
//! | `DescriptorRejected(reason)` | `StreamDescriptor` | fail | 0 | descriptor hash\[..8\] | `aux[6..8]` = reason code |
//! | `SegmentVerified(seg_id, root)` | `StreamSegment` | pass | `seg_id` | root\[..8\] | |
//! | `StreamPoisoned(seg_id, chunk_index, reason)` | `StreamPoisoned` | fail | `seg_id` | binding\[..8\] | `aux[0..4]` = chunk index, `aux[6..8]` = reason code |
//!
//! `StreamFault` records a refused frame that was counted against the fault
//! budget (so up to `fault_budget` tampered frames still leave a trail).
//! `StreamComplete` marks the stream finishing, and `ModuleValidated` /
//! `ModuleRejected` record the verdict of the incremental module validator
//! that consumes a streamed executable.
//!
//! `capability_hash` is the FNV-1a fold of the package identity when the
//! descriptor commits to one, else of the descriptor hash, so a stream's
//! records line up with the instance records `rvm-launch` writes later.

use super::admission::{AdmissionError, AdmissionEvent, StreamAdmission};
use super::commit::descriptor_hash;
use super::error::StreamError;
use super::events::StreamState;
use crate::detail::DetailCode;
use crate::verify::{CheckKind, Outcome, VerificationRecord};
use crate::witness::{build_record_with_payload, WitnessContext};
use rvm_witness::WitnessLog;

/// A stream event worth a witness record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEvent {
    /// The descriptor passed every invariant.
    DescriptorVerified {
        /// SHA-256 of the signed descriptor.
        descriptor_hash: [u8; 32],
    },
    /// The descriptor was refused.
    DescriptorRejected {
        /// SHA-256 of the refused descriptor bytes.
        descriptor_hash: [u8; 32],
        /// Why.
        reason: StreamError,
    },
    /// Every chunk of a segment matched its commitment.
    SegmentVerified {
        /// The segment.
        seg_id: u64,
        /// Its chunk-table hash (the segment root).
        root: [u8; 32],
    },
    /// The stream is poisoned.
    StreamPoisoned {
        /// The segment involved, if any.
        seg_id: Option<u64>,
        /// The chunk index involved.
        chunk_index: u32,
        /// Why.
        reason: StreamError,
    },
    /// A frame was refused and counted against the fault budget.
    StreamFault {
        /// The segment involved, if any.
        seg_id: Option<u64>,
        /// The chunk index involved.
        chunk_index: u32,
        /// Why.
        reason: StreamError,
    },
    /// The stream completed.
    StreamComplete,
    /// A streamed executable module passed incremental validation.
    ModuleValidated {
        /// The segment carrying the module.
        seg_id: u64,
    },
    /// A streamed executable module failed validation or policy.
    ModuleRejected {
        /// The segment carrying the module.
        seg_id: u64,
    },
}

/// The `(record, payload)` pair for an event.
#[must_use]
#[allow(clippy::too_many_lines)] // one arm per event: a table, not logic
pub fn event_record(ev: &StreamEvent, binding: &[u8; 32]) -> (VerificationRecord, [u8; 8]) {
    let head = |hash: &[u8; 32]| {
        let mut p = [0u8; 8];
        p.copy_from_slice(&hash[..8]);
        p
    };
    let rec = |check, outcome, seg: Option<u64>, index: usize, detail| VerificationRecord {
        check,
        outcome,
        segment_index: Some(index),
        segment_id: seg,
        segment_type: 0,
        detail,
    };
    match *ev {
        StreamEvent::DescriptorVerified { descriptor_hash } => (
            rec(
                CheckKind::StreamDescriptor,
                Outcome::Pass,
                None,
                0,
                DetailCode::StreamDescriptorAccepted,
            ),
            head(&descriptor_hash),
        ),
        StreamEvent::DescriptorRejected {
            descriptor_hash,
            reason,
        } => (
            rec(
                CheckKind::StreamDescriptor,
                Outcome::Fail,
                None,
                0,
                DetailCode::StreamRefused(reason),
            ),
            head(&descriptor_hash),
        ),
        StreamEvent::SegmentVerified { seg_id, root } => (
            rec(
                CheckKind::StreamSegment,
                Outcome::Pass,
                Some(seg_id),
                0,
                DetailCode::StreamSegmentAccepted,
            ),
            head(&root),
        ),
        StreamEvent::StreamPoisoned {
            seg_id,
            chunk_index,
            reason,
        } => (
            rec(
                CheckKind::StreamPoisoned,
                Outcome::Fail,
                seg_id,
                chunk_index as usize,
                DetailCode::StreamRefused(reason),
            ),
            head(binding),
        ),
        StreamEvent::ModuleValidated { seg_id } => (
            rec(
                CheckKind::StreamModule,
                Outcome::Pass,
                Some(seg_id),
                0,
                DetailCode::StreamModuleValidated,
            ),
            head(binding),
        ),
        StreamEvent::ModuleRejected { seg_id } => (
            rec(
                CheckKind::StreamModule,
                Outcome::Fail,
                Some(seg_id),
                0,
                DetailCode::StreamModuleRejected,
            ),
            head(binding),
        ),
        StreamEvent::StreamFault {
            seg_id,
            chunk_index,
            reason,
        } => (
            rec(
                CheckKind::StreamFault,
                Outcome::Fail,
                seg_id,
                chunk_index as usize,
                DetailCode::StreamRefused(reason),
            ),
            head(binding),
        ),
        StreamEvent::StreamComplete => (
            rec(
                CheckKind::StreamComplete,
                Outcome::Pass,
                None,
                0,
                DetailCode::StreamCompleted,
            ),
            head(binding),
        ),
    }
}

/// Append the record for `ev`; returns the sequence number the log assigned.
pub fn emit_event<const N: usize>(
    ev: &StreamEvent,
    binding: &[u8; 32],
    log: &WitnessLog<N>,
    ctx: WitnessContext,
) -> u64 {
    let (record, payload) = event_record(ev, binding);
    log.append(build_record_with_payload(&record, binding, payload, ctx))
}

/// Push one frame into `adm` and witness what it caused: the descriptor
/// verdict, each segment that finished, each counted fault, completion and, if
/// the package is refused, the failing records of the report; plus the
/// transition into `Poisoned` with the segment, chunk and reason.
///
/// # Errors
///
/// Exactly what [`StreamAdmission::push`] returns; the witness record is
/// written first, so a caller that drops the error leaves the refusal in the
/// chain.
pub fn push_witnessed<'a, const N: usize>(
    adm: &mut StreamAdmission<'_>,
    frame: &'a [u8],
    log: &WitnessLog<N>,
    ctx: WitnessContext,
) -> Result<AdmissionEvent<'a>, AdmissionError> {
    push_witnessed_with(adm, frame, log, ctx, true)
}

/// [`push_witnessed`], optionally leaving `StreamComplete` to the caller (a
/// session writes it only once the package has also been admitted).
///
/// # Errors
///
/// As [`push_witnessed`].
pub fn push_witnessed_with<'a, const N: usize>(
    adm: &mut StreamAdmission<'_>,
    frame: &'a [u8],
    log: &WitnessLog<N>,
    ctx: WitnessContext,
    emit_complete: bool,
) -> Result<AdmissionEvent<'a>, AdmissionError> {
    let was = adm.state();
    let faults_before = adm.verifier().faults();
    let result = adm.push(frame);
    let binding = binding_of(adm).unwrap_or_else(|| descriptor_hash(frame.get(5..).unwrap_or(&[])));
    match &result {
        Ok(AdmissionEvent::DescriptorVerified {
            descriptor_hash, ..
        }) => {
            emit_event(
                &StreamEvent::DescriptorVerified {
                    descriptor_hash: *descriptor_hash,
                },
                &binding,
                log,
                ctx,
            );
        }
        Ok(AdmissionEvent::Chunk {
            chunk,
            segment_verified,
            complete,
            ..
        }) => {
            if *segment_verified {
                let root = adm
                    .verifier()
                    .descriptor()
                    .and_then(|d| d.find(chunk.seg_id).map(|i| d.entries[i].chunk_table_hash))
                    .unwrap_or([0; 32]);
                emit_event(
                    &StreamEvent::SegmentVerified {
                        seg_id: chunk.seg_id,
                        root,
                    },
                    &binding,
                    log,
                    ctx,
                );
            }
            if complete.is_some() {
                if emit_complete {
                    emit_event(&StreamEvent::StreamComplete, &binding, log, ctx);
                }
                if let Some(report) = adm.report() {
                    emit_report_failures(report, log, ctx);
                }
            }
        }
        Ok(
            AdmissionEvent::TableVerified { .. }
            | AdmissionEvent::Duplicate { .. }
            | AdmissionEvent::Unverified { .. }
            | AdmissionEvent::DuplicateDescriptor,
        )
        | Err(_) => {}
    }
    if adm.verifier().faults() > faults_before {
        if let Some(f) = adm.verifier().last_fault() {
            emit_event(
                &StreamEvent::StreamFault {
                    seg_id: f.seg_id,
                    chunk_index: f.chunk_index,
                    reason: f.reason,
                },
                &binding,
                log,
                ctx,
            );
        }
    }
    witness_transition(adm, was, &binding, log, ctx);
    result
}

/// Write one record for every failing check of `report`, bound to the
/// package identity, exactly as [`crate::emit_report`] does for a buffered
/// `verify`. Passing checks are not repeated.
pub fn emit_report_failures<const N: usize>(
    report: &crate::verify::VerificationReport,
    log: &WitnessLog<N>,
    ctx: WitnessContext,
) -> usize {
    let mut n = 0;
    for r in report.records.iter().filter(|r| r.outcome == Outcome::Fail) {
        crate::witness::emit_record(r, &report.rvf_identity, log, ctx);
        n += 1;
    }
    n
}

/// Write the record for a state transition into `Rejected` or `Poisoned`
/// that happened since `was` (nothing if the state did not change).
pub fn witness_transition<const N: usize>(
    adm: &StreamAdmission<'_>,
    was: StreamState,
    binding: &[u8; 32],
    log: &WitnessLog<N>,
    ctx: WitnessContext,
) {
    match (was, adm.state()) {
        (StreamState::AwaitDescriptor, StreamState::Rejected(reason)) => {
            emit_event(
                &StreamEvent::DescriptorRejected {
                    descriptor_hash: *binding,
                    reason,
                },
                binding,
                log,
                ctx,
            );
        }
        (prev, StreamState::Poisoned(reason)) if !matches!(prev, StreamState::Poisoned(_)) => {
            let info = adm.verifier().poison_info();
            emit_event(
                &StreamEvent::StreamPoisoned {
                    seg_id: info.and_then(|i| i.seg_id),
                    chunk_index: info.map_or(0, |i| i.chunk_index),
                    reason: info.map_or(reason, |i| i.reason),
                },
                binding,
                log,
                ctx,
            );
        }
        _ => {}
    }
}

/// [`StreamAdmission::finish_identity`], witnessing a mismatch poison.
///
/// # Errors
///
/// As the verifier.
pub fn finish_identity_witnessed<const N: usize>(
    adm: &mut StreamAdmission<'_>,
    read_at: impl FnMut(u64, &mut [u8]) -> bool,
    log: &WitnessLog<N>,
    ctx: WitnessContext,
) -> Result<(), StreamError> {
    let was = adm.state();
    let r = adm.finish_identity(read_at);
    if let Some(b) = binding_of(adm) {
        witness_transition(adm, was, &b, log, ctx);
    }
    r
}

/// The 32-byte value stream records bind to: the package identity when the
/// descriptor commits to one, else the descriptor hash. `None` before a
/// descriptor is accepted.
#[must_use]
pub fn binding_of(adm: &StreamAdmission<'_>) -> Option<[u8; 32]> {
    let d = adm.verifier().descriptor()?;
    Some(
        if d.header.flags & super::descriptor::FLAG_IDENTITY_PRESENT != 0 {
            d.header.rvf_identity
        } else {
            d.descriptor_hash
        },
    )
}
