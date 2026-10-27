//! Verifying a whole buffer against its signed descriptor.
//!
//! [`crate::verify()`] must guess where segments and the trailing root page
//! are, because a legacy container carries no table. When the package's RVSD
//! descriptor is at hand (inline or as a sidecar) the guess is unnecessary:
//! the signed table says exactly where every segment and the page are, and this
//! function cuts the buffer there. It is the same rule set as the streamed path
//! (the same segment checker and the same report builder), fed from memory.

use super::admission::AdmissionError;
use super::commit::leaf_hash;
use super::descriptor::{VerifiedDescriptor, FLAG_IDENTITY_PRESENT, SEG_TYPE_ROOT_PAGE};
use super::segment::{SegmentChecker, SegmentFault};
use crate::container::{is_level0_page, ParsedSegment};
use crate::error::RvfError;
use crate::format::SEG_TYPE_META;
use crate::hash::sha256;
use crate::report::{build_report, Declarations, Delivery, ReportInput, SegmentFacts};
use crate::verify::{VerificationReport, VerifyOptions};
use alloc::vec::Vec;
use subtle::ConstantTimeEq;

/// Verify `data` as the body `desc` describes.
///
/// Every chunk is checked against the signed commitments and, when the
/// descriptor commits to an identity, `SHA-256(data)` must equal it; then the
/// ADR-155 rules run exactly as on the streamed path. The buffer is authenticated by the descriptor exactly as a stream is, so
/// a stream-profiled package is satisfied (`StreamProfileSatisfied`) without
/// the buffered-loader permission.
///
/// # Errors
///
/// [`AdmissionError`]: the buffer is not the described body, or a segment is
/// not well formed.
pub fn verify_with_descriptor(
    data: &[u8],
    opts: &VerifyOptions,
    desc: &VerifiedDescriptor,
) -> Result<VerificationReport, AdmissionError> {
    let bad = |e: RvfError| AdmissionError::Malformed {
        seg_id: 0,
        error: e,
    };
    let h = desc.header;
    if data.len() as u64 != h.body_len {
        return Err(bad(RvfError::Truncated));
    }
    let identity = sha256(data);
    if h.flags & FLAG_IDENTITY_PRESENT == 0 {
        return Err(AdmissionError::IdentityRequired);
    }
    if !bool::from(identity.ct_eq(&h.rvf_identity)) {
        return Err(AdmissionError::Stream(super::StreamError::IdentityMismatch));
    }
    let mut segments: Vec<ParsedSegment> = Vec::new();
    let mut facts: Vec<SegmentFacts> = Vec::new();
    let mut meta: Vec<&[u8]> = Vec::new();
    let last = desc
        .entries
        .iter()
        .rposition(|e| e.seg_type != SEG_TYPE_ROOT_PAGE);
    for (i, e) in desc.entries.iter().enumerate() {
        let start = usize::try_from(e.body_offset).map_err(|_| bad(RvfError::Truncated))?;
        let end =
            usize::try_from(e.body_offset + e.stored_len).map_err(|_| bad(RvfError::Truncated))?;
        let bytes = &data[start..end];
        let cs = h.chunk_size().map_or(bytes.len().max(1), |c| c as usize);
        let n = h.chunk_count(e.stored_len).unwrap_or(1);
        let mut leaves = Vec::new();
        for (idx, c) in bytes.chunks(cs).enumerate() {
            leaves.push(leaf_hash(&h.file_id, e.seg_id, idx as u32, c));
        }
        let ok = if n == 1 {
            leaves.first() == Some(&e.chunk_table_hash)
        } else {
            super::commit::chunk_list_hash(&h.file_id, e.seg_id, &leaves) == e.chunk_table_hash
        };
        if !ok {
            return Err(AdmissionError::Stream(
                super::StreamError::ChunkHashMismatch,
            ));
        }
        if e.seg_type == SEG_TYPE_ROOT_PAGE {
            if !is_level0_page(bytes) {
                return Err(bad(RvfError::TrailingBytes));
            }
            continue;
        }
        let mut chk = SegmentChecker::new(
            e.seg_id,
            e.seg_type,
            e.body_offset,
            e.stored_len,
            e.uncompressed_len,
        );
        let fault = |f: SegmentFault| match f {
            SegmentFault::Malformed(error) => AdmissionError::Malformed {
                seg_id: e.seg_id,
                error,
            },
            SegmentFault::DescriptorMismatch => {
                AdmissionError::DescriptorMismatch { seg_id: e.seg_id }
            }
        };
        for c in bytes.chunks(cs) {
            chk.push(c).map_err(fault)?;
        }
        let (seg, f) = chk.finish(segments.len(), Some(i) == last).map_err(fault)?;
        if seg.header.seg_type == SEG_TYPE_META && !seg.header.is_encrypted() {
            let ps = start + 64;
            meta.push(&data[ps..ps + seg.header.payload_length as usize]);
        }
        segments.push(seg);
        facts.push(f);
    }
    if segments.is_empty() {
        return Err(bad(RvfError::NoSegments));
    }
    Ok(build_report(
        &ReportInput {
            identity,
            container_bytes: data.len() as u64,
            segments: &segments,
            facts: &facts,
            meta: Declarations {
                meta_payloads: meta,
            },
            delivery: Delivery::Streamed,
        },
        opts,
    ))
}
