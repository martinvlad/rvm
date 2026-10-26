//! Inspection-only walk over an RVF segment stream.
//!
//! This module is the single place that turns raw bytes into a segment
//! inventory, and it is deliberately the only place that touches offsets. It
//! upholds ADR-284 §1.7: the walk reads 64-byte headers and records byte
//! ranges. It never maps, links, interprets, or executes a payload.
//! Executable payload bytes leave this module only as `&[u8]` handed to a
//! hash or a signature check.
//!
//! Layout of one segment on the wire:
//!
//! ```text
//! [ 64-byte header ][ payload_length bytes ][ signature footer? ][ zero pad ]
//! ```
//!
//! The footer is present exactly when the header's `SIGNED` flag is set, and
//! its own trailing `footer_length` field gives its size. The next segment
//! begins at the next 64-byte boundary.

use crate::error::{RvfError, RvfResult};
use crate::format::{
    align_up, compute_footer_length, decode_signature_footer, SegmentHeader, MAX_SEGMENTS,
    MAX_SEGMENT_PAYLOAD, SEGMENT_HEADER_SIZE,
};
use alloc::vec::Vec;
use core::ops::Range;

/// One segment located in the byte stream. Holds ranges, never payload copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSegment {
    /// Zero-based position in the stream.
    pub index: usize,
    /// Byte offset of the segment header.
    pub offset: usize,
    /// The parsed 64-byte header.
    pub header: SegmentHeader,
    /// Byte range of the payload within the container.
    pub payload: Range<usize>,
    /// Byte range of the signature footer, when the `SIGNED` flag is set.
    pub footer: Option<Range<usize>>,
}

impl ParsedSegment {
    /// Whether the header declares a signature footer.
    #[inline]
    #[must_use]
    pub const fn is_signed(&self) -> bool {
        self.header.is_signed()
    }

    /// Whether this segment's payload is code a runtime would execute.
    #[inline]
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.header.is_executable()
    }

    /// The payload bytes, borrowed from the container this segment came from.
    ///
    /// # Panics
    ///
    /// If `data` is not the container the segment was walked from. Every
    /// caller inside this crate passes the same slice it walked.
    #[inline]
    #[must_use]
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[self.payload.clone()]
    }
}

/// Magic of the 4096-byte Level-0 root manifest page that `rvf-forge-core`
/// appends to an authored container: the little-endian bytes `30 4D 56 52`,
/// mnemonic `RVM0` under big-endian rendering. Matches RuVector
/// `rvf_types::ROOT_MANIFEST_MAGIC`.
pub const ROOT_PAGE_MAGIC: u32 = 0x5256_4D30;

/// Size of the Level-0 root manifest page in bytes.
pub const ROOT_PAGE_SIZE: usize = 4096;

/// The result of [`walk_container`]: the segment inventory plus the trailing
/// Level-0 root page region, when the container has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkedContainer {
    /// Segments in stream order. The root page is not a segment and is not
    /// listed here.
    pub segments: Vec<ParsedSegment>,
    /// Byte range of the trailing 4096-byte root page (`RVM0`), if present.
    /// It always ends at `data.len()`.
    pub root_page: Option<Range<usize>>,
}

/// Locate a trailing Level-0 root page.
///
/// The page is recognised by its `RVM0` magic at exactly `len - 4096`, the only
/// place the format permits it, and only when at least one segment header's
/// worth of bytes precedes it. A bare segment stream that merely happens to be
/// long is therefore still walked whole. Mirrors `rvf-forge-core`
/// `container::split_root_manifest`.
fn split_root_page(data: &[u8]) -> (&[u8], Option<Range<usize>>) {
    if data.len() < ROOT_PAGE_SIZE + SEGMENT_HEADER_SIZE {
        return (data, None);
    }
    let start = data.len() - ROOT_PAGE_SIZE;
    let magic = u32::from_le_bytes([
        data[start],
        data[start + 1],
        data[start + 2],
        data[start + 3],
    ]);
    if magic == ROOT_PAGE_MAGIC {
        (&data[..start], Some(start..data.len()))
    } else {
        (data, None)
    }
}

/// Walk `data`, recognising an optional trailing Level-0 root page.
///
/// The root page is reported in [`WalkedContainer::root_page`] instead of being
/// misread as a segment header. The page is **not authenticated by this
/// function**; its bytes are covered by the container identity hash only.
///
/// # Errors
///
/// As [`walk`].
pub fn walk_container(data: &[u8]) -> RvfResult<WalkedContainer> {
    let (body, root_page) = split_root_page(data);
    let segments = walk_segments(body)?;
    Ok(WalkedContainer {
        segments,
        root_page,
    })
}

/// Walk `data` and return every segment in stream order.
///
/// A trailing Level-0 root page, if present, is skipped (see
/// [`walk_container`] to learn where it was). Containers without a root page
/// are walked exactly as before.
///
/// The rejection set mirrors the RuVector reader: bad magic, truncated
/// streams, payload lengths past the end, inconsistent footers, and a
/// `SIGNED` flag with no signature behind it. Files written by the legacy
/// `rvf-runtime` `RvfStore` dialect (unpadded segments) are rejected; see
/// RuVector ADR-354 and `tests/fixtures/README.md`.
///
/// # Errors
///
/// One of the [`RvfError`] variants describing which structural rule the
/// container broke.
pub fn walk(data: &[u8]) -> RvfResult<Vec<ParsedSegment>> {
    walk_container(data).map(|w| w.segments)
}

/// Walk a segment area that has already had any root page trimmed.
fn walk_segments(data: &[u8]) -> RvfResult<Vec<ParsedSegment>> {
    if data.len() < SEGMENT_HEADER_SIZE {
        return Err(RvfError::Truncated);
    }

    let mut segments: Vec<ParsedSegment> = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let remaining = data.len() - offset;

        // A short, all-zero tail is alignment padding, not a truncated segment.
        if remaining < SEGMENT_HEADER_SIZE {
            if data[offset..].iter().all(|&b| b == 0) {
                break;
            }
            return Err(RvfError::TrailingBytes);
        }

        if segments.len() >= MAX_SEGMENTS {
            return Err(RvfError::TooManySegments);
        }

        let header = SegmentHeader::parse(&data[offset..])?;

        if header.payload_length > MAX_SEGMENT_PAYLOAD {
            return Err(RvfError::PayloadTooLarge);
        }

        let payload_start = offset + SEGMENT_HEADER_SIZE;
        let payload_end = usize::try_from(header.payload_length)
            .ok()
            .and_then(|len| payload_start.checked_add(len))
            .ok_or(RvfError::PayloadOutOfBounds)?;
        if payload_end > data.len() {
            return Err(RvfError::PayloadOutOfBounds);
        }

        let mut end = payload_end;
        let mut footer = None;
        if header.is_signed() {
            let decoded = decode_signature_footer(&data[payload_end..])?;
            // A segment's zero padding decodes as a structurally valid but
            // empty footer. Accepting that would let any segment claim SIGNED
            // by setting one flag bit and changing nothing else, so require
            // the footer to actually carry a signature and to be internally
            // consistent about its own length.
            if decoded.sig_length == 0 {
                return Err(RvfError::SignedFlagWithoutFooter);
            }
            if decoded.footer_length != compute_footer_length(decoded.sig_length) {
                return Err(RvfError::MalformedFooter);
            }

            let footer_len = decoded.footer_length as usize;
            let footer_end = payload_end
                .checked_add(footer_len)
                .filter(|e| *e <= data.len())
                .ok_or(RvfError::MalformedFooter)?;
            footer = Some(payload_end..footer_end);
            end = footer_end;
        }

        let next = align_up(end);
        if next <= offset {
            return Err(RvfError::NoForwardProgress);
        }

        segments.push(ParsedSegment {
            index: segments.len(),
            offset,
            header,
            payload: payload_start..payload_end,
            footer,
        });

        offset = next.min(data.len());
        if next > data.len() {
            // The final segment's alignment padding was truncated. The
            // segment itself is intact, so this is not an error.
            break;
        }
    }

    if segments.is_empty() {
        return Err(RvfError::NoSegments);
    }
    Ok(segments)
}

/// The root manifest segment, when the container has one.
///
/// The *last* manifest in the stream is the root: later manifests supersede
/// earlier ones, matching the RuVector reader.
#[must_use]
pub fn root_manifest(segments: &[ParsedSegment]) -> Option<&ParsedSegment> {
    segments
        .iter()
        .rev()
        .find(|s| s.header.seg_type == crate::format::SEG_TYPE_MANIFEST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{SEGMENT_ALIGNMENT, SEG_TYPE_MANIFEST, SEG_TYPE_META, SEG_TYPE_WASM};
    use crate::testkit;

    #[test]
    fn walks_a_two_segment_stream() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"first", 1);
        data.extend(testkit::unsigned_segment(
            SEG_TYPE_META,
            b"second payload",
            2,
        ));

        let segs = walk(&data).unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].header.segment_id, 1);
        assert_eq!(segs[0].payload(&data), b"first");
        assert_eq!(segs[1].header.segment_id, 2);
        assert_eq!(segs[1].payload(&data), b"second payload");
        assert_eq!(segs[1].offset, SEGMENT_ALIGNMENT * 2);
    }

    #[test]
    fn rejects_a_stream_shorter_than_a_header() {
        assert_eq!(walk(&[0u8; 10]), Err(RvfError::Truncated));
    }

    #[test]
    fn rejects_a_bad_magic() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data[0] ^= 0xff;
        assert_eq!(walk(&data), Err(RvfError::BadMagic));
    }

    #[test]
    fn rejects_a_payload_length_past_the_end() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        // payload_length lives at header offset 0x10.
        data[0x10..0x18].copy_from_slice(&4096u64.to_le_bytes());
        assert_eq!(walk(&data), Err(RvfError::PayloadOutOfBounds));
    }

    #[test]
    fn rejects_a_payload_length_over_the_format_maximum() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data[0x10..0x18].copy_from_slice(&(MAX_SEGMENT_PAYLOAD + 1).to_le_bytes());
        assert_eq!(walk(&data), Err(RvfError::PayloadTooLarge));
    }

    #[test]
    fn rejects_signed_flag_without_a_footer() {
        let data = testkit::signed_flag_without_footer(SEG_TYPE_WASM, b"code", 1);
        assert_eq!(walk(&data), Err(RvfError::SignedFlagWithoutFooter));
    }

    #[test]
    fn rejects_a_footer_whose_declared_length_is_inconsistent() {
        let kp = testkit::TestKeypair::deterministic(3);
        let mut data = testkit::signed_segment(SEG_TYPE_WASM, b"code", 1, &kp);
        // The footer's trailing footer_length is the last 4 bytes before pad.
        let footer_start = SEGMENT_HEADER_SIZE + 4;
        let len_at = footer_start + 4 + 64;
        data[len_at..len_at + 4].copy_from_slice(&999u32.to_le_bytes());
        assert_eq!(walk(&data), Err(RvfError::MalformedFooter));
    }

    #[test]
    fn accepts_a_well_formed_signed_segment() {
        let kp = testkit::TestKeypair::deterministic(3);
        let data = testkit::signed_segment(SEG_TYPE_WASM, b"code", 1, &kp);
        let segs = walk(&data).unwrap();
        assert_eq!(segs.len(), 1);
        assert!(segs[0].is_signed());
        assert!(segs[0].is_executable());
        assert_eq!(segs[0].footer.clone().unwrap().len(), 72);
    }

    #[test]
    fn rejects_non_zero_trailing_bytes() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data.extend_from_slice(b"junk");
        assert_eq!(walk(&data), Err(RvfError::TrailingBytes));
    }

    #[test]
    fn accepts_zero_padding_after_the_last_segment() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_META, b"x", 1);
        data.extend_from_slice(&[0u8; 8]);
        assert_eq!(walk(&data).unwrap().len(), 1);
    }

    #[test]
    fn root_manifest_is_the_last_manifest_in_the_stream() {
        let mut data = testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"first", 1);
        data.extend(testkit::unsigned_segment(SEG_TYPE_META, b"m", 2));
        data.extend(testkit::unsigned_segment(SEG_TYPE_MANIFEST, b"root", 3));

        let segs = walk(&data).unwrap();
        assert_eq!(root_manifest(&segs).unwrap().header.segment_id, 3);
    }

    #[test]
    fn root_manifest_is_absent_when_no_manifest_segment_exists() {
        let data = testkit::unsigned_segment(SEG_TYPE_META, b"m", 1);
        let segs = walk(&data).unwrap();
        assert!(root_manifest(&segs).is_none());
    }
}
