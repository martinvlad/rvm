//! Incremental per-segment checks on released chunks.
//!
//! [`crate::verify()`] checks a segment's content hash, signature footer and
//! structure from a buffer it holds whole. A stream cannot hold a large
//! segment whole, and must not (that is the memory bound), so
//! [`SegmentChecker`] computes the same facts while the segment's chunks go
//! by: a few hasher states, the 64-byte header, and the signature footer.
//! The facts then feed the same record builder `verify` uses.

use crate::container::ParsedSegment;
use crate::error::RvfError;
use crate::format::{
    align_up, build_signed_message_from_hash, compute_footer_length, decode_signature_footer,
    is_executable, SegmentHeader, MAX_SEGMENT_PAYLOAD, MAX_SIGNATURE_LENGTH, SEGMENT_ALIGNMENT,
    SEGMENT_HEADER_SIZE,
};
use crate::report::{SegmentFacts, SigFacts};
use alloc::vec::Vec;
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use subtle::ConstantTimeEq;
use xxhash_rust::xxh3::Xxh3;

/// Largest signature footer: 4 + `MAX_SIGNATURE_LENGTH` + 4.
const MAX_FOOTER: usize = 8 + MAX_SIGNATURE_LENGTH as usize;

/// Why a segment could not be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SegmentFault {
    /// The bytes are not a well-formed segment ([`crate::verify()`] would
    /// return this [`RvfError`]).
    Malformed(RvfError),
    /// The segment header disagrees with the signed table entry.
    DescriptorMismatch,
}

impl From<RvfError> for SegmentFault {
    fn from(e: RvfError) -> Self {
        Self::Malformed(e)
    }
}

type FaultResult<T> = core::result::Result<T, SegmentFault>;

fn sat(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Where a pushed slice sits relative to the segment payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PayloadSpan {
    /// Start within the pushed slice.
    pub start: usize,
    /// End within the pushed slice (`start == end` when none).
    pub end: usize,
    /// Offset of the span's first byte within the segment payload.
    pub payload_offset: u64,
}

/// Accumulates one segment's facts from its chunks, in order.
pub(crate) struct SegmentChecker {
    seg_id: u64,
    seg_type: u8,
    stored_len: u64,
    body_offset: u64,
    pos: u64,
    head: [u8; SEGMENT_HEADER_SIZE],
    header: Option<SegmentHeader>,
    xxh: Option<Xxh3>,
    shake: Option<Shake256>,
    sha: Option<Sha256>,
    tail: Vec<u8>,
    /// The last (up to) 63 bytes seen, to judge a zero tail after the last
    /// segment the way the buffered walk does.
    last: Vec<u8>,
}

impl SegmentChecker {
    pub(crate) fn new(seg_id: u64, seg_type: u8, body_offset: u64, stored_len: u64) -> Self {
        Self {
            seg_id,
            seg_type,
            stored_len,
            body_offset,
            pos: 0,
            head: [0; SEGMENT_HEADER_SIZE],
            header: None,
            xxh: None,
            shake: None,
            sha: None,
            tail: Vec::new(),
            last: Vec::new(),
        }
    }

    /// The parsed header, once 64 bytes have been seen.
    pub(crate) const fn header(&self) -> Option<&SegmentHeader> {
        self.header.as_ref()
    }

    /// Feed the next in-order bytes of the stored segment.
    pub(crate) fn push(&mut self, mut bytes: &[u8]) -> FaultResult<PayloadSpan> {
        {
            const KEEP: usize = SEGMENT_ALIGNMENT - 1;
            let all = bytes;
            if all.len() >= KEEP {
                self.last.clear();
                self.last.extend_from_slice(&all[all.len() - KEEP..]);
            } else {
                self.last.extend_from_slice(all);
                let excess = self.last.len().saturating_sub(KEEP);
                self.last.drain(..excess);
            }
        }
        let mut span = PayloadSpan {
            start: 0,
            end: 0,
            payload_offset: 0,
        };
        let mut consumed = 0usize;
        if self.pos < SEGMENT_HEADER_SIZE as u64 {
            let at = self.pos as usize;
            let take = (SEGMENT_HEADER_SIZE - at).min(bytes.len());
            self.head[at..at + take].copy_from_slice(&bytes[..take]);
            self.pos += take as u64;
            bytes = &bytes[take..];
            consumed = take;
            if self.pos == SEGMENT_HEADER_SIZE as u64 {
                self.start_payload()?;
            }
        }
        if let Some(h) = self.header {
            let payload_end = SEGMENT_HEADER_SIZE as u64 + h.payload_length;
            if self.pos < payload_end && !bytes.is_empty() {
                let take = (payload_end - self.pos).min(bytes.len() as u64) as usize;
                let part = &bytes[..take];
                if let Some(x) = &mut self.xxh {
                    x.update(part);
                }
                if let Some(s) = &mut self.shake {
                    s.update(part);
                }
                if let Some(s) = &mut self.sha {
                    sha2::Digest::update(s, part);
                }
                span = PayloadSpan {
                    start: consumed,
                    end: consumed + take,
                    payload_offset: self.pos - SEGMENT_HEADER_SIZE as u64,
                };
                self.pos += take as u64;
                bytes = &bytes[take..];
            }
            if !bytes.is_empty() {
                if h.is_signed() && self.tail.len() < MAX_FOOTER {
                    let room = MAX_FOOTER - self.tail.len();
                    self.tail.extend_from_slice(&bytes[..room.min(bytes.len())]);
                }
                self.pos += bytes.len() as u64;
            }
        }
        Ok(span)
    }

    fn start_payload(&mut self) -> FaultResult<()> {
        let h = SegmentHeader::parse(&self.head)?;
        if h.payload_length > MAX_SEGMENT_PAYLOAD {
            return Err(RvfError::PayloadTooLarge.into());
        }
        if SEGMENT_HEADER_SIZE as u64 + h.payload_length > self.stored_len {
            return Err(RvfError::PayloadOutOfBounds.into());
        }
        if h.seg_type != self.seg_type || h.segment_id != self.seg_id {
            // The descriptor and the segment disagree about what this is.
            return Err(SegmentFault::DescriptorMismatch);
        }
        // The content hash is XXH3-128 unless the header says SHAKE-256; the
        // signature always covers the SHAKE-256-128 of the payload.
        if h.checksum_algo == 2 {
            self.shake = Some(Shake256::default());
        } else {
            self.xxh = Some(Xxh3::new());
            if h.is_signed() {
                self.shake = Some(Shake256::default());
            }
        }
        if is_executable(h.seg_type) {
            self.sha = Some(<Sha256 as sha2::Digest>::new());
        }
        self.header = Some(h);
        Ok(())
    }

    /// Complete the segment: structure, content hash and signature facts.
    /// `is_last` marks the last segment before any root page, whose trailing
    /// alignment padding may be absent.
    pub(crate) fn finish(
        self,
        index: usize,
        is_last: bool,
    ) -> FaultResult<(ParsedSegment, SegmentFacts)> {
        let Some(h) = self.header else {
            return Err(RvfError::Truncated.into());
        };
        let payload_end = SEGMENT_HEADER_SIZE as u64 + h.payload_length;
        let (footer_len, sig) = if h.is_signed() {
            let decoded = decode_signature_footer(&self.tail)?;
            if decoded.sig_length == 0 {
                return Err(RvfError::SignedFlagWithoutFooter.into());
            }
            if decoded.footer_length != compute_footer_length(decoded.sig_length) {
                return Err(RvfError::MalformedFooter.into());
            }
            let flen = u64::from(decoded.footer_length);
            if payload_end + flen > self.stored_len {
                return Err(RvfError::MalformedFooter.into());
            }
            (
                flen,
                Some((decoded.sig_algo, decoded.sig_length, decoded.signature)),
            )
        } else {
            (0, None)
        };
        let end = payload_end + footer_len;
        let next = align_up(sat(end)) as u64;
        if self.stored_len > next {
            // Only a short all-zero tail after the last segment is padding.
            let extra = (self.stored_len - next) as usize;
            let zero_tail = is_last
                && extra < SEGMENT_HEADER_SIZE
                && extra <= self.last.len()
                && self.last[self.last.len() - extra..].iter().all(|&b| b == 0);
            if !zero_tail {
                return Err(RvfError::TrailingBytes.into());
            }
        }
        if self.stored_len < next && !is_last {
            return Err(RvfError::Truncated.into());
        }

        let mut shake_hash = [0u8; 16];
        if let Some(s) = self.shake {
            s.finalize_xof().read(&mut shake_hash);
        }
        let content = if h.checksum_algo == 2 {
            shake_hash
        } else {
            self.xxh.map_or([0; 16], |x| x.digest128().to_le_bytes())
        };
        let content_hash_ok: bool = content.ct_eq(&h.content_hash).into();
        let sig = match sig {
            None => SigFacts::Unsigned,
            Some((algo, length, signature)) => SigFacts::Decoded {
                algo,
                length,
                signature: <[u8; 64]>::try_from(signature).ok(),
                message: build_signed_message_from_hash(&h, &shake_hash),
            },
        };
        let payload_start = self.body_offset + SEGMENT_HEADER_SIZE as u64;
        let parsed = ParsedSegment {
            index,
            offset: sat(self.body_offset),
            header: h,
            payload: sat(payload_start)..sat(payload_start + h.payload_length),
            footer: h
                .is_signed()
                .then(|| sat(self.body_offset + payload_end)..sat(self.body_offset + end)),
        };
        let facts = SegmentFacts {
            content_hash_ok,
            sig,
            payload_sha256: self.sha.map(|s| sha2::Digest::finalize(s).into()),
        };
        Ok((parsed, facts))
    }
}
