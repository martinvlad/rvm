//! The RVSD descriptor (ADR-353 sections 1 and 2): fixed layout, length-checked
//! before any allocation proportional to declared counts, authenticated before
//! the table is read.
//!
//! The descriptor decoder is the only parser of unauthenticated bytes on the
//! stream path, so it is written to never index past the slice it was given and
//! to allocate only after the exact descriptor length has been proven.

use super::commit::{descriptor_hash, signer_key_id, verify_descriptor_signature, SIG_LEN};
use super::error::{StreamError, StreamResult};
use super::StreamPolicy;
use crate::format::segment_class;
use alloc::vec::Vec;

/// Descriptor magic, compared as raw bytes.
pub const MAGIC: [u8; 4] = *b"RVSD";
/// The only descriptor version.
pub const VERSION: u16 = 1;
/// Offset of the first table entry.
pub const HEADER_SIZE: usize = 0x90;
/// Size of one table entry.
pub const ENTRY_SIZE: usize = 72;
/// Bytes after the table: `sig_len u16` and the signature.
pub const TRAILER_SIZE: usize = 2 + SIG_LEN;
/// Flag bit0: chunk tables are present.
pub const FLAG_CHUNKED: u16 = 1;
/// Flag bit1: `rvf_identity` is meaningful.
pub const FLAG_IDENTITY_PRESENT: u16 = 2;
/// Flag bit2: nothing may execute before `Complete`.
pub const FLAG_REQUIRE_COMPLETE_BEFORE_EXEC: u16 = 4;
/// All defined flag bits.
pub const FLAGS_KNOWN: u16 = 7;
/// `chunk_log2` of the segment-granular profile.
pub const CHUNK_LOG2_SEGMENT: u8 = 0xFF;
/// Smallest chunked `chunk_log2`.
pub const CHUNK_LOG2_MIN: u8 = 12;
/// Largest chunked `chunk_log2`.
pub const CHUNK_LOG2_MAX: u8 = 30;
/// Descriptor-local `seg_type` of the trailing Level-0 root page.
pub const SEG_TYPE_ROOT_PAGE: u8 = 0xFE;
/// Number of stages addressable by `requires_mask`.
pub const MAX_STAGES: u8 = 32;

/// The validated fixed header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamHeader {
    /// Flag bits.
    pub flags: u16,
    /// `0xFF` or `12..=30`.
    pub chunk_log2: u8,
    /// Artifact lineage id.
    pub file_id: [u8; 16],
    /// Monotone epoch.
    pub epoch: u64,
    /// Total body bytes.
    pub body_len: u64,
    /// SHA-256 of the body; zero unless `identity_present`.
    pub rvf_identity: [u8; 32],
    /// `capabilityPolicyHash`.
    pub policy_hash: [u8; 32],
    /// Number of table entries.
    pub seg_count: u32,
    /// Expiry in ns; `0` means none.
    pub expires_ns: u64,
    /// First 8 bytes of `SHA-256(public key)`.
    pub signer_key_id: [u8; 8],
}

/// One 72-byte table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamEntry {
    /// Segment id, unique within the descriptor.
    pub seg_id: u64,
    /// Segment type (`0xFE` is the root page pseudo-entry).
    pub seg_type: u8,
    /// Delivery stage `0..32`.
    pub stage: u8,
    /// Reserved entry flags, carried verbatim.
    pub flags: u16,
    /// Bit i set: stage i must be fully verified before release.
    pub requires_mask: u32,
    /// Offset in the body.
    pub body_offset: u64,
    /// Whole stored segment length (header, payload, footer, padding).
    pub stored_len: u64,
    /// Declared uncompressed length, bounded by policy.
    pub uncompressed_len: u64,
    /// Leaf hash (one chunk) or chunk-list hash (several).
    pub chunk_table_hash: [u8; 32],
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
fn arr<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    let mut a = [0u8; N];
    a.copy_from_slice(&b[o..o + N]);
    a
}

impl StreamHeader {
    /// Parse and statically validate the first [`HEADER_SIZE`] bytes: magic,
    /// version, flags, algorithms, `chunk_log2`, reserved bytes and
    /// `table_len == 72 * seg_count`.
    ///
    /// # Errors
    ///
    /// The first [`StreamError`] the fixed layout violates.
    pub fn parse(b: &[u8]) -> StreamResult<Self> {
        if b.len() < HEADER_SIZE {
            return Err(StreamError::DescriptorTruncated);
        }
        if b[0..4] != MAGIC {
            return Err(StreamError::BadMagic);
        }
        if u16_at(b, 4) != VERSION {
            return Err(StreamError::UnsupportedVersion);
        }
        let flags = u16_at(b, 6);
        let chunk_log2 = b[9];
        let chunked_ok = if chunk_log2 == CHUNK_LOG2_SEGMENT {
            flags & FLAG_CHUNKED == 0
        } else {
            (CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&chunk_log2) && flags & FLAG_CHUNKED != 0
        };
        // hash_alg 1 = SHA-256 (2 is reserved for BLAKE3), sig_alg 0 = Ed25519.
        if flags & !FLAGS_KNOWN != 0
            || b[8] != 1
            || u16_at(b, 0x0A) != 0
            || u32_at(b, 0x0C) != 0
            || b[0x88..0x90] != [0u8; 8]
            || !chunked_ok
        {
            return Err(StreamError::BadFlags);
        }
        let seg_count = u32_at(b, 0x70);
        let table_len = u32_at(b, 0x74);
        if u64::from(seg_count) * ENTRY_SIZE as u64 != u64::from(table_len) {
            return Err(StreamError::TableInvalid);
        }
        let rvf_identity: [u8; 32] = arr(b, 0x30);
        if flags & FLAG_IDENTITY_PRESENT == 0 && rvf_identity != [0u8; 32] {
            return Err(StreamError::BadFlags);
        }
        Ok(Self {
            flags,
            chunk_log2,
            file_id: arr(b, 0x10),
            epoch: u64_at(b, 0x20),
            body_len: u64_at(b, 0x28),
            rvf_identity,
            policy_hash: arr(b, 0x50),
            seg_count,
            expires_ns: u64_at(b, 0x78),
            signer_key_id: arr(b, 0x80),
        })
    }

    /// Chunk size in bytes; `None` for the segment-granular profile.
    #[must_use]
    pub const fn chunk_size(&self) -> Option<u64> {
        if self.chunk_log2 == CHUNK_LOG2_SEGMENT {
            None
        } else {
            Some(1u64 << self.chunk_log2)
        }
    }

    /// Chunks in a segment of `stored_len` bytes (at least 1); `None` when the
    /// count does not fit a `u32`.
    #[must_use]
    pub fn chunk_count(&self, stored_len: u64) -> Option<u32> {
        match self.chunk_size() {
            Some(cs) if stored_len > cs => u32::try_from(stored_len.div_ceil(cs)).ok(),
            _ => Some(1),
        }
    }

    /// Length of chunk `index` of a segment of `stored_len` bytes.
    #[must_use]
    pub fn chunk_len(&self, stored_len: u64, index: u32) -> Option<u64> {
        let n = self.chunk_count(stored_len)?;
        if index >= n {
            return None;
        }
        match self.chunk_size() {
            Some(cs) if n > 1 => {
                if index + 1 < n {
                    Some(cs)
                } else {
                    Some(stored_len - cs * (u64::from(n) - 1))
                }
            }
            _ => Some(stored_len),
        }
    }
}

impl StreamEntry {
    fn from_bytes(b: &[u8]) -> Self {
        Self {
            seg_id: u64_at(b, 0),
            seg_type: b[8],
            stage: b[9],
            flags: u16_at(b, 10),
            requires_mask: u32_at(b, 12),
            body_offset: u64_at(b, 16),
            stored_len: u64_at(b, 24),
            uncompressed_len: u64_at(b, 32),
            chunk_table_hash: arr(b, 40),
        }
    }

    /// Encode to the 72-byte wire form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ENTRY_SIZE] {
        let mut b = [0u8; ENTRY_SIZE];
        b[0..8].copy_from_slice(&self.seg_id.to_le_bytes());
        b[8] = self.seg_type;
        b[9] = self.stage;
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        b[12..16].copy_from_slice(&self.requires_mask.to_le_bytes());
        b[16..24].copy_from_slice(&self.body_offset.to_le_bytes());
        b[24..32].copy_from_slice(&self.stored_len.to_le_bytes());
        b[32..40].copy_from_slice(&self.uncompressed_len.to_le_bytes());
        b[40..72].copy_from_slice(&self.chunk_table_hash);
        b
    }
}

impl StreamHeader {
    /// Encode to the 0x90-byte wire form (producer side and tests).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut b = [0u8; HEADER_SIZE];
        b[0..4].copy_from_slice(&MAGIC);
        b[4..6].copy_from_slice(&VERSION.to_le_bytes());
        b[6..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8] = 1;
        b[9] = self.chunk_log2;
        b[0x10..0x20].copy_from_slice(&self.file_id);
        b[0x20..0x28].copy_from_slice(&self.epoch.to_le_bytes());
        b[0x28..0x30].copy_from_slice(&self.body_len.to_le_bytes());
        b[0x30..0x50].copy_from_slice(&self.rvf_identity);
        b[0x50..0x70].copy_from_slice(&self.policy_hash);
        b[0x70..0x74].copy_from_slice(&self.seg_count.to_le_bytes());
        let table_len = self.seg_count.wrapping_mul(ENTRY_SIZE as u32);
        b[0x74..0x78].copy_from_slice(&table_len.to_le_bytes());
        b[0x78..0x80].copy_from_slice(&self.expires_ns.to_le_bytes());
        b[0x80..0x88].copy_from_slice(&self.signer_key_id);
        b
    }
}

/// A descriptor that passed every ADR-353 section 2 invariant.
#[derive(Debug, Clone)]
pub struct VerifiedDescriptor {
    /// The validated fixed header.
    pub header: StreamHeader,
    /// Table entries in body order.
    pub entries: Vec<StreamEntry>,
    /// `(seg_id, entry index)` sorted by `seg_id`, for lookup.
    pub index: Vec<(u64, u32)>,
    /// SHA-256 of the complete signed descriptor.
    pub descriptor_hash: [u8; 32],
    /// The trusted key that verified the signature.
    pub signer: [u8; 32],
}

impl VerifiedDescriptor {
    /// The entry index of `seg_id`.
    #[must_use]
    pub fn find(&self, seg_id: u64) -> Option<usize> {
        self.index
            .binary_search_by_key(&seg_id, |(id, _)| *id)
            .ok()
            .map(|i| self.index[i].1 as usize)
    }
}

/// Exact descriptor length for `seg_count` entries; `None` on overflow.
#[must_use]
pub fn descriptor_len(seg_count: u32) -> Option<usize> {
    (seg_count as usize)
        .checked_mul(ENTRY_SIZE)?
        .checked_add(HEADER_SIZE + TRAILER_SIZE)
}

/// Decode and fully verify a signed descriptor under `policy`.
///
/// Checks run in a fixed order and the first failure is the reported reason:
/// size cap, fixed header, `seg_count` cap, exact length, `sig_len`, signer
/// lookup, signature (`verify_strict`), expiry, expected `policy_hash`, epoch
/// pin, then the table.
///
/// # Errors
///
/// The [`StreamError`] of the first violated invariant.
pub fn decode_descriptor(
    bytes: &[u8],
    policy: &StreamPolicy<'_>,
) -> StreamResult<VerifiedDescriptor> {
    if bytes.len() > policy.max_descriptor_bytes {
        return Err(StreamError::LimitExceeded);
    }
    let h = StreamHeader::parse(bytes)?;
    if h.seg_count > policy.max_segments || h.seg_count as usize > policy.size.max_segments {
        return Err(StreamError::LimitExceeded);
    }
    if descriptor_len(h.seg_count) != Some(bytes.len()) {
        return Err(StreamError::DescriptorTruncated);
    }
    let sig_len_at = HEADER_SIZE + h.seg_count as usize * ENTRY_SIZE;
    if usize::from(u16_at(bytes, sig_len_at)) != SIG_LEN {
        return Err(StreamError::DescriptorTruncated);
    }

    let mut signer = None;
    let mut known = false;
    for pk in policy.trusted_keys {
        if signer_key_id(pk) == h.signer_key_id {
            known = true;
            if verify_descriptor_signature(bytes, pk) {
                signer = Some(*pk);
                break;
            }
        }
    }
    let signer = match signer {
        Some(s) => s,
        None if known => return Err(StreamError::BadSignature),
        None => return Err(StreamError::UnknownSigner),
    };

    if h.expires_ns != 0 && policy.replay.is_pinned() {
        match policy.replay.now_ns() {
            None => return Err(StreamError::ClockRequired),
            Some(now) if now >= h.expires_ns => return Err(StreamError::Expired),
            Some(_) => {}
        }
    }
    if policy
        .expected_policy_hash
        .is_some_and(|p| p != h.policy_hash)
    {
        return Err(StreamError::PolicyMismatch);
    }
    let dhash = descriptor_hash(bytes);
    // A pin binds a lineage: the file id *and* the signer that published it.
    // A descriptor from another signer is not that lineage and is judged by
    // the trust set alone.
    if let Some(pin) = policy.replay.lookup(&h.signer_key_id, &h.file_id) {
        if h.epoch < pin.epoch {
            return Err(StreamError::StaleEpoch);
        }
        if h.epoch == pin.epoch && pin.descriptor_hash != dhash {
            return Err(StreamError::EpochConflict);
        }
    }

    let (entries, index) = parse_table(&bytes[HEADER_SIZE..sig_len_at], &h, policy)?;
    Ok(VerifiedDescriptor {
        header: h,
        entries,
        index,
        descriptor_hash: dhash,
        signer,
    })
}

type Table = (Vec<StreamEntry>, Vec<(u64, u32)>);

fn parse_table(table: &[u8], h: &StreamHeader, policy: &StreamPolicy<'_>) -> StreamResult<Table> {
    use StreamError::{LimitExceeded as Limit, TableInvalid as Invalid};
    if h.seg_count == 0 {
        return Err(Invalid);
    }
    if h.body_len > policy.size.max_container_bytes {
        return Err(Limit);
    }
    let mut entries = Vec::with_capacity(h.seg_count as usize);
    let mut expect_off = 0u64;
    let mut class_total = [0u64; 4];
    let mut union_req = [0u32; MAX_STAGES as usize];
    for (i, raw) in table.chunks_exact(ENTRY_SIZE).enumerate() {
        let e = StreamEntry::from_bytes(raw);
        if e.body_offset != expect_off || e.stored_len == 0 {
            return Err(Invalid);
        }
        if e.flags != 0 {
            return Err(Invalid);
        }
        if e.seg_type == SEG_TYPE_ROOT_PAGE {
            if i + 1 != h.seg_count as usize
                || e.stored_len != crate::container::ROOT_PAGE_SIZE as u64
                || e.uncompressed_len != 0
            {
                return Err(Invalid);
            }
        } else if e.stored_len < 64 {
            return Err(Invalid);
        }
        if e.stage >= MAX_STAGES || e.requires_mask & (1u32 << e.stage) != 0 {
            return Err(Invalid);
        }
        if e.stored_len > policy.max_segment_bytes
            || e.uncompressed_len > policy.max_uncompressed_len
        {
            return Err(Limit);
        }
        if h.chunk_size().is_none() && e.stored_len > u64::from(u32::MAX) {
            return Err(Limit);
        }
        let Some(n) = h.chunk_count(e.stored_len) else {
            return Err(Limit);
        };
        if u64::from(n) > 1 && u64::from(n) * 32 > policy.max_table_bytes {
            return Err(Limit);
        }
        let class = segment_class(e.seg_type);
        let c = class as usize;
        class_total[c] = class_total[c].checked_add(e.stored_len).ok_or(Limit)?;
        if class_total[c] > policy.size.budget_for(class) {
            return Err(Limit);
        }
        expect_off = e.body_offset.checked_add(e.stored_len).ok_or(Invalid)?;
        union_req[e.stage as usize] |= e.requires_mask;
        entries.push(e);
    }
    if expect_off != h.body_len {
        return Err(Invalid);
    }
    let mut index: Vec<(u64, u32)> = entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.seg_id, i as u32))
        .collect();
    index.sort_unstable();
    if index.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(Invalid);
    }
    stages_acyclic(&union_req)?;
    Ok((entries, index))
}

/// Stage `s` may require stage `t` only if `t` does not (transitively) require
/// `s`; otherwise no delivery order could ever release a chunk.
fn stages_acyclic(req: &[u32; MAX_STAGES as usize]) -> StreamResult<()> {
    let mut done = 0u32;
    for _ in 0..MAX_STAGES {
        let mut progressed = false;
        for (s, r) in req.iter().enumerate() {
            if done & (1 << s) == 0 && r & !done == 0 {
                done |= 1 << s;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }
    if done == u32::MAX {
        Ok(())
    } else {
        Err(StreamError::TableInvalid)
    }
}
