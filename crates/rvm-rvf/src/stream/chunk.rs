//! The chunk path of [`StreamVerifier`]: every check between a chunk frame
//! arriving and a [`VerifiedChunk`] being released.

use super::commit::leaf_hash;
use super::descriptor::SEG_TYPE_ROOT_PAGE;
use super::error::{StreamError, StreamResult};
use super::events::{Event, IdentityStatus, StreamState, VerifiedChunk};
use super::verifier::StreamVerifier;
use crate::container::ROOT_PAGE_MAGIC;
use crate::format::{is_executable, SEGMENT_MAGIC_BYTES};
use sha2::Digest;
use subtle::ConstantTimeEq;

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn rd64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Index-class segment types: Index, HotCache and MetaIndex.
const fn is_index(seg_type: u8) -> bool {
    matches!(seg_type, 0x02 | 0x08 | 0x0D)
}

impl StreamVerifier<'_> {
    pub(super) fn on_chunk<'a>(&mut self, f: &'a [u8]) -> StreamResult<Event<'a>> {
        if f.len() < 17 {
            return Err(self.poison(StreamError::FrameSizeLie));
        }
        let (seg_id, idx, len) = (rd64(f, 1), rd32(f, 9), rd32(f, 13));
        let bytes = &f[17..];
        if len as usize != bytes.len() {
            return Err(self.poison_at(StreamError::FrameSizeLie, Some(seg_id), idx));
        }
        let Some(i) = self.desc.as_ref().and_then(|d| d.find(seg_id)) else {
            return Err(self.fault(StreamError::UnexpectedFrame, Some(seg_id), idx));
        };
        if idx < self.segs[i].next {
            return self.on_duplicate_chunk(i, idx, bytes);
        }
        self.admit_chunk(i, seg_id, idx, bytes)?;
        let (h, e) = {
            let d = self.desc.as_ref().expect("descriptor installed");
            (d.header, d.entries[i])
        };
        let segment_offset = h.chunk_size().map_or(0, |cs| u64::from(idx) * cs);
        let body_offset = e.body_offset + segment_offset;
        let completes_segment = self.segs[i].next + 1 == self.segs[i].n;
        let completes_stream = completes_segment && self.left == 1;
        if let Some(t) = &mut self.identity {
            if t.feasible && t.pos == body_offset {
                t.hasher.update(bytes);
                t.pos += bytes.len() as u64;
            } else {
                t.feasible = false;
            }
        }
        // The identity verdict is reached before anything is advanced, so a
        // chunk that fails it leaves the segment records exactly as they were.
        let complete = if completes_stream {
            match self.completion_status(bytes.len() as u64) {
                Ok(st) => Some(st),
                Err(c) => return Err(self.poison_at(c, Some(seg_id), idx)),
            }
        } else {
            None
        };
        let mut stage_verified = None;
        let s = &mut self.segs[i];
        s.next += 1;
        if completes_segment {
            s.done = true;
            self.left -= 1;
            let st = e.stage as usize;
            self.stage_remaining[st] -= 1;
            if self.stage_remaining[st] == 0 {
                stage_verified = Some(e.stage);
            }
        }
        self.verified_bytes += bytes.len() as u64;
        self.released_chunks += 1;
        if let Some(st) = complete {
            self.identity_status = Some(st);
            self.state = if st == IdentityStatus::Unverifiable {
                StreamState::CompleteUnverified
            } else {
                StreamState::Complete
            };
        }
        Ok(Event::Chunk {
            chunk: VerifiedChunk {
                seg_id,
                seg_type: e.seg_type,
                chunk_index: idx,
                segment_offset,
                body_offset,
                bytes,
            },
            segment_verified: completes_segment,
            stage_verified,
            complete,
        })
    }

    /// Every check on a chunk frame up to and including the leaf hash and the
    /// weak-checksum rule. Returns the segment's entry index.
    fn admit_chunk(&mut self, i: usize, seg_id: u64, idx: u32, bytes: &[u8]) -> StreamResult<()> {
        let (h, e) = {
            let d = self.desc.as_ref().expect("descriptor installed");
            (d.header, d.entries[i])
        };
        let s = &self.segs[i];
        if s.done || idx != s.next {
            return Err(self.fault(StreamError::UnexpectedFrame, Some(seg_id), idx));
        }
        if h.chunk_len(e.stored_len, idx) != Some(bytes.len() as u64) {
            return Err(self.poison_at(StreamError::FrameSizeLie, Some(seg_id), idx));
        }
        if s.n > 1 && s.leaves.is_none() {
            return Err(self.fault(StreamError::UnexpectedFrame, Some(seg_id), idx));
        }
        let mut need = e.requires_mask;
        while need != 0 {
            let st = need.trailing_zeros() as usize;
            need &= need - 1;
            if self.stage_remaining[st] != 0 {
                return Err(self.fault(StreamError::RequirementsUnmet, Some(seg_id), idx));
            }
        }
        let leaf = leaf_hash(&h.file_id, seg_id, idx, bytes);
        let mut want = e.chunk_table_hash;
        if let Some(l) = &s.leaves {
            want.copy_from_slice(&l[idx as usize * 32..idx as usize * 32 + 32]);
        }
        if !bool::from(leaf.ct_eq(&want)) {
            return Err(self.fault(StreamError::ChunkHashMismatch, Some(seg_id), idx));
        }
        if idx == 0 && (is_executable(e.seg_type) || is_index(e.seg_type)) {
            // The bytes are authenticated, but a non-cryptographic checksum
            // claim must not feed an executor or an index (ADR-353 2.6).
            if bytes[0..4] != SEGMENT_MAGIC_BYTES || bytes[5] != e.seg_type {
                return Err(self.poison_at(StreamError::TableInvalid, Some(seg_id), idx));
            }
            if bytes[0x20] <= 1 {
                return Err(self.poison_at(StreamError::WeakChecksum, Some(seg_id), idx));
            }
        }
        if idx == 0
            && e.seg_type == SEG_TYPE_ROOT_PAGE
            && bytes[..4] != ROOT_PAGE_MAGIC.to_le_bytes()
        {
            return Err(self.poison_at(StreamError::TableInvalid, Some(seg_id), idx));
        }
        Ok(())
    }

    /// A chunk below the next expected index: idempotent if it hashes to the
    /// verified leaf (and counted against the duplicate cap), otherwise an
    /// ordinary hash-mismatch fault.
    fn on_duplicate_chunk<'a>(
        &mut self,
        i: usize,
        idx: u32,
        bytes: &[u8],
    ) -> StreamResult<Event<'a>> {
        let (h, e) = {
            let d = self.desc.as_ref().expect("descriptor installed");
            (d.header, d.entries[i])
        };
        let seg_id = e.seg_id;
        if h.chunk_len(e.stored_len, idx) != Some(bytes.len() as u64) {
            return Err(self.poison_at(StreamError::FrameSizeLie, Some(seg_id), idx));
        }
        let mut want = e.chunk_table_hash;
        if let Some(l) = &self.segs[i].leaves {
            want.copy_from_slice(&l[idx as usize * 32..idx as usize * 32 + 32]);
        }
        if !bool::from(leaf_hash(&h.file_id, seg_id, idx, bytes).ct_eq(&want)) {
            return Err(self.fault(StreamError::ChunkHashMismatch, Some(seg_id), idx));
        }
        self.count_duplicate(seg_id, idx)?;
        Ok(Event::Duplicate {
            seg_id,
            chunk_index: idx,
        })
    }

    /// The identity verdict for the chunk that would complete the stream.
    /// `extra` is that chunk's length. Changes no segment record.
    fn completion_status(&self, extra: u64) -> StreamResult<IdentityStatus> {
        let h = self.desc.as_ref().expect("descriptor installed").header;
        if self.verified_bytes + extra != h.body_len {
            return Err(StreamError::TableInvalid);
        }
        match &self.identity {
            None => Ok(IdentityStatus::NotPresent),
            Some(t) if t.feasible && t.pos == h.body_len => {
                let got: [u8; 32] = t.hasher.clone().finalize().into();
                if bool::from(got.ct_eq(&h.rvf_identity)) {
                    Ok(IdentityStatus::Verified)
                } else {
                    Err(StreamError::IdentityMismatch)
                }
            }
            Some(_) => Ok(IdentityStatus::Unverifiable),
        }
    }
}
