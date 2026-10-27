//! Frame encoding and byte-stream reassembly (ADR-353 section 4).
//!
//! * `0x00 DESCRIPTOR`: `type u8 | len u32 | descriptor`
//! * `0x01 CHUNK`: `type u8 | seg_id u64 | chunk_index u32 | len u32 | bytes`
//! * `0x02 CHUNK_TABLE`: `type u8 | seg_id u64 | n u32 | n * 32-byte leaves`

use super::error::{StreamError, StreamResult};
use super::events::StreamState;
use alloc::vec::Vec;

/// Frame type: inline descriptor.
pub const FRAME_DESCRIPTOR: u8 = 0x00;
/// Frame type: chunk.
pub const FRAME_CHUNK: u8 = 0x01;
/// Frame type: chunk table.
pub const FRAME_CHUNK_TABLE: u8 = 0x02;

/// Encode a descriptor frame.
#[must_use]
pub fn descriptor_frame(descriptor: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(5 + descriptor.len());
    f.push(FRAME_DESCRIPTOR);
    f.extend_from_slice(&(descriptor.len() as u32).to_le_bytes());
    f.extend_from_slice(descriptor);
    f
}

/// Encode a chunk frame.
#[must_use]
pub fn chunk_frame(seg_id: u64, chunk_index: u32, bytes: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(17 + bytes.len());
    f.push(FRAME_CHUNK);
    f.extend_from_slice(&seg_id.to_le_bytes());
    f.extend_from_slice(&chunk_index.to_le_bytes());
    f.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    f.extend_from_slice(bytes);
    f
}

/// Encode a chunk-table frame from `leaves`.
#[must_use]
pub fn table_frame(seg_id: u64, leaves: &[[u8; 32]]) -> Vec<u8> {
    let mut f = Vec::with_capacity(13 + 32 * leaves.len());
    f.push(FRAME_CHUNK_TABLE);
    f.extend_from_slice(&seg_id.to_le_bytes());
    f.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
    for l in leaves {
        f.extend_from_slice(l);
    }
    f
}

const fn header_len(frame_type: u8) -> Option<usize> {
    match frame_type {
        FRAME_DESCRIPTOR => Some(5),
        FRAME_CHUNK => Some(17),
        FRAME_CHUNK_TABLE => Some(13),
        _ => None,
    }
}

/// The payload size a complete frame header declares.
fn declared_payload(h: &[u8]) -> u64 {
    let u32_at = |o: usize| u64::from(u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]));
    match h[0] {
        FRAME_DESCRIPTOR => u32_at(1),
        FRAME_CHUNK => u32_at(13),
        _ => 32 * u32_at(9),
    }
}

/// Something frames can be pushed into: a [`super::StreamVerifier`], or a
/// [`super::StreamAdmission`] wrapping one.
pub trait FrameTarget {
    /// What an accepted frame yields.
    type Out<'a>;
    /// What a refused frame yields.
    type Error;

    /// The verifier's state.
    fn state(&self) -> StreamState;
    /// The largest payload a frame of this type may declare right now.
    fn frame_payload_limit(&self, frame_type: u8) -> u64;
    /// Poison the stream (a size lie found while reassembling).
    fn poison(&mut self, reason: StreamError) -> StreamError;
    /// Push one complete frame.
    ///
    /// # Errors
    ///
    /// The target's refusal.
    fn push_frame<'a>(&mut self, frame: &'a [u8]) -> Result<Self::Out<'a>, Self::Error>;
}

/// Reassembles frames from arbitrary byte splits and feeds a verifier.
///
/// The size a frame header declares is checked against the verifier's limits,
/// which derive from the signed descriptor, as soon as the header is complete
/// and before a single payload byte is buffered. At most one frame is
/// buffered, and a frame that arrives whole at the front of the input is
/// pushed without being copied.
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
    need: Option<usize>,
}

impl FrameReader {
    /// An empty reader.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buf: Vec::new(),
            need: None,
        }
    }

    /// Bytes currently buffered (a partial frame).
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Consume `data`: every completed frame is pushed into `v` and its result
    /// handed to `sink`.
    ///
    /// # Errors
    ///
    /// Once the stream cannot accept more input (the rest of `data` is
    /// discarded) or a header declares an illegal size or an unknown type.
    pub fn feed<T, F>(&mut self, v: &mut T, mut data: &[u8], mut sink: F) -> StreamResult<()>
    where
        T: FrameTarget,
        F: for<'x> FnMut(Result<T::Out<'x>, T::Error>),
    {
        while !data.is_empty() {
            match v.state() {
                StreamState::Poisoned(_) => return Err(StreamError::Poisoned),
                StreamState::Rejected(_)
                | StreamState::Complete
                | StreamState::CompleteUnverified
                | StreamState::Suspended => return Err(StreamError::BadState),
                _ => {}
            }
            if self.buf.is_empty() {
                if let Some(hl) = header_len(data[0]) {
                    if data.len() >= hl {
                        let total = Self::admit(v, &data[..hl])?;
                        if data.len() >= total {
                            sink(v.push_frame(&data[..total]));
                            data = &data[total..];
                            continue;
                        }
                    }
                } else {
                    return Err(v.poison(StreamError::UnexpectedFrame));
                }
            }
            let target = match self.need {
                Some(total) => total,
                None => header_len(self.buf.first().copied().unwrap_or(data[0]))
                    .ok_or(StreamError::UnexpectedFrame)?,
            };
            let take = (target - self.buf.len()).min(data.len());
            self.buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.need.is_none() && self.buf.len() == target {
                self.need = Some(Self::admit(v, &self.buf)?);
            }
            if Some(self.buf.len()) == self.need {
                let frame = core::mem::take(&mut self.buf);
                self.need = None;
                sink(v.push_frame(&frame));
            }
        }
        Ok(())
    }

    /// Check the declared payload against the verifier before buffering and
    /// return the frame's total length.
    fn admit<T: FrameTarget>(v: &mut T, header: &[u8]) -> StreamResult<usize> {
        let payload = declared_payload(header);
        if payload > v.frame_payload_limit(header[0]) {
            return Err(v.poison(StreamError::FrameSizeLie));
        }
        Ok(header.len() + payload as usize)
    }
}
