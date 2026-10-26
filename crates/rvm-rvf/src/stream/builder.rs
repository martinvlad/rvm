//! Producer side of the stream descriptor, for tests and benchmarks.
//!
//! Production RVM only consumes streams. This builder exists so a test can
//! turn any RVF body into a signed descriptor and a frame sequence, tamper
//! with either, and show the receiver refusing the tampering. It is compiled
//! only under `cfg(test)` or the `testkit` feature.

#![allow(clippy::must_use_candidate)]

use super::commit::{chunk_list_hash, leaf_hash, signed_message, signer_key_id};
use super::descriptor::{
    StreamEntry, StreamHeader, CHUNK_LOG2_SEGMENT, FLAG_CHUNKED, FLAG_IDENTITY_PRESENT,
    FLAG_REQUIRE_COMPLETE_BEFORE_EXEC, SEG_TYPE_ROOT_PAGE,
};
use super::frame::{chunk_frame, descriptor_frame, table_frame};
use crate::container::walk_container;
use crate::error::RvfResult;
use crate::format::{is_executable, SEG_TYPE_MANIFEST, SEG_TYPE_META};
use crate::hash::sha256;
use alloc::vec::Vec;
use ed25519_dalek::{Signer, SigningKey};

/// Delivery order of the segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Order {
    /// Body order.
    File,
    /// `(stage, body order)`.
    Stage,
}

/// How segments are assigned to stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stages {
    /// Everything in stage 0, nothing required.
    Flat,
    /// Manifest and metadata in stage 0; executables in stage 1 requiring
    /// stage 0; everything else in stage 2 requiring stages 0 and 1.
    ByType,
}

/// Configurable producer of descriptors and frames.
#[derive(Clone)]
pub struct StreamBuilder {
    signing: SigningKey,
    /// Artifact lineage id.
    pub file_id: [u8; 16],
    /// Descriptor epoch.
    pub epoch: u64,
    /// `0xFF` for the segment-granular profile, else `12..=30`.
    pub chunk_log2: u8,
    /// Expiry in ns (`0` = none).
    pub expires_ns: u64,
    /// `capabilityPolicyHash`.
    pub policy_hash: [u8; 32],
    /// Whether the descriptor commits to the body hash.
    pub identity: bool,
    /// Set `require_complete_before_exec`.
    pub require_complete: bool,
    /// Sign this identity instead of the body's real SHA-256 (a descriptor
    /// that lies about the identity, for tests).
    pub identity_override: Option<[u8; 32]>,
    /// Frame delivery order.
    pub order: Order,
    /// Stage assignment.
    pub stages: Stages,
}

/// One table entry's span of the body.
#[derive(Debug, Clone, Copy)]
pub struct Span {
    /// Segment id.
    pub seg_id: u64,
    /// Segment type (`0xFE` for the root page).
    pub seg_type: u8,
    /// First body byte.
    pub start: usize,
    /// One past the last body byte.
    pub end: usize,
    /// Declared `uncompressed_len`.
    pub uncompressed: u32,
}

/// A built stream.
#[derive(Debug, Clone)]
pub struct StreamBundle {
    /// The signed descriptor bytes.
    pub descriptor: Vec<u8>,
    /// SHA-256 of the descriptor.
    pub descriptor_hash: [u8; 32],
    /// The header that was signed.
    pub header: StreamHeader,
    /// The table that was signed, in body order.
    pub entries: Vec<StreamEntry>,
    /// Frames in delivery order, descriptor frame first.
    pub frames: Vec<Vec<u8>>,
}

impl StreamBuilder {
    /// A builder signing with the Ed25519 key derived from `seed`.
    #[must_use]
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(&seed),
            file_id: *b"rvm-testkit-file",
            epoch: 1,
            chunk_log2: 12,
            expires_ns: 0,
            policy_hash: [0xAB; 32],
            identity: true,
            require_complete: false,
            identity_override: None,
            order: Order::File,
            stages: Stages::Flat,
        }
    }

    /// The public key a receiver must trust.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn stage_of(&self, seg_type: u8) -> (u8, u32) {
        match self.stages {
            Stages::Flat => (0, 0),
            Stages::ByType => {
                if seg_type == SEG_TYPE_META || seg_type == SEG_TYPE_MANIFEST {
                    (0, 0)
                } else if is_executable(seg_type) {
                    (1, 0b1)
                } else {
                    (2, 0b11)
                }
            }
        }
    }

    /// Build the descriptor and frames for `body`, which must be an RVF
    /// container [`walk_container`] accepts.
    ///
    /// # Errors
    ///
    /// The structural error if `body` is not a walkable container.
    pub fn build(&self, body: &[u8]) -> RvfResult<StreamBundle> {
        let walked = walk_container(body)?;
        let mut spans: Vec<Span> = Vec::new();
        for (i, seg) in walked.segments.iter().enumerate() {
            let end = walked.segments.get(i + 1).map_or_else(
                || walked.root_page.as_ref().map_or(body.len(), |r| r.start),
                |next| next.offset,
            );
            spans.push(Span {
                seg_id: seg.header.segment_id,
                seg_type: seg.header.seg_type,
                start: seg.offset,
                end,
                uncompressed: seg.header.uncompressed_len,
            });
        }
        if let Some(r) = &walked.root_page {
            spans.push(Span {
                seg_id: u64::MAX,
                seg_type: SEG_TYPE_ROOT_PAGE,
                start: r.start,
                end: r.end,
                uncompressed: 0,
            });
        }
        Ok(self.build_spans(body, &spans))
    }

    /// Build the descriptor and frames for `body` cut at explicit `spans`,
    /// without requiring that `body` walks. A test uses this to commit a
    /// descriptor to bytes that are authentic but not a well-formed container.
    ///
    /// # Panics
    ///
    /// If a span lies outside `body`.
    #[must_use]
    pub fn build_spans(&self, body: &[u8], spans: &[Span]) -> StreamBundle {
        let chunk_size = (self.chunk_log2 != CHUNK_LOG2_SEGMENT).then(|| 1usize << self.chunk_log2);
        let mut entries = Vec::new();
        let mut leaves_by_entry: Vec<Vec<[u8; 32]>> = Vec::new();
        for &Span {
            seg_id,
            seg_type,
            start,
            end,
            uncompressed,
        } in spans
        {
            let bytes = &body[start..end];
            let step = chunk_size.unwrap_or(bytes.len().max(1));
            let leaves: Vec<[u8; 32]> = bytes
                .chunks(step)
                .enumerate()
                .map(|(i, c)| leaf_hash(&self.file_id, seg_id, i as u32, c))
                .collect();
            let commitment = if leaves.len() == 1 {
                leaves[0]
            } else {
                chunk_list_hash(&self.file_id, seg_id, &leaves)
            };
            let (stage, requires_mask) = self.stage_of(seg_type);
            entries.push(StreamEntry {
                seg_id,
                seg_type,
                stage,
                flags: 0,
                requires_mask,
                body_offset: start as u64,
                stored_len: bytes.len() as u64,
                uncompressed_len: u64::from(uncompressed),
                chunk_table_hash: commitment,
            });
            leaves_by_entry.push(leaves);
        }

        let mut flags = 0;
        if chunk_size.is_some() {
            flags |= FLAG_CHUNKED;
        }
        if self.identity {
            flags |= FLAG_IDENTITY_PRESENT;
        }
        if self.require_complete {
            flags |= FLAG_REQUIRE_COMPLETE_BEFORE_EXEC;
        }
        let public = self.public_key();
        let header = StreamHeader {
            flags,
            chunk_log2: self.chunk_log2,
            file_id: self.file_id,
            epoch: self.epoch,
            body_len: body.len() as u64,
            rvf_identity: if self.identity {
                self.identity_override.unwrap_or_else(|| sha256(body))
            } else {
                [0; 32]
            },
            policy_hash: self.policy_hash,
            seg_count: entries.len() as u32,
            expires_ns: self.expires_ns,
            signer_key_id: signer_key_id(&public),
        };
        let mut descriptor = header.to_bytes().to_vec();
        for e in &entries {
            descriptor.extend_from_slice(&e.to_bytes());
        }
        descriptor.extend_from_slice(&64u16.to_le_bytes());
        let signature = self.signing.sign(&signed_message(&descriptor)).to_bytes();
        descriptor.extend_from_slice(&signature);

        let mut order: Vec<usize> = (0..entries.len()).collect();
        if self.order == Order::Stage {
            order.sort_by_key(|&i| (entries[i].stage, i));
        }
        let mut frames = alloc::vec![descriptor_frame(&descriptor)];
        for i in order {
            let e = &entries[i];
            let bytes = &body[e.body_offset as usize..(e.body_offset + e.stored_len) as usize];
            if leaves_by_entry[i].len() > 1 {
                frames.push(table_frame(e.seg_id, &leaves_by_entry[i]));
            }
            let step = chunk_size.unwrap_or(bytes.len().max(1));
            for (idx, c) in bytes.chunks(step).enumerate() {
                frames.push(chunk_frame(e.seg_id, idx as u32, c));
            }
        }
        StreamBundle {
            descriptor_hash: super::commit::descriptor_hash(&descriptor),
            descriptor,
            header,
            entries,
            frames,
        }
    }
}
