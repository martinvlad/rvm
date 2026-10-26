//! Hash commitments of ADR-353 section 3, restated independently of RuVector.
//!
//! * leaf: `SHA-256(0x00 || file_id || seg_id u64 || chunk_index u32 || chunk_len u64 || bytes)`
//! * chunk list: `SHA-256(0x01 || file_id || seg_id u64 || n u32 || leaf_0 || ... )`
//! * signer key id: first 8 bytes of `SHA-256(public key)`
//! * descriptor signature: Ed25519 `verify_strict` over
//!   `"RVF-v1-stream-descriptor\0" || every descriptor byte before the 64-byte signature`

use alloc::vec::Vec;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Domain tag of a chunk leaf.
pub const LEAF_TAG: u8 = 0x00;
/// Domain tag of a chunk table.
pub const TABLE_TAG: u8 = 0x01;
/// Domain-separation prefix of the signed descriptor message.
pub const SIG_DOMAIN: &[u8] = b"RVF-v1-stream-descriptor\0";
/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;

/// The leaf hash of one chunk; `chunk_len` is `bytes.len()`.
#[must_use]
pub fn leaf_hash(file_id: &[u8; 16], seg_id: u64, chunk_index: u32, bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_TAG]);
    h.update(file_id);
    h.update(seg_id.to_le_bytes());
    h.update(chunk_index.to_le_bytes());
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
    h.finalize().into()
}

/// The chunk-list hash over a flat run of `n * 32` leaf bytes, or `None` when
/// the length is not a multiple of 32 or `n` does not fit a `u32`.
#[must_use]
pub fn chunk_list_hash_flat(file_id: &[u8; 16], seg_id: u64, flat: &[u8]) -> Option<[u8; 32]> {
    if flat.len() % 32 != 0 {
        return None;
    }
    let n = u32::try_from(flat.len() / 32).ok()?;
    let mut h = Sha256::new();
    h.update([TABLE_TAG]);
    h.update(file_id);
    h.update(seg_id.to_le_bytes());
    h.update(n.to_le_bytes());
    h.update(flat);
    Some(h.finalize().into())
}

/// The chunk-list hash over a slice of leaves.
#[must_use]
pub fn chunk_list_hash(file_id: &[u8; 16], seg_id: u64, leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([TABLE_TAG]);
    h.update(file_id);
    h.update(seg_id.to_le_bytes());
    h.update((leaves.len() as u32).to_le_bytes());
    for l in leaves {
        h.update(l);
    }
    h.finalize().into()
}

/// First 8 bytes of `SHA-256(public_key)`.
#[must_use]
pub fn signer_key_id(public_key: &[u8; 32]) -> [u8; 8] {
    let d = Sha256::digest(public_key);
    let mut id = [0u8; 8];
    id.copy_from_slice(&d[..8]);
    id
}

/// SHA-256 of a complete signed descriptor: the value a package contract or
/// an epoch pin carries.
#[must_use]
pub fn descriptor_hash(descriptor: &[u8]) -> [u8; 32] {
    Sha256::digest(descriptor).into()
}

/// The message an Ed25519 descriptor signature covers. `unsigned` is every
/// descriptor byte before the signature, `sig_len` included.
#[must_use]
pub fn signed_message(unsigned: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + unsigned.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(unsigned);
    m
}

/// Whether the trailing 64 bytes of `descriptor` are a valid `verify_strict`
/// signature, under `public_key`, over the rest.
#[must_use]
pub fn verify_descriptor_signature(descriptor: &[u8], public_key: &[u8; 32]) -> bool {
    if descriptor.len() < SIG_LEN {
        return false;
    }
    let (unsigned, sig) = descriptor.split_at(descriptor.len() - SIG_LEN);
    let mut s = [0u8; SIG_LEN];
    s.copy_from_slice(sig);
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify_strict(&signed_message(unsigned), &Signature::from_bytes(&s))
        .is_ok()
}
