//! Fuzz the descriptor decoder, the only parser of unauthenticated bytes.
//!
//! Two modes per input, chosen by the first byte:
//! * raw: the bytes are handed to `decode_descriptor` as they are, which
//!   exercises length, header and signature handling;
//! * resigned: the bytes are treated as an unsigned descriptor body, `sig_len`
//!   and a valid signature are appended, so the table invariants (contiguity,
//!   uniqueness, limits, stage cycles) are reached with arbitrary content.
//!
//! Properties: never panics; never allocates beyond the policy bound (the
//! decoder checks lengths before allocating); an accepted descriptor satisfies
//! the invariants it promises.
#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use rvm_rvf::stream::{decode_descriptor, signed_message, StreamPolicy, ENTRY_SIZE, HEADER_SIZE};

const SEED: [u8; 32] = [0x2a; 32];

fn check(bytes: &[u8], keys: &[[u8; 32]]) {
    let policy = StreamPolicy::new(keys);
    if let Ok(d) = decode_descriptor(bytes, &policy) {
        // Everything an accepted descriptor promises.
        assert_eq!(d.entries.len(), d.header.seg_count as usize);
        assert_eq!(bytes.len(), HEADER_SIZE + ENTRY_SIZE * d.entries.len() + 66);
        let mut next = 0u64;
        for e in &d.entries {
            assert_eq!(e.body_offset, next);
            assert!(e.stored_len > 0);
            next += e.stored_len;
            assert!(e.stage < 32);
            assert_eq!(e.requires_mask & (1 << e.stage), 0);
        }
        assert_eq!(next, d.header.body_len);
        let mut ids: Vec<u64> = d.entries.iter().map(|e| e.seg_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), d.entries.len());
    }
}

fuzz_target!(|data: &[u8]| {
    let key = SigningKey::from_bytes(&SEED);
    let keys = [key.verifying_key().to_bytes()];
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        check(rest, &keys);
    } else {
        // Keep the header's key id honest so the signer lookup succeeds.
        let mut unsigned = rest.to_vec();
        if unsigned.len() >= 0x88 {
            let id = rvm_rvf::stream::signer_key_id(&keys[0]);
            unsigned[0x80..0x88].copy_from_slice(&id);
        }
        unsigned.extend_from_slice(&64u16.to_le_bytes());
        let sig = key.sign(&signed_message(&unsigned)).to_bytes();
        unsigned.extend_from_slice(&sig);
        check(&unsigned, &keys);
    }
});
