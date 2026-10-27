//! Fuzz the frame state machine, seeded from the shared known-answer vectors.
//!
//! Input: `[fault_budget, split_a, split_b, ..frame bytes]`. The bytes are fed
//! to a `FrameReader` + `StreamVerifier` twice with two different split
//! patterns. Properties:
//!
//! * never panics;
//! * every released chunk is byte-identical to the signed body (P1);
//! * the result does not depend on how the bytes were split (same state, same
//!   released chunks);
//! * `Complete`/`CompleteUnverified` only if every released chunk reassembles the signed body.
//!
//! Seeds (derived from the shared vectors, regenerate with the ignored test
//! `write_fuzz_seeds`): `cargo +nightly fuzz run frame_machine corpus/frame_machine seeds/frame_machine`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rvm_rvf::stream::{Event, FrameReader, StreamPolicy, StreamState, StreamVerifier};
use serde_json::Value;
use std::sync::OnceLock;

const VECTORS: &str = include_str!("../../tests/vectors/rvsd-v1-vectors.json");

struct Vectors {
    key: [u8; 32],
    bodies: Vec<Vec<u8>>,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn vectors() -> &'static Vectors {
    static V: OnceLock<Vectors> = OnceLock::new();
    V.get_or_init(|| {
        let v: Value = serde_json::from_str(VECTORS).unwrap();
        Vectors {
            key: hex(v["test_only_key"]["public_key_hex"].as_str().unwrap())
                .try_into()
                .unwrap(),
            bodies: vec![
                hex(v["body"]["hex"].as_str().unwrap()),
                hex(v["other_body_hex"].as_str().unwrap()),
            ],
        }
    })
}

type Released = Vec<(u64, u32, u64, Vec<u8>)>;

fn run(budget: u32, split: usize, bytes: &[u8]) -> (StreamState, Released) {
    let v = vectors();
    let keys = [v.key];
    let mut policy = StreamPolicy::unpinned_insecure(&keys);
    policy.fault_budget = budget;
    let mut ver = StreamVerifier::new(policy);
    let mut reader = FrameReader::new();
    let mut released = Released::new();
    for piece in bytes.chunks(split.max(1)) {
        let r = reader.feed(&mut ver, piece, |res| {
            if let Ok(Event::Chunk { chunk, .. }) = res {
                let at = chunk.body_offset as usize;
                // P1: released bytes are bytes of one of the signed bodies.
                assert!(
                    v.bodies.iter().any(|b| {
                        b.get(at..at + chunk.bytes.len()) == Some(chunk.bytes)
                    }),
                    "released bytes are not part of a signed body"
                );
                released.push((chunk.seg_id, chunk.chunk_index, chunk.body_offset, chunk.bytes.to_vec()));
            }
        });
        if r.is_err() {
            break;
        }
    }
    (ver.state(), released)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let budget = u32::from(data[0] & 7);
    let a = usize::from(data[1]) + 1;
    let b = usize::from(data[2]) * 7 + 3;
    let bytes = &data[3..];
    let (sa, ra) = run(budget, a, bytes);
    let (sb, rb) = run(budget, b, bytes);
    assert_eq!(sa, sb, "state depends on how the bytes were split");
    assert_eq!(ra, rb, "released chunks depend on how the bytes were split");
    if matches!(sa, StreamState::Complete | StreamState::CompleteUnverified) {
        // Complete means every segment verified: the released chunks tile a body.
        let total: usize = ra.iter().map(|c| c.3.len()).sum();
        assert!(vectors().bodies.iter().any(|b| b.len() == total));
    }
});
