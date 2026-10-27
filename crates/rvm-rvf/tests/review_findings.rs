//! Adversarial-review repros (branch feat/ofer-review-rvm). Ids match
//! review-rvm-report.md. Tests named `rfNN_*` that PASS demonstrate a defect;
//! tests named `probe_*` are robustness probes that are expected to pass.

mod common;

use common::{builder, good_body, noise, opts, run_bundle, small_body};
use ed25519_dalek::{Signer, SigningKey};
use rvm_rvf::stream::builder::{Order, Span};
use rvm_rvf::stream::{
    signed_message, FrameReader, StreamAdmission, StreamPolicy, StreamState, HEADER_SIZE,
};
use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
use rvm_rvf::{verify, RvfError, ROOT_PAGE_MAGIC};
use std::panic::{catch_unwind, AssertUnwindSafe};

/// RF-01: a body whose last 4096 bytes start, inside a META payload, with the
/// root-page magic. The signed descriptor cuts it correctly into two ordinary
/// segments and the stream completes; the buffered walk mistakes the tail of
/// the payload for a Level-0 page and refuses the same bytes.
#[test]
fn rf01_rvm0_inside_a_payload_splits_stream_and_buffered_verdicts() {
    let mut body = unsigned_segment(0x05, b"root", 1); // 128 bytes
    let first_len = body.len();
    let mut payload = noise(8_000, 77);
    let total = first_len + 64 + 8_000; // 8192, already 64-aligned
    assert_eq!(total % 64, 0);
    let at = (total - 4096) - (first_len + 64);
    payload[at..at + 4].copy_from_slice(&ROOT_PAGE_MAGIC.to_le_bytes());
    body.extend(unsigned_segment(0x07, &payload, 2));
    assert_eq!(body.len(), total);

    // Buffered: refused as a structural error (tail of the payload is "the page").
    assert_eq!(verify(&body, &opts()).unwrap_err(), RvfError::PayloadOutOfBounds);

    // Stream: descriptor committed to the true segment boundaries.
    let b = builder(12, Order::File);
    let spans = [
        Span { seg_id: 1, seg_type: 0x05, start: 0, end: first_len, uncompressed: 0 },
        Span { seg_id: 2, seg_type: 0x07, start: first_len, end: total, uncompressed: 0 },
    ];
    let bundle = b.build_spans(&body, &spans);
    let keys = [b.public_key()];
    let run = run_bundle(&bundle, &keys, &opts());
    assert_eq!(run.state, StreamState::Complete, "{:?}", run.first_error);
    assert!(run.report.is_some(), "stream admitted what verify() refuses");
}

/// RF-02: calling the public `discard_derived_state` on a live (not poisoned)
/// admission makes the next completing segment index an emptied vector.
#[test]
fn rf02_discard_derived_state_on_a_live_stream_panics_later() {
    let body = small_body();
    let b = builder(0xFF, Order::File);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mut policy = StreamPolicy::new(&keys);
    policy.size = opts().size_policy;
    let mut adm = StreamAdmission::new(policy, opts());
    adm.push(&bundle.frames[0]).unwrap();
    adm.discard_derived_state();
    let r = catch_unwind(AssertUnwindSafe(|| {
        for f in &bundle.frames[1..] {
            let _ = adm.push(f);
        }
    }));
    assert!(r.is_err(), "expected an index-out-of-bounds panic");
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn drive(frames: &[Vec<u8>], keys: &[[u8; 32]]) {
    let mut policy = StreamPolicy::new(keys);
    policy.size = opts().size_policy;
    let mut adm = StreamAdmission::new(policy, opts());
    for f in frames {
        let _ = adm.push(f);
    }
}

fn drive_reader(frames: &[Vec<u8>], keys: &[[u8; 32]], rng: &mut Rng) {
    let mut policy = StreamPolicy::new(keys);
    policy.size = opts().size_policy;
    let mut adm = StreamAdmission::new(policy, opts());
    let all: Vec<u8> = frames.concat();
    let mut rd = FrameReader::new();
    let mut at = 0;
    while at < all.len() {
        let n = 1 + rng.below(700);
        let end = (at + n).min(all.len());
        if rd.feed(&mut adm, &all[at..end], |_| {}).is_err() {
            break;
        }
        at = end;
    }
}

/// Probe: byte-level and field-level mutation of authentic frames, pushed raw
/// and through the reassembler with hostile splits, must never panic.
#[test]
fn probe_mutated_frames_never_panic() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for (body, log2, order) in [
        (small_body(), 12u8, Order::File),
        (good_body(), 12, Order::Stage),
        (good_body(), 0xFF, Order::File),
    ] {
        let b = builder(log2, order);
        let bundle = b.build(&body).unwrap();
        let keys = [b.public_key()];
        for _ in 0..300 {
            let mut frames = bundle.frames.clone();
            for _ in 0..1 + rng.below(3) {
                let i = rng.below(frames.len());
                match rng.below(8) {
                    0 => {
                        let l = frames[i].len();
                        if l > 0 {
                            let at = rng.below(l);
                            frames[i][at] ^= 1 << rng.below(8);
                        }
                    }
                    1 => {
                        let l = frames[i].len();
                        frames[i].truncate(rng.below(l + 1));
                    }
                    2 => {
                        frames.remove(i);
                    }
                    3 => {
                        let f = frames[i].clone();
                        frames.insert(i, f);
                    }
                    4 => {
                        let j = rng.below(frames.len());
                        frames.swap(i, j);
                    }
                    5 => {
                        // extreme length / count fields
                        for off in [1usize, 5, 9, 13] {
                            if frames[i].len() >= off + 4 && rng.below(2) == 0 {
                                let v = [0xFFFF_FFFFu32, 0x8000_0000, 0, 1][rng.below(4)];
                                frames[i][off..off + 4].copy_from_slice(&v.to_le_bytes());
                            }
                        }
                    }
                    6 => frames[i].extend_from_slice(&noise(rng.below(100), rng.next())),
                    _ => {
                        let l = noise(rng.below(40), rng.next());
                        frames.insert(i, l);
                    }
                }
                if frames.is_empty() {
                    frames.push(vec![]);
                }
            }
            let r = catch_unwind(AssertUnwindSafe(|| {
                drive(&frames, &keys);
                drive_reader(&frames, &keys, &mut Rng(rng.0 | 1));
            }));
            assert!(r.is_ok(), "panic on mutated stream");
        }
    }
}

/// Probe: authenticated-but-hostile descriptors (mutated table, re-signed with
/// the trusted key) followed by the original frames never panic.
#[test]
fn probe_resigned_hostile_descriptors_never_panic() {
    let sk = SigningKey::from_bytes(&[0x5A; 32]);
    let mut rng = Rng(0xDEAD_BEEF_0BAD_F00D);
    for (body, log2, order) in [
        (small_body(), 12u8, Order::File),
        (good_body(), 12, Order::Stage),
        (good_body(), 0xFF, Order::Stage),
    ] {
        let b = builder(log2, order);
        let bundle = b.build(&body).unwrap();
        let keys = [b.public_key()];
        let n = bundle.descriptor.len();
        for _ in 0..300 {
            let mut d = bundle.descriptor.clone();
            for _ in 0..1 + rng.below(4) {
                // bias towards table fields and header counts
                let at = if rng.below(2) == 0 {
                    0x08 + rng.below(0x88)
                } else {
                    HEADER_SIZE + rng.below(n - HEADER_SIZE - 66)
                };
                match rng.below(3) {
                    0 => d[at] ^= 1 << rng.below(8),
                    1 => d[at] = rng.next() as u8,
                    _ => d[at] = 0xFF,
                }
            }
            let body_end = n - 64;
            let sig = sk.sign(&signed_message(&d[..body_end])).to_bytes();
            d[body_end..].copy_from_slice(&sig);
            let mut frames = bundle.frames.clone();
            frames[0] = rvm_rvf::stream::descriptor_frame(&d);
            let r = catch_unwind(AssertUnwindSafe(|| {
                drive(&frames, &keys);
                drive_reader(&frames, &keys, &mut Rng(rng.0 | 1));
            }));
            assert!(r.is_ok(), "panic on hostile re-signed descriptor");
        }
    }
}

/// Probe: header-only differential for unsigned filler used by RF-01 above.
#[test]
fn probe_unsigned_segment_helpers_are_aligned() {
    assert_eq!(unsigned_segment_with(0x07, b"x", 1, 2).len() % 64, 0);
}
