//! Round-3 review: the `parallel-identity` worker (branch feat/ofer-review-rvm).
//! Run with `--features parallel-identity`; gated so the default build is
//! unaffected. Use `--test-threads=1` for the thread-count test.
#![cfg(feature = "parallel-identity")]

mod common;

use common::{builder, good_body, noise};
use rvm_rvf::stream::builder::{Order, StreamBundle};
use rvm_rvf::stream::{
    Event, FrameReader, IdentityStatus, StreamError, StreamPolicy, StreamState, StreamVerifier,
};
use rvm_rvf::testkit::unsigned_segment;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

fn big_body(mib: usize) -> Vec<u8> {
    let mut b = good_body();
    b.extend(unsigned_segment(0x01, &noise(mib << 20, 3), 50));
    b
}

fn pol(keys: &[[u8; 32]]) -> StreamPolicy<'_> {
    StreamPolicy::unpinned_insecure(keys)
}

fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
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

/// Probe: a mid-stream clone carries the identity so far, finishing either
/// copy leaves the other alone, and dropping the original does not disturb
/// the clone (no shared or double-finalized state).
#[test]
fn clone_mid_stream_is_independent() {
    let body = big_body(5);
    let b = builder(16, Order::File);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mut v = StreamVerifier::new(pol(&keys));
    let third = bundle.frames.len() / 3;
    for f in &bundle.frames[..third] {
        v.push(f).unwrap();
    }
    let mut c1 = v.clone();
    let c2 = v.clone();
    drop(c2); // dropping a clone must not join/close anything shared
    for f in &bundle.frames[third..third * 2] {
        v.push(f).unwrap();
    }
    let mut c3 = v.clone(); // clone of a clone-able, partially-advanced original
    drop(v); // original (and its worker) gone mid-stream
    for f in &bundle.frames[third..] {
        c1.push(f).unwrap();
    }
    for f in &bundle.frames[third * 2..] {
        c3.push(f).unwrap();
    }
    assert_eq!(c1.state(), StreamState::Complete);
    assert_eq!(c3.state(), StreamState::Complete);
    assert_eq!(c1.identity_status(), Some(IdentityStatus::Verified));
    assert_eq!(c3.identity_status(), Some(IdentityStatus::Verified));
}

/// Probe: a clone taken after the stream completed, and one taken from a
/// lying stream one chunk before the end, give the same verdicts as inline.
#[test]
fn clone_at_the_end_and_lie_detection() {
    let body = big_body(5);
    let mut b = builder(16, Order::File);
    b.identity_override = Some([0x77; 32]);
    let lie = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let n = lie.frames.len();
    let mut v = StreamVerifier::new(pol(&keys));
    for f in &lie.frames[..n - 1] {
        v.push(f).unwrap();
    }
    let mut c = v.clone();
    assert_eq!(
        v.push(&lie.frames[n - 1]).err(),
        Some(StreamError::IdentityMismatch)
    );
    assert_eq!(
        c.push(&lie.frames[n - 1]).err(),
        Some(StreamError::IdentityMismatch)
    );
    assert!(matches!(c.state(), StreamState::Poisoned(_)));
}

/// Probe: out-of-order (stage) delivery with a worker present stays
/// unverifiable, never "Verified".
#[test]
fn stage_order_with_a_worker_is_unverifiable() {
    let body = big_body(5);
    let b = builder(16, Order::Stage);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mut v = StreamVerifier::new(pol(&keys));
    for f in &bundle.frames {
        v.push(f).unwrap();
    }
    assert_eq!(v.state(), StreamState::CompleteUnverified);
    assert_eq!(v.identity_status(), Some(IdentityStatus::Unverifiable));
}

// RV3-01 (worker thread lifetime) moved to `identity_worker_lifetime.rs`: it counts
// threads, so it needs a test binary of its own.

fn collect(
    bundle_frames: &[Vec<u8>],
    keys: &[[u8; 32]],
    body_len: usize,
) -> (StreamState, Option<IdentityStatus>, Vec<u8>, bool) {
    let mut v = StreamVerifier::new(pol(keys));
    let mut got = vec![0u8; body_len];
    let mut seen = vec![false; body_len];
    for f in bundle_frames {
        if let Ok(Event::Chunk { chunk, .. }) = v.push(f) {
            let at = chunk.body_offset as usize;
            if at + chunk.bytes.len() <= body_len {
                got[at..at + chunk.bytes.len()].copy_from_slice(chunk.bytes);
                seen[at..at + chunk.bytes.len()]
                    .iter_mut()
                    .for_each(|s| *s = true);
            }
        }
    }
    let all = seen.iter().all(|s| *s);
    (v.state(), v.identity_status(), got, all)
}

fn mutate(rng: &mut Rng, mut frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    for _ in 0..1 + rng.below(3) {
        let i = rng.below(frames.len());
        match rng.below(7) {
            0 if !frames[i].is_empty() => {
                let l = frames[i].len();
                frames[i][rng.below(l)] ^= 1 << rng.below(8);
            }
            1 => {
                let l = frames[i].len();
                frames[i].truncate(rng.below(l + 1));
            }
            2 if frames.len() > 1 => {
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
                // replace a chunk's payload with another chunk's payload
                let j = rng.below(frames.len());
                let src = frames[j].clone();
                if frames[i].len() == src.len() && frames[i].len() > 17 {
                    frames[i] = src;
                }
            }
            _ => {
                let j = rng.below(frames.len());
                frames.swap(i, j);
            }
        }
    }
    frames
}

/// Probe (time bounded, ~90 s in release): mutation of a 5 MiB / 64 KiB-chunk
/// stream so the worker runs. Properties: (a) never a panic; (b) the verdict is
/// deterministic across two runs (no race); (c) Complete with a verified
/// identity implies the released bytes are exactly the signed body.
#[test]
fn probe_worker_mutation_campaign() {
    let secs: u64 = std::env::var("R3_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let body = big_body(5);
    let mut rng = Rng(0x5EED_CAFE_F00D_0001);
    let mut execs = 0u64;
    let mut completes = 0u64;
    let start = Instant::now();
    for order in [Order::File, Order::Stage].iter().cycle() {
        if start.elapsed() > Duration::from_secs(secs) {
            break;
        }
        let b = builder(16, *order);
        let bundle: StreamBundle = b.build(&body).unwrap();
        let keys = [b.public_key()];
        for _ in 0..40 {
            let frames = mutate(&mut rng, bundle.frames.clone());
            let r = catch_unwind(AssertUnwindSafe(|| {
                let a = collect(&frames, &keys, body.len());
                let c = collect(&frames, &keys, body.len());
                assert_eq!((a.0, a.1), (c.0, c.1), "non-deterministic verdict");
                if matches!(a.0, StreamState::Complete | StreamState::CompleteUnverified) {
                    assert!(a.3, "complete without every byte");
                    assert_eq!(a.2, body, "complete with different bytes");
                    if a.0 == StreamState::Complete {
                        assert_eq!(a.1, Some(IdentityStatus::Verified));
                    }
                    return true;
                }
                false
            }));
            match r {
                Ok(true) => completes += 1,
                Ok(false) => {}
                Err(_) => panic!("panic/assert on mutated stream"),
            }
            execs += 1;
        }
    }
    eprintln!(
        "worker campaign: {execs} mutated streams ({completes} completed) in {:?}",
        start.elapsed()
    );
    assert!(execs > 20);
}

/// Probe: the byte reader fed hostile splits of a worker-sized stream.
#[test]
fn probe_reader_with_worker_matches_push() {
    let body = big_body(5);
    let b = builder(16, Order::File);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let all: Vec<u8> = bundle.frames.concat();
    for split in [1usize << 16, 4093, 70_001] {
        let mut v = StreamVerifier::new(pol(&keys));
        let mut rd = FrameReader::new();
        for piece in all.chunks(split) {
            rd.feed(&mut v, piece, |_| {}).unwrap();
        }
        assert_eq!(v.state(), StreamState::Complete, "split {split}");
        assert_eq!(v.identity_status(), Some(IdentityStatus::Verified));
    }
}

/// Probe: stage order + `finish_identity` with a >= 4 MiB body (so the
/// confirming hash also runs on a worker). Good bytes confirm; a flipped byte
/// anywhere is refused with ChunkHashMismatch and poisons; a `read_at` that
/// returns different bytes on a second read cannot split leaf and identity
/// (both hash the same buffer).
#[test]
fn finish_identity_with_a_worker_confirms_and_refuses() {
    let body = big_body(5);
    let b = builder(16, Order::Stage);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mk = || {
        let mut v = StreamVerifier::new(pol(&keys));
        for f in &bundle.frames {
            v.push(f).unwrap();
        }
        assert_eq!(v.state(), StreamState::CompleteUnverified);
        v
    };
    let mut v = mk();
    v.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    })
    .unwrap();
    assert_eq!(v.state(), StreamState::Complete);
    assert_eq!(v.identity_status(), Some(IdentityStatus::Verified));

    for at in [0usize, body.len() / 2, body.len() - 1] {
        let mut v = mk();
        let r = v.finish_identity(|off, buf| {
            buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
            let o = off as usize;
            if (o..o + buf.len()).contains(&at) {
                buf[at - o] ^= 1;
            }
            true
        });
        assert_eq!(
            r.err(),
            Some(StreamError::ChunkHashMismatch),
            "flip at {at}"
        );
        assert!(matches!(v.state(), StreamState::Poisoned(_)));
    }
    // read failure mid-way: BadState, and the worker is dropped cleanly.
    let mut v = mk();
    let mut calls = 0;
    let r = v.finish_identity(|off, buf| {
        calls += 1;
        if calls > 20 {
            return false;
        }
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    });
    assert_eq!(r.err(), Some(StreamError::BadState));
    drop(v);
}

/// Probe (manual): run under `ulimit -u <small>` with `--test-threads=1` to make
/// `thread::Builder::spawn` fail. The verifier must fall back to inline hashing
/// and still reach Verified (and a lie must still be caught). Passes trivially
/// when threads can be created; the thread count shows which case ran.
#[test]
fn spawn_failure_falls_back_to_inline() {
    let body = big_body(5);
    let mut b = builder(16, Order::File);
    let truth = b.build(&body).unwrap();
    b.identity_override = Some([9; 32]);
    let lie = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mut v = StreamVerifier::new(pol(&keys));
    for f in &truth.frames {
        v.push(f).unwrap();
    }
    assert_eq!(v.identity_status(), Some(IdentityStatus::Verified));
    let mut v = StreamVerifier::new(pol(&keys));
    let n = lie.frames.len();
    for f in &lie.frames[..n - 1] {
        v.push(f).unwrap();
    }
    assert_eq!(
        v.push(&lie.frames[n - 1]).err(),
        Some(StreamError::IdentityMismatch)
    );
    eprintln!("spawn_failure probe: {} threads in process", threads());
}
