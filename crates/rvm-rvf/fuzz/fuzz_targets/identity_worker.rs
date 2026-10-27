//! Round-3 target: reach the `parallel-identity` worker (body >= 4 MiB, 64 KiB
//! chunks) with a structure-aware edit script over the authentic frames.
//! Input: `[order, (op u8, a u16, b u16)*]`. Properties: no panic; two runs of
//! the same frames agree (no race); Complete implies the released bytes are the
//! signed body and a `Complete` state carries a Verified identity.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder};
use rvm_rvf::stream::{Event, IdentityStatus, StreamPolicy, StreamState, StreamVerifier};
use rvm_rvf::testkit::{signed_segment_with, unsigned_segment, unsigned_segment_with, TestKeypair};
use rvm_rvf::CAPABILITY_DECLARATION_KEY;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

// Coverage of the worker path, measured by this harness (not the implementation):
// a descriptor accepted for a 5 MiB / 64 KiB-chunk body in file order must raise
// the process thread count by one (the identity worker).
static EXECS: AtomicU64 = AtomicU64::new(0);
static WORKER_SPAWNED: AtomicU64 = AtomicU64::new(0);
static WORKER_COMPLETED: AtomicU64 = AtomicU64::new(0);

fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").map_or(0, |d| d.count())
}

struct Fx {
    body: Vec<u8>,
    key: [u8; 32],
    frames: [Vec<Vec<u8>>; 2],
}

fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let kp = TestKeypair::deterministic(11);
        let mut body = unsigned_segment(0x07, format!("{CAPABILITY_DECLARATION_KEY}=clock").as_bytes(), 1);
        body.extend(signed_segment_with(0x10, b"\0asm\x01\0\0\0", 2, &kp, 2));
        let mut x = 0x1234_5678_9abc_def1u64;
        let bulk: Vec<u8> = (0..(5usize << 20))
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        body.extend(unsigned_segment_with(0x01, &bulk, 3, 2));
        body.extend(unsigned_segment(0x05, b"root", 4));
        let mk = |order: Order| {
            let mut b = StreamBuilder::new([0x2a; 32]);
            b.chunk_log2 = 16;
            b.order = order;
            if order == Order::Stage {
                b.stages = Stages::ByType;
            }
            (b.public_key(), b.build(&body).unwrap().frames)
        };
        let (key, f0) = mk(Order::File);
        let (_, f1) = mk(Order::Stage);
        Fx { body, key, frames: [f0, f1] }
    })
}

fn run(frames: &[Vec<u8>]) -> (StreamState, Option<IdentityStatus>, Vec<u8>, usize) {
    let f = fx();
    let keys = [f.key];
    let mut v = StreamVerifier::new(StreamPolicy::unpinned_insecure(&keys));
    let t0 = threads();
    let mut counted = false;
    let mut got = vec![0u8; f.body.len()];
    let mut released = 0usize;
    for fr in frames {
        let r = v.push(fr);
        if !counted && matches!(r, Ok(Event::DescriptorVerified { .. })) {
            counted = true;
            if threads() > t0 {
                WORKER_SPAWNED.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Ok(Event::Chunk { chunk, .. }) = r {
            let at = chunk.body_offset as usize;
            if at + chunk.bytes.len() <= got.len() {
                got[at..at + chunk.bytes.len()].copy_from_slice(chunk.bytes);
                released += chunk.bytes.len();
            }
        }
    }
    if counted && v.state() == StreamState::Complete {
        WORKER_COMPLETED.fetch_add(1, Ordering::Relaxed);
    }
    (v.state(), v.identity_status(), got, released)
}

fuzz_target!(|data: &[u8]| {
    let Some((&order, ops)) = data.split_first() else { return };
    let f = fx();
    let mut frames = f.frames[usize::from(order & 1)].clone();
    for op in ops.chunks_exact(5) {
        let (k, a, b) = (op[0], usize::from(u16::from_le_bytes([op[1], op[2]])), usize::from(u16::from_le_bytes([op[3], op[4]])));
        let n = frames.len();
        let i = a % n;
        match k % 6 {
            0 => {
                let l = frames[i].len();
                if l > 0 {
                    frames[i][b % l] ^= 1 << (k >> 5);
                }
            }
            1 => {
                let l = frames[i].len();
                frames[i].truncate(b % (l + 1));
            }
            2 if n > 1 => {
                frames.remove(i);
            }
            3 => {
                let fr = frames[i].clone();
                frames.insert(b % (n + 1), fr);
            }
            4 => frames.swap(i, b % n),
            _ => {
                // overwrite a chunk payload with another frame's bytes
                let src = frames[b % n].clone();
                if src.len() == frames[i].len() {
                    frames[i] = src;
                }
            }
        }
    }
    let n = EXECS.fetch_add(1, Ordering::Relaxed);
    if n % 500 == 499 {
        eprintln!(
            "identity_worker coverage: execs={} worker_spawned={} worker_completed={}",
            n + 1,
            WORKER_SPAWNED.load(Ordering::Relaxed),
            WORKER_COMPLETED.load(Ordering::Relaxed)
        );
    }
    let a = run(&frames);
    let c = run(&frames);
    assert_eq!((a.0, a.1), (c.0, c.1), "race: verdict differs between runs");
    if matches!(a.0, StreamState::Complete | StreamState::CompleteUnverified) {
        assert_eq!(a.2, f.body, "complete with different bytes");
        assert_eq!(a.3, f.body.len());
        if a.0 == StreamState::Complete {
            assert_eq!(a.1, Some(IdentityStatus::Verified));
        }
    }
});
