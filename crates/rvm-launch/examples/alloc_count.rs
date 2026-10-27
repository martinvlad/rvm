//! Allocations and copies per MiB on the session path (ADR-160 optimisation
//! pass). A counting allocator wraps the system one.

#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_launch::StreamSession;
use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder};
use rvm_rvf::stream::{StreamAdmission, StreamPolicy, StreamVerifier};
use rvm_rvf::testkit::{signed_segment_with, unsigned_segment, TestKeypair};
use rvm_rvf::{SizePolicy, VerifyOptions, CAPABILITY_DECLARATION_KEY};
use rvm_wasm::{ImportPolicy, ModulePolicy};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
// SAFETY-free wrapper: forwards to System.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(l.size() as u64, Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(n as u64, Relaxed);
        System.realloc(p, l, n)
    }
}
#[global_allocator]
static A: Counting = Counting;

fn count<R>(f: impl FnOnce() -> R) -> (R, u64, u64) {
    let (a, b) = (ALLOCS.load(Relaxed), BYTES.load(Relaxed));
    let r = f();
    (r, ALLOCS.load(Relaxed) - a, BYTES.load(Relaxed) - b)
}

fn main() {
    let kp = TestKeypair::deterministic(11);
    let module = wasm_common::synthetic_module(300_000);
    let mut body = unsigned_segment(
        0x07,
        format!("{CAPABILITY_DECLARATION_KEY}=clock").as_bytes(),
        1,
    );
    body.extend(signed_segment_with(0x10, &module, 2, &kp, 2));
    let bulk: Vec<u8> = (0..64usize << 20).map(|i| (i * 31) as u8).collect();
    body.extend(unsigned_segment(0x01, &bulk, 10));
    body.extend(unsigned_segment(0x05, b"root", 3));
    let mut b = StreamBuilder::new([0x5A; 32]);
    b.chunk_log2 = 16;
    b.order = Order::File;
    b.stages = Stages::Flat;
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mib = (body.len() >> 20) as f64;
    let mut pol = StreamPolicy::unpinned_insecure(&keys);
    pol.size = SizePolicy::permissive();
    pol.size.max_segments = 4096;
    let opts = VerifyOptions::with_trusted_keys(vec![kp.public])
        .with_size_policy(SizePolicy::permissive());
    println!("body {mib} MiB, {} frames", bundle.frames.len());
    let report = |name: &str, a: u64, by: u64| {
        println!(
            "{name:<12} allocations {a:>6} ({:>7.2}/MiB)  bytes allocated {:>10} ({:>8.0} B/MiB)",
            a as f64 / mib,
            by,
            by as f64 / mib
        );
    };
    let (_, a, by) = count(|| {
        let mut v = StreamVerifier::new(pol);
        for f in &bundle.frames {
            v.push(f).unwrap();
        }
    });
    report("verifier", a, by);
    let (_, a, by) = count(|| {
        let mut s = StreamAdmission::new(pol, opts.clone());
        for f in &bundle.frames {
            s.push(f).unwrap();
        }
    });
    report("admission", a, by);
    let base = ModulePolicy {
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    };
    let (_, a, by) = count(|| {
        let mut s = StreamSession::new(pol, opts.clone(), base.clone());
        for f in &bundle.frames {
            s.push(f).unwrap();
        }
        s.take_module(2).unwrap();
    });
    report("session", a, by);
    let all: Vec<u8> = bundle.frames.concat();
    for split in [1500usize, 16 << 10] {
        let (_, a, by) = count(|| {
            let mut s = StreamSession::new(pol, opts.clone(), base.clone());
            for piece in all.chunks(split) {
                s.feed(piece, |_| {}).unwrap();
            }
        });
        report(&format!("feed({split}B)"), a, by);
        let mut v: Vec<f64> = (0..7)
            .map(|_| {
                let t = std::time::Instant::now();
                let mut s = StreamSession::new(pol, opts.clone(), base.clone());
                for piece in all.chunks(split) {
                    s.feed(piece, |_| {}).unwrap();
                }
                all.len() as f64 / t.elapsed().as_secs_f64() / 1e9
            })
            .collect();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        println!(
            "             throughput median {:.2} GB/s [{:.2}-{:.2}]",
            v[3], v[0], v[6]
        );
    }
}
