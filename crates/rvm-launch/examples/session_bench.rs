//! Plain timing harness for project Ofer (ADR-160): B3 peak memory and B4
//! verification throughput. Run in release; nothing here is on a production
//! path.
//!
//! ```text
//! cargo run --release -p rvm-launch --example session_bench -- b3     # peak memory, one process per case
//! cargo run --release -p rvm-launch --example session_bench -- b4     # throughput
//! ```
//!
//! B3 spawns itself once per case, because `VmHWM` is a process-lifetime high
//! water mark and two cases in one process would contaminate each other. The
//! streaming child reads the body from a file in chunk-sized pieces and never
//! holds more than the frame it is pushing, as a socket reader would; the
//! buffered child reads the whole file into a `Vec`, which is what
//! `verify(&[u8])` requires.

#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_launch::StreamSession;
use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder};
use rvm_rvf::stream::{
    StreamAdmission, StreamPolicy, StreamVerifier, FRAME_CHUNK, FRAME_CHUNK_TABLE,
};
use rvm_rvf::testkit::{signed_segment_with, unsigned_segment, TestKeypair};
use rvm_rvf::{verify, SizePolicy, VerifyOptions, CAPABILITY_DECLARATION_KEY};
use rvm_wasm::{ImportPolicy, ModulePolicy};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

const SEED: [u8; 32] = [0x5A; 32];

fn kp() -> TestKeypair {
    TestKeypair::deterministic(11)
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// A package of about `total` bytes: capabilities, a signed ~300 KB module,
/// `segments` equal model segments (XXH3 content hash, the writer's default),
/// a manifest.
fn body(total: usize, segments: usize) -> Vec<u8> {
    let module = wasm_common::synthetic_module(300_000);
    let mut d = unsigned_segment(
        0x07,
        format!("{CAPABILITY_DECLARATION_KEY}=clock").as_bytes(),
        1,
    );
    d.extend(signed_segment_with(0x10, &module, 2, &kp(), 2));
    let each = total.saturating_sub(d.len()) / segments;
    for i in 0..segments {
        d.extend(unsigned_segment(
            0x01,
            &noise(each, i as u64 + 1),
            10 + i as u64,
        ));
    }
    d.extend(unsigned_segment(0x05, b"root", 3));
    d
}

fn opts() -> VerifyOptions {
    VerifyOptions::with_trusted_keys(vec![kp().public]).with_size_policy(SizePolicy::permissive())
}

fn builder(chunk_log2: u8) -> StreamBuilder {
    let mut b = StreamBuilder::new(SEED);
    b.chunk_log2 = chunk_log2;
    b.order = Order::File;
    b.stages = Stages::Flat;
    b
}

fn policy(keys: &[[u8; 32]]) -> StreamPolicy<'_> {
    let mut p = StreamPolicy::unpinned_insecure(keys);
    p.size = SizePolicy::permissive();
    p.size.max_segments = 4096;
    p.max_segment_bytes = 1 << 40;
    p
}

fn vm_hwm_kib() -> u64 {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn load_avg() -> String {
    fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .trim()
        .to_string()
}

// ---------------------------------------------------------------- B3 ----

/// Writes the body, and a plan the streaming child replays:
/// `[tag u8][len u32][bytes]` for descriptor/table frames (tag 0/1) and
/// `[2][seg_id u64][chunk_index u32][file_offset u64][len u32]` for chunks.
fn prepare(dir: &Path, total: usize, segments: usize, chunk_log2: u8) {
    let body = body(total, segments);
    fs::write(dir.join("body.rvf"), &body).unwrap();
    let b = builder(chunk_log2);
    let bundle = b.build(&body).unwrap();
    let mut plan = Vec::new();
    for f in &bundle.frames {
        match f[0] {
            0 | FRAME_CHUNK_TABLE => {
                plan.push(u8::from(f[0] != 0));
                plan.extend_from_slice(&(f.len() as u32).to_le_bytes());
                plan.extend_from_slice(f);
            }
            _ => {
                let seg = u64::from_le_bytes(f[1..9].try_into().unwrap());
                let idx = u32::from_le_bytes(f[9..13].try_into().unwrap());
                let len = u32::from_le_bytes(f[13..17].try_into().unwrap());
                let e = bundle.entries.iter().find(|e| e.seg_id == seg).unwrap();
                let cs = b.chunk_log2;
                let off = e.body_offset + if cs == 0xFF { 0 } else { u64::from(idx) << cs };
                plan.push(2);
                plan.extend_from_slice(&seg.to_le_bytes());
                plan.extend_from_slice(&idx.to_le_bytes());
                plan.extend_from_slice(&off.to_le_bytes());
                plan.extend_from_slice(&len.to_le_bytes());
            }
        }
    }
    fs::write(dir.join("plan.bin"), plan).unwrap();
    fs::write(dir.join("key.bin"), b.public_key()).unwrap();
}

fn child_buffered(dir: &Path) {
    let start = vm_hwm_kib();
    let t = Instant::now();
    let data = fs::read(dir.join("body.rvf")).unwrap();
    let report = verify(&data, &opts()).unwrap();
    assert!(report.ok);
    println!(
        "RESULT buffered hwm_kib={} base_kib={start} secs={:.3}",
        vm_hwm_kib(),
        t.elapsed().as_secs_f64()
    );
}

fn child_stream(dir: &Path) {
    let start = vm_hwm_kib();
    let key: [u8; 32] = fs::read(dir.join("key.bin")).unwrap().try_into().unwrap();
    let keys = [key];
    let plan = fs::read(dir.join("plan.bin")).unwrap();
    let mut body = fs::File::open(dir.join("body.rvf")).unwrap();
    let base = ModulePolicy {
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    };
    let mut session = StreamSession::new(policy(&keys), opts(), base);
    let mut buf: Vec<u8> = Vec::new();
    let mut at = 0usize;
    let t = Instant::now();
    while at < plan.len() {
        let tag = plan[at];
        at += 1;
        if tag == 2 {
            let seg = u64::from_le_bytes(plan[at..at + 8].try_into().unwrap());
            let idx = u32::from_le_bytes(plan[at + 8..at + 12].try_into().unwrap());
            let off = u64::from_le_bytes(plan[at + 12..at + 20].try_into().unwrap());
            let len = u32::from_le_bytes(plan[at + 20..at + 24].try_into().unwrap()) as usize;
            at += 24;
            buf.clear();
            buf.push(FRAME_CHUNK);
            buf.extend_from_slice(&seg.to_le_bytes());
            buf.extend_from_slice(&idx.to_le_bytes());
            buf.extend_from_slice(&(len as u32).to_le_bytes());
            let head = buf.len();
            buf.resize(head + len, 0);
            body.seek(SeekFrom::Start(off)).unwrap();
            body.read_exact(&mut buf[head..]).unwrap();
        } else {
            let len = u32::from_le_bytes(plan[at..at + 4].try_into().unwrap()) as usize;
            at += 4;
            buf.clear();
            buf.extend_from_slice(&plan[at..at + len]);
            at += len;
        }
        session.push(&buf).expect("stream push");
    }
    session.take_module(2).expect("module");
    println!(
        "RESULT stream hwm_kib={} base_kib={start} secs={:.3}",
        vm_hwm_kib(),
        t.elapsed().as_secs_f64()
    );
}

fn b3() {
    println!(
        "B3 peak memory (VmHWM), one process per case. load average at start: {}",
        load_avg()
    );
    let exe = std::env::current_exe().unwrap();
    println!(
        "{:<34} {:>12} {:>12} {:>9}",
        "case", "VmHWM MiB", "above idle", "secs"
    );
    for (mib, segs) in [(16usize, 4usize), (256, 16)] {
        for (label, chunk_log2, mode) in [
            ("whole-buffer verify()", 16u8, "buffered"),
            ("stream, chunked 64 KiB (M2)", 16, "stream"),
            ("stream, segment-granular (M1)", 0xFF, "stream"),
        ] {
            let dir: PathBuf = std::env::temp_dir().join(format!("ofer-b3-{mib}-{chunk_log2}"));
            fs::create_dir_all(&dir).unwrap();
            let status = std::process::Command::new(&exe)
                .args([
                    "prepare",
                    &mib.to_string(),
                    &segs.to_string(),
                    &chunk_log2.to_string(),
                    dir.to_str().unwrap(),
                ])
                .status()
                .unwrap();
            assert!(status.success());
            let out = std::process::Command::new(&exe)
                .args([&format!("child-{mode}"), dir.to_str().unwrap()])
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            let line = text
                .lines()
                .find(|l| l.starts_with("RESULT"))
                .unwrap_or("RESULT missing");
            let get = |k: &str| -> f64 {
                line.split_whitespace()
                    .find_map(|w| w.strip_prefix(&format!("{k}=")))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(f64::NAN)
            };
            let (hwm, base) = (get("hwm_kib"), get("base_kib"));
            println!(
                "{:<34} {:>12.1} {:>12.1} {:>9.2}   [{mib} MiB body, {segs} model segments]",
                label,
                hwm / 1024.0,
                (hwm - base) / 1024.0,
                get("secs")
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }
}

// ---------------------------------------------------------------- B4 ----

fn gbps(bytes: usize, secs: f64) -> f64 {
    bytes as f64 / secs / 1e9
}

fn best_of<F: FnMut() -> f64>(n: usize, mut f: F) -> f64 {
    (0..n).map(|_| f()).fold(0.0_f64, f64::max)
}

fn b4() {
    println!(
        "B4 verification throughput. load average at start: {}",
        load_avg()
    );
    let total = 256usize << 20;
    let body = body(total, 8);
    println!(
        "body: {} MiB, release build, best of 5, in-memory frames (no I/O)",
        body.len() >> 20
    );
    let o = opts();
    let buffered = best_of(5, || {
        let t = Instant::now();
        let r = verify(&body, &o).unwrap();
        assert!(r.ok);
        gbps(body.len(), t.elapsed().as_secs_f64())
    });
    println!(
        "{:<44} {:>8.2} GB/s",
        "whole-buffer verify() (identity+hash+sig)", buffered
    );
    for (label, chunk_log2) in [
        ("64 KiB chunks", 16u8),
        ("256 KiB chunks", 18),
        ("1 MiB chunks", 20),
        ("segment-granular (M1)", 0xFF),
    ] {
        let b = builder(chunk_log2);
        let bundle = b.build(&body).unwrap();
        let keys = [b.public_key()];
        let verifier = best_of(5, || {
            let mut v = StreamVerifier::new(policy(&keys));
            let t = Instant::now();
            for f in &bundle.frames {
                v.push(f).unwrap();
            }
            gbps(body.len(), t.elapsed().as_secs_f64())
        });
        let admission = best_of(5, || {
            let mut a = StreamAdmission::new(policy(&keys), o.clone());
            let t = Instant::now();
            for f in &bundle.frames {
                a.push(f).unwrap();
            }
            assert!(a.report().unwrap().ok);
            gbps(body.len(), t.elapsed().as_secs_f64())
        });
        let session = best_of(3, || {
            let base = ModulePolicy {
                imports: ImportPolicy::AllowAll,
                ..ModulePolicy::default()
            };
            let mut s = StreamSession::new(policy(&keys), o.clone(), base);
            let t = Instant::now();
            for f in &bundle.frames {
                s.push(f).unwrap();
            }
            gbps(body.len(), t.elapsed().as_secs_f64())
        });
        println!(
            "{label:<44} verifier {verifier:>6.2}  admission {admission:>6.2}  session(+wasm validate) {session:>6.2}  GB/s   descriptor {} B ({:.4}% of body)",
            bundle.descriptor.len(),
            bundle.descriptor.len() as f64 * 100.0 / body.len() as f64
        );
    }
    // The identity pass hashes every byte a second time; a sender may omit it.
    let mut b = builder(16);
    b.identity = false;
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let no_identity = best_of(5, || {
        let mut v = StreamVerifier::new(policy(&keys));
        let t = Instant::now();
        for f in &bundle.frames {
            v.push(f).unwrap();
        }
        gbps(body.len(), t.elapsed().as_secs_f64())
    });
    println!(
        "{:<44} verifier {no_identity:>6.2} GB/s  (descriptor does not commit to rvf_identity)",
        "64 KiB chunks, no identity pass"
    );
    let _ = std::io::stdout().flush();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("b3") => b3(),
        Some("b4") => b4(),
        Some("prepare") => {
            let n = |i: usize| args[i].parse::<usize>().unwrap();
            prepare(
                Path::new(&args[4]),
                n(1) << 20,
                n(2),
                args[3].parse().unwrap(),
            );
        }
        Some("child-buffered") => child_buffered(Path::new(&args[1])),
        Some("child-stream") => child_stream(Path::new(&args[1])),
        _ => eprintln!("usage: stream_bench b3|b4"),
    }
}
