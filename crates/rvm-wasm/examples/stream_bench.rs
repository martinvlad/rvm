//! Plain timing harness: streaming vs whole-buffer wasm validation.
//!
//! `cargo run --release -p rvm-wasm --features std --example stream_bench`
//!
//! Throughput is measured in-process; peak memory is measured in a child
//! process per (mode, size) from /proc/self/status VmHWM after resetting the
//! peak via /proc/self/clear_refs, so the module's own bytes (the stand-in for
//! the transport buffer) are excluded from the delta.

#[path = "../tests/common/mod.rs"]
mod common;

use rvm_wasm::{wasm_features, ImportPolicy, ModulePolicy, StreamingModuleValidator};
use std::time::Instant;

fn policy() -> ModulePolicy {
    ModulePolicy {
        max_module_bytes: 64 << 20,
        max_section_bytes: 64 << 20,
        max_function_body_bytes: 1 << 20,
        max_functions: u32::MAX,
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    }
}

fn buffered(m: &[u8]) {
    wasmparser::Validator::new_with_features(wasm_features())
        .validate_all(m)
        .expect("valid");
}

fn streaming(m: &[u8], chunk: usize) {
    let mut v = StreamingModuleValidator::new(policy());
    for c in m.chunks(chunk) {
        v.push(c).expect("valid");
    }
    v.finish().expect("valid");
}

fn status_kb(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

fn time_mbps(m: &[u8], iters: u32, f: impl Fn(&[u8])) -> f64 {
    f(m); // warm
    let t = Instant::now();
    for _ in 0..iters {
        f(m);
    }
    let secs = t.elapsed().as_secs_f64() / f64::from(iters);
    m.len() as f64 / secs / 1_048_576.0
}

fn child(mode: &str, size: usize) {
    let m = common::synthetic_module(size);
    // Touch every page so the module is resident before the baseline.
    let _ = m.iter().fold(0u8, |a, b| a ^ b);
    std::fs::write("/proc/self/clear_refs", "5").expect("reset VmHWM");
    let base = status_kb("VmRSS:");
    match mode {
        "buffered" => buffered(&m),
        "stream4k" => streaming(&m, 4096),
        "stream1" => streaming(&m, 1),
        other => panic!("unknown mode {other}"),
    }
    let hwm = status_kb("VmHWM:");
    println!("{}", hwm.saturating_sub(base));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "--child" {
        child(&args[2], args[3].parse().unwrap());
        return;
    }
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    println!("loadavg at start: {}", load.trim());
    println!(
        "{:>9} {:>9} {:>14} {:>14} {:>14} {:>14}",
        "target", "actual", "buffered MB/s", "stream1shot", "stream4KiB", "stream1B"
    );
    for (size, iters) in [(64usize << 10, 200u32), (1 << 20, 30), (16 << 20, 3)] {
        let m = common::synthetic_module(size);
        let b = time_mbps(&m, iters, buffered);
        let s_all = time_mbps(&m, iters, |m| streaming(m, m.len()));
        let s_4k = time_mbps(&m, iters, |m| streaming(m, 4096));
        let s_1 = if size <= 1 << 20 {
            format!("{:.1}", time_mbps(&m, iters.min(5), |m| streaming(m, 1)))
        } else {
            "n/a".into()
        };
        println!(
            "{:>9} {:>9} {:>14.1} {:>14.1} {:>14.1} {:>14}",
            size,
            m.len(),
            b,
            s_all,
            s_4k,
            s_1
        );
    }
    println!("\npeak extra memory over the resident module (VmHWM delta, KiB):");
    println!(
        "{:>9} {:>10} {:>10} {:>10}",
        "target", "buffered", "stream4K", "stream1B"
    );
    let exe = std::env::current_exe().unwrap();
    for size in [64usize << 10, 1 << 20, 16 << 20] {
        let mut row = Vec::new();
        for mode in ["buffered", "stream4k", "stream1"] {
            if mode == "stream1" && size > 1 << 20 {
                row.push("n/a".to_string());
                continue;
            }
            let out = std::process::Command::new(&exe)
                .args(["--child", mode, &size.to_string()])
                .output()
                .expect("spawn child");
            row.push(String::from_utf8_lossy(&out.stdout).trim().to_string());
        }
        println!("{:>9} {:>10} {:>10} {:>10}", size, row[0], row[1], row[2]);
    }
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    println!("loadavg at end: {}", load.trim());
}
