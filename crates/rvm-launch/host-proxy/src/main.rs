//! B5: a HOST PROXY for time-to-first-instruction (ADR-160, project Ofer).
//!
//! RVM has no execution engine, so true time-to-first-instruction on RVM is
//! not measurable. This binary measures what a *host* can: wall time from the
//! first byte of a package arriving to
//!
//! 1. `validated`: the module's segment is verified and the incremental
//!    validator finished (the earliest moment a stage-ordered stream could
//!    start the module if early start were implemented; this code does NOT
//!    start earlier than `module`);
//! 2. `module`: the stream is `Complete` and `take_module` returned a
//!    `VerifiedModule` (when `Instance::start_verified` becomes callable);
//! 3. `instance`: the module is compiled and instantiated in wasmi;
//! 4. `call`: an exported function has returned (the first instruction the
//!    host engine runs).
//!
//! The link is simulated by pacing frames at a fixed rate. The buffered
//! baseline receives everything, then `rvm_rvf::verify`, then wasmi.
//! Everything here is a proxy: wasmi executes, RVM does not.

#[path = "../../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_launch::{SessionEvent, StreamSession};
use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder};
use rvm_rvf::stream::StreamPolicy;
use rvm_rvf::testkit::{signed_segment_with, unsigned_segment, TestKeypair};
use rvm_rvf::{verify, walk, SizePolicy, VerifyOptions, CAPABILITY_DECLARATION_KEY};
use rvm_wasm::{ImportPolicy, ModulePolicy};
use std::time::{Duration, Instant};

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

fn package(module: &[u8], bulk: usize) -> Vec<u8> {
    let mut d = unsigned_segment(
        0x07,
        format!("{CAPABILITY_DECLARATION_KEY}=clock").as_bytes(),
        1,
    );
    d.extend(signed_segment_with(0x10, module, 2, &kp(), 2));
    for i in 0..4u64 {
        d.extend(unsigned_segment(0x01, &noise(bulk / 4, i + 1), 10 + i));
    }
    d.extend(unsigned_segment(0x05, b"root", 3));
    d
}

/// Compile, instantiate and call `f(1)` in wasmi. Returns (instance_at, call_at).
fn run_in_wasmi(module: &[u8], t0: Instant) -> (Duration, Duration) {
    let engine = wasmi::Engine::default();
    let m = wasmi::Module::new(&engine, module).expect("wasmi accepts the module");
    let mut store = wasmi::Store::new(&engine, ());
    let linker = <wasmi::Linker<()>>::new(&engine);
    let instance = linker
        .instantiate_and_start(&mut store, &m)
        .expect("instantiate");
    let at_instance = t0.elapsed();
    let f = instance
        .get_typed_func::<i32, i32>(&store, "f")
        .expect("export f");
    let _ = f.call(&mut store, 1).expect("call");
    (at_instance, t0.elapsed())
}

/// Wait until `deadline` (spin for the last 200 us).
fn wait_until(deadline: Instant) {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let left = deadline - now;
        if left > Duration::from_micros(400) {
            std::thread::sleep(left - Duration::from_micros(300));
        } else {
            std::hint::spin_loop();
        }
    }
}

struct Times {
    validated: Duration,
    module: Duration,
    instance: Duration,
    call: Duration,
}

fn stream_once(order: Order, rate: Option<f64>, body: &[u8]) -> Times {
    let mut b = StreamBuilder::new([0x5A; 32]);
    b.chunk_log2 = 16;
    b.order = order;
    b.stages = if order == Order::Stage {
        Stages::ByType
    } else {
        Stages::Flat
    };
    let bundle = b.build(body).unwrap();
    let keys = [b.public_key()];
    let mut policy = StreamPolicy::unpinned_insecure(&keys);
    policy.size = SizePolicy::permissive();
    policy.size.max_segments = 4096;
    let opts = VerifyOptions::with_trusted_keys(vec![kp().public])
        .with_size_policy(SizePolicy::permissive());
    let base = ModulePolicy {
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    };
    let mut session = StreamSession::new(policy, opts, base);
    let t0 = Instant::now();
    let mut sent = 0usize;
    let mut validated = None;
    for f in &bundle.frames {
        sent += f.len();
        if let Some(r) = rate {
            wait_until(t0 + Duration::from_secs_f64(sent as f64 / r));
        }
        match session.push(f).expect("stream push") {
            SessionEvent::Chunk {
                seg_id: 2,
                segment_verified: true,
                ..
            } => validated = Some(t0.elapsed()),
            _ => {}
        }
    }
    let vm = session.take_module(2).expect("module");
    let module_at = t0.elapsed();
    let (instance, call) = run_in_wasmi(vm.as_bytes(), t0);
    Times {
        validated: validated.expect("validated"),
        module: module_at,
        instance,
        call,
    }
}

fn buffered_once(rate: Option<f64>, body: &[u8]) -> Times {
    let t0 = Instant::now();
    if let Some(r) = rate {
        // The whole file must arrive before the buffered path can start.
        wait_until(t0 + Duration::from_secs_f64(body.len() as f64 / r));
    }
    let opts = VerifyOptions::with_trusted_keys(vec![kp().public])
        .with_size_policy(SizePolicy::permissive());
    let report = verify(body, &opts).unwrap();
    assert!(report.ok);
    let seg = walk(body)
        .unwrap()
        .into_iter()
        .find(|s| s.is_executable())
        .unwrap();
    let module = seg.payload(body).to_vec();
    assert!(report.executables[0].matches(&module));
    let module_at = t0.elapsed();
    let (instance, call) = run_in_wasmi(&module, t0);
    Times {
        validated: module_at,
        module: module_at,
        instance,
        call,
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn row(label: &str, rate: &str, runs: &[Times]) {
    let m =
        |f: fn(&Times) -> Duration| median(runs.iter().map(|t| f(t).as_secs_f64() * 1e3).collect());
    println!(
        "{label:<26} {rate:<10} validated {:>8.1}  module {:>8.1}  instance {:>8.1}  call {:>8.1}  (ms, median of {})",
        m(|t| t.validated),
        m(|t| t.module),
        m(|t| t.instance),
        m(|t| t.call),
        runs.len()
    );
}

fn main() {
    let load = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    println!(
        "B5 HOST PROXY (wasmi executes; RVM does not). load average at start: {}",
        load.trim()
    );
    let module = wasm_common::synthetic_module(300_000);
    let bulk = 64 << 20;
    let body = package(&module, bulk);
    println!(
        "package {} MiB: module {} KiB (valid, wasmi-instantiable), {} MiB model data, 64 KiB chunks",
        body.len() >> 20,
        module.len() >> 10,
        bulk >> 20
    );
    for (rate_label, rate) in [
        ("unthrottled", None),
        ("1 Gbit/s", Some(125e6)),
        ("100 Mbit/s", Some(12.5e6)),
    ] {
        let reps = if rate.is_some_and(|r| r < 20e6) { 3 } else { 7 };
        let runs: Vec<Times> = (0..reps).map(|_| buffered_once(rate, &body)).collect();
        row("buffered verify()+wasmi", rate_label, &runs);
        let runs: Vec<Times> = (0..reps)
            .map(|_| stream_once(Order::File, rate, &body))
            .collect();
        row("stream, file order", rate_label, &runs);
        let runs: Vec<Times> = (0..reps)
            .map(|_| stream_once(Order::Stage, rate, &body))
            .collect();
        row("stream, stage order", rate_label, &runs);
    }
}
