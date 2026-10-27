#![allow(dead_code)]
//! Shared corpus and drivers for the streaming tests.

use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder, StreamBundle};
use rvm_rvf::stream::{AdmissionError, StreamAdmission, StreamPolicy, StreamState};
use rvm_rvf::testkit::{
    minimal_container, signed_segment_with, unsigned_segment, unsigned_segment_with, TestKeypair,
};
use rvm_rvf::{
    VerificationReport, VerifyOptions, CAPABILITY_DECLARATION_KEY, STREAM_PROFILE_DECLARATION_KEY,
};

pub const WASM: &[u8] = b"\0asm\x01\0\0\0";
pub const SEG_META: u8 = 0x07;
pub const SEG_MANIFEST: u8 = 0x05;
pub const SEG_WASM: u8 = 0x10;
pub const SEG_VEC: u8 = 0x01;
pub const SEG_INDEX: u8 = 0x02;
pub const SEG_QUANT: u8 = 0x06;

pub fn segment_key() -> TestKeypair {
    TestKeypair::deterministic(11)
}

pub fn builder(chunk_log2: u8, order: Order) -> StreamBuilder {
    let mut b = StreamBuilder::new([0x5A; 32]);
    b.chunk_log2 = chunk_log2;
    b.order = order;
    b.stages = if order == Order::Stage {
        Stages::ByType
    } else {
        Stages::Flat
    };
    b
}

pub fn opts() -> VerifyOptions {
    VerifyOptions::with_trusted_keys(vec![segment_key().public])
}

/// Deterministic pseudo-random bytes.
pub fn noise(len: usize, seed: u64) -> Vec<u8> {
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

fn meta(lines: &str) -> Vec<u8> {
    unsigned_segment(SEG_META, lines.as_bytes(), 1)
}

/// A good package: capabilities, a signed SHAKE-checked wasm module, a model
/// segment spanning several 4 KiB chunks, an index segment, and the manifest.
pub fn good_body() -> Vec<u8> {
    let kp = segment_key();
    let mut d = meta(&format!("{CAPABILITY_DECLARATION_KEY}=network,clock"));
    d.extend(signed_segment_with(SEG_WASM, WASM, 2, &kp, 2));
    d.extend(unsigned_segment(SEG_VEC, &noise(10_000, 1), 3));
    d.extend(unsigned_segment_with(SEG_INDEX, &noise(5_000, 2), 4, 2));
    d.extend(unsigned_segment(SEG_QUANT, &noise(300, 3), 5));
    d.extend(unsigned_segment(SEG_MANIFEST, b"root", 6));
    d
}

/// Flip one payload byte of segment `seg_id`; headers stay intact.
pub fn flip_payload_byte(body: &mut [u8], seg_id: u64, at: usize) {
    let segs = rvm_rvf::walk(body).unwrap();
    let seg = segs.iter().find(|s| s.header.segment_id == seg_id).unwrap();
    body[seg.payload.start + at] ^= 0x40;
}

/// Named bodies: both sides (`verify` and the stream) must treat each the same.
pub fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let kp = segment_key();
    let other = TestKeypair::deterministic(12);
    let mut v = vec![("good", good_body())];
    v.push(("minimal", minimal_container("network")));
    {
        let mut d = minimal_container("memory");
        d.extend(unsigned_segment_with(SEG_WASM, WASM, 3, 2));
        v.push(("unsigned-executable", d));
    }
    {
        let mut d = minimal_container("memory");
        d.extend(signed_segment_with(SEG_WASM, WASM, 3, &other, 2));
        v.push(("executable-signed-by-an-untrusted-key", d));
    }
    {
        let mut b = good_body();
        flip_payload_byte(&mut b, 3, 10);
        v.push(("content-hash-mismatch", b));
    }
    v.push(("unknown-capability", minimal_container("warp-drive")));
    v.push(("unrepresentable-capability", minimal_container("clipboard")));
    {
        let mut d = meta(&format!("{CAPABILITY_DECLARATION_KEY}=clock"));
        d.extend(signed_segment_with(SEG_WASM, WASM, 2, &kp, 2));
        v.push(("no-root-manifest", d));
    }
    {
        let mut d = good_body();
        d.extend(unsigned_segment(SEG_META, b"note=after the manifest", 7));
        v.push(("late-metadata", d));
    }
    {
        let mut d = minimal_container("clock");
        d.extend(signed_segment_with(SEG_WASM, WASM, 3, &kp, 2));
        d.extend(vec![0u8; 40]); // short zero tail after the last segment
        v.push(("zero-tail", d));
    }
    {
        // RF-01: four payload bytes that spell the root magic where a page would
        // end must not move the segment boundary on either path.
        let mut body = unsigned_segment(SEG_MANIFEST, b"root", 1);
        let first = body.len();
        let mut payload = noise(8_000, 77);
        let at = (first + 64 + 8_000 - 4096) - (first + 64);
        payload[at..at + 4].copy_from_slice(&rvm_rvf::ROOT_PAGE_MAGIC.to_le_bytes());
        body.extend(unsigned_segment(SEG_META, &payload, 2));
        v.push(("rvm0-magic-inside-a-payload", body));
    }
    {
        let mut d = good_body();
        d.extend(unsigned_segment(
            SEG_META,
            format!("{STREAM_PROFILE_DECLARATION_KEY}=required").as_bytes(),
            9,
        ));
        v.push(("declares-stream-profile", d));
    }
    v
}

pub struct Run {
    pub state: StreamState,
    pub report: Option<VerificationReport>,
    pub first_error: Option<(usize, AdmissionError)>,
    pub failure: Option<AdmissionError>,
    pub payload_bytes: u64,
}

/// Push every frame of `bundle` through a fresh admission.
pub fn run_bundle(bundle: &StreamBundle, keys: &[[u8; 32]], opts: &VerifyOptions) -> Run {
    let mut policy = StreamPolicy::unpinned_insecure(keys);
    policy.size = opts.size_policy;
    let mut adm = StreamAdmission::new(policy, opts.clone());
    let mut first_error = None;
    let mut payload_bytes = 0u64;
    for (i, f) in bundle.frames.iter().enumerate() {
        match adm.push(f) {
            Ok(rvm_rvf::stream::AdmissionEvent::Chunk { payload, .. }) => {
                payload_bytes += payload.len() as u64;
            }
            Ok(_) => {}
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some((i, e));
                }
            }
        }
    }
    Run {
        state: adm.state(),
        failure: adm.failure(),
        report: adm.report().cloned(),
        first_error,
        payload_bytes,
    }
}

/// A small package whose stream has a handful of frames, for exhaustive tests.
pub fn small_body() -> Vec<u8> {
    let kp = segment_key();
    let mut d = meta(&format!("{CAPABILITY_DECLARATION_KEY}=clock"));
    d.extend(signed_segment_with(SEG_WASM, WASM, 2, &kp, 2));
    d.extend(unsigned_segment(SEG_VEC, &noise(700, 9), 3));
    d.extend(unsigned_segment(SEG_MANIFEST, b"root", 4));
    d
}
