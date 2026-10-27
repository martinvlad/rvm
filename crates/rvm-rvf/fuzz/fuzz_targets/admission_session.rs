//! Fuzz StreamAdmission through StreamSession (round-2 review target).
//!
//! The input is an edit script over an authentic, signed stream:
//! `[mode, split_a, split_b, (pos u32, val u8)*]`. Modes:
//!   0..=3  patch the concatenated frames (file/stage order, chunk 0xFF/12)
//!   4..=7  patch the UNSIGNED descriptor of the same streams, re-sign it with
//!          the trusted key, then deliver the authentic chunk frames
//! The stream is fed through `StreamSession::feed` with two split patterns.
//! Properties: never panics; the verdict does not depend on the split; a
//! session that reaches `Complete` with a verified identity yields a module
//! that is byte-identical to the authentic one (modes 0..=3 only, since a
//! re-signed descriptor may legitimately commit to other bytes).
#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use rvm_launch::{SessionState, StreamSession};
use rvm_rvf::stream::builder::{Order, Stages, StreamBuilder};
use rvm_rvf::stream::{signed_message, StreamPolicy};
use rvm_rvf::testkit::{signed_segment_with, unsigned_segment, unsigned_segment_with, TestKeypair};
use rvm_rvf::{VerifyOptions, CAPABILITY_DECLARATION_KEY};
use rvm_wasm::{ImportPolicy, ModulePolicy};
use std::sync::OnceLock;

const MODULE: [u8; 36] = [
    0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 1, 4, 1, 0x60, 0, 0, 3, 2, 1, 0, 7, 5, 1, 1, 0x66, 0, 0, 10,
    4, 1, 2, 0, 0x0b, 0, 0, 0, 0, 0,
];

struct Fx {
    key: [u8; 32],
    seg_key: [u8; 32],
    // (concatenated frames, unsigned descriptor, chunk frames, module)
    variants: Vec<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)>,
}

fn fx() -> &'static Fx {
    static F: OnceLock<Fx> = OnceLock::new();
    F.get_or_init(|| {
        let kp = TestKeypair::deterministic(11);
        let module = &MODULE[..31];
        let meta = format!("{CAPABILITY_DECLARATION_KEY}=clock");
        let mut body = unsigned_segment(0x07, meta.as_bytes(), 1);
        body.extend(signed_segment_with(0x10, module, 2, &kp, 2));
        body.extend(unsigned_segment_with(0x01, &[7u8; 9000], 3, 2));
        body.extend(unsigned_segment(0x05, b"root", 4));
        let mut variants = Vec::new();
        let mut key = [0u8; 32];
        for (log2, order) in [
            (0xFFu8, Order::File),
            (12, Order::File),
            (0xFF, Order::Stage),
            (12, Order::Stage),
        ] {
            let mut b = StreamBuilder::new([0x2a; 32]);
            b.chunk_log2 = log2;
            b.order = order;
            if order == Order::Stage {
                b.stages = Stages::ByType;
            }
            key = b.public_key();
            let bundle = b.build(&body).unwrap();
            let all: Vec<u8> = bundle.frames.concat();
            let d = bundle.descriptor[..bundle.descriptor.len() - 64].to_vec();
            variants.push((all, d, bundle.frames[1..].to_vec()));
        }
        Fx {
            key,
            seg_key: kp.public,
            variants,
        }
    })
}

fn frame(d: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8];
    f.extend_from_slice(&(d.len() as u32).to_le_bytes());
    f.extend_from_slice(d);
    f
}

fn run(bytes: &[u8], split: usize) -> (SessionState, Option<Vec<u8>>) {
    let f = fx();
    let keys = [f.key];
    let mut policy = StreamPolicy::unpinned_insecure(&keys);
    policy.size = rvm_rvf::SizePolicy::permissive();
    policy.size.max_segments = 4096;
    let opts = VerifyOptions::with_trusted_keys(vec![f.seg_key]);
    let base = ModulePolicy {
        imports: ImportPolicy::AllowAll,
        ..ModulePolicy::default()
    };
    let mut s = StreamSession::new(policy, opts, base);
    for piece in bytes.chunks(split.max(1)) {
        if s.feed(piece, |_| {}).is_err() {
            break;
        }
    }
    // stage-order streams complete unverified; confirm with the true body if
    // the harness can (it cannot here), so only file-order yields a module.
    let m = s.take_module(2).ok().map(|m| m.as_bytes().to_vec());
    (s.state(), m)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let f = fx();
    let mode = data[0] as usize;
    let (v, resign) = (&f.variants[mode & 3], mode & 4 != 0);
    let a = usize::from(data[1]) + 1;
    let b = usize::from(data[2]) * 7 + 3;
    let edits = &data[3..];
    let stream: Vec<u8> = if resign {
        let mut d = v.1.clone();
        for e in edits.chunks_exact(5) {
            let pos = u32::from_le_bytes([e[0], e[1], e[2], e[3]]) as usize;
            if !d.is_empty() {
                let l = d.len();
                d[pos % l] ^= e[4];
            }
        }
        let sk = SigningKey::from_bytes(&[0x2a; 32]);
        let sig = sk.sign(&signed_message(&d)).to_bytes();
        d.extend_from_slice(&sig);
        let mut out = frame(&d);
        for c in &v.2 {
            out.extend_from_slice(c);
        }
        out
    } else {
        let mut s = v.0.clone();
        for e in edits.chunks_exact(5) {
            let pos = u32::from_le_bytes([e[0], e[1], e[2], e[3]]) as usize;
            if !s.is_empty() {
                let l = s.len();
                s[pos % l] ^= e[4];
            }
        }
        // a trailing odd byte truncates
        if edits.len() % 5 == 1 {
            let l = s.len();
            s.truncate((usize::from(edits[edits.len() - 1]) * l) / 256);
        }
        s
    };
    let ra = run(&stream, a);
    let rb = run(&stream, b);
    assert_eq!(ra.0, rb.0, "session state depends on the split");
    assert_eq!(ra.1, rb.1, "module depends on the split");
    if !resign {
        if let Some(m) = &ra.1 {
            assert_eq!(m.as_slice(), &MODULE[..31], "a module that is not the signed one");
        }
    }
});
