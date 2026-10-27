//! P7: sizes a descriptor or a frame claims are rejected before allocation.
//!
//! One `#[test]` runs every scenario in sequence because the allocator
//! counters are process-wide.

mod common;

use common::{builder, noise, segment_key, SEG_MANIFEST, SEG_VEC};
use ed25519_dalek::{Signer, SigningKey};
use peak_alloc::PeakAlloc;
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::{
    descriptor_frame, signed_message, signer_key_id, FrameReader, StreamAdmission, StreamEntry,
    StreamError, StreamHeader, StreamPolicy, StreamState, StreamVerifier,
};
use rvm_rvf::testkit::unsigned_segment;
use rvm_rvf::VerifyOptions;

#[global_allocator]
static PEAK: PeakAlloc = PeakAlloc;

const SEED: [u8; 32] = [0x5A; 32];

/// Bytes allocated above the starting level while `f` ran.
fn extra_peak<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let base = PEAK.current_usage();
    PEAK.reset_peak_usage();
    let r = f();
    (r, PEAK.peak_usage().saturating_sub(base))
}

fn entry(seg_id: u64, offset: u64, stored: u64) -> StreamEntry {
    StreamEntry {
        seg_id,
        seg_type: SEG_MANIFEST,
        stage: 0,
        flags: 0,
        requires_mask: 0,
        body_offset: offset,
        stored_len: stored,
        uncompressed_len: 0,
        chunk_table_hash: [0; 32],
    }
}

/// A descriptor signed by the trusted key whose fields may lie.
fn signed_descriptor(h: StreamHeader, entries: &[StreamEntry]) -> Vec<u8> {
    let key = SigningKey::from_bytes(&SEED);
    let mut d = h.to_bytes().to_vec();
    for e in entries {
        d.extend_from_slice(&e.to_bytes());
    }
    d.extend_from_slice(&64u16.to_le_bytes());
    let sig = key.sign(&signed_message(&d)).to_bytes();
    d.extend_from_slice(&sig);
    d
}

fn header(seg_count: u32, body_len: u64) -> StreamHeader {
    let key = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    StreamHeader {
        flags: 1,
        chunk_log2: 12,
        file_id: [3; 16],
        epoch: 1,
        body_len,
        rvf_identity: [0; 32],
        policy_hash: [0; 32],
        seg_count,
        expires_ns: 0,
        signer_key_id: signer_key_id(&key),
    }
}

#[test]
fn sizes_are_rejected_before_anything_proportional_is_allocated() {
    let key = SigningKey::from_bytes(&SEED).verifying_key().to_bytes();
    let keys = [key];
    let policy = StreamPolicy::unpinned_insecure(&keys);
    let bound = policy.descriptor_alloc_bound();

    // 1. Descriptors that lie about sizes, validly signed.
    let lies: Vec<(&str, Vec<u8>, StreamError)> = vec![
        (
            "stored_len 2^62",
            signed_descriptor(header(1, 1 << 62), &[entry(1, 0, 1 << 62)]),
            StreamError::LimitExceeded,
        ),
        (
            "uncompressed_len 2^63",
            {
                let mut e = entry(1, 0, 128);
                e.uncompressed_len = 1 << 63;
                signed_descriptor(header(1, 128), &[e])
            },
            StreamError::LimitExceeded,
        ),
        (
            "body_len far beyond the entries",
            signed_descriptor(header(1, u64::MAX / 2), &[entry(1, 0, 128)]),
            StreamError::LimitExceeded,
        ),
        (
            "body_len 2^40 but entries cover 128 bytes",
            {
                let mut p = header(1, 128);
                p.body_len = 1 << 20;
                signed_descriptor(p, &[entry(1, 0, 128)])
            },
            StreamError::TableInvalid,
        ),
        (
            "seg_count 2^32 - 1 (the table cannot fit the length)",
            {
                let mut d = header(u32::MAX, 128).to_bytes().to_vec();
                d[0x74..0x78].copy_from_slice(&0u32.to_le_bytes());
                d.extend_from_slice(&[0u8; 66]);
                d
            },
            StreamError::TableInvalid,
        ),
        (
            "seg_count 2^20 with a header-sized body of bytes",
            {
                let mut d = header(1 << 20, 128).to_bytes().to_vec();
                d.extend_from_slice(&[0u8; 66]);
                d
            },
            StreamError::LimitExceeded,
        ),
    ];
    for (name, d, want) in &lies {
        let mut v = StreamVerifier::new(StreamPolicy::unpinned_insecure(&keys));
        let frame = descriptor_frame(d);
        let (r, extra) = extra_peak(|| v.push(&frame).err());
        assert_eq!(r, Some(*want), "{name}");
        assert_eq!(v.state(), StreamState::Rejected(*want), "{name}");
        println!("lie {name:<60} -> {want}  extra peak {extra} B (bound {bound})");
        assert!(extra <= bound, "{name}: {extra} > {bound}");
        assert!(
            extra < 16 * 1024,
            "{name}: tiny lies should cost almost nothing, {extra}"
        );
    }

    // 2. A frame header that lies about its payload, after a good descriptor.
    let b = builder(12, Order::File);
    let body = {
        let mut d = unsigned_segment(SEG_VEC, &noise(9_000, 1), 1);
        d.extend(unsigned_segment(SEG_MANIFEST, b"root", 2));
        d
    };
    let bundle = b.build(&body).unwrap();
    let bkeys = [b.public_key()];
    let mut v = StreamVerifier::new(StreamPolicy::unpinned_insecure(&bkeys));
    let mut reader = FrameReader::new();
    reader
        .feed(&mut v, &bundle.frames[0], |_| {})
        .expect("descriptor");
    let mut chunk_lie = vec![1u8];
    chunk_lie.extend_from_slice(&1u64.to_le_bytes());
    chunk_lie.extend_from_slice(&0u32.to_le_bytes());
    chunk_lie.extend_from_slice(&u32::MAX.to_le_bytes());
    let (r, extra) = extra_peak(|| reader.feed(&mut v, &chunk_lie, |_| {}));
    assert_eq!(r.err(), Some(StreamError::FrameSizeLie));
    assert!(extra < 1024, "a 4 GiB chunk claim cost {extra} bytes");
    assert!(matches!(v.state(), StreamState::Poisoned(_)));

    let mut v = StreamVerifier::new(StreamPolicy::unpinned_insecure(&bkeys));
    let mut reader = FrameReader::new();
    let mut desc_lie = vec![0u8];
    desc_lie.extend_from_slice(&u32::MAX.to_le_bytes());
    let (r, extra) = extra_peak(|| reader.feed(&mut v, &desc_lie, |_| {}));
    assert_eq!(r.err(), Some(StreamError::FrameSizeLie));
    assert!(extra < 1024, "a 4 GiB descriptor claim cost {extra} bytes");

    let mut v = StreamVerifier::new(StreamPolicy::unpinned_insecure(&bkeys));
    let mut reader = FrameReader::new();
    reader.feed(&mut v, &bundle.frames[0], |_| {}).unwrap();
    let mut table_lie = vec![2u8];
    table_lie.extend_from_slice(&1u64.to_le_bytes());
    table_lie.extend_from_slice(&(1u32 << 31).to_le_bytes());
    let (r, extra) = extra_peak(|| reader.feed(&mut v, &table_lie, |_| {}));
    assert_eq!(r.err(), Some(StreamError::FrameSizeLie));
    assert!(extra < 1024, "a 2^31-leaf table claim cost {extra} bytes");

    // 3. Bounded memory on a real stream: 16 MiB of model data in 64 KiB chunks
    //    through full admission, never more than a small constant above the
    //    frames the test itself holds.
    let kp = segment_key();
    let mut big = rvm_rvf::testkit::signed_segment_with(0x10, common::WASM, 1, &kp, 2);
    big.extend(unsigned_segment(SEG_VEC, &noise(16 << 20, 5), 2));
    big.extend(unsigned_segment(SEG_MANIFEST, b"root", 3));
    let mut bb = builder(16, Order::File);
    bb.identity = true;
    let bundle = bb.build(&big).unwrap();
    drop(big);
    let bkeys = [bb.public_key()];
    let opts = VerifyOptions::with_trusted_keys(vec![kp.public]);
    let mut p = StreamPolicy::unpinned_insecure(&bkeys);
    p.size = rvm_rvf::SizePolicy::permissive();
    let mut adm = StreamAdmission::new(p, opts);
    let (_, extra) = extra_peak(|| {
        for f in &bundle.frames {
            adm.push(f).expect("good stream");
        }
    });
    assert_eq!(adm.state(), StreamState::Complete);
    assert!(adm.report().expect("report").ok);
    println!("16 MiB admission: extra peak {extra} B");
    assert!(
        extra < 256 * 1024,
        "verifying 16 MiB used {extra} bytes above the frames themselves"
    );
}
