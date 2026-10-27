//! Adversarial properties of the stream verifier (ADR-353 acceptance list).
//!
//! * P1 released chunks are a byte-identical subset of the signed set, for any
//!   byte sequence
//! * P2 a single bit flip is refused
//! * P3 truncation at every byte offset never completes
//! * P4 permuting, duplicating, deleting and inserting frames never completes
//!   with different bytes
//! * P5 replay: an old epoch, or the same epoch with other content
//! * P6 splice: a validly hashed chunk of another file, same signer

mod common;

use common::{builder, good_body, small_body};
use proptest::prelude::*;
use rvm_rvf::stream::builder::{Order, StreamBundle};
use rvm_rvf::stream::{
    leaf_hash, EpochPin, Event, FrameReader, StreamAdmission, StreamError, StreamPolicy,
    StreamState, StreamVerifier,
};
use rvm_rvf::VerifyOptions;
use std::collections::HashMap;

struct Fixture {
    key: [u8; 32],
    body: Vec<u8>,
    bundle: StreamBundle,
    /// `(seg_id, chunk_index) -> signed bytes`
    signed: HashMap<(u64, u32), Vec<u8>>,
}

fn fixture(body: Vec<u8>, chunk_log2: u8) -> Fixture {
    let b = builder(chunk_log2, Order::File);
    let bundle = b.build(&body).unwrap();
    let mut signed = HashMap::new();
    for f in &bundle.frames {
        if f[0] == 1 {
            let seg = u64::from_le_bytes(f[1..9].try_into().unwrap());
            let idx = u32::from_le_bytes(f[9..13].try_into().unwrap());
            signed.insert((seg, idx), f[17..].to_vec());
        }
    }
    Fixture {
        key: b.public_key(),
        body,
        bundle,
        signed,
    }
}

fn policy(keys: &[[u8; 32]], budget: u32) -> StreamPolicy<'_> {
    let mut p = StreamPolicy::unpinned_insecure(keys);
    p.fault_budget = budget;
    p
}

/// Feed `frames`; assert P1 for everything released; return the final state.
fn feed_and_check(fx: &Fixture, frames: &[Vec<u8>], budget: u32) -> StreamState {
    let keys = [fx.key];
    let mut v = StreamVerifier::new(policy(&keys, budget));
    let mut seen: HashMap<(u64, u32), ()> = HashMap::new();
    let mut body = vec![0u8; fx.body.len()];
    for f in frames {
        if let Ok(Event::Chunk { chunk, .. }) = v.push(f) {
            let want = fx
                .signed
                .get(&(chunk.seg_id, chunk.chunk_index))
                .expect("released chunk is in the signed set");
            assert_eq!(chunk.bytes, want.as_slice(), "released bytes differ");
            assert!(seen.insert((chunk.seg_id, chunk.chunk_index), ()).is_none());
            let at = chunk.body_offset as usize;
            body[at..at + chunk.bytes.len()].copy_from_slice(chunk.bytes);
        }
    }
    if v.state() == StreamState::Complete {
        assert_eq!(body, fx.body, "Complete with different bytes");
        assert_eq!(seen.len(), fx.signed.len());
    }
    v.state()
}

#[derive(Debug, Clone)]
enum Edit {
    Flip { frame: usize, byte: usize, mask: u8 },
    Drop(usize),
    Dup(usize),
    Swap(usize, usize),
    Insert { at: usize, frame: Vec<u8> },
    Cut { frame: usize, to: usize },
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        (any::<usize>(), any::<usize>(), 1u8..=255).prop_map(|(frame, byte, mask)| Edit::Flip {
            frame,
            byte,
            mask
        }),
        any::<usize>().prop_map(Edit::Drop),
        any::<usize>().prop_map(Edit::Dup),
        (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Edit::Swap(a, b)),
        (
            any::<usize>(),
            proptest::collection::vec(any::<u8>(), 0..64)
        )
            .prop_map(|(at, frame)| Edit::Insert { at, frame }),
        (any::<usize>(), any::<usize>()).prop_map(|(frame, to)| Edit::Cut { frame, to }),
    ]
}

fn apply(base: &[Vec<u8>], edits: &[Edit]) -> Vec<Vec<u8>> {
    let mut f = base.to_vec();
    for e in edits {
        let n = f.len().max(1);
        match e {
            Edit::Flip { frame, byte, mask } => {
                let fr = &mut f[frame % n];
                if !fr.is_empty() {
                    let at = byte % fr.len();
                    fr[at] ^= mask;
                }
            }
            Edit::Drop(i) => {
                if !f.is_empty() {
                    f.remove(i % n);
                }
            }
            Edit::Dup(i) => {
                if !f.is_empty() {
                    let c = f[i % n].clone();
                    f.insert(i % n, c);
                }
            }
            Edit::Swap(a, b) => {
                if !f.is_empty() {
                    f.swap(a % n, b % n);
                }
            }
            Edit::Insert { at, frame } => f.insert(at % (n + 1), frame.clone()),
            Edit::Cut { frame, to } => {
                if !f.is_empty() {
                    let fr = &mut f[frame % n];
                    let len = fr.len();
                    fr.truncate(to % (len + 1));
                }
            }
        }
    }
    f
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    /// P1 + P4: any edit sequence over a valid stream releases only signed
    /// bytes, and never completes with different bytes.
    #[test]
    fn edited_streams_release_only_signed_bytes(
        chunk in prop_oneof![Just(0xFFu8), Just(12u8)],
        edits in proptest::collection::vec(edit(), 0..6),
        budget in 0u32..8,
    ) {
        let fx = fixture(good_body(), chunk);
        let frames = apply(&fx.bundle.frames, &edits);
        feed_and_check(&fx, &frames, budget);
    }

    /// P1 on arbitrary bytes: random frames never release anything.
    #[test]
    fn random_frames_release_nothing_unsigned(
        frames in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..80), 0..12),
        budget in 0u32..8,
    ) {
        let fx = fixture(small_body(), 12);
        let keys = [fx.key];
        let mut v = StreamVerifier::new(policy(&keys, budget));
        for f in &frames {
            if let Ok(Event::Chunk { .. }) = v.push(f) {
                panic!("a random frame released a chunk");
            }
        }
        prop_assert!(v.state() != StreamState::Complete);
    }

    /// P1 through the frame reader: arbitrary byte splits of an edited stream.
    #[test]
    fn split_independence_and_p1_through_the_frame_reader(
        edits in proptest::collection::vec(edit(), 0..4),
        cuts in proptest::collection::vec(1usize..400, 1..40),
    ) {
        let fx = fixture(small_body(), 12);
        let frames = apply(&fx.bundle.frames, &edits);
        let stream: Vec<u8> = frames.concat();
        let keys = [fx.key];
        let mut v = StreamVerifier::new(policy(&keys, 4));
        let mut reader = FrameReader::new();
        let mut rest = stream.as_slice();
        let mut i = 0;
        let mut released = 0;
        while !rest.is_empty() {
            let take = cuts[i % cuts.len()].min(rest.len());
            i += 1;
            let (a, b) = rest.split_at(take);
            rest = b;
            let r = reader.feed(&mut v, a, |res| {
                if let Ok(Event::Chunk { chunk, .. }) = res {
                    assert_eq!(chunk.bytes, fx.signed[&(chunk.seg_id, chunk.chunk_index)].as_slice());
                    released += 1;
                }
            });
            if r.is_err() { break; }
        }
        prop_assert!(released <= fx.signed.len());
        if v.state() == StreamState::Complete {
            prop_assert_eq!(released, fx.signed.len());
        }
    }

    /// P2: a single bit flip anywhere in a chunk or table frame is refused.
    #[test]
    fn a_bit_flip_in_any_frame_is_refused(frame in any::<usize>(), byte in any::<usize>(), bit in 0u8..8) {
        let fx = fixture(good_body(), 12);
        let n = frame % fx.bundle.frames.len();
        let mut frames = fx.bundle.frames.clone();
        let len = frames[n].len();
        frames[n][byte % len] ^= 1 << bit;
        let keys = [fx.key];
        let mut v = StreamVerifier::new(policy(&keys, 0));
        let mut refused = false;
        for (i, f) in frames.iter().enumerate() {
            match v.push(f) {
                Ok(_) => prop_assert!(!(i == n && refused)),
                Err(_) => {
                    if i == n { refused = true; }
                }
            }
        }
        prop_assert!(refused, "the flipped frame {n} was accepted");
        prop_assert!(v.state() != StreamState::Complete);
    }
}

#[test]
fn p2_every_bit_of_every_frame_of_a_small_stream_is_refused() {
    for chunk_log2 in [0xFF, 12] {
        let fx = fixture(small_body(), chunk_log2);
        let keys = [fx.key];
        let mut states = Vec::new();
        let mut v = StreamVerifier::new(policy(&keys, 0));
        for f in &fx.bundle.frames {
            states.push(v.clone());
            v.push(f).unwrap();
        }
        assert_eq!(v.state(), StreamState::Complete);
        let mut flips = 0u64;
        for (n, f) in fx.bundle.frames.iter().enumerate() {
            for byte in 0..f.len() {
                for bit in 0..8 {
                    let mut g = f.clone();
                    g[byte] ^= 1 << bit;
                    let mut s = states[n].clone();
                    assert!(
                        s.push(&g).is_err(),
                        "chunk_log2={chunk_log2:#x}: flip frame {n} byte {byte} bit {bit} accepted"
                    );
                    flips += 1;
                }
            }
        }
        assert!(flips > 10_000, "{flips}");
    }
}

#[test]
fn p3_truncation_at_every_byte_offset_never_completes() {
    for chunk_log2 in [0xFF, 12] {
        let fx = fixture(small_body(), chunk_log2);
        let stream: Vec<u8> = fx.bundle.frames.concat();
        let keys = [fx.key];
        let opts = VerifyOptions::with_trusted_keys(vec![common::segment_key().public]);
        for cut in 0..stream.len() {
            // Verifier through the frame reader.
            let mut v = StreamVerifier::new(policy(&keys, 4));
            let mut r = FrameReader::new();
            let _ = r.feed(&mut v, &stream[..cut], |_| {});
            assert_ne!(v.state(), StreamState::Complete, "cut at {cut}");
            // Admission must not produce a report either.
            let mut adm = StreamAdmission::new(policy(&keys, 4), opts.clone());
            let mut r = FrameReader::new();
            let _ = r.feed(&mut adm, &stream[..cut], |_| {});
            assert!(adm.report().is_none(), "cut at {cut}");
        }
        // The full stream does complete.
        let mut v = StreamVerifier::new(policy(&keys, 4));
        let mut r = FrameReader::new();
        r.feed(&mut v, &stream, |_| {}).unwrap();
        assert_eq!(v.state(), StreamState::Complete);
    }
}

#[test]
fn p3_a_suspended_stream_is_resumable_but_never_complete() {
    let fx = fixture(good_body(), 12);
    let keys = [fx.key];
    let mut v = StreamVerifier::new(policy(&keys, 4));
    let half = fx.bundle.frames.len() / 2;
    for f in &fx.bundle.frames[..half] {
        v.push(f).unwrap();
    }
    assert_eq!(v.end_of_input(), StreamState::Suspended);
    assert!(v.push(&fx.bundle.frames[half]).is_err());
    assert!(v.resume());
    for f in &fx.bundle.frames[half..] {
        v.push(f).unwrap();
    }
    assert_eq!(v.state(), StreamState::Complete);
}

#[test]
fn p5_replay_of_an_older_or_conflicting_descriptor() {
    let body = small_body();
    let mut b = builder(12, Order::File);
    b.epoch = 5;
    let accepted = b.build(&body).unwrap();
    let keys = [b.public_key()];
    // An older epoch signed by the same key.
    let mut old = b.clone();
    old.epoch = 4;
    let old = old.build(&body).unwrap();
    // The same epoch, different content (another policy hash).
    let mut other = b.clone();
    other.policy_hash = [0xCD; 32];
    let other = other.build(&body).unwrap();

    let pin = EpochPin {
        epoch: 5,
        descriptor_hash: accepted.descriptor_hash,
        signer_key_id: accepted.header.signer_key_id,
    };
    let lookup = move |sg: &[u8; 8], _: &[u8; 16]| Some(pin).filter(|p| &p.signer_key_id == sg);
    for (bundle, want) in [
        (&old, Some(StreamError::StaleEpoch)),
        (&other, Some(StreamError::EpochConflict)),
        (&accepted, None),
    ] {
        let mut p = StreamPolicy::unpinned_insecure(&keys);
        p.replay = rvm_rvf::stream::ReplayProtection::Lookup {
            pin: &lookup,
            now_ns: None,
        };
        let mut v = StreamVerifier::new(p);
        let r = v.push(&bundle.frames[0]);
        assert_eq!(r.err(), want);
        if let Some(e) = want {
            assert_eq!(v.state(), StreamState::Rejected(e));
            // Nothing after a rejected descriptor is accepted.
            assert!(v.push(&bundle.frames[1]).is_err());
        }
    }
}

#[test]
fn p6_a_chunk_from_another_file_signed_by_the_same_key_is_refused() {
    let body_a = good_body();
    // Another artifact of the same publisher: same layout, one model byte differs.
    let mut body_b = good_body();
    common::flip_payload_byte(&mut body_b, 3, 10);
    let a = builder(12, Order::File);
    let mut b = builder(12, Order::File);
    b.file_id = *b"another-file-id!";
    let (sa, sb) = (a.build(&body_a).unwrap(), b.build(&body_b).unwrap());
    assert_eq!(a.public_key(), b.public_key());
    assert_eq!(sa.frames.len(), sb.frames.len());
    let mut spliced = 0;
    for victim in 1..sa.frames.len() {
        if sa.frames[victim] == sb.frames[victim] {
            continue;
        }
        let keys = [a.public_key()];
        let mut v = StreamVerifier::new(policy(&keys, 0));
        for f in &sa.frames[..victim] {
            v.push(f).unwrap();
        }
        let want = if sa.frames[victim][0] == 2 {
            StreamError::TableHashMismatch
        } else {
            StreamError::ChunkHashMismatch
        };
        assert_eq!(
            v.push(&sb.frames[victim]).err(),
            Some(want),
            "frame {victim} types a={} b={} lens {} {} seg a={:?} b={:?}",
            sa.frames[victim][0],
            sb.frames[victim][0],
            sa.frames[victim].len(),
            sb.frames[victim].len(),
            &sa.frames[victim][1..9],
            &sb.frames[victim][1..9]
        );
        assert!(matches!(v.state(), StreamState::Poisoned(_)));
        spliced += 1;
    }
    assert!(spliced >= 2, "{spliced}");
    // The binding is in the hash itself: identical bytes commit differently
    // under different file ids, so one file's commitments never certify another's.
    let (fa, fb) = (a.file_id, b.file_id);
    let bytes = [7u8; 100];
    assert_ne!(leaf_hash(&fa, 3, 0, &bytes), leaf_hash(&fb, 3, 0, &bytes));
    assert_ne!(
        rvm_rvf::stream::chunk_list_hash(&fa, 3, &[[1; 32]]),
        rvm_rvf::stream::chunk_list_hash(&fb, 3, &[[1; 32]])
    );
}

#[test]
fn a_retry_within_the_fault_budget_completes_and_beyond_it_poisons() {
    let fx = fixture(good_body(), 12);
    let keys = [fx.key];
    let victim = fx
        .bundle
        .frames
        .iter()
        .position(|f| f[0] == 1 && f.len() > 100)
        .unwrap();
    let mut bad = fx.bundle.frames[victim].clone();
    bad[40] ^= 1;
    for budget in 0..4u32 {
        let mut v = StreamVerifier::new(policy(&keys, budget));
        for f in &fx.bundle.frames[..victim] {
            v.push(f).unwrap();
        }
        // `budget` corrupted deliveries are tolerated, the next one poisons.
        for _ in 0..budget {
            assert_eq!(v.push(&bad).err(), Some(StreamError::ChunkHashMismatch));
            assert!(!matches!(v.state(), StreamState::Poisoned(_)));
        }
        for f in &fx.bundle.frames[victim..] {
            v.push(f).unwrap();
        }
        assert_eq!(v.state(), StreamState::Complete, "budget {budget}");

        let mut v = StreamVerifier::new(policy(&keys, budget));
        for f in &fx.bundle.frames[..victim] {
            v.push(f).unwrap();
        }
        for _ in 0..=budget {
            let _ = v.push(&bad);
        }
        assert!(matches!(v.state(), StreamState::Poisoned(_)));
        assert!(v.push(&fx.bundle.frames[victim]).is_err());
    }
}
