//! Known-answer vectors shared with RuVector (`rvsd-v1-vectors.json`).
//!
//! `rvm-rvf` restates the RVSD wire format instead of depending on `rvf-wire`;
//! these vectors are what keep the two implementations byte-compatible. The
//! test passes only if every positive stream produces the listed events, every
//! negative case is refused with the listed reason and code at the listed
//! frame, and nothing is released after a poison.

use rvm_rvf::stream::{
    chunk_list_hash, decode_descriptor, descriptor_hash, leaf_hash, signer_key_id, EpochPin, Event,
    IdentityStatus, StreamPolicy, StreamState, StreamVerifier,
};
use rvm_rvf::{sha256, SizePolicy};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/rvsd-v1-vectors.json");
const PINNED_SHA256: &str = "e274900baf2788fee3714c392512efa145b737cd5d0c38a4179b0edee0ff6735";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
fn hex32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}
fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

struct Case {
    keys: Vec<[u8; 32]>,
    fault_budget: u32,
    pin: Option<EpochPin>,
    now_ns: Option<u64>,
}

impl Case {
    fn from_json(p: &Value) -> Self {
        Self {
            keys: p["trusted_public_keys_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| hex32(k.as_str().unwrap()))
                .collect(),
            fault_budget: p["fault_budget"].as_u64().unwrap() as u32,
            pin: p["epoch_pin"].as_object().map(|o| EpochPin {
                epoch: o["epoch"].as_u64().unwrap(),
                descriptor_hash: o["descriptor_hash_hex"].as_str().map(hex32),
            }),
            now_ns: p["now_ns"].as_u64(),
        }
    }
}

fn run<'p>(case: &'p Case, pin: &'p dyn Fn(&[u8; 16]) -> Option<EpochPin>) -> StreamVerifier<'p> {
    let mut policy = StreamPolicy::new(&case.keys);
    policy.size = SizePolicy::permissive();
    policy.size.max_segments = 16384;
    policy.fault_budget = case.fault_budget;
    policy.now_ns = case.now_ns;
    if case.pin.is_some() {
        policy.epoch_pin = Some(pin);
    }
    StreamVerifier::new(policy)
}

fn state_string(s: StreamState) -> String {
    match s {
        StreamState::AwaitDescriptor => "AwaitDescriptor".into(),
        StreamState::Ready => "Ready".into(),
        StreamState::Receiving => "Receiving".into(),
        StreamState::Suspended => "Suspended".into(),
        StreamState::Complete => "Complete".into(),
        StreamState::Rejected(e) => format!("Rejected:{}", e.name()),
        StreamState::Poisoned(e) => format!("Poisoned:{}", e.name()),
    }
}

fn check_event(frame: usize, got: &Event<'_>, want: &Value) {
    match (got, want["event"].as_str().unwrap()) {
        (
            Event::DescriptorVerified {
                descriptor_hash,
                seg_count,
                body_len,
            },
            "DescriptorVerified",
        ) => {
            assert_eq!(
                to_hex(descriptor_hash),
                want["descriptor_hash_hex"],
                "f{frame}"
            );
            assert_eq!(u64::from(*seg_count), want["seg_count"].as_u64().unwrap());
            assert_eq!(*body_len, want["body_len"].as_u64().unwrap());
        }
        (Event::TableVerified { seg_id }, "TableVerified") => {
            assert_eq!(*seg_id, want["seg_id"].as_u64().unwrap(), "f{frame}");
        }
        (
            Event::Chunk {
                chunk,
                segment_verified,
                stage_verified,
                complete,
            },
            "Chunk",
        ) => {
            assert_eq!(chunk.seg_id, want["seg_id"].as_u64().unwrap(), "f{frame}");
            assert_eq!(
                u64::from(chunk.chunk_index),
                want["chunk_index"].as_u64().unwrap()
            );
            assert_eq!(chunk.body_offset, want["body_offset"].as_u64().unwrap());
            assert_eq!(chunk.bytes.len() as u64, want["len"].as_u64().unwrap());
            assert_eq!(
                *segment_verified,
                want["segment_verified"].as_bool().unwrap()
            );
            assert_eq!(
                stage_verified.map(u64::from),
                want["stage_verified"].as_u64(),
                "f{frame} stage"
            );
            let c = complete.map(|c| match c {
                IdentityStatus::Verified => "Verified",
                IdentityStatus::Unverifiable => "Unverifiable",
                IdentityStatus::NotPresent => "NotPresent",
            });
            assert_eq!(c, want["complete"].as_str(), "f{frame} complete");
        }
        (g, w) => panic!("frame {frame}: got {g:?}, want {w}"),
    }
}

#[test]
fn the_vector_file_is_the_one_that_was_recorded() {
    assert_eq!(to_hex(&sha256(VECTORS.as_bytes())), PINNED_SHA256);
}

#[test]
fn positive_streams_produce_the_listed_events() {
    let v = vectors();
    let key = hex32(v["test_only_key"]["public_key_hex"].as_str().unwrap());
    assert_eq!(
        to_hex(&signer_key_id(&key)),
        v["test_only_key"]["signer_key_id_hex"]
    );
    let body = hex(v["body"]["hex"].as_str().unwrap());
    assert_eq!(to_hex(&sha256(&body)), v["body"]["sha256_hex"]);
    let file_id: [u8; 16] = hex(v["file_id_hex"].as_str().unwrap()).try_into().unwrap();

    for stream in v["streams"].as_array().unwrap() {
        let name = stream["name"].as_str().unwrap();
        let case = Case {
            keys: vec![key],
            fault_budget: 4,
            pin: None,
            now_ns: None,
        };
        let none = |_: &[u8; 16]| None;
        // Descriptor decode and every table entry.
        let desc_bytes = hex(stream["descriptor_hex"].as_str().unwrap());
        assert_eq!(
            to_hex(&descriptor_hash(&desc_bytes)),
            stream["descriptor_hash_hex"],
            "{name}"
        );
        let mut p = StreamPolicy::new(&case.keys);
        p.size = SizePolicy::permissive();
        let d = decode_descriptor(&desc_bytes, &p).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(d.entries.len(), stream["entries"].as_array().unwrap().len());
        for (e, j) in d.entries.iter().zip(stream["entries"].as_array().unwrap()) {
            assert_eq!(e.seg_id, j["seg_id"].as_u64().unwrap());
            assert_eq!(u64::from(e.seg_type), j["seg_type"].as_u64().unwrap());
            assert_eq!(u64::from(e.stage), j["stage"].as_u64().unwrap());
            assert_eq!(
                u64::from(e.requires_mask),
                j["requires_mask"].as_u64().unwrap()
            );
            assert_eq!(e.body_offset, j["body_offset"].as_u64().unwrap());
            assert_eq!(e.stored_len, j["stored_len"].as_u64().unwrap());
            assert_eq!(e.uncompressed_len, j["uncompressed_len"].as_u64().unwrap());
            assert_eq!(
                to_hex(&e.chunk_table_hash),
                j["chunk_table_hash_hex"],
                "{name}"
            );
            // Recompute the commitments from the body bytes.
            let seg = &body[e.body_offset as usize..(e.body_offset + e.stored_len) as usize];
            let cs = d.header.chunk_size().unwrap_or(u64::MAX) as usize;
            let leaves: Vec<[u8; 32]> = seg
                .chunks(cs.min(seg.len()))
                .enumerate()
                .map(|(i, c)| leaf_hash(&file_id, e.seg_id, i as u32, c))
                .collect();
            for (l, jl) in leaves.iter().zip(j["leaf_hashes_hex"].as_array().unwrap()) {
                assert_eq!(&to_hex(l), jl.as_str().unwrap(), "{name} leaf");
            }
            let committed = if leaves.len() == 1 {
                leaves[0]
            } else {
                chunk_list_hash(&file_id, e.seg_id, &leaves)
            };
            assert_eq!(committed, e.chunk_table_hash, "{name} commitment");
        }
        // The frame state machine.
        let mut ver = run(&case, &none);
        for (i, f) in stream["frames"].as_array().unwrap().iter().enumerate() {
            let bytes = hex(f["hex"].as_str().unwrap());
            let ev = ver
                .push(&bytes)
                .unwrap_or_else(|e| panic!("{name} frame {i}: {e}"));
            check_event(i, &ev, &f["expect"]);
        }
        assert_eq!(
            state_string(ver.state()),
            stream["final_state"].as_str().unwrap(),
            "{name}"
        );
    }
}

fn apply_edits(base: &[Vec<u8>], edits: &[Value]) -> Vec<Vec<u8>> {
    let mut frames = base.to_vec();
    for e in edits {
        let u = |k: &str| e[k].as_u64().unwrap() as usize;
        match e["op"].as_str().unwrap() {
            "xor" => frames[u("frame")][u("offset")] ^= e["mask"].as_u64().unwrap() as u8,
            "drop" => {
                frames.remove(u("frame"));
            }
            "dup" => {
                let f = frames[u("frame")].clone();
                frames.insert(u("frame") + 1, f);
            }
            "swap" => frames.swap(u("a"), u("b")),
            "keep_first" => frames.truncate(u("count")),
            "insert" => frames.insert(u("at"), hex(e["hex"].as_str().unwrap())),
            "replace" => frames[u("frame")] = hex(e["hex"].as_str().unwrap()),
            "cut_tail_bytes" => {
                let f = &mut frames[u("frame")];
                f.truncate(f.len() - u("bytes"));
            }
            op => panic!("unknown edit op {op}"),
        }
    }
    frames
}

fn run_case(v: &Value, c: &Value) {
    let name = c["name"].as_str().unwrap();
    let stream = v["streams"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == c["stream"])
        .unwrap();
    let base: Vec<Vec<u8>> = stream["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| hex(f["hex"].as_str().unwrap()))
        .collect();
    let frames = apply_edits(&base, c["edits"].as_array().unwrap());
    let case = Case::from_json(&c["policy"]);
    let pin = case.pin;
    let lookup = move |_: &[u8; 16]| pin;
    let mut ver = run(&case, &lookup);
    let want = &c["expect"];
    let mut first_error = None;
    for (i, f) in frames.iter().enumerate() {
        let before = (ver.released_chunks(), ver.verified_bytes());
        let was_poisoned = matches!(ver.state(), StreamState::Poisoned(_));
        match ver.push(f) {
            Ok(_) => assert!(!was_poisoned, "{name}: frame {i} accepted after poison"),
            Err(e) => {
                if first_error.is_none() {
                    first_error = Some((i, e));
                } else if was_poisoned {
                    assert_eq!(e.code(), 0x0817, "{name}: frame {i} after poison");
                    assert_eq!(before, (ver.released_chunks(), ver.verified_bytes()));
                }
            }
        }
    }
    match (first_error, want["first_error_frame"].as_u64()) {
        (None, None) => {}
        (Some((i, e)), Some(wi)) => {
            assert_eq!(i as u64, wi, "{name}: first error frame");
            assert_eq!(e.name(), want["reason"].as_str().unwrap(), "{name}: reason");
            assert_eq!(
                format!("0x{:04x}", e.code()),
                want["code"].as_str().unwrap(),
                "{name}: code"
            );
        }
        (g, w) => panic!("{name}: first error {g:?} but vector says {w:?}"),
    }
    assert_eq!(
        state_string(ver.state()),
        want["final_state"].as_str().unwrap(),
        "{name}: final state"
    );
    assert_eq!(
        ver.released_chunks(),
        want["released_chunks"].as_u64().unwrap(),
        "{name}: released chunks"
    );
    assert_eq!(
        ver.verified_bytes(),
        want["released_bytes"].as_u64().unwrap(),
        "{name}: released bytes"
    );
    assert_eq!(
        ver.state() == StreamState::Complete,
        want["complete"].as_bool().unwrap(),
        "{name}: complete"
    );
}

#[test]
fn positive_variants_complete() {
    let v = vectors();
    let variants = v["positive_variants"].as_array().unwrap();
    assert!(!variants.is_empty());
    for c in variants {
        run_case(&v, c);
    }
}

#[test]
fn every_negative_case_is_refused_as_listed() {
    let v = vectors();
    let negatives = v["negative"].as_array().unwrap();
    assert_eq!(negatives.len(), 30);
    for c in negatives {
        run_case(&v, c);
    }
}

/// Writes the fuzz seed corpus. Run with
/// `FUZZ_SEED_DIR=crates/rvm-rvf/fuzz/corpus cargo test -p rvm-rvf --test stream_vectors -- --ignored write_fuzz_seeds`.
#[test]
#[ignore = "writes files; run by hand to refresh the fuzz corpus"]
fn write_fuzz_seeds() {
    let Ok(dir) = std::env::var("FUZZ_SEED_DIR") else {
        return;
    };
    let v = vectors();
    let desc_dir = format!("{dir}/descriptor_decode");
    let frame_dir = format!("{dir}/frame_machine");
    std::fs::create_dir_all(&desc_dir).unwrap();
    std::fs::create_dir_all(&frame_dir).unwrap();
    for stream in v["streams"].as_array().unwrap() {
        let name = stream["name"].as_str().unwrap();
        // Raw mode (even first byte): the signed descriptor as it is.
        let mut raw = vec![0u8];
        raw.extend(hex(stream["descriptor_hex"].as_str().unwrap()));
        std::fs::write(format!("{desc_dir}/{name}-raw"), raw).unwrap();
        // Resigned mode (odd first byte): the unsigned part of the descriptor.
        let d = hex(stream["descriptor_hex"].as_str().unwrap());
        let mut re = vec![1u8];
        re.extend_from_slice(&d[..d.len() - 66]);
        std::fs::write(format!("{desc_dir}/{name}-resigned"), re).unwrap();
        // The frame stream: budget 4, two split bytes, then every frame.
        let mut f = vec![4u8, 63, 20];
        for fr in stream["frames"].as_array().unwrap() {
            f.extend(hex(fr["hex"].as_str().unwrap()));
        }
        std::fs::write(format!("{frame_dir}/{name}"), f).unwrap();
    }
}
