//! ADR-160 item 6: descriptor, segment and poison events are witnessed, pass
//! and fail alike, through the existing `rvm-rvf` witness path.

mod common;

use common::{builder, good_body, opts};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::witness::push_witnessed;
use rvm_rvf::stream::{StreamAdmission, StreamError, StreamPolicy, StreamState};
use rvm_rvf::{CheckKind, WitnessContext};
use rvm_types::{ActionKind, WitnessRecord};
use rvm_witness::WitnessLog;

const CTX: WitnessContext = WitnessContext::new(3, 777);

fn records(log: &WitnessLog<128>) -> Vec<WitnessRecord> {
    (0..log.len()).filter_map(|i| log.get(i)).collect()
}

fn kinds(rs: &[WitnessRecord], check: CheckKind) -> Vec<&WitnessRecord> {
    rs.iter().filter(|r| r.flags == check as u8).collect()
}

#[test]
fn a_good_stream_witnesses_the_descriptor_every_segment_and_completion() {
    let b = builder(12, Order::File);
    let bundle = b.build(&good_body()).unwrap();
    let keys = [b.public_key()];
    let mut adm = StreamAdmission::new(StreamPolicy::unpinned_insecure(&keys), opts());
    let log = WitnessLog::<128>::new();
    for f in &bundle.frames {
        push_witnessed(&mut adm, f, &log, CTX).unwrap();
    }
    assert_eq!(adm.state(), StreamState::Complete);
    let rs = records(&log);
    let desc = kinds(&rs, CheckKind::StreamDescriptor);
    assert_eq!(desc.len(), 1);
    assert_eq!(desc[0].action_kind, ActionKind::ProofVerifiedP2 as u8);
    let segs = kinds(&rs, CheckKind::StreamSegment);
    assert_eq!(segs.len(), bundle.entries.len());
    for (r, e) in segs.iter().zip(&bundle.entries) {
        assert_eq!(r.target_object_id, e.seg_id);
        assert_eq!(
            r.payload[..],
            e.chunk_table_hash[..8],
            "root in the payload"
        );
        assert_eq!(r.action_kind, ActionKind::ProofVerifiedP2 as u8);
    }
    assert_eq!(kinds(&rs, CheckKind::StreamComplete).len(), 1);
    assert!(kinds(&rs, CheckKind::StreamPoisoned).is_empty());
    assert!(rvm_witness::verify_chain(&rs).is_ok());
    assert!(rs
        .iter()
        .all(|r| r.actor_partition_id == 3 && r.timestamp_ns == 777));
}

#[test]
fn a_rejected_descriptor_is_witnessed_with_its_reason() {
    let b = builder(12, Order::File);
    let bundle = b.build(&good_body()).unwrap();
    let other = [[9u8; 32]];
    let mut adm = StreamAdmission::new(StreamPolicy::unpinned_insecure(&other), opts());
    let log = WitnessLog::<128>::new();
    let err = push_witnessed(&mut adm, &bundle.frames[0], &log, CTX).unwrap_err();
    assert!(err.to_string().contains("UnknownSigner"), "{err}");
    let rs = records(&log);
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].flags, CheckKind::StreamDescriptor as u8);
    assert_eq!(rs[0].action_kind, ActionKind::ProofRejected as u8);
    assert_eq!(
        u16::from_le_bytes([rs[0].aux[6], rs[0].aux[7]]),
        StreamError::UnknownSigner.code()
    );
}

#[test]
fn a_poisoned_stream_is_witnessed_with_segment_chunk_and_reason() {
    let b = builder(12, Order::File);
    let mut bundle = b.build(&good_body()).unwrap();
    // Corrupt the second chunk of the 10 000-byte vector segment (id 3).
    let at = bundle
        .frames
        .iter()
        .position(|f| f[0] == 1 && f[1..9] == 3u64.to_le_bytes() && f[9..13] == 1u32.to_le_bytes())
        .unwrap();
    bundle.frames[at][40] ^= 1;
    let keys = [b.public_key()];
    let mut policy = StreamPolicy::unpinned_insecure(&keys);
    policy.fault_budget = 0;
    let mut adm = StreamAdmission::new(policy, opts());
    let log = WitnessLog::<128>::new();
    for f in &bundle.frames[..=at] {
        let _ = push_witnessed(&mut adm, f, &log, CTX);
    }
    // Frames after the poison are refused and add no second poison record.
    for f in &bundle.frames[at + 1..] {
        assert!(push_witnessed(&mut adm, f, &log, CTX).is_err());
    }
    let rs = records(&log);
    let p = kinds(&rs, CheckKind::StreamPoisoned);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].action_kind, ActionKind::ProofRejected as u8);
    assert_eq!(p[0].target_object_id, 3);
    assert_eq!(p[0].aux[0..4], 1u32.to_le_bytes());
    assert_eq!(
        u16::from_le_bytes([p[0].aux[6], p[0].aux[7]]),
        StreamError::ChunkHashMismatch.code()
    );
    assert!(kinds(&rs, CheckKind::StreamComplete).is_empty());
    assert!(rvm_witness::verify_chain(&rs).is_ok());
}
