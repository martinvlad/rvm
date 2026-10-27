//! Terminal states, `finish_identity`, and what an epoch pin binds.

mod common;

use common::{builder, good_body, small_body};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::{
    EpochPin, FrameReader, StreamError, StreamPolicy, StreamState, StreamVerifier,
};

fn policy(keys: &[[u8; 32]], budget: u32) -> StreamPolicy<'_> {
    let mut p = StreamPolicy::unpinned_insecure(keys);
    p.fault_budget = budget;
    p
}

#[test]
fn terminal_states_are_never_poisoned_and_late_frames_are_refused_with_bad_state() {
    for (order, want) in [
        (Order::File, StreamState::Complete),
        (Order::Stage, StreamState::CompleteUnverified),
    ] {
        let b = builder(12, order);
        let bundle = b.build(&good_body()).unwrap();
        let keys = [b.public_key()];
        let mut v = StreamVerifier::new(policy(&keys, 0));
        for f in &bundle.frames {
            v.push(f).unwrap();
        }
        assert_eq!(v.state(), want);
        // A late frame, even a hostile one, is refused without a state change.
        for f in [&bundle.frames[1], &bundle.frames[0], &vec![0x7Fu8, 1, 2]] {
            assert_eq!(v.push(f).err(), Some(StreamError::BadState));
            assert_eq!(v.state(), want);
        }
        // So is a reader-level size lie.
        assert_eq!(
            v.poison(StreamError::FrameSizeLie),
            StreamError::FrameSizeLie
        );
        assert_eq!(
            v.state(),
            want,
            "a completed stream is not poisoned from outside"
        );
        let mut r = FrameReader::new();
        assert!(r.feed(&mut v, &[1, 0, 0, 0], |_| {}).is_err());
        assert_eq!(v.state(), want);
    }
    // Suspended is terminal too.
    let b = builder(12, Order::File);
    let bundle = b.build(&good_body()).unwrap();
    let keys = [b.public_key()];
    let mut v = StreamVerifier::new(policy(&keys, 0));
    v.push(&bundle.frames[0]).unwrap();
    v.push(&bundle.frames[1]).unwrap();
    assert_eq!(v.end_of_input(), StreamState::Suspended);
    v.poison(StreamError::FrameSizeLie);
    assert_eq!(v.state(), StreamState::Suspended);
}

#[test]
fn only_finish_identity_turns_a_completed_stream_into_poisoned() {
    let body = good_body();
    let mut b = builder(12, Order::Stage);
    b.identity_override = Some([0x77; 32]);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mut v = StreamVerifier::new(policy(&keys, 0));
    for f in &bundle.frames {
        v.push(f).unwrap();
    }
    assert_eq!(v.state(), StreamState::CompleteUnverified);
    let r = v.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    });
    assert_eq!(r.err(), Some(StreamError::IdentityMismatch));
    assert!(matches!(
        v.state(),
        StreamState::Poisoned(StreamError::IdentityMismatch)
    ));

    // The honest case moves CompleteUnverified to Complete.
    let b = builder(12, Order::Stage);
    let bundle = b.build(&body).unwrap();
    let keys = [b.public_key()];
    let mut v = StreamVerifier::new(policy(&keys, 0));
    for f in &bundle.frames {
        v.push(f).unwrap();
    }
    v.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    })
    .unwrap();
    assert_eq!(v.state(), StreamState::Complete);
}

#[test]
fn an_epoch_pin_binds_its_signer_as_well_as_the_file() {
    let body = small_body();
    let mut a = builder(12, Order::File);
    a.epoch = 5;
    let accepted = a.build(&body).unwrap();
    let mut other_signer = rvm_rvf::stream::builder::StreamBuilder::new([0x6B; 32]);
    other_signer.file_id = a.file_id; // same lineage id, different publisher
    other_signer.epoch = 1;
    let o = other_signer.build(&body).unwrap();
    let keys = [a.public_key(), other_signer.public_key()];
    let pin = EpochPin {
        epoch: 5,
        descriptor_hash: accepted.descriptor_hash,
        signer_key_id: accepted.header.signer_key_id,
    };
    let lookup = move |sg: &[u8; 8], _: &[u8; 16]| Some(pin).filter(|p| &p.signer_key_id == sg);
    let mut p = StreamPolicy::unpinned_insecure(&keys);
    p.replay = rvm_rvf::stream::ReplayProtection::Lookup {
        pin: &lookup,
        now_ns: None,
    };
    // The other publisher's epoch 1 is not a replay of publisher A's epoch 5...
    let mut v = StreamVerifier::new(p);
    assert!(v.push(&o.frames[0]).is_ok());
    // ...but publisher A's own epoch 1 is.
    let mut old = a.clone();
    old.epoch = 1;
    let oa = old.build(&body).unwrap();
    let mut v = StreamVerifier::new(p);
    assert_eq!(v.push(&oa.frames[0]).err(), Some(StreamError::StaleEpoch));
}

#[test]
fn the_memory_pin_store_is_keyed_by_signer_and_advances_only_by_compare_and_set() {
    use rvm_rvf::stream::{MemoryPinStore, PinStore};
    let store = MemoryPinStore::new();
    let (a, b, file) = ([1u8; 8], [2u8; 8], [9u8; 16]);
    let pin = |epoch, signer| EpochPin {
        epoch,
        descriptor_hash: [epoch as u8; 32],
        signer_key_id: signer,
    };
    assert!(store.advance(&a, &file, None, pin(5, a)));
    // Another signer's lineage is separate.
    assert_eq!(store.lookup(&b, &file), None);
    assert!(store.advance(&b, &file, None, pin(10, b)));
    assert_eq!(store.lookup(&a, &file).unwrap().epoch, 5);
    // A stale expectation loses the race.
    assert!(!store.advance(&a, &file, None, pin(6, a)));
    assert!(!store.advance(&a, &file, Some(pin(4, a)), pin(6, a)));
    // Never backwards, even from the right expectation.
    assert!(!store.advance(&a, &file, Some(pin(5, a)), pin(4, a)));
    assert!(store.advance(&a, &file, Some(pin(5, a)), pin(7, a)));
    assert_eq!(store.lookup(&a, &file).unwrap().epoch, 7);
    assert_eq!(store.len(), 2);
}
