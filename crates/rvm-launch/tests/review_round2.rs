//! Round-2 adversarial review (branch feat/ofer-review-rvm). `r1_*` re-attack
//! the round-1 findings through the new API (they pass when the fix holds);
//! `r2_*` attack the new surface. A `r2_*` test that PASSES while its doc says
//! DEFECT demonstrates a defect.

mod stream_common;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_host::WasmAdapter;
use rvm_launch::{
    Instance, InstanceId, InstanceState, PoisonObligation, SessionError, SessionEvent,
    SessionState, StreamSession,
};
use rvm_rvf::stream::builder::{Order, StreamBuilder, StreamBundle};
use rvm_rvf::stream::{
    FrameTarget, IdentityStatus, MemoryPinStore, ReplayProtection, StreamError, StreamPolicy,
    StreamState,
};
use rvm_rvf::{sha256, WitnessContext};
use rvm_wasm::agent::AgentManager;
use rvm_witness::WitnessLog;
use stream_common::*;

fn pinned<'k>(keys: &'k [[u8; 32]], store: &'k MemoryPinStore) -> StreamSession<'k> {
    let mut p = StreamPolicy::new(
        keys,
        ReplayProtection::Store {
            store,
            now_ns: None,
        },
    );
    p.size = rvm_rvf::SizePolicy::permissive();
    p.size.max_segments = 4096;
    StreamSession::new(p, opts(), base_policy())
}

fn signer(seed: u8, epoch: u64, order: Order) -> StreamBuilder {
    let mut b = StreamBuilder::new([seed; 32]);
    b.chunk_log2 = 12;
    b.epoch = epoch;
    b.order = order;
    if order == Order::Stage {
        b.stages = rvm_rvf::stream::builder::Stages::ByType;
    }
    b
}

fn bundle_for(b: &StreamBuilder) -> (StreamBundle, Vec<u8>) {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    (b.build(&body).unwrap(), body)
}

fn run(s: &mut StreamSession<'_>, bundle: &StreamBundle) -> Result<(), SessionError> {
    for f in &bundle.frames {
        s.push(f)?;
    }
    Ok(())
}

// ---------------------------------------------------------------- round 1

#[test]
fn r1_preauth_junk_poison_owes_nothing() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);
    let mut s = stream(&keys, bundle, base_policy());
    assert!(s.session.push(&[0x7F, 1, 2, 3]).is_err());
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert!(s.session.poison().unwrap().descriptor_hash.is_none());
    assert!(s.session.take_obligation().is_none());
}

#[test]
fn r1_replayed_authentic_frames_no_longer_poison_and_do_not_reach_other_tenants() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);
    // Tenant B: clean, Running.
    let mut tb = stream(&keys, bundle.clone(), base_policy());
    run_all(&mut tb).unwrap();
    let log = WitnessLog::<512>::new();
    let mut agents = AgentManager::<4>::new();
    let mut inst_b = Instance::create(
        InstanceId::new(2),
        WasmAdapter::new(),
        tb.session.package().unwrap().clone(),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();
    inst_b
        .start_verified(tb.session.take_module(2).unwrap(), &mut agents, &log, 2)
        .unwrap();
    // Tenant A: replay storm of an authentic chunk.
    let mut ta = stream(&keys, bundle.clone(), base_policy());
    ta.session.push(&bundle.frames[0]).unwrap();
    ta.session.push(&bundle.frames[1]).unwrap();
    for _ in 0..6 {
        assert_eq!(
            ta.session.push(&bundle.frames[1]),
            Ok(SessionEvent::Duplicate { seg_id: 1 })
        );
    }
    assert_eq!(ta.session.state(), SessionState::Receiving);
    // Force an authenticated poison on A (a wrong-length chunk is a size lie).
    let mut lie = bundle.frames[1].clone();
    lie.truncate(lie.len() - 1);
    let plen = (lie.len() - 17) as u32;
    lie[13..17].copy_from_slice(&plen.to_le_bytes());
    assert!(ta.session.push(&lie).is_err());
    assert_eq!(ta.session.state(), SessionState::Poisoned);
    let ob = ta.session.take_obligation().expect("authenticated poison");
    let mut table = rvm_cap::CapabilityTable::<8>::new();
    let d = ob
        .discharge(
            &mut table,
            std::slice::from_mut(&mut inst_b),
            &mut agents,
            &log,
            3,
        )
        .unwrap();
    assert_eq!(d.terminated, 0, "tenant B untouched");
    assert_eq!(inst_b.state(), InstanceState::Running);
}

#[test]
fn r1_stage_order_lie_is_not_startable_and_failure_is_witnessed() {
    let mut b = signer(0x5A, 1, Order::Stage);
    b.identity_override = Some([0x99; 32]);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);
    let mut s = stream(&keys, bundle, base_policy());
    run_all(&mut s).unwrap();
    assert_eq!(s.session.stream_state(), StreamState::CompleteUnverified);
    assert_eq!(s.session.take_module(2).err(), Some(SessionError::IdentityUnverified));
    assert!(s.session.package().is_none());
}

// ---------------------------------------------------------------- round 2

/// RV2-01 DEFECT: the pin store keeps one slot per file_id and the descriptor
/// check ignores a pin from another signer. A second trusted signer that
/// publishes the same file_id at a higher epoch overwrites the first signer's
/// pin; the first signer's OLD descriptors are then accepted again.
#[test]
fn r2_pin_slot_is_overwritten_by_a_second_trusted_signer_reopening_rollback() {
    let store = MemoryPinStore::new();
    let a9 = signer(0x5A, 9, Order::File);
    let b10 = signer(0x6B, 10, Order::File);
    let a3 = signer(0x5A, 3, Order::File);
    let keys = [a9.public_key(), b10.public_key()];

    let mut s = pinned(&keys, &store);
    run(&mut s, &bundle_for(&a9).0).unwrap();
    assert_eq!(s.state(), SessionState::Complete);

    // Sanity: the pin works against A's own replay.
    let mut s = pinned(&keys, &store);
    assert!(run(&mut s, &bundle_for(&a3).0).is_err());

    // Signer B (also trusted) publishes the same file_id, epoch 10.
    let mut s = pinned(&keys, &store);
    run(&mut s, &bundle_for(&b10).0).unwrap();

    // A's epoch 3 now completes.
    let mut s = pinned(&keys, &store);
    run(&mut s, &bundle_for(&a3).0).unwrap();
    assert_eq!(s.state(), SessionState::Complete, "rollback accepted");
    assert!(s.take_module(2).is_ok());
}

/// RV2-02 DEFECT: the pin is consulted only when the descriptor arrives and
/// recorded only at completion, so an older descriptor accepted before a newer
/// one completes still completes (and its module is startable) afterwards.
#[test]
fn r2_pin_is_not_rechecked_at_completion_so_two_sessions_race_to_a_rollback() {
    let store = MemoryPinStore::new();
    let old = signer(0x5A, 4, Order::File);
    let new = signer(0x5A, 5, Order::File);
    let keys = [old.public_key()];
    let (b_old, _) = bundle_for(&old);
    let (b_new, _) = bundle_for(&new);

    let mut s_old = pinned(&keys, &store);
    s_old.push(&b_old.frames[0]).unwrap(); // descriptor looked up: no pin yet
    let mut s_new = pinned(&keys, &store);
    run(&mut s_new, &b_new).unwrap();
    assert_eq!(store.lookup_epoch(), Some(5));
    // Epoch 4 now finishes AFTER epoch 5 was installed.
    for f in &b_old.frames[1..] {
        s_old.push(f).unwrap();
    }
    assert_eq!(s_old.state(), SessionState::Complete);
    assert!(s_old.take_module(2).is_ok(), "epoch 4 module handed out after epoch 5");
}

trait EpochOf {
    fn lookup_epoch(&self) -> Option<u64>;
}
impl EpochOf for MemoryPinStore {
    fn lookup_epoch(&self) -> Option<u64> {
        use rvm_rvf::stream::PinStore;
        self.lookup(b"rvm-testkit-file").map(|p| p.epoch)
    }
}

/// Sound: a cut stream, and an unconfirmed stage-order stream, record nothing.
#[test]
fn r2_pin_not_recorded_for_cut_or_unconfirmed_streams() {
    let store = MemoryPinStore::new();
    let b = signer(0x5A, 7, Order::File);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);
    let mut s = pinned(&keys, &store);
    for f in &bundle.frames[..bundle.frames.len() - 1] {
        s.push(f).unwrap();
    }
    assert!(store.is_empty());

    let st = signer(0x5A, 7, Order::Stage);
    let (bundle, body) = bundle_for(&st);
    let mut s = pinned(&keys, &store);
    run(&mut s, &bundle).unwrap();
    assert!(store.is_empty(), "CompleteUnverified must not pin");
    s.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    })
    .unwrap();
    assert_eq!(store.len(), 1);
}

/// RV2-03 DEFECT (Low): finish_identity trusts `read_at`. A rogue descriptor
/// signer claims the identity of a different, well-known body B0; the host's
/// persistence layer (or anything answering read_at) returns B0; the stream
/// is confirmed Verified although the module that was streamed is not part of
/// B0.
#[test]
fn r2_finish_identity_does_not_bind_the_confirming_bytes_to_the_streamed_bytes() {
    let module = wasm_common::synthetic_module(3_000);
    let streamed = package_body(&module, "clock", 2);
    let mut b0 = streamed.clone();
    let n = b0.len();
    b0[n - 70] ^= 1; // some other body of the same length
    let mut b = signer(0x5A, 1, Order::Stage);
    b.identity_override = Some(sha256(&b0));
    let keys = [b.public_key()];
    let bundle = b.build(&streamed).unwrap();
    let mut s = stream(&keys, bundle, base_policy());
    run_all(&mut s).unwrap();
    s.session
        .finish_identity(|off, buf| {
            buf.copy_from_slice(&b0[off as usize..off as usize + buf.len()]);
            true
        })
        .unwrap();
    assert_eq!(s.session.identity_status(), Some(IdentityStatus::Verified));
    assert!(s.session.take_module(2).is_ok());
}

/// Sound: second finish_identity, wrong persisted body.
#[test]
fn r2_finish_identity_second_call_and_wrong_body() {
    let b = signer(0x5A, 1, Order::Stage);
    let keys = [b.public_key()];
    let (bundle, body) = bundle_for(&b);
    let mut s = stream(&keys, bundle.clone(), base_policy());
    run_all(&mut s).unwrap();
    confirm(&mut s, &body);
    let again = s.session.finish_identity(|_, buf| {
        buf.fill(0);
        true
    });
    assert!(again.is_err());
    assert_eq!(s.session.state(), SessionState::Complete);
    assert_eq!(s.session.identity_status(), Some(IdentityStatus::Verified));
    assert!(s.session.take_module(2).is_ok());

    let mut s = stream(&keys, bundle, base_policy());
    run_all(&mut s).unwrap();
    let r = s.session.finish_identity(|_, buf| {
        buf.fill(0);
        true
    });
    assert!(r.is_err());
    assert_eq!(s.session.state(), SessionState::Poisoned);
}

/// Duplicates: cap, differing bytes, faults hidden among duplicates.
#[test]
fn r2_duplicate_rule_cap_and_fault_accounting() {
    let b = signer(0x5A, 1, Order::File);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);

    // Flood cap.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    s.session.push(&bundle.frames[0]).unwrap();
    s.session.push(&bundle.frames[1]).unwrap();
    let mut n = 0u64;
    while s.session.state() == SessionState::Receiving {
        let _ = s.session.push(&bundle.frames[1]);
        n += 1;
        assert!(n < 100_000);
    }
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert_eq!(
        s.session.poison().unwrap().info.reason,
        StreamError::DuplicateFlood
    );
    eprintln!("flood poisoned after {n} duplicates");

    // A repeat with different bytes is a hash fault, never an ignored duplicate.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    s.session.push(&bundle.frames[0]).unwrap();
    s.session.push(&bundle.frames[1]).unwrap();
    let mut bad = bundle.frames[1].clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(s.session.push(&bad).is_err());
    assert_eq!(s.session.stream_state(), StreamState::Receiving);
    // Faults interleaved with many duplicates still add up to a poison.
    let mut faults = 1;
    while s.session.state() == SessionState::Receiving {
        for _ in 0..20 {
            let _ = s.session.push(&bundle.frames[1]);
        }
        let _ = s.session.push(&bad);
        faults += 1;
        assert!(faults < 20);
    }
    assert_eq!(s.session.poison().unwrap().info.reason, StreamError::ChunkHashMismatch);

    // A duplicate descriptor with other bytes is a fault; identical is ignored.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    s.session.push(&bundle.frames[0]).unwrap();
    assert_eq!(
        s.session.push(&bundle.frames[0]),
        Ok(SessionEvent::DuplicateDescriptor)
    );
    let mut other = bundle.frames[0].clone();
    let l = other.len();
    other[l - 1] ^= 1;
    assert!(s.session.push(&other).is_err());
}

/// RV2-04 DEFECT (Low): the pre-descriptor poison produced by the byte reader
/// is not witnessed (binding_of needs a descriptor).
#[test]
fn r2_feed_witnessed_does_not_record_a_preauth_reader_poison() {
    let b = signer(0x5A, 1, Order::File);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);
    let mut s = stream(&keys, bundle, base_policy());
    let log = WitnessLog::<64>::new();
    let r = s.session.feed_witnessed(&[0x7F, 0, 0, 0, 0], &log, WitnessContext::new(1, 1), |_| {});
    assert!(r.is_err());
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert_eq!(log.total_emitted(), 0, "poisoned, zero witness records");
}

/// RV2-05 DEFECT (Low): `PoisonObligation::discharge` removes only the root
/// slots. A capability derived from an installed root (parent_index link)
/// survives; and `for_session` lets any holder of a (sequential, public)
/// session id terminate another session's instances.
#[test]
fn r2_discharge_leaves_derived_children_and_for_session_is_forgeable() {
    use rvm_types::{CapRights, CapToken, CapType, PartitionId};
    let mut table = rvm_cap::CapabilityTable::<8>::new();
    let tok = CapToken::new(1, CapType::Region, CapRights::READ, 0);
    let (ri, rg) = table.insert_root(tok, PartitionId::new(1), 0).unwrap();
    let (ci, cg) = table
        .insert_derived(tok, PartitionId::new(2), 1, ri, 0)
        .unwrap();

    // A live instance of another session.
    let b = signer(0x5A, 1, Order::File);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);
    let mut other = stream(&keys, bundle, base_policy());
    run_all(&mut other).unwrap();
    let log = WitnessLog::<512>::new();
    let mut agents = AgentManager::<4>::new();
    let mut inst = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        other.session.package().unwrap().clone(),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();
    inst.start_verified(other.session.take_module(2).unwrap(), &mut agents, &log, 2)
        .unwrap();

    let forged = PoisonObligation::for_session(other.session.session_id(), vec![(ri, rg)]);
    let d = forged
        .discharge(&mut table, std::slice::from_mut(&mut inst), &mut agents, &log, 3)
        .unwrap();
    assert_eq!((d.revoked, d.terminated), (1, 1));
    assert_eq!(inst.state(), InstanceState::Terminated);
    assert!(table.lookup(ri, rg).is_err());
    assert!(table.lookup(ci, cg).is_ok(), "derived child outlives its revoked root");
}

/// Sound: a completed session cannot be poisoned from outside, so a started
/// instance never has an obligation; the trait method is a no-op there.
#[test]
fn r2_completed_session_cannot_be_poisoned_externally() {
    let b = signer(0x5A, 1, Order::File);
    let keys = [b.public_key()];
    let (bundle, _) = bundle_for(&b);
    let mut s = stream(&keys, bundle, base_policy());
    run_all(&mut s).unwrap();
    let _ = FrameTarget::poison(&mut s.session, StreamError::FrameSizeLie);
    assert_eq!(s.session.state(), SessionState::Complete);
    assert!(s.session.take_obligation().is_none());
    assert!(s.session.take_module(2).is_ok());
}

/// Re-attack RV-04/05: refusal after complete, counted faults and a failed
/// finish_identity all leave failing witness records now.
#[test]
fn r1_refusals_and_faults_are_witnessed() {
    use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
    let fails = |log: &WitnessLog<512>| {
        (0..log.len()).filter(|&i| log.get(i).unwrap().aux[5] == 1).count()
    };
    let ctx = WitnessContext::new(1, 1);

    // unsigned executable -> PackageRefused with failing records
    let module = wasm_common::synthetic_module(3_000);
    let mut body = unsigned_segment(0x07, b"rvf.capabilities=clock", 1);
    body.extend(unsigned_segment_with(0x10, &module, 2, 2));
    body.extend(unsigned_segment(0x05, b"root", 3));
    let b = signer(0x5A, 1, Order::File);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    let log = WitnessLog::<512>::new();
    let mut last = Ok(SessionEvent::Descriptor);
    for f in &s.bundle.frames.clone() {
        last = s.session.push_witnessed(f, &log, ctx);
        if last.is_err() {
            break;
        }
    }
    assert_eq!(last, Err(SessionError::PackageRefused));
    assert!(fails(&log) > 0);

    // counted fault
    let (bundle, body) = bundle_for(&b);
    let mut s = stream(&keys, bundle.clone(), base_policy());
    let log = WitnessLog::<512>::new();
    s.session.push_witnessed(&bundle.frames[0], &log, ctx).unwrap();
    s.session.push_witnessed(&bundle.frames[1], &log, ctx).unwrap();
    let before = fails(&log);
    let mut bad = bundle.frames[1].clone();
    *bad.last_mut().unwrap() ^= 1;
    let _ = s.session.push_witnessed(&bad, &log, ctx);
    assert!(fails(&log) > before);

    // failed finish_identity
    let mut st = signer(0x5A, 1, Order::Stage);
    st.identity_override = Some([9; 32]);
    let (bundle, body2) = bundle_for(&st);
    let mut s = stream(&keys, bundle, base_policy());
    run_all(&mut s).unwrap();
    let log = WitnessLog::<512>::new();
    let r = s.session.finish_identity_witnessed(
        |o, buf| {
            buf.copy_from_slice(&body2[o as usize..o as usize + buf.len()]);
            true
        },
        &log,
        ctx,
    );
    assert!(r.is_err());
    assert!(fails(&log) > 0);
    let _ = body;
}
