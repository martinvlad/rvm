//! Adversarial-review repros (branch feat/ofer-review-rvm). Each test is
//! marked with its finding id from review-rvm-report.md. A test that PASSES
//! demonstrates the defect (it asserts the undesirable behaviour).

mod stream_common;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_cap::{CapManagerConfig, CapabilityManager};
use rvm_host::WasmAdapter;
use rvm_launch::{Instance, InstanceId, InstanceState, SessionError, SessionState};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::{StreamPolicy, StreamState};
use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
use rvm_rvf::{WitnessContext, CAPABILITY_DECLARATION_KEY};
use rvm_types::{CapRights, CapType, PartitionId};
use rvm_wasm::agent::AgentManager;
use rvm_witness::WitnessLog;
use stream_common::*;

fn all_rights() -> CapRights {
    CapRights::READ | CapRights::WRITE | CapRights::GRANT | CapRights::REVOKE
}

/// RV-01: one unauthenticated byte poisons a session before any descriptor is
/// accepted; the documented consumer effect is a GLOBAL capability epoch bump
/// that invalidates an unrelated partition's capability.
#[test]
fn rv01_unauthenticated_frame_poisons_and_global_epoch_bump_revokes_bystander() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let module = wasm_common::synthetic_module(1_000);
    let mut s = stream(&keys, b.build(&package_body(&module, "clock", 2)).unwrap(), base_policy());

    // The attacker has no key and no knowledge of the package: junk frame.
    let err = s.session.push(&[0x7F, 1, 2, 3]).unwrap_err();
    assert!(matches!(err, SessionError::Stream(_)));
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert_eq!(s.session.poison().unwrap().descriptor_hash, [0u8; 32]);

    let mut caps = CapabilityManager::<8>::new(CapManagerConfig::default());
    let (idx, generation) = caps
        .create_root_capability(CapType::Region, all_rights(), 0, PartitionId::new(7))
        .unwrap();
    assert!(caps.verify_p1(idx, generation, CapRights::READ).is_ok());
    assert!(s.session.revoke_capabilities(&mut caps));
    // The bystander's handle is now stale although it has nothing to do with
    // this stream.
    assert!(caps.verify_p1(idx, generation, CapRights::READ).is_err());
}

/// RV-02: an on-path attacker that forges nothing and only DUPLICATES five
/// authentic frames poisons the stream (fault budget 4) - and the poison
/// effects fan out to every instance that shares the descriptor hash, i.e.
/// another tenant running the same package.
#[test]
fn rv02_replaying_authentic_frames_poisons_and_terminates_other_tenants() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let module = wasm_common::synthetic_module(1_000);
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();

    // Tenant B: a clean stream of the same package, instance Running.
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
    assert_eq!(inst_b.state(), InstanceState::Running);

    // Tenant A's link: descriptor, then the first chunk replayed 6 times.
    let mut ta = stream(&keys, bundle.clone(), base_policy());
    ta.session.push(&bundle.frames[0]).unwrap();
    ta.session.push(&bundle.frames[1]).unwrap();
    let mut outcomes = 0;
    for _ in 0..6 {
        if ta.session.push(&bundle.frames[1]).is_err() {
            outcomes += 1;
        }
        if ta.session.state() == SessionState::Poisoned {
            break;
        }
    }
    assert!(outcomes >= 5);
    assert_eq!(ta.session.state(), SessionState::Poisoned);

    // Tenant B's instance, which never saw the attack, is terminated.
    let n = ta
        .session
        .terminate_instances(std::slice::from_mut(&mut inst_b), &mut agents, &log, 3)
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(inst_b.state(), InstanceState::Terminated);
}

/// RV-03: stage-ordered delivery + a descriptor that lies about rvf_identity:
/// the session reaches Complete, hands out a VerifiedModule and the instance
/// reaches Running without finish_identity ever being called; the session has
/// no accessor that tells the caller the identity is unverified; and a
/// pinned `expected_identity` passes on the CLAIMED value.
#[test]
fn rv03_unverifiable_identity_still_yields_startable_module_and_passes_identity_pin() {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let lie = [0x99u8; 32];
    let mut b = builder(12, Order::Stage);
    b.identity_override = Some(lie);
    let keys = [b.public_key()];
    let bundle = b.build(&body).unwrap();

    let mut policy = StreamPolicy::new(&keys);
    policy.size = rvm_rvf::SizePolicy::permissive();
    policy.size.max_segments = 4096;
    let opts = opts().expect_identity(lie); // the host pins the identity it expects
    let mut session = rvm_launch::StreamSession::new(policy, opts, base_policy());
    for f in &bundle.frames {
        session.push(f).unwrap();
    }
    assert_eq!(session.state(), SessionState::Complete);
    assert_eq!(session.stream_state(), StreamState::Complete);
    let report = session.report().unwrap();
    assert!(report.ok, "pinned identity passes on the claimed value");
    assert_ne!(report.rvf_identity, rvm_rvf::sha256(&body), "claim != body hash");

    let log = WitnessLog::<512>::new();
    let mut agents = AgentManager::<4>::new();
    let mut inst = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        session.package().unwrap().clone(),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();
    let vm = session.take_module(2).unwrap();
    inst.start_verified(vm, &mut agents, &log, 2).unwrap();
    assert_eq!(inst.state(), InstanceState::Running);
    // finish_identity was never required; had it been called it would poison.
}

/// RV-04: a stream that completes but whose package is refused by ADR-155
/// admission (unsigned executable) writes SegmentVerified + StreamComplete
/// (pass) witness records and NO failing record at all.
#[test]
fn rv04_package_refused_after_complete_emits_no_failure_witness() {
    let module = wasm_common::synthetic_module(3_000);
    let mut body = unsigned_segment(
        0x07,
        format!("{CAPABILITY_DECLARATION_KEY}=clock").as_bytes(),
        1,
    );
    body.extend(unsigned_segment_with(0x10, &module, 2, 2));
    body.extend(unsigned_segment(0x05, b"root", 3));
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    let log = WitnessLog::<512>::new();
    let ctx = WitnessContext::new(1, 1);
    let mut last = Ok(rvm_launch::SessionEvent::Descriptor);
    for f in &s.bundle.frames.clone() {
        last = s.session.push_witnessed(f, &log, ctx);
        if last.is_err() {
            break;
        }
    }
    assert_eq!(last, Err(SessionError::PackageRefused));
    assert_eq!(s.session.state(), SessionState::Failed);
    let (mut pass, mut fail) = (0, 0);
    for i in 0..log.len() {
        let r = log.get(i).unwrap();
        // aux[5] = outcome (0 pass, 1 fail, 2 skip)
        match r.aux[5] {
            0 => pass += 1,
            1 => fail += 1,
            _ => {}
        }
    }
    assert!(pass > 0);
    assert_eq!(fail, 0, "no record says the package was refused");
}

/// RV-05: counted faults (a corrupted chunk, a replayed chunk) are refused but
/// leave no witness record unless they end up poisoning the stream; and
/// `finish_identity` has no witnessed variant at all.
#[test]
fn rv05_counted_faults_are_not_witnessed() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let module = wasm_common::synthetic_module(1_000);
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
    let mut s = stream(&keys, bundle.clone(), base_policy());
    let log = WitnessLog::<512>::new();
    let ctx = WitnessContext::new(1, 1);
    s.session.push_witnessed(&bundle.frames[0], &log, ctx).unwrap();
    let before = log.total_emitted();
    // a bit-flipped copy of the first chunk
    let mut bad = bundle.frames[1].clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    for _ in 0..3 {
        assert!(s.session.push_witnessed(&bad, &log, ctx).is_err());
    }
    assert_eq!(s.session.state(), SessionState::Receiving);
    assert_eq!(log.total_emitted(), before, "3 hash-mismatch refusals, 0 records");
}
