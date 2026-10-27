//! P8 (poison), P9 (downgrade) and the weak-checksum rule, end to end.

mod stream_common;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_host::{Placement, WasmAdapter};
use rvm_launch::{verify, Instance, InstanceId, InstanceState, SessionError, SessionState};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::StreamState;
use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
use rvm_rvf::{CheckKind, WitnessContext, CAPABILITY_DECLARATION_KEY};
use rvm_types::PartitionId;
use rvm_wasm::agent::AgentManager;
use rvm_witness::WitnessLog;
use stream_common::*;

#[test]
fn a_package_that_fails_admission_yields_no_module() {
    // Unsigned executable: authentic bytes, but ADR-155 refuses the package.
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
    assert_eq!(run_all(&mut s), Err(SessionError::PackageRefused));
    assert_eq!(s.session.state(), SessionState::Failed);
    assert!(s.session.take_module(2).is_err());
    assert!(s.session.package().is_none());
    // The report is still there to explain why.
    assert!(!s.session.report().unwrap().ok);
}

#[test]
fn a_weak_checksum_executable_is_poisoned_on_the_stream_path_only() {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 1); // XXH3: not authenticity
                                                  // The buffered loader keeps accepting it (legacy behaviour)...
    let log = WitnessLog::<64>::new();
    let report = verify(&body, &opts(), &log, WitnessContext::new(1, 1)).unwrap();
    assert!(report.ok, "{:?}", report.failures());
    // ...the stream path refuses it, at the executable's first chunk.
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    let err = run_all(&mut s).unwrap_err();
    assert!(
        matches!(
            err,
            SessionError::Stream(rvm_rvf::stream::AdmissionError::Stream(
                rvm_rvf::stream::StreamError::WeakChecksum
            ))
        ),
        "{err}"
    );
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert_eq!(s.session.poison().unwrap().info.seg_id, Some(2));
}

#[test]
fn a_stream_profiled_package_is_refused_by_the_buffered_loader() {
    let module = wasm_common::synthetic_module(3_000);
    let mut body = package_body(&module, "clock", 2);
    body.extend(unsigned_segment(
        0x07,
        format!("{}=required", rvm_rvf::STREAM_PROFILE_DECLARATION_KEY).as_bytes(),
        9,
    ));
    let log = WitnessLog::<128>::new();
    let report = verify(&body, &opts(), &log, WitnessContext::new(1, 1)).unwrap();
    assert!(!report.ok);
    assert!(report.first_failure(CheckKind::StreamProfile).is_some());
    assert!(rvm_host::VerifiedPackage::from_report(&report).is_err());
    // The refusal is in the witness chain.
    assert!(log.total_emitted() as usize >= report.records.len());

    let mut permitted = opts();
    permitted.permit_buffered_stream_profile = true;
    // The permission alone is not enough: an unpinned buffer is unauthenticated.
    let report = verify(&body, &permitted, &log, WitnessContext::new(1, 2)).unwrap();
    assert!(report.first_failure(CheckKind::StreamProfile).is_some());
    let permitted = permitted.expect_identity(rvm_rvf::sha256(&body));
    let report = verify(&body, &permitted, &log, WitnessContext::new(1, 3)).unwrap();
    assert!(report.ok, "{:?}", report.failures());

    // Streamed, it needs no permission.
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    run_all(&mut s).unwrap();
    assert!(s.session.take_module(2).is_ok());
}

#[test]
fn a_lying_identity_in_stage_order_is_refused_until_confirmed_and_poisons_on_mismatch() {
    // Stage-ordered delivery completes with an `Unverifiable` identity; the
    // descriptor's identity is a lie.
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let mut b = builder(12, Order::Stage);
    b.identity_override = Some([0x99; 32]);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    run_all(&mut s).unwrap();
    assert_eq!(s.session.state(), SessionState::Complete);
    assert_eq!(s.session.stream_state(), StreamState::CompleteUnverified);
    assert_eq!(
        s.session.identity_status(),
        Some(rvm_rvf::stream::IdentityStatus::Unverifiable)
    );
    // Nothing is derived from the claimed identity.
    assert_eq!(
        s.session.take_module(2).err(),
        Some(SessionError::IdentityUnverified)
    );
    assert!(s.session.package().is_none());
    let mut table = rvm_cap::CapabilityTable::<8>::new();
    assert_eq!(
        s.session
            .install_capabilities(&mut table, PartitionId::new(1), 0, 1)
            .err(),
        Some(SessionError::IdentityUnverified)
    );
    assert!(table.is_empty());

    let r = s.session.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    });
    assert!(r.is_err());
    assert_eq!(s.session.state(), SessionState::Poisoned);
    let p = s.session.poison().unwrap();
    assert_eq!(p.descriptor_hash, Some(s.bundle.descriptor_hash));
    assert!(s.session.take_module(2).is_err());
    assert!(s.session.package().is_none());
    assert!(s.session.report().is_none());
    // An authenticated poison leaves exactly one obligation.
    let ob = s.session.take_obligation().expect("obligation");
    assert_eq!(ob.session_id(), s.session.session_id());
    assert!(s.session.take_obligation().is_none());
}

#[test]
fn confirming_the_identity_unlocks_the_module_and_the_package() {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let b = builder(12, Order::Stage);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    run_all(&mut s).unwrap();
    assert!(s.session.package().is_none());
    confirm(&mut s, &body);
    assert_eq!(s.session.stream_state(), StreamState::Complete);
    assert_eq!(
        s.session.identity_status(),
        Some(rvm_rvf::stream::IdentityStatus::Verified)
    );
    assert!(s.session.package().is_some());
    assert!(s.session.take_module(2).is_ok());
}

#[test]
fn a_poison_obligation_touches_only_its_own_sessions_capabilities_and_instances() {
    // Two tenants stream the same package (same descriptor hash).
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&body).unwrap();
    let mut a = stream(&keys, bundle.clone(), base_policy());
    let mut tenant_b = stream(&keys, bundle, base_policy());
    run_all(&mut a).unwrap();
    run_all(&mut tenant_b).unwrap();
    assert_ne!(a.session.session_id(), tenant_b.session.session_id());

    let log = WitnessLog::<512>::new();
    let mut table = rvm_cap::CapabilityTable::<16>::new();
    let n_a = a
        .session
        .install_capabilities(&mut table, PartitionId::new(1), 0, 100)
        .unwrap();
    let n_b = tenant_b
        .session
        .install_capabilities(&mut table, PartitionId::new(2), 0, 200)
        .unwrap();
    assert!(n_a > 0 && n_b > 0);
    let before = table.len();
    let owned_by = |t: &rvm_cap::CapabilityTable<16>, p: u32| {
        t.iter()
            .filter(|(_, slot)| slot.owner == PartitionId::new(p))
            .count()
    };

    let mut agents_a = AgentManager::<4>::new();
    let mut agents_b = AgentManager::<4>::new();
    let mut inst_a = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        a.session.package().unwrap().clone(),
        Placement::new(PartitionId::new(1), 0, 16),
        &log,
        1,
    )
    .unwrap();
    let mut inst_b = Instance::create(
        InstanceId::new(2),
        WasmAdapter::new(),
        tenant_b.session.package().unwrap().clone(),
        Placement::new(PartitionId::new(2), 0, 16),
        &log,
        1,
    )
    .unwrap();
    inst_a
        .start_verified(a.session.take_module(2).unwrap(), &mut agents_a, &log, 2)
        .unwrap();
    inst_b
        .start_verified(
            tenant_b.session.take_module(2).unwrap(),
            &mut agents_b,
            &log,
            2,
        )
        .unwrap();

    // A host that tracked session A's installs (here: the handles it got back
    // from the table) owes exactly those and A's instances.
    let handles_a: Vec<(u32, u32)> = table
        .iter()
        .filter(|(_, slot)| slot.owner == PartitionId::new(1))
        .map(|(i, slot)| (i, slot.generation))
        .collect();
    let ob = rvm_launch::PoisonObligation::for_session(a.session.session_id(), handles_a);
    let mut instances = [inst_a, inst_b];
    // Instances of both tenants are offered; only A's is terminated. (Agents
    // are keyed by package identity, so each tenant has its own manager; the
    // obligation only ever calls the one it is given, for A's instance.)
    let d = ob
        .discharge(&mut table, &mut instances, &mut agents_a, &log, 3)
        .unwrap();
    assert_eq!(d.revoked, n_a);
    assert_eq!(d.terminated, 1);
    assert_eq!(instances[0].state(), InstanceState::Terminated);
    assert_eq!(instances[1].state(), InstanceState::Running);
    assert_eq!(table.len(), before - n_a);
    assert_eq!(owned_by(&table, 1), 0);
    assert_eq!(owned_by(&table, 2), n_b, "tenant B keeps every capability");
}
