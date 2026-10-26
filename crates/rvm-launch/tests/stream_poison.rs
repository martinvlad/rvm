//! P8 (poison), P9 (downgrade) and the weak-checksum rule, end to end.

mod stream_common;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_cap::{CapManagerConfig, CapabilityManager};
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
    let report = verify(&body, &permitted, &log, WitnessContext::new(1, 2)).unwrap();
    assert!(report.ok, "{:?}", report.failures());

    // Streamed, it needs no permission.
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    run_all(&mut s).unwrap();
    assert!(s.session.take_module(2).is_ok());
}

#[test]
fn a_poisoned_stream_revokes_terminates_and_drops() {
    // Stage-ordered delivery completes with an `Unverifiable` identity; the
    // persisted body is then re-read, and the descriptor's identity is a lie.
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let mut b = builder(12, Order::Stage);
    b.identity_override = Some([0x99; 32]);
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build(&body).unwrap(), base_policy());
    run_all(&mut s).unwrap();
    assert_eq!(s.session.state(), SessionState::Complete);
    assert_eq!(
        s.session.stream_state(),
        StreamState::Complete,
        "stage order cannot check the identity while streaming"
    );

    let log = WitnessLog::<512>::new();
    let mut agents = AgentManager::<4>::new();
    let mut insts: Vec<_> = (1..=2u32)
        .map(|id| {
            Instance::create(
                InstanceId::new(u64::from(id)),
                WasmAdapter::new(),
                s.session.package().unwrap().clone(),
                Placement::new(PartitionId::new(id), 0, 16),
                &log,
                1,
            )
            .unwrap()
        })
        .collect();
    // One instance from the stream; the other is unrelated and must survive.
    let vm = s.session.take_module(2).unwrap();
    insts[0].start_verified(vm, &mut agents, &log, 2).unwrap();
    // (Agents are keyed by package identity, so the bystander gets its own manager.)
    let mut other_agents = AgentManager::<4>::new();
    insts[1].start(&module, &mut other_agents, &log, 2).unwrap();

    let mut caps = CapabilityManager::<8>::new(CapManagerConfig::default());
    assert!(
        !s.session.revoke_capabilities(&mut caps),
        "not poisoned yet"
    );
    let epoch = caps.epoch();

    let r = s.session.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    });
    assert!(r.is_err());
    assert_eq!(s.session.state(), SessionState::Poisoned);
    let p = s.session.poison().unwrap();
    assert_eq!(p.descriptor_hash, s.bundle.descriptor_hash);

    // Effect 1: capabilities revoked (epoch bumped).
    assert!(s.session.revoke_capabilities(&mut caps));
    assert_eq!(caps.epoch(), epoch.wrapping_add(1));
    // Effect 2: instances started from this stream are terminated, others not.
    let n = s
        .session
        .terminate_instances(&mut insts, &mut agents, &log, 3)
        .unwrap();
    assert_eq!(n, 1);
    assert_eq!(insts[0].state(), InstanceState::Terminated);
    assert_eq!(insts[1].state(), InstanceState::Running);
    // Effect 3: derived state is gone.
    assert!(s.session.package().is_none());
    assert!(s.session.take_module(2).is_err());
    assert!(s.session.report().is_none());
}

#[test]
fn file_order_catches_a_lying_identity_before_the_last_chunk_is_released() {
    let module = wasm_common::synthetic_module(3_000);
    let mut b = builder(12, Order::File);
    b.identity_override = Some([0x99; 32]);
    let keys = [b.public_key()];
    let mut s = stream(
        &keys,
        b.build(&package_body(&module, "clock", 2)).unwrap(),
        base_policy(),
    );
    let err = run_all(&mut s).unwrap_err();
    assert!(
        matches!(
            err,
            SessionError::Stream(rvm_rvf::stream::AdmissionError::Stream(
                rvm_rvf::stream::StreamError::IdentityMismatch
            ))
        ),
        "{err}"
    );
    assert_eq!(s.session.state(), SessionState::Poisoned);
    assert!(s.session.take_module(2).is_err());
}
