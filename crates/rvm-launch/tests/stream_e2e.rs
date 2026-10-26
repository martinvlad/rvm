//! P8, P9 and P11 end to end: a real WASM module streamed in chunks through
//! authentication, admission and incremental validation into
//! `Instance::start_verified`.
//!
//! RVM has no execution engine, so "start" here means admission and slot
//! activation: the instance reaches `Running` and holds the module bytes; no
//! instruction is interpreted.

#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_host::WasmAdapter;
use rvm_launch::{
    Instance, InstanceId, InstanceState, LaunchError, SessionError, SessionEvent, SessionState,
    StreamSession,
};
use rvm_rvf::stream::builder::{Order, StreamBundle};
use rvm_rvf::stream::StreamPolicy;
use rvm_rvf::{CheckKind, WitnessContext};
use rvm_wasm::agent::AgentManager;
use rvm_wasm::{ModulePolicy, StreamingModuleValidator};
use rvm_witness::WitnessLog;
mod stream_common;
use stream_common::*;
use wasm_common::corpus::{bad_modules, policy_cases, valid_modules};

#[test]
fn every_valid_module_streams_validates_and_starts_under_every_profile() {
    let mut modules = valid_modules();
    modules.push(("synthetic_200k", wasm_common::synthetic_module(200_000)));
    for (name, module) in modules {
        for (chunk_log2, order) in [(0xFF, Order::File), (12, Order::File), (12, Order::Stage)] {
            let b = builder(chunk_log2, order);
            let keys = [b.public_key()];
            let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
            let mut s = stream(&keys, bundle, base_policy());
            run_all(&mut s).unwrap_or_else(|e| panic!("{name}: {e}"));
            let ctx = format!("{name} {chunk_log2:#x} {order:?}");
            assert_eq!(s.session.state(), SessionState::Complete, "{ctx}");
            let vm = s
                .session
                .take_module(2)
                .unwrap_or_else(|e| panic!("{ctx}: {e}"));
            assert_eq!(vm.as_bytes(), module.as_slice(), "{ctx}");
            assert_eq!(vm.validated().byte_len(), module.len() as u64);

            let log = WitnessLog::<512>::new();
            let mut agents = AgentManager::<4>::new();
            let package = s.session.package().unwrap().clone();
            let mut inst = Instance::create(
                InstanceId::new(1),
                WasmAdapter::new(),
                package,
                PLACEMENT,
                &log,
                1,
            )
            .unwrap();
            assert_eq!(inst.state(), InstanceState::Created);
            assert!(inst.module_bytes().is_none(), "nothing before start");
            inst.start_verified(vm, &mut agents, &log, 2)
                .unwrap_or_else(|e| panic!("{ctx}: {e}"));
            assert_eq!(inst.state(), InstanceState::Running, "{ctx}");
            assert_eq!(inst.module_bytes(), Some(module.as_slice()), "{ctx}");
            assert_eq!(inst.stream_origin(), Some(&s.bundle.descriptor_hash));
        }
    }
}

#[test]
fn a_module_split_across_chunks_really_spans_several() {
    let module = wasm_common::synthetic_module(20_000);
    let b = builder(12, Order::File);
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
    let wasm_chunks = bundle
        .frames
        .iter()
        .filter(|f| f[0] == 1 && f[1..9] == 2u64.to_le_bytes())
        .count();
    assert!(wasm_chunks >= 5, "{wasm_chunks}");
}

#[test]
fn every_malformed_module_is_rejected_and_never_starts() {
    let mut corpus: Vec<(String, Vec<u8>, ModulePolicy)> = bad_modules()
        .into_iter()
        .map(|(n, m)| (n.to_string(), m, base_policy()))
        .collect();
    for (n, m, p, _) in policy_cases() {
        corpus.push((n.to_string(), m, p));
    }
    let mut refused = 0;
    for (name, module, policy) in corpus {
        // The reference verdict: the validator on the whole module at once.
        let want_ok = {
            let mut v = StreamingModuleValidator::new(policy.clone());
            v.push(&module).and_then(|_| v.finish()).is_ok()
        };
        for chunk_log2 in [0xFF, 12] {
            let b = builder(chunk_log2, Order::File);
            let keys = [b.public_key()];
            let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
            let mut sp = StreamPolicy::new(&keys);
            sp.size = rvm_rvf::SizePolicy::permissive();
            sp.size.max_segments = 4096;
            let mut session = StreamSession::with_module_policy(sp, opts(), policy.clone());
            let mut outcome = Ok(());
            for f in &bundle.frames {
                if let Err(e) = session.push(f) {
                    outcome = Err(e);
                    break;
                }
            }
            if want_ok {
                outcome.unwrap_or_else(|e| panic!("{name}: valid module refused: {e}"));
                assert!(session.take_module(2).is_ok(), "{name}");
            } else {
                refused += 1;
                let err = outcome.expect_err(&name);
                assert!(
                    matches!(err, SessionError::Module { seg_id: 2, .. }),
                    "{name}: {err}"
                );
                assert_eq!(session.state(), SessionState::Failed, "{name}");
                assert!(session.take_module(2).is_err(), "{name}: module available");
                assert!(session.package().is_none(), "{name}: package available");
            }
        }
    }
    assert!(refused >= 30, "corpus too small: {refused}");
}

#[test]
fn a_module_is_unreachable_until_the_stream_is_complete() {
    let module = wasm_common::synthetic_module(10_000);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
    let mut s = stream(&keys, bundle, base_policy());
    assert_eq!(
        s.session.take_module(2).err(),
        Some(SessionError::NotComplete)
    );
    let frames = s.bundle.frames.clone();
    for (i, f) in frames.iter().enumerate() {
        let ev = s.session.push(f).unwrap();
        if i + 1 < frames.len() {
            // Even once the module's own segment is verified, nothing is
            // handed out before the whole package is admitted.
            assert_eq!(
                s.session.take_module(2).err(),
                Some(SessionError::NotComplete)
            );
            assert!(s.session.package().is_none());
        } else {
            assert_eq!(ev, SessionEvent::Complete);
        }
    }
    assert!(s.session.take_module(2).is_ok());
    // And it is handed out once.
    assert_eq!(
        s.session.take_module(2).err(),
        Some(SessionError::NoSuchModule)
    );
}

#[test]
fn mutating_the_transport_buffer_never_changes_what_the_instance_holds() {
    let module = wasm_common::synthetic_module(30_000);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
    let mut s = stream(
        &keys,
        StreamBundle {
            frames: vec![],
            ..bundle.clone()
        },
        base_policy(),
    );
    // The transport owns one reusable buffer and scribbles over it as soon as
    // each push returns, as a hostile or merely buggy transport could.
    let mut buf = Vec::new();
    for f in &bundle.frames {
        buf.clear();
        buf.extend_from_slice(f);
        s.session.push(&buf).unwrap();
        buf.iter_mut().for_each(|b| *b = 0xEE);
    }
    let vm = s.session.take_module(2).unwrap();
    assert_eq!(vm.as_bytes(), module.as_slice());

    let log = WitnessLog::<512>::new();
    let mut agents = AgentManager::<4>::new();
    let mut inst = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        s.session.package().unwrap().clone(),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();
    inst.start_verified(vm, &mut agents, &log, 2).unwrap();
    // Scribble again after hand-off.
    buf.iter_mut().for_each(|b| *b = 0x77);
    assert_eq!(inst.module_bytes(), Some(module.as_slice()));
}

#[test]
fn a_module_from_another_package_is_refused_and_witnessed() {
    let mod_a = wasm_common::synthetic_module(3_000);
    let mod_b = wasm_common::synthetic_module(3_100);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let mut a = stream(
        &keys,
        b.build(&package_body(&mod_a, "clock", 2)).unwrap(),
        base_policy(),
    );
    let mut other = stream(
        &keys,
        b.build(&package_body(&mod_b, "clock", 2)).unwrap(),
        base_policy(),
    );
    run_all(&mut a).unwrap();
    run_all(&mut other).unwrap();
    let vm_a = a.session.take_module(2).unwrap();

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
    assert_eq!(
        inst.start_verified(vm_a, &mut agents, &log, 2),
        Err(LaunchError::ExecutableMismatch)
    );
    assert_eq!(inst.state(), InstanceState::Created);
    assert!(inst.module_bytes().is_none());
    let rejected = (0..log.len())
        .filter_map(|i| log.get(i))
        .filter(|r| rvm_launch::event_of(r) == Some(rvm_launch::LaunchEvent::ExecutableRejected))
        .count();
    assert_eq!(rejected, 1);
}

#[test]
fn module_validation_is_witnessed_pass_and_fail() {
    let ctx = WitnessContext::new(1, 5);
    for (module, ok) in [
        (wasm_common::synthetic_module(2_000), true),
        (vec![0u8, 0x61, 0x73, 0x6d, 2, 0, 0, 0], false),
    ] {
        let b = builder(12, Order::File);
        let keys = [b.public_key()];
        let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
        let mut policy = StreamPolicy::new(&keys);
        policy.size = rvm_rvf::SizePolicy::permissive();
        policy.size.max_segments = 4096;
        let mut session = StreamSession::new(policy, opts(), base_policy());
        let log = WitnessLog::<256>::new();
        for f in &bundle.frames {
            if session.push_witnessed(f, &log, ctx).is_err() {
                break;
            }
        }
        let records: Vec<_> = (0..log.len()).filter_map(|i| log.get(i)).collect();
        let module_records: Vec<_> = records
            .iter()
            .filter(|r| r.flags == CheckKind::StreamModule as u8)
            .collect();
        assert_eq!(module_records.len(), 1, "ok={ok}");
        assert_eq!(module_records[0].target_object_id, 2);
        let want = if ok {
            rvm_types::ActionKind::ProofVerifiedP2
        } else {
            rvm_types::ActionKind::ProofRejected
        };
        assert_eq!(module_records[0].action_kind, want as u8);
        assert_eq!(session.state() == SessionState::Complete, ok);
        assert!(rvm_witness::verify_chain(&records).is_ok());
    }
}
