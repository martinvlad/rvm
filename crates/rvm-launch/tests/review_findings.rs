//! Adversarial-review findings RV-01..RV-07, inverted: each test now asserts
//! the fixed behaviour (the review's originals asserted the defect).

mod stream_common;
#[path = "../../rvm-wasm/tests/common/mod.rs"]
mod wasm_common;

use rvm_host::WasmAdapter;
use rvm_launch::{
    Instance, InstanceId, InstanceState, SessionError, SessionEvent, SessionState, StreamSession,
};
use rvm_rvf::stream::builder::Order;
use rvm_rvf::stream::{MemoryPinStore, ReplayProtection, StreamError, StreamPolicy, StreamState};
use rvm_rvf::testkit::{unsigned_segment, unsigned_segment_with};
use rvm_rvf::{CheckKind, WitnessContext, CAPABILITY_DECLARATION_KEY};
use rvm_wasm::agent::AgentManager;
use rvm_witness::WitnessLog;
use stream_common::*;

const CTX: WitnessContext = WitnessContext::new(1, 1);

fn records(log: &WitnessLog<512>) -> Vec<rvm_types::WitnessRecord> {
    (0..log.len()).filter_map(|i| log.get(i)).collect()
}

/// RV-01: a junk frame kills its own session and nothing else. There is no
/// global epoch bump to offer, and a poison before any descriptor was
/// authenticated issues no obligation at all.
#[test]
fn rv01_unauthenticated_frame_poisons_only_its_own_session_and_issues_no_obligation() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let module = wasm_common::synthetic_module(1_000);
    let mut s = stream(
        &keys,
        b.build(&package_body(&module, "clock", 2)).unwrap(),
        base_policy(),
    );

    let err = s.session.push(&[0x7F, 1, 2, 3]).unwrap_err();
    assert!(matches!(err, SessionError::Stream(_)));
    assert_eq!(s.session.state(), SessionState::Poisoned);
    let report = s.session.poison().unwrap();
    assert_eq!(report.descriptor_hash, None);
    assert!(!report.authenticated());
    assert!(
        s.session.take_obligation().is_none(),
        "nothing was granted or started, so nothing is owed"
    );
}

/// RV-02: replaying authentic frames does not poison the stream, and a poison
/// that does happen reaches only its own session's capabilities and instances.
#[test]
fn rv02_replayed_authentic_frames_are_ignored_and_never_poison() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let module = wasm_common::synthetic_module(1_000);
    let body = package_body(&module, "clock", 2);
    let bundle = b.build(&body).unwrap();

    let mut a = stream(&keys, bundle.clone(), base_policy());
    a.session.push(&bundle.frames[0]).unwrap();
    a.session.push(&bundle.frames[1]).unwrap();
    for _ in 0..20 {
        assert_eq!(
            a.session.push(&bundle.frames[1]),
            Ok(SessionEvent::Duplicate { seg_id: 1 })
        );
        assert_eq!(
            a.session.push(&bundle.frames[0]),
            Ok(SessionEvent::DuplicateDescriptor)
        );
    }
    assert_eq!(a.session.state(), SessionState::Receiving);
    for f in &bundle.frames[2..] {
        a.session.push(f).unwrap();
    }
    assert_eq!(a.session.state(), SessionState::Complete);
    assert!(a.session.take_module(2).is_ok());
}

/// RV-02 (flood): a storm beyond the cap does poison, bounded and typed.
#[test]
fn rv02_a_duplicate_flood_poisons_with_its_own_reason() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let module = wasm_common::synthetic_module(1_000);
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
    let mut policy = StreamPolicy::unpinned_insecure(&keys);
    policy.size = rvm_rvf::SizePolicy::permissive();
    policy.size.max_segments = 4096;
    policy.max_duplicate_frames = Some(10);
    let mut s = StreamSession::new(policy, opts(), base_policy());
    s.push(&bundle.frames[0]).unwrap();
    s.push(&bundle.frames[1]).unwrap();
    let mut errs = 0;
    for _ in 0..20 {
        if s.push(&bundle.frames[1]).is_err() {
            errs += 1;
        }
    }
    assert_eq!(s.state(), SessionState::Poisoned);
    assert_eq!(s.poison().unwrap().info.reason, StreamError::DuplicateFlood);
    assert!(errs >= 10);
    // An authenticated poison leaves one obligation naming this session only.
    assert!(s.take_obligation().is_some());
}

/// RV-03: stage-ordered delivery plus a lying `rvf_identity`: the host's pin on
/// the claimed identity passes the report, but neither a module nor a package
/// is available until the identity is confirmed, and confirmation fails.
#[test]
fn rv03_unverifiable_identity_yields_no_module_and_no_package() {
    let module = wasm_common::synthetic_module(3_000);
    let body = package_body(&module, "clock", 2);
    let lie = [0x99u8; 32];
    let mut b = builder(12, Order::Stage);
    b.identity_override = Some(lie);
    let keys = [b.public_key()];
    let bundle = b.build(&body).unwrap();

    let mut policy = StreamPolicy::unpinned_insecure(&keys);
    policy.size = rvm_rvf::SizePolicy::permissive();
    policy.size.max_segments = 4096;
    let mut session = StreamSession::new(policy, opts().expect_identity(lie), base_policy());
    for f in &bundle.frames {
        session.push(f).unwrap();
    }
    assert_eq!(session.state(), SessionState::Complete);
    assert_eq!(session.stream_state(), StreamState::CompleteUnverified);
    assert!(session.report().unwrap().ok, "the pin matched the claim");
    assert_ne!(
        session.report().unwrap().rvf_identity,
        rvm_rvf::sha256(&body)
    );
    assert_eq!(
        session.take_module(2).err(),
        Some(SessionError::IdentityUnverified)
    );
    assert!(session.package().is_none());
    // Confirmation against the persisted body refuses the lie.
    let r = session.finish_identity(|off, buf| {
        buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
        true
    });
    assert!(r.is_err());
    assert_eq!(session.state(), SessionState::Poisoned);
    assert!(session.take_module(2).is_err());
}

/// RV-04: a stream that completes but whose package is refused writes the
/// failing checks of the report, not just pass records.
#[test]
fn rv04_package_refused_after_complete_witnesses_the_failing_checks() {
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
    let mut last = Ok(SessionEvent::Descriptor);
    for f in &s.bundle.frames.clone() {
        last = s.session.push_witnessed(f, &log, CTX);
        if last.is_err() {
            break;
        }
    }
    assert_eq!(last, Err(SessionError::PackageRefused));
    assert_eq!(s.session.state(), SessionState::Failed);
    let rs = records(&log);
    let failed: Vec<_> = rs.iter().filter(|r| r.aux[5] == 1).collect();
    assert!(!failed.is_empty(), "no record says the package was refused");
    assert!(
        failed
            .iter()
            .any(|r| r.flags == CheckKind::ExecutableSigned as u8),
        "the unsigned executable is named"
    );
    // The success marker is not written for a refused package.
    assert!(rs
        .iter()
        .all(|r| r.flags != CheckKind::StreamComplete as u8));
}

/// RV-05: counted faults, a failed `finish_identity` and a reader-level size
/// lie all leave witness records.
#[test]
fn rv05_faults_finish_identity_and_reader_poison_are_witnessed() {
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let module = wasm_common::synthetic_module(1_000);
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();

    // Counted faults.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    let log = WitnessLog::<512>::new();
    s.session
        .push_witnessed(&bundle.frames[0], &log, CTX)
        .unwrap();
    let before = log.total_emitted();
    let mut bad = bundle.frames[1].clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    for _ in 0..3 {
        assert!(s.session.push_witnessed(&bad, &log, CTX).is_err());
    }
    assert_eq!(s.session.state(), SessionState::Receiving);
    let faults = records(&log)
        .into_iter()
        .filter(|r| r.flags == CheckKind::StreamFault as u8)
        .count();
    assert_eq!(faults, 3);
    assert_eq!(log.total_emitted(), before + 3);

    // Reader-level poison: a header that lies about its size.
    let mut s = stream(&keys, bundle.clone(), base_policy());
    let log = WitnessLog::<512>::new();
    s.session
        .feed_witnessed(&bundle.frames[0], &log, CTX, |_| {})
        .unwrap();
    let mut lie = vec![1u8];
    lie.extend_from_slice(&1u64.to_le_bytes());
    lie.extend_from_slice(&0u32.to_le_bytes());
    lie.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(s.session.feed_witnessed(&lie, &log, CTX, |_| {}).is_err());
    assert_eq!(s.session.state(), SessionState::Poisoned);
    let p: Vec<_> = records(&log)
        .into_iter()
        .filter(|r| r.flags == CheckKind::StreamPoisoned as u8)
        .collect();
    assert_eq!(p.len(), 1);
    assert_eq!(
        u16::from_le_bytes([p[0].aux[6], p[0].aux[7]]),
        StreamError::FrameSizeLie.code()
    );

    // finish_identity mismatch.
    let body = package_body(&module, "clock", 2);
    let mut sb = builder(12, Order::Stage);
    sb.identity_override = Some([0x42; 32]);
    let skeys = [sb.public_key()];
    let mut s = stream(&skeys, sb.build(&body).unwrap(), base_policy());
    let log = WitnessLog::<512>::new();
    for f in &s.bundle.frames.clone() {
        s.session.push_witnessed(f, &log, CTX).unwrap();
    }
    let r = s.session.finish_identity_witnessed(
        |off, buf| {
            buf.copy_from_slice(&body[off as usize..off as usize + buf.len()]);
            true
        },
        &log,
        CTX,
    );
    assert!(r.is_err());
    let p: Vec<_> = records(&log)
        .into_iter()
        .filter(|r| r.flags == CheckKind::StreamPoisoned as u8)
        .collect();
    assert_eq!(p.len(), 1);
    assert_eq!(
        u16::from_le_bytes([p[0].aux[6], p[0].aux[7]]),
        StreamError::IdentityMismatch.code()
    );
}

/// RV-05 (cause kept): an admission-level poison records its real reason.
#[test]
fn rv05_admission_poisons_keep_their_own_reason() {
    let module = wasm_common::synthetic_module(1_000);
    let mut body = package_body(&module, "clock", 2);
    // Corrupt the vector segment's magic after the descriptor is built over it:
    // the descriptor commits to the corrupted bytes, only the segment rules object.
    let at = rvm_rvf::walk(&body).unwrap()[2].offset;
    body[at] ^= 0xFF;
    let b = builder(12, Order::File);
    let spans = {
        let w = rvm_rvf::walk(&package_body(&module, "clock", 2)).unwrap();
        w.iter()
            .enumerate()
            .map(|(i, s)| rvm_rvf::stream::builder::Span {
                seg_id: s.header.segment_id,
                seg_type: s.header.seg_type,
                start: s.offset,
                end: w.get(i + 1).map_or(body.len(), |n| n.offset),
                uncompressed: 0,
            })
            .collect::<Vec<_>>()
    };
    let keys = [b.public_key()];
    let mut s = stream(&keys, b.build_spans(&body, &spans), base_policy());
    let e = run_all(&mut s).unwrap_err();
    assert_eq!(s.session.state(), SessionState::Poisoned, "{e}");
    assert_eq!(
        s.session.poison().unwrap().info.reason,
        StreamError::SegmentMalformed,
        "{e}"
    );
}

/// RV-07: the pin is recorded exactly once, after admission with a verified
/// identity; a cut, poisoned or refused stream does not move it; an old epoch
/// is then refused; a clockless receiver refuses an expiring descriptor.
#[test]
fn rv07_pins_are_recorded_only_after_admission_and_enforced() {
    let module = wasm_common::synthetic_module(1_000);
    let body = package_body(&module, "clock", 2);
    let store = MemoryPinStore::new();
    let mut b = builder(12, Order::File);
    b.epoch = 5;
    let keys = [b.public_key()];
    let bundle = b.build(&body).unwrap();
    let mk = |bundle: &rvm_rvf::stream::builder::StreamBundle| {
        let mut policy = StreamPolicy::new(
            &keys,
            ReplayProtection::Store {
                store: &store,
                now_ns: Some(10),
            },
        );
        policy.size = rvm_rvf::SizePolicy::permissive();
        policy.size.max_segments = 4096;
        (
            StreamSession::new(policy, opts(), base_policy()),
            bundle.clone(),
        )
    };

    // A cut stream: descriptor accepted, then nothing. No pin.
    let (mut cut, bd) = mk(&bundle);
    cut.push(&bd.frames[0]).unwrap();
    assert!(
        store.is_empty(),
        "accepting a descriptor must not move the pin"
    );

    // A corrupted stream: poisoned. No pin.
    let (mut bad, bd) = mk(&bundle);
    let mut frames = bd.frames.clone();
    let n = frames.len();
    frames[n - 1][20] ^= 1;
    let mut policy_budget_zero_ok = true;
    for f in &frames {
        if bad.push(f).is_err() {
            policy_budget_zero_ok = false;
        }
    }
    assert!(!policy_budget_zero_ok);
    assert!(store.is_empty());

    // A clean stream: pinned after Complete.
    let (mut ok, bd) = mk(&bundle);
    for f in &bd.frames {
        ok.push(f).unwrap();
    }
    assert_eq!(store.len(), 1);

    // Replays: an older epoch, and the same epoch with other content.
    let mut older = b.clone();
    older.epoch = 4;
    let mut other = b.clone();
    other.policy_hash = [0xCD; 32];
    for (bundle, want) in [
        (older.build(&body).unwrap(), StreamError::StaleEpoch),
        (other.build(&body).unwrap(), StreamError::EpochConflict),
    ] {
        let (mut s, bd) = mk(&bundle);
        assert_eq!(
            s.push(&bd.frames[0]).err(),
            Some(SessionError::Stream(
                rvm_rvf::stream::AdmissionError::Stream(want)
            ))
        );
    }

    // Expiry needs a clock.
    let mut expiring = b.clone();
    expiring.expires_ns = 1_000;
    let eb = expiring.build(&body).unwrap();
    let store2 = MemoryPinStore::new();
    let mut p = StreamPolicy::new(
        &keys,
        ReplayProtection::Store {
            store: &store2,
            now_ns: None,
        },
    );
    p.size = rvm_rvf::SizePolicy::permissive();
    let mut s = StreamSession::new(p, opts(), base_policy());
    assert_eq!(
        s.push(&eb.frames[0]).err(),
        Some(SessionError::Stream(
            rvm_rvf::stream::AdmissionError::Stream(StreamError::ClockRequired)
        ))
    );
}

/// Instances started from a session remember that session, not just the
/// descriptor.
#[test]
fn started_instances_remember_their_session_not_just_the_descriptor() {
    let module = wasm_common::synthetic_module(1_000);
    let b = builder(12, Order::File);
    let keys = [b.public_key()];
    let bundle = b.build(&package_body(&module, "clock", 2)).unwrap();
    let mut a = stream(&keys, bundle, base_policy());
    run_all(&mut a).unwrap();
    let log = WitnessLog::<512>::new();
    let mut agents = AgentManager::<4>::new();
    let mut inst = Instance::create(
        InstanceId::new(1),
        WasmAdapter::new(),
        a.session.package().unwrap().clone(),
        PLACEMENT,
        &log,
        1,
    )
    .unwrap();
    inst.start_verified(a.session.take_module(2).unwrap(), &mut agents, &log, 2)
        .unwrap();
    assert_eq!(inst.state(), InstanceState::Running);
    assert_eq!(
        inst.stream_origin().unwrap().session_id,
        a.session.session_id()
    );
}
