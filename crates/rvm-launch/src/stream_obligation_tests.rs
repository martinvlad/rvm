//! `PoisonObligation::discharge`: scoped to one session, cascading through
//! derived capabilities. (In-crate because only the session can issue an
//! obligation; `for_session` is crate-private so nobody can forge one.)

use super::*;
use crate::state::InstanceId;
use crate::stream_module::StreamOrigin;
use rvm_host::{Placement, WasmAdapter};
use rvm_types::{CapRights, CapToken, CapType, PartitionId};
use rvm_wasm::agent::AgentManager;

type Log = WitnessLog<256>;

fn running(id: u64, session: u64, log: &Log) -> (Instance<WasmAdapter>, AgentManager<4>) {
    let mut agents = AgentManager::<4>::new();
    let mut inst = Instance::create(
        InstanceId::new(id),
        WasmAdapter::new(),
        rvm_host::testkit::package("memory,clock"),
        Placement::new(PartitionId::new(1), 0, 16),
        log,
        1,
    )
    .unwrap();
    inst.start(&rvm_host::testkit::MINIMAL_WASM, &mut agents, log, 2)
        .unwrap();
    inst.stream_origin = Some(StreamOrigin {
        session_id: session,
        descriptor_hash: [9; 32],
    });
    (inst, agents)
}

#[test]
fn discharge_revokes_derived_children_and_leaves_unrelated_capabilities() {
    let tok = CapToken::new(1, CapType::Region, CapRights::READ, 0);
    let mut table = CapabilityTable::<8>::new();
    let (ri, rg) = table.insert_root(tok, PartitionId::new(1), 0).unwrap();
    let (ci, _) = table
        .insert_derived(tok, PartitionId::new(2), 1, ri, 0)
        .unwrap();
    let (gi, gg) = table
        .insert_derived(tok, PartitionId::new(3), 2, ci, 0)
        .unwrap();
    let (ui, ug) = table.insert_root(tok, PartitionId::new(4), 0).unwrap();

    let log = Log::new();
    let mut none: [Instance<WasmAdapter>; 0] = [];
    let mut agents = AgentManager::<4>::new();
    let d = PoisonObligation::for_session(1, alloc::vec![(ri, rg)])
        .discharge(&mut table, &mut none, &mut agents, &log, 3)
        .unwrap();
    assert_eq!(d.revoked, 3, "root, child and grandchild");
    assert!(table.lookup(ri, rg).is_err());
    assert!(table.lookup(gi, gg).is_err());
    assert!(table.lookup(ui, ug).is_ok(), "an unrelated root survives");
}

#[test]
fn discharge_terminates_only_its_own_sessions_instances() {
    let log = Log::new();
    let (a, mut agents_a) = running(1, 7, &log);
    let (b, _agents_b) = running(2, 8, &log);
    let mut instances = [a, b];
    let mut table = CapabilityTable::<2>::new();
    let d = PoisonObligation::for_session(7, alloc::vec![])
        .discharge(&mut table, &mut instances, &mut agents_a, &log, 3)
        .unwrap();
    assert_eq!(d.terminated, 1);
    assert_eq!(instances[0].state(), InstanceState::Terminated);
    assert_eq!(instances[1].state(), InstanceState::Running);

    // An obligation for a session that started nothing touches nothing.
    let d = PoisonObligation::for_session(99, alloc::vec![])
        .discharge(&mut table, &mut instances, &mut agents_a, &log, 4)
        .unwrap();
    assert_eq!(d.terminated, 0);
    assert_eq!(instances[1].state(), InstanceState::Running);
}
