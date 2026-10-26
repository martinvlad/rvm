//! Guards and bookkeeping shared by the lifecycle operations of [`Instance`].

use crate::error::{LaunchError, LaunchResult};
use crate::instance::Instance;
use crate::state::{is_legal, LifecycleOp};
use crate::witness::{emit, emit_illegal, LaunchEvent, LaunchWitnessContext};
use rvm_host::HostAdapter;
use rvm_types::fnv1a_32;
use rvm_witness::WitnessLog;

impl<A: HostAdapter> Instance<A> {
    pub(crate) fn witness_context(&self, timestamp_ns: u64) -> LaunchWitnessContext {
        LaunchWitnessContext {
            instance: self.id(),
            rvf_identity: *self.package.identity(),
            partition: self.isolation.placement.partition,
            timestamp_ns,
        }
    }

    /// Refuse an operation the state machine does not allow, witnessing the
    /// refusal first.
    pub(crate) fn guard<const N: usize>(
        &mut self,
        op: LifecycleOp,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        if is_legal(self.state, op) {
            return Ok(());
        }
        let start = log.total_emitted();
        emit_illegal(log, &self.witness_context(timestamp_ns), self.state, op);
        self.record_range(start, log.total_emitted());
        Err(LaunchError::IllegalTransition {
            from: self.state,
            op,
        })
    }

    pub(crate) fn record_range(&mut self, start: u64, end: u64) {
        if end > start {
            self.ranges.push((start, end));
        }
    }

    pub(crate) fn guard_executable<const N: usize>(
        &mut self,
        module: &[u8],
        log: &WitnessLog<N>,
        timestamp_ns: u64,
        start: u64,
    ) -> LaunchResult<()> {
        if self.package.accepts_wasm(module) {
            return Ok(());
        }
        emit(
            log,
            LaunchEvent::ExecutableRejected,
            &self.witness_context(timestamp_ns),
            self.state,
            fnv1a_32(module),
        );
        self.record_range(start, log.total_emitted());
        Err(LaunchError::ExecutableMismatch)
    }
}
