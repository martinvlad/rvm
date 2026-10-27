//! Starting an instance from a [`VerifiedModule`] (ADR-160 item 5).

use crate::error::{LaunchError, LaunchResult};
use crate::instance::Instance;
use crate::state::LifecycleOp;
use crate::stream_module::{StreamOrigin, VerifiedModule};
use crate::witness::{emit, LaunchEvent};
use rvm_host::HostAdapter;
use rvm_types::fnv1a_32;
use rvm_wasm::agent::AgentManager;
use rvm_witness::WitnessLog;

impl<A: HostAdapter> Instance<A> {
    /// Admit a stream-verified module and begin execution.
    ///
    /// This is [`Instance::start`] for the stream path, with three differences:
    /// the only input that can reach it is a [`VerifiedModule`], which the
    /// stream session builds only from bytes that were authenticated, validated
    /// and complete; the module must come from *this instance's package*; and
    /// the module is **moved** into the instance's own storage, so no buffer the
    /// transport still holds can change what the instance holds.
    ///
    /// The existing length and SHA-256 check ([`rvm_host::VerifiedPackage::accepts_wasm`])
    /// still runs, on the instance's copy, and so do the adapter's size and
    /// framing checks. Starting here means admission and slot activation; RVM
    /// has no execution engine, so nothing is interpreted.
    ///
    /// # Errors
    ///
    /// [`LaunchError::IllegalTransition`] unless the instance is `Created`,
    /// [`LaunchError::ExecutableMismatch`] when the module belongs to another
    /// package or fails the identity check (witnessed first),
    /// [`LaunchError::Host`] when the adapter refuses and
    /// [`LaunchError::Backend`] when the agent registry refuses.
    pub fn start_verified<const M: usize, const N: usize>(
        &mut self,
        module: VerifiedModule,
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<()> {
        self.guard(LifecycleOp::Start, log, timestamp_ns)?;
        let start = log.total_emitted();
        let (bytes, _executable, rvf_identity, origin) = module.into_parts();

        if rvf_identity != *self.package.identity() {
            return Err(self.refuse_module(&bytes, log, timestamp_ns, start));
        }
        self.guard_executable(&bytes, log, timestamp_ns, start)?;

        let agent = self
            .adapter
            .spawn(&self.isolation, &bytes, agents, log, timestamp_ns)?;
        agents.activate(agent).map_err(LaunchError::Backend)?;

        self.agent = Some(agent);
        self.state = crate::state::InstanceState::Running;
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.module = Some(bytes);
        self.stream_origin = Some(origin);
        emit(
            log,
            LaunchEvent::InstanceStarted,
            &self.witness_context(timestamp_ns),
            self.state,
            len,
        );
        self.record_range(start, log.total_emitted());
        Ok(())
    }

    /// The module bytes held in this instance's own storage, when it was
    /// started through [`Self::start_verified`].
    #[must_use]
    pub fn module_bytes(&self) -> Option<&[u8]> {
        self.module.as_deref()
    }

    /// The stream session and signed descriptor this instance was started
    /// from, when it was started through [`Self::start_verified`].
    #[must_use]
    pub const fn stream_origin(&self) -> Option<&StreamOrigin> {
        self.stream_origin.as_ref()
    }

    fn refuse_module<const N: usize>(
        &mut self,
        bytes: &[u8],
        log: &WitnessLog<N>,
        timestamp_ns: u64,
        start: u64,
    ) -> LaunchError {
        emit(
            log,
            LaunchEvent::ExecutableRejected,
            &self.witness_context(timestamp_ns),
            self.state,
            fnv1a_32(bytes),
        );
        self.record_range(start, log.total_emitted());
        LaunchError::ExecutableMismatch
    }
}
