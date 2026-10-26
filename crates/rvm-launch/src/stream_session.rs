//! A verified streaming session: bytes in, a startable module out.
//!
//! [`StreamSession`] joins the three stages ADR-160 puts between a socket and
//! an agent slot:
//!
//! ```text
//! frames -> StreamAdmission -> WASM payload -> StreamingModuleValidator -> VerifiedModule
//!           (authenticate +     (only released     (limits from signed
//!            ADR-155 rules)      payload bytes)     SizePolicy)
//! ```
//!
//! # Why it lives in `rvm-launch`
//!
//! It must name three things at once: the admission layer (`rvm-rvf`), the
//! module validator (`rvm-wasm`), and the instances that a poisoned stream has
//! to terminate (`rvm-launch`). `rvm-host` sits below `Instance` and cannot
//! name it; `rvm-rvf` and `rvm-wasm` must not depend on each other. `rvm-launch`
//! is the lowest crate that sees all three, and it already owns the lifecycle
//! that `start_verified` extends.
//!
//! # When a module becomes available
//!
//! [`StreamSession::take_module`] returns a [`VerifiedModule`] only after the
//! stream is `Complete` and admission produced a passing report. That is
//! stricter than ADR-160 item 5 (which only requires the module's own segment
//! to be verified): the capability mapping and the root-manifest rule are
//! package-level facts that need the whole descriptor's worth of segments. A
//! stage-ordered stream could release a component earlier; this session does
//! not, and says so rather than guessing at a partial package.
//!
//! # Poison
//!
//! A poisoned stream is terminal ([`SessionState::Poisoned`]). The session
//! drops every byte it derived from the stream, refuses [`take_module`] and
//! exposes the three consumer effects ADR-353 section 5 names:
//! [`revoke_capabilities`] (an `rvm-cap` epoch bump),
//! [`terminate_instances`] (every instance started from this stream) and the
//! dropped state itself.
//!
//! [`take_module`]: StreamSession::take_module
//! [`revoke_capabilities`]: StreamSession::revoke_capabilities
//! [`terminate_instances`]: StreamSession::terminate_instances

use crate::error::LaunchResult;
use crate::instance::Instance;
use crate::state::InstanceState;
use crate::stream_module::VerifiedModule;
use crate::stream_session_types::{PoisonReport, SessionError, SessionEvent, SessionState};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use rvm_cap::CapabilityManager;
use rvm_host::{HostAdapter, VerifiedPackage};
use rvm_rvf::stream::witness::{binding_of, emit_event, push_witnessed, StreamEvent};
use rvm_rvf::stream::{
    AdmissionError, AdmissionEvent, PoisonInfo, StreamAdmission, StreamPolicy, StreamState,
};
use rvm_rvf::{SizePolicy, VerificationReport, VerifyOptions, WitnessContext};
use rvm_wasm::agent::AgentManager;
use rvm_wasm::{ModuleError, ModulePolicy, StreamingModuleValidator};
use rvm_witness::WitnessLog;

/// The `seg_type` of a WASM runtime segment.
const SEG_TYPE_WASM: u8 = rvm_rvf::format::SEG_TYPE_WASM;

/// Writes a stream event to the caller's witness log.
type Emit<'a> = Option<&'a dyn Fn(&StreamEvent, &[u8; 32])>;

struct ExecProgress {
    validator: StreamingModuleValidator,
    bytes: Vec<u8>,
}

/// The module validation limits a signed [`SizePolicy`] implies.
///
/// `base` supplies the structural limits (function body size, locals, the
/// import policy, the largest buffered section); the signed policy supplies
/// the module size: `max_runtime_bytes`, which may exceed the 1 MiB constant.
/// A section is never allowed to be larger than the module itself.
/// [`rvm_wasm::MAX_MODULE_SIZE`] stays the executor backstop at start (ADR-155 section
/// 4), so a module the policy admits but the backstop refuses is witnessed and
/// refused there, not here.
#[must_use]
pub fn module_policy_for(size: &SizePolicy, base: ModulePolicy) -> ModulePolicy {
    let limit = usize::try_from(size.max_runtime_bytes).unwrap_or(usize::MAX);
    ModulePolicy {
        max_module_bytes: limit,
        max_section_bytes: limit.min(base.max_section_bytes),
        ..base
    }
}

/// Stream in, startable module out. See the [module documentation](self).
pub struct StreamSession<'p> {
    admission: StreamAdmission<'p>,
    module_policy: ModulePolicy,
    exec: BTreeMap<u64, ExecProgress>,
    ready: BTreeMap<u64, (Vec<u8>, rvm_wasm::ValidatedModule)>,
    package: Option<VerifiedPackage>,
    state: SessionState,
    failure: Option<SessionError>,
    poison: Option<PoisonReport>,
}

impl<'p> StreamSession<'p> {
    /// A session whose module limits derive from `policy.size` and `base`.
    #[must_use]
    pub fn new(policy: StreamPolicy<'p>, opts: VerifyOptions, base: ModulePolicy) -> Self {
        let module_policy = module_policy_for(&policy.size, base);
        Self::with_module_policy(policy, opts, module_policy)
    }

    /// A session with exactly `module_policy`, not derived from the size
    /// policy.
    #[must_use]
    pub fn with_module_policy(
        policy: StreamPolicy<'p>,
        opts: VerifyOptions,
        module_policy: ModulePolicy,
    ) -> Self {
        Self {
            admission: StreamAdmission::new(policy, opts),
            module_policy,
            exec: BTreeMap::new(),
            ready: BTreeMap::new(),
            package: None,
            state: SessionState::Receiving,
            failure: None,
            poison: None,
        }
    }

    /// The session state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// The first failure, if the session failed.
    #[must_use]
    pub const fn failure(&self) -> Option<&SessionError> {
        self.failure.as_ref()
    }

    /// The admission report, once the stream completed.
    #[must_use]
    pub fn report(&self) -> Option<&VerificationReport> {
        self.admission.report()
    }

    /// The verified package, once the stream completed and passed.
    #[must_use]
    pub const fn package(&self) -> Option<&VerifiedPackage> {
        self.package.as_ref()
    }

    /// The verifier's view of the stream.
    #[must_use]
    pub fn stream_state(&self) -> StreamState {
        self.admission.state()
    }

    /// The hash of the signed descriptor, once accepted.
    #[must_use]
    pub fn descriptor_hash(&self) -> Option<[u8; 32]> {
        self.admission
            .verifier()
            .descriptor()
            .map(|d| d.descriptor_hash)
    }

    /// Why the stream was poisoned, once it is.
    #[must_use]
    pub const fn poison(&self) -> Option<&PoisonReport> {
        self.poison.as_ref()
    }

    /// Accept one complete frame.
    ///
    /// # Errors
    ///
    /// The frame was refused, or a module in it failed validation. Nothing
    /// refused reaches the validator or the module buffer.
    pub fn push(&mut self, frame: &[u8]) -> Result<SessionEvent, SessionError> {
        if self.state != SessionState::Receiving {
            return Err(SessionError::Unusable);
        }
        let result = self.admission.push(frame);
        self.after(result, None)
    }

    /// [`Self::push`], writing the stream's witness records first: the
    /// descriptor verdict, each verified segment, module validation, completion
    /// and poisoning.
    ///
    /// # Errors
    ///
    /// As [`Self::push`]; the records are in the log either way.
    pub fn push_witnessed<const N: usize>(
        &mut self,
        frame: &[u8],
        log: &WitnessLog<N>,
        ctx: WitnessContext,
    ) -> Result<SessionEvent, SessionError> {
        if self.state != SessionState::Receiving {
            return Err(SessionError::Unusable);
        }
        let result = push_witnessed(&mut self.admission, frame, log, ctx);
        self.after(
            result,
            Some(&|ev: &StreamEvent, b: &[u8; 32]| {
                emit_event(ev, b, log, ctx);
            }),
        )
    }

    fn after(
        &mut self,
        result: Result<AdmissionEvent<'_>, AdmissionError>,
        witness: Emit<'_>,
    ) -> Result<SessionEvent, SessionError> {
        let ev = match result {
            Ok(ev) => ev,
            Err(e) => {
                self.check_poisoned();
                return Err(SessionError::Stream(e));
            }
        };
        let (out, complete) = match ev {
            AdmissionEvent::DescriptorVerified { .. } => (SessionEvent::Descriptor, false),
            AdmissionEvent::TableVerified { .. } => (SessionEvent::Table, false),
            AdmissionEvent::Chunk {
                chunk,
                payload,
                segment_verified,
                stage_verified,
                complete,
                ..
            } => {
                if chunk.seg_type == SEG_TYPE_WASM {
                    if let Err(e) =
                        self.feed_module(chunk.seg_id, payload, segment_verified, witness)
                    {
                        self.fail(e.clone());
                        return Err(e);
                    }
                }
                (
                    SessionEvent::Chunk {
                        seg_id: chunk.seg_id,
                        segment_verified,
                        stage_verified,
                    },
                    complete.is_some(),
                )
            }
        };
        if complete {
            return self.on_complete();
        }
        Ok(out)
    }

    fn feed_module(
        &mut self,
        seg_id: u64,
        payload: &[u8],
        segment_verified: bool,
        witness: Emit<'_>,
    ) -> Result<(), SessionError> {
        let policy = &self.module_policy;
        let progress = self.exec.entry(seg_id).or_insert_with(|| ExecProgress {
            validator: StreamingModuleValidator::new(policy.clone()),
            bytes: Vec::new(),
        });
        let binding = binding_of(&self.admission).unwrap_or([0; 32]);
        let reject = |error: ModuleError| {
            if let Some(w) = witness {
                w(&StreamEvent::ModuleRejected { seg_id }, &binding);
            }
            SessionError::Module { seg_id, error }
        };
        if !payload.is_empty() {
            progress.validator.push(payload).map_err(reject)?;
            progress.bytes.extend_from_slice(payload);
        }
        if segment_verified {
            let done = self.exec.remove(&seg_id).expect("module in progress");
            let validated = done.validator.finish().map_err(reject)?;
            if let Some(w) = witness {
                w(&StreamEvent::ModuleValidated { seg_id }, &binding);
            }
            self.ready.insert(seg_id, (done.bytes, validated));
        }
        Ok(())
    }

    fn on_complete(&mut self) -> Result<SessionEvent, SessionError> {
        let package = self
            .admission
            .report()
            .and_then(|r| VerifiedPackage::from_report(r).ok());
        if let Some(p) = package {
            self.package = Some(p);
            self.state = SessionState::Complete;
            Ok(SessionEvent::Complete)
        } else {
            self.fail(SessionError::PackageRefused);
            Err(SessionError::PackageRefused)
        }
    }

    fn fail(&mut self, e: SessionError) {
        self.state = SessionState::Failed;
        self.exec.clear();
        self.ready.clear();
        self.package = None;
        self.failure = Some(e);
    }

    fn check_poisoned(&mut self) {
        if let StreamState::Poisoned(reason) = self.admission.state() {
            if self.poison.is_none() {
                let info = self
                    .admission
                    .verifier()
                    .poison_info()
                    .unwrap_or(PoisonInfo {
                        seg_id: None,
                        chunk_index: 0,
                        reason,
                    });
                self.poison = Some(PoisonReport {
                    descriptor_hash: self.descriptor_hash().unwrap_or([0; 32]),
                    info,
                });
            }
            self.state = SessionState::Poisoned;
            self.exec.clear();
            self.ready.clear();
            self.package = None;
            self.admission.discard_derived_state();
        }
    }

    /// Hand over the validated module of segment `seg_id`.
    ///
    /// # Errors
    ///
    /// [`SessionError::NotComplete`] before the stream completed,
    /// [`SessionError::Unusable`] after a failure or poison,
    /// [`SessionError::NoSuchModule`] when that segment carried no validated
    /// WASM module, and [`SessionError::IdentityMismatch`] if the buffered
    /// bytes do not match the verified executable (length and SHA-256).
    pub fn take_module(&mut self, seg_id: u64) -> Result<VerifiedModule, SessionError> {
        match self.state {
            SessionState::Receiving => return Err(SessionError::NotComplete),
            SessionState::Failed | SessionState::Poisoned => return Err(SessionError::Unusable),
            SessionState::Complete => {}
        }
        let report = self.admission.report().ok_or(SessionError::Unusable)?;
        let executable = *report
            .executables
            .iter()
            .find(|e| e.segment_id == seg_id && e.segment_type == SEG_TYPE_WASM)
            .ok_or(SessionError::NoSuchModule)?;
        let rvf_identity = report.rvf_identity;
        let (bytes, validated) = self
            .ready
            .remove(&seg_id)
            .ok_or(SessionError::NoSuchModule)?;
        if !executable.matches(&bytes) {
            return Err(SessionError::IdentityMismatch);
        }
        let descriptor_hash = self.descriptor_hash().unwrap_or([0; 32]);
        Ok(VerifiedModule::new(
            bytes,
            executable,
            validated,
            rvf_identity,
            descriptor_hash,
        ))
    }

    /// For a stream that completed with an `Unverifiable` identity (chunks
    /// arrived in stage order): re-read the persisted body in file order and
    /// check `SHA-256 == rvf_identity`. A mismatch poisons the stream and the
    /// poison effects apply.
    ///
    /// # Errors
    ///
    /// [`SessionError::Stream`] with the verifier's refusal.
    pub fn finish_identity(
        &mut self,
        read_at: impl FnMut(u64, &mut [u8]) -> bool,
    ) -> Result<(), SessionError> {
        let r = self
            .admission
            .finish_identity(read_at)
            .map_err(|e| SessionError::Stream(AdmissionError::Stream(e)));
        self.check_poisoned();
        r
    }

    /// Poison effect 1: revoke what the stream's package was granted, by
    /// bumping the `rvm-cap` epoch so every handle issued before it is stale.
    ///
    /// Returns `false` (and does nothing) unless the stream is poisoned.
    ///
    /// The bump is global to the manager. [`rvm_rvf::CapabilityMapping::install`]
    /// does not hand back the handles it creates, so a targeted revoke of just
    /// this package's capabilities is not reachable from here; a caller that
    /// kept the handles can `revoke` them itself.
    pub fn revoke_capabilities<const N: usize>(&self, caps: &mut CapabilityManager<N>) -> bool {
        if self.state != SessionState::Poisoned {
            return false;
        }
        caps.increment_epoch();
        true
    }

    /// Poison effect 2: terminate every instance in `instances` that was
    /// started from this stream and is not already terminated. Returns how
    /// many were terminated.
    ///
    /// # Errors
    ///
    /// The first lifecycle error from a termination.
    pub fn terminate_instances<A: HostAdapter, const M: usize, const N: usize>(
        &self,
        instances: &mut [Instance<A>],
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<usize> {
        let Some(origin) = self.poison.as_ref().map(|p| p.descriptor_hash) else {
            return Ok(0);
        };
        let mut n = 0;
        for i in instances.iter_mut() {
            if i.stream_origin() == Some(&origin) && i.state() != InstanceState::Terminated {
                i.terminate(agents, log, timestamp_ns)?;
                n += 1;
            }
        }
        Ok(n)
    }
}
