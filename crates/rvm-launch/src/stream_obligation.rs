//! What a poisoned stream leaves the host to do, as a value it must discharge.

use crate::error::LaunchResult;
use crate::instance::Instance;
use crate::state::InstanceState;
use alloc::vec::Vec;
use rvm_cap::CapabilityTable;
use rvm_host::HostAdapter;
use rvm_wasm::agent::AgentManager;
use rvm_witness::WitnessLog;

/// The consumer effects of a poisoned stream (ADR-353 section 5), scoped to
/// what *this session* created:
///
/// * the capabilities this session installed (its own `(index, generation)`
///   handles, revoked one by one; there is no global epoch bump), and
/// * the instances started from this session (matched by session id, not by
///   descriptor hash, so another tenant streaming the same package is not
///   touched).
///
/// A session that was poisoned before it authenticated a descriptor issues no
/// obligation: it granted nothing and started nothing.
///
/// Obtain it from [`StreamSession::take_obligation`](crate::StreamSession::take_obligation)
/// after any error that leaves the session `Poisoned` (a refused frame, a
/// failed `finish_identity`), and [`discharge`](Self::discharge) it.
#[must_use = "a poisoned stream's capabilities and instances stay live until the obligation is discharged"]
#[derive(Debug)]
pub struct PoisonObligation {
    pub(crate) session_id: u64,
    pub(crate) handles: Vec<(u32, u32)>,
}

/// What discharging an obligation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Discharged {
    /// Capabilities revoked.
    pub revoked: usize,
    /// Instances terminated.
    pub terminated: usize,
}

impl PoisonObligation {
    /// An obligation for `session_id` covering `handles`. Crate-private: only
    /// the session that owns the id can issue one (a public constructor with a
    /// guessable sequential id would let any caller name another tenant's
    /// session).
    #[cfg(test)]
    pub(crate) fn for_session(session_id: u64, handles: Vec<(u32, u32)>) -> Self {
        Self {
            session_id,
            handles,
        }
    }

    /// The session this obligation belongs to.
    #[must_use]
    pub const fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Revoke the capabilities the session installed into `caps`, and
    /// terminate every instance in `instances` that was started from it.
    ///
    /// # Errors
    ///
    /// The first lifecycle error from a termination. Capabilities are revoked
    /// first, so a failed termination never leaves them live.
    pub fn discharge<A: HostAdapter, const C: usize, const M: usize, const N: usize>(
        self,
        caps: &mut CapabilityTable<C>,
        instances: &mut [Instance<A>],
        agents: &mut AgentManager<M>,
        log: &WitnessLog<N>,
        timestamp_ns: u64,
    ) -> LaunchResult<Discharged> {
        let mut gone: Vec<u32> = Vec::new();
        for (index, generation) in &self.handles {
            if caps.remove(*index, *generation).is_ok() {
                gone.push(*index);
            }
        }
        // Capabilities derived from the revoked roots go too: sweep the table
        // for slots whose parent was just removed, until none is left. (A
        // slot records its parent's index but not its generation; the sweep
        // runs at once, before any slot can be reused.)
        let mut revoked = gone.len();
        loop {
            let children: Vec<(u32, u32)> = caps
                .iter()
                .filter(|(_, slot)| slot.depth > 0 && gone.contains(&slot.parent_index))
                .map(|(index, slot)| (index, slot.generation))
                .collect();
            if children.is_empty() {
                break;
            }
            for (index, generation) in children {
                if caps.remove(index, generation).is_ok() {
                    gone.push(index);
                    revoked += 1;
                }
            }
        }
        let mut terminated = 0;
        for i in instances.iter_mut() {
            if i.stream_origin().map(|o| o.session_id) == Some(self.session_id)
                && i.state() != InstanceState::Terminated
            {
                i.terminate(agents, log, timestamp_ns)?;
                terminated += 1;
            }
        }
        Ok(Discharged {
            revoked,
            terminated,
        })
    }
}

#[cfg(test)]
#[path = "stream_obligation_tests.rs"]
mod tests;
