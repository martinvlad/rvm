//! Replay protection: the pin store and the protocol around it.
//!
//! A descriptor's `epoch` only means something to a receiver that remembers the
//! highest epoch it has accepted for each `file_id`. [`PinStore`] is that
//! memory, and [`MemoryPinStore`] is a reference in-process implementation.
//!
//! # Protocol: pin only after admission
//!
//! 1. Before the descriptor is accepted, [`ReplayProtection`] looks the
//!    `file_id` up: an older epoch is `StreamStaleEpoch`, the same epoch with a
//!    different descriptor hash is `StreamEpochConflict`.
//! 2. The pin is **not** advanced when the descriptor is accepted. A stream
//!    that is cut, poisoned, or whose package is refused must not move the pin,
//!    or an attacker could burn an epoch by truncating a stream.
//! 3. `rvm_launch::StreamSession` records `(epoch, descriptor_hash)`
//!    exactly once, when the stream is `Complete`, its identity is `Verified`
//!    and the package passed ADR-155 admission.
//!
//! Pins are keyed by `(signer_key_id, file_id)` and advance by compare-and-set
//! ([`PinStore::advance`]): the session re-checks the pin when the stream
//! completes (a session that started at epoch 4 and finished after epoch 5 was
//! pinned is refused), then advances from the value it checked against.

use super::EpochPin;
use alloc::collections::BTreeMap;
use core::cell::RefCell;

/// Durable memory of the highest accepted `(epoch, descriptor hash)` per
/// lineage, where a lineage is a `(signer_key_id, file_id)` pair: a second
/// trusted signer publishing the same `file_id` has its own pin and neither can
/// displace or bypass the other's.
///
/// Methods take `&self` so a policy can borrow the store for lookups while a
/// session records into it; implementations use interior mutability.
pub trait PinStore {
    /// The pin for the lineage, if one was recorded.
    fn lookup(&self, signer: &[u8; 8], file_id: &[u8; 16]) -> Option<EpochPin>;

    /// Atomic compare-and-set: advance the lineage's pin to `new` only if the
    /// current pin is exactly `expected` (`None` = none recorded), and `new` is
    /// not older than `expected`. Returns whether it advanced. A caller that
    /// loses the race re-reads, re-checks and retries.
    fn advance(
        &self,
        signer: &[u8; 8],
        file_id: &[u8; 16],
        expected: Option<EpochPin>,
        new: EpochPin,
    ) -> bool;
}

/// `(signer_key_id, file_id)`.
type Lineage = ([u8; 8], [u8; 16]);

/// An in-process [`PinStore`]. Not durable: a restart forgets every pin, which
/// reopens the replay window. A production host persists its store. Uses
/// interior mutability without a lock: not for use from interrupt context.
#[derive(Debug, Default)]
pub struct MemoryPinStore {
    pins: RefCell<BTreeMap<Lineage, EpochPin>>,
}

impl MemoryPinStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pins: RefCell::new(BTreeMap::new()),
        }
    }

    /// Number of lineages pinned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins.borrow().len()
    }

    /// Whether nothing is pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pins.borrow().is_empty()
    }
}

impl PinStore for MemoryPinStore {
    fn lookup(&self, signer: &[u8; 8], file_id: &[u8; 16]) -> Option<EpochPin> {
        self.pins.borrow().get(&(*signer, *file_id)).copied()
    }

    fn advance(
        &self,
        signer: &[u8; 8],
        file_id: &[u8; 16],
        expected: Option<EpochPin>,
        new: EpochPin,
    ) -> bool {
        let mut pins = self.pins.borrow_mut();
        let key = (*signer, *file_id);
        let current = pins.get(&key).copied();
        if current != expected || expected.is_some_and(|e| new.epoch < e.epoch) {
            return false;
        }
        pins.insert(key, new);
        true
    }
}
