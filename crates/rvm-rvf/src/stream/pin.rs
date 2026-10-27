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
//! A store must be monotone: [`PinStore::record`] never lowers an epoch, and at
//! an equal epoch keeps the first descriptor hash it saw.

use super::EpochPin;
use alloc::collections::BTreeMap;
use core::cell::RefCell;

/// Durable memory of the highest accepted `(epoch, descriptor hash)` per file.
///
/// Methods take `&self` so a policy can borrow the store for lookups while a
/// session records into it; implementations use interior mutability.
pub trait PinStore {
    /// The pin for `file_id`, if one was recorded.
    fn lookup(&self, file_id: &[u8; 16]) -> Option<EpochPin>;

    /// Record an admitted descriptor. Must not lower an existing epoch.
    fn record(&self, file_id: &[u8; 16], pin: EpochPin);
}

/// An in-process [`PinStore`]. Not durable: a restart forgets every pin, which
/// reopens the replay window. A production host persists its store.
#[derive(Debug, Default)]
pub struct MemoryPinStore {
    pins: RefCell<BTreeMap<[u8; 16], EpochPin>>,
}

impl MemoryPinStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pins: RefCell::new(BTreeMap::new()),
        }
    }

    /// Number of files pinned.
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
    fn lookup(&self, file_id: &[u8; 16]) -> Option<EpochPin> {
        self.pins.borrow().get(file_id).copied()
    }

    fn record(&self, file_id: &[u8; 16], pin: EpochPin) {
        let mut pins = self.pins.borrow_mut();
        match pins.get(file_id) {
            Some(old) if old.epoch >= pin.epoch => {}
            _ => {
                pins.insert(*file_id, pin);
            }
        }
    }
}
