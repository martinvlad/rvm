//! The running `SHA-256` of the body, for the identity check at completion.
//!
//! Inline by default: every released chunk is hashed a second time on the
//! caller's thread (the first time is its leaf). With the `parallel-identity`
//! feature (which needs `std`) the second hash runs on a worker thread that is
//! fed copies of the chunks through a bounded queue, so the two SHA-256 passes
//! overlap. The digest is identical either way and is always complete before
//! the final chunk is released: [`IdentityTracker::digest`] waits for the
//! queue to drain. `no_std` builds do not compile any of the threaded code.

use sha2::{Digest, Sha256};

#[cfg(feature = "parallel-identity")]
mod worker {
    use super::Sha256;
    use sha2::Digest;
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use std::thread::JoinHandle;
    use std::vec::Vec;

    /// Chunks larger than this are hashed inline: the queue holds copies, so
    /// its memory is `QUEUE * chunk`, and a segment-granular stream can have
    /// chunks as large as a segment.
    pub(super) const MAX_CHUNK: usize = 1 << 20;
    /// Chunks in flight.
    const QUEUE: usize = 4;
    /// Bodies smaller than this are not worth a thread.
    pub(super) const MIN_BODY: u64 = 4 << 20;

    enum Msg {
        Data(Vec<u8>),
        Snapshot(SyncSender<Sha256>),
    }

    pub(super) struct Worker {
        tx: Option<SyncSender<Msg>>,
        handle: Option<JoinHandle<()>>,
    }

    impl Worker {
        pub(super) fn spawn() -> Option<Self> {
            let (tx, rx): (SyncSender<Msg>, Receiver<Msg>) = sync_channel(QUEUE);
            let handle = std::thread::Builder::new()
                .name("rvm-rvf-identity".into())
                .spawn(move || {
                    let mut h = Sha256::new();
                    for m in rx {
                        match m {
                            Msg::Data(v) => h.update(&v),
                            Msg::Snapshot(reply) => {
                                let _ = reply.send(h.clone());
                            }
                        }
                    }
                })
                .ok()?;
            Some(Self {
                tx: Some(tx),
                handle: Some(handle),
            })
        }

        /// Queue a copy of `bytes`; `false` if the worker is gone.
        pub(super) fn update(&self, bytes: &[u8]) -> bool {
            self.tx
                .as_ref()
                .is_some_and(|tx| tx.send(Msg::Data(bytes.to_vec())).is_ok())
        }

        /// The hasher state after every queued chunk (waits for the queue).
        pub(super) fn snapshot(&self) -> Option<Sha256> {
            let (rtx, rrx) = sync_channel(1);
            self.tx.as_ref()?.send(Msg::Snapshot(rtx)).ok()?;
            rrx.recv().ok()
        }
    }

    impl Drop for Worker {
        fn drop(&mut self) {
            drop(self.tx.take());
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }
}

/// Running identity hash plus the file-order bookkeeping.
pub(super) struct IdentityTracker {
    hasher: Sha256,
    pub(super) pos: u64,
    pub(super) feasible: bool,
    #[cfg(feature = "parallel-identity")]
    worker: Option<worker::Worker>,
}

impl IdentityTracker {
    /// A tracker for a body of `body_len` bytes delivered in chunks of at most
    /// `max_chunk` bytes.
    pub(super) fn new(body_len: u64, max_chunk: u64) -> Self {
        #[cfg(not(feature = "parallel-identity"))]
        let _ = (body_len, max_chunk);
        Self {
            hasher: Sha256::new(),
            pos: 0,
            feasible: true,
            #[cfg(feature = "parallel-identity")]
            worker: (body_len >= worker::MIN_BODY && max_chunk <= worker::MAX_CHUNK as u64)
                .then(worker::Worker::spawn)
                .flatten(),
        }
    }

    /// Absorb the next in-order bytes.
    pub(super) fn update(&mut self, bytes: &[u8]) {
        #[cfg(feature = "parallel-identity")]
        if let Some(w) = &self.worker {
            if w.update(bytes) {
                return;
            }
            // The worker died: the running hash can no longer be trusted to be
            // complete, so the identity is reported unverifiable rather than
            // wrong or skipped.
            self.feasible = false;
            return;
        }
        self.hasher.update(bytes);
    }

    /// The digest of everything absorbed so far, without consuming the tracker.
    #[allow(clippy::unnecessary_wraps)] // `None` only with the threaded worker
    pub(super) fn digest(&self) -> Option<[u8; 32]> {
        #[cfg(feature = "parallel-identity")]
        if let Some(w) = &self.worker {
            return w.snapshot().map(|h| h.finalize().into());
        }
        Some(self.hasher.clone().finalize().into())
    }
}

impl Clone for IdentityTracker {
    fn clone(&self) -> Self {
        #[cfg(feature = "parallel-identity")]
        if let Some(w) = &self.worker {
            // A clone is a snapshot: it carries the state after every queued
            // chunk and continues inline.
            return match w.snapshot() {
                Some(hasher) => Self {
                    hasher,
                    pos: self.pos,
                    feasible: self.feasible,
                    worker: None,
                },
                None => Self {
                    hasher: Sha256::new(),
                    pos: self.pos,
                    feasible: false,
                    worker: None,
                },
            };
        }
        Self {
            hasher: self.hasher.clone(),
            pos: self.pos,
            feasible: self.feasible,
            #[cfg(feature = "parallel-identity")]
            worker: None,
        }
    }
}
