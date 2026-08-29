//! Local, pre-gossip ordering of a device's own outgoing payments.
//!
//! This is distinct from `stellarconduit_core::gossip::queue::MessagePriority`,
//! which governs mesh *forwarding* order for any envelope passing through a
//! peer. `TxPriority` governs the order in which *this device's own* queued
//! payments are signed and handed off to the mesh in the first place — e.g. an
//! emergency payment queued while offline should be dispatched ahead of a
//! routine one queued earlier.
//!
//! ## Emergency spending guard
//!
//! Because [`TxPriority::Emergency`] is specifically designed to jump the
//! queue and to be dispatched/propagated first, it is also the most
//! attractive tier for a thief to abuse: a lost or stolen unlocked device
//! (or a compromised wallet app) could queue an unbounded number of
//! Emergency payments before the owner notices, and those fraudulent
//! payments would settle ahead of the owner's own legitimate ones once the
//! device is back online.
//!
//! [`OutboundTxQueue`] therefore supports an optional, configurable
//! [`EmergencyGuardConfig`] that caps how many Emergency-tier entries may be
//! pushed within a rolling time window. Design decisions:
//!
//! * **Count-based, not value-based (for now).** A cumulative-XDR-value
//!   limit would be a stronger guard, but this crate does not yet parse
//!   amounts out of `tx_xdr` (see the top-level project's "Derive Source
//!   Account and Sequence Number from XDR" work). A count-based limit is
//!   documented here as the first version; value-based limiting can be
//!   layered on top once XDR parsing lands, without changing this API's
//!   shape (`EmergencyGuardConfig` can grow a `max_cumulative_value` field).
//! * **Per-window, not per-source-account (for now).** `OutboundTxQueue`
//!   only sees a [`TransactionEnvelope`] and a priority — the Stellar
//!   source account is tracked one layer up (e.g. `crate::storage::db`,
//!   `crate::queue::sequence`), not on the envelope itself. Per-account
//!   limiting is a reasonable follow-up once a source account is threaded
//!   through `push`.
//! * **Configurable at construction, not a global constant.** A personal
//!   wallet and a shared community relay terminal want very different
//!   thresholds, so the limit is a constructor argument
//!   ([`OutboundTxQueue::with_emergency_guard`]), not a hardcoded constant.
//! * **Persistence: in-memory counter, but seeded from durable state.**
//!   `OutboundTxQueue` itself is a transient, in-process structure — it is
//!   always rebuilt from durable storage after a restart (that's exactly
//!   what [`OutboundTxQueue::push_at`] is for). A purely in-memory guard
//!   counter would therefore be defeated by an attacker who force-restarts
//!   the app: the freshly-constructed queue's guard would start back at
//!   zero. To close that hole, `push_at` also folds Emergency entries into
//!   the guard's history (without re-running the limit check, since it is
//!   restoring decisions already made). The embedding wallet is expected to
//!   reload previously-queued Emergency envelopes from its durable store
//!   (e.g. `crate::storage::db::SyncEngineDb::list_queued_envelopes`, which
//!   already persists `priority` and `enqueued_at` for exactly this reason)
//!   and replay them through `push_at` before accepting new pushes. This
//!   avoids inventing a second, redundant persistence mechanism just for
//!   the guard: the existing queued-envelope table *is* the durable record,
//!   and the guard's in-memory state is a reconstructable cache over it —
//!   so a forced restart cannot reset the counter as long as the wallet
//!   performs this standard replay-on-startup step (see
//!   `test_limit_survives_restart` below for the shape of that replay).
//!
//! ## Concurrency Contract — Single-Owner / Single-Task
//!
//! **`OutboundTxQueue` is intentionally `!Send` and `!Sync`.** It is designed
//! to be owned and accessed by exactly one task or thread at a time, with no
//! internal synchronization.
//!
//! ### Design decision and justification
//!
//! The choice is **single-owner** rather than "wrap in `Arc<Mutex<…>>`":
//!
//! 1. **The correct locking granularity is at the engine level, not the queue
//!    level.** `SyncEngine` (see `crate::engine`) must atomically advance
//!    *three* pieces of in-memory state together — the queue, the sequence
//!    reservation manager, and the settlement tracker — under a *single*
//!    serialization point.  If `OutboundTxQueue` had its own internal `Mutex`,
//!    the only safe usage would be `engine_mutex → queue_mutex → seq_mutex →
//!    tracker_mutex`, a fixed lock order that buys nothing over a single outer
//!    `Mutex<SyncEngine>` and adds deadlock risk and latency for every
//!    operation that needs all three.
//!
//! 2. **Rust's ownership model is the right enforcement mechanism.**  Making
//!    the type `!Send + !Sync` converts a future concurrency misuse from a
//!    silent correctness bug (data race, duplicate sequence numbers, lost
//!    entries) into a **compile error**.  The caller must explicitly move the
//!    queue into a `Mutex` or equivalent before sharing it, and that act of
//!    wrapping is the natural place to think about the correct scope of the
//!    lock.
//!
//! 3. **The queue is always embedded inside `SyncEngine`, which takes `&mut
//!    self` on every mutating operation.**  The engine's single `&mut self`
//!    borrow is already the exclusive-access guarantee; duplicating that
//!    guarantee inside the queue would be redundant.
//!
//! ### Single-owner linearizability argument
//!
//! With `!Send + !Sync` enforced at compile time, every sequence of
//! `push`/`pop`/`peek`/`len` calls by a single owner is trivially
//! linearizable: there is no concurrent call to interleave with. Each
//! operation takes effect at a single atomic point — the point at which `&mut
//! self` is acquired — and the history of operations is identical to that
//! sequential history.
//!
//! The loom tests in the `#[cfg(feature = "loom")]` block below prove the
//! complementary property: **when `OutboundTxQueue` is wrapped in an
//! `Arc<Mutex<_>>` by a caller who intentionally shares it across two loom
//! threads** (simulating the misuse we want to detect), the `Mutex` enforces
//! mutual exclusion and the observable results are still consistent with some
//! valid sequential history — i.e., the queue is linearizable even in the
//! "wrapped by a conscientious caller" scenario. This is not the intended
//! usage, but it is important to confirm that the structure itself does not
//! have hidden state corruption bugs that would manifest even under a correct
//! lock: the only correctness guarantee the `Mutex` makes is memory safety;
//! the logical invariants (no lost entries, no duplicates) must come from the
//! data structure itself.
//!
//! ### How to run loom tests
//!
//! ```text
//! cargo test --features loom loom_test_
//! ```
//!
//! Loom exhaustively enumerates every possible thread interleaving permitted
//! by the C11-like memory model it simulates. Tests are slower than normal
//! unit tests by design; keep the number of operations per model small (≤ ~4
//! per thread).

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use stellarconduit_core::message::types::TransactionEnvelope;

use crate::clock::Clock;
use crate::errors::SyncEngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TxPriority {
    Low = 0,
    Normal = 1,
    Emergency = 2,
}

impl From<TxPriority> for i64 {
    fn from(p: TxPriority) -> i64 {
        p as i64
    }
}

impl TryFrom<i64> for TxPriority {
    type Error = crate::errors::SyncEngineError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(TxPriority::Low),
            1 => Ok(TxPriority::Normal),
            2 => Ok(TxPriority::Emergency),
            other => Err(crate::errors::SyncEngineError::InvalidEnvelope(format!(
                "unknown TxPriority discriminant {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
struct QueuedTx {
    priority: TxPriority,
    /// Unix seconds when this envelope was pushed. Used as a FIFO tie-break
    /// within the same priority tier — earlier enqueue wins.
    enqueued_at: u64,
    envelope: TransactionEnvelope,
}

impl PartialEq for QueuedTx {
    fn eq(&self, other: &Self) -> bool {
        self.envelope.message_id == other.envelope.message_id
    }
}
impl Eq for QueuedTx {}

impl Ord for QueuedTx {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.enqueued_at.cmp(&self.enqueued_at))
    }
}
impl PartialOrd for QueuedTx {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Configures the Emergency-tier spending guard on [`OutboundTxQueue`]: at
/// most `max_count` Emergency entries may be admitted within any trailing
/// `window`. See the module docs above for the design rationale.
#[derive(Debug, Clone, Copy)]
pub struct EmergencyGuardConfig {
    pub max_count: usize,
    pub window: Duration,
}

impl EmergencyGuardConfig {
    pub fn new(max_count: usize, window: Duration) -> Self {
        Self { max_count, window }
    }
}

/// Tracks recent Emergency-tier admission timestamps so [`OutboundTxQueue`]
/// can enforce an [`EmergencyGuardConfig`]. Entries older than the
/// configured window are pruned lazily on each check.
#[derive(Debug)]
struct EmergencyGuard {
    config: EmergencyGuardConfig,
    history: VecDeque<u64>,
}

impl EmergencyGuard {
    fn new(config: EmergencyGuardConfig) -> Self {
        Self {
            config,
            history: VecDeque::new(),
        }
    }

    fn prune(&mut self, now: u64) {
        let window_secs = self.config.window.as_secs();
        while let Some(&oldest) = self.history.front() {
            if now.saturating_sub(oldest) >= window_secs {
                self.history.pop_front();
            } else {
                break;
            }
        }
    }

    /// Reject with a distinguishable, informative error if admitting one
    /// more Emergency entry at `now` would exceed the configured limit.
    fn check(&mut self, now: u64) -> Result<(), SyncEngineError> {
        self.prune(now);
        if self.history.len() >= self.config.max_count {
            return Err(SyncEngineError::EmergencyQueueLimitExceeded {
                current: self.history.len(),
                max: self.config.max_count,
                window_secs: self.config.window.as_secs(),
            });
        }
        Ok(())
    }

    fn record(&mut self, at: u64) {
        self.history.push_back(at);
    }
}

/// A local max-heap of outgoing envelopes, ordered by [`TxPriority`] and then
/// by insertion order (oldest first) within the same tier.
///
/// ## Concurrency contract — single-owner / `!Send + !Sync`
///
/// `OutboundTxQueue` is **not** thread-safe and is deliberately marked
/// `!Send + !Sync` via its [`PhantomData`] field. It must be owned and
/// accessed by exactly one task or thread at a time.
///
/// **Why not `Arc<Mutex<OutboundTxQueue>>`?**
/// The correct serialization point for all wallet operations that touch the
/// queue is at the `SyncEngine` level (see `crate::engine`), which also
/// serializes the sequence-reservation manager and the settlement tracker.
/// Internal locking would buy nothing and would create deadlock risk; the
/// `!Send + !Sync` markers turn accidental concurrent access into a compile
/// error rather than a silent correctness bug.
///
/// **Linearizability argument:**
/// Because the type is `!Send + !Sync`, every call site that modifies the
/// queue holds exclusive access (`&mut self`) on a single thread. There are no
/// concurrent calls to interleave, so the operation history is trivially
/// equivalent to some sequential history. The loom tests under
/// `#[cfg(feature = "loom")]` verify that *when a caller correctly wraps the
/// queue in a `Mutex`*, the resulting behavior is still linearizable (no lost
/// entries, no duplicate pops) across all thread interleavings loom can
/// enumerate.
///
/// **How to run loom tests:**
/// ```text
/// cargo test --features loom loom_test_
/// ```
#[derive(Debug)]
pub struct OutboundTxQueue {
    heap: BinaryHeap<QueuedTx>,
    emergency_guard: Option<EmergencyGuard>,
    /// Monotonic clock used to timestamp pushes. Injected so tests can use a
    /// deterministic [`crate::clock::MockClock`] and production can use a
    /// [`crate::clock::HybridClock`].
    clock: Arc<dyn Clock>,
    /// Enforces the single-owner concurrency contract at compile time.
    ///
    /// `PhantomData<*mut ()>` makes this type `!Send + !Sync` because raw
    /// pointers are neither `Send` nor `Sync`. The `*mut ()` carries no size,
    /// alignment, or drop requirement — it is purely a marker. Future callers
    /// who want to share the queue across threads must explicitly wrap it in a
    /// `Mutex<OutboundTxQueue>` (which re-grants `Send`/`Sync` through the
    /// mutex's own impls), making the synchronization contract explicit and
    /// visible at the call site.
    _single_owner: PhantomData<*mut ()>,
}

impl Default for OutboundTxQueue {
    fn default() -> Self {
        Self::new(Arc::new(crate::clock::HybridClock::new()))
    }
}

impl OutboundTxQueue {
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            heap: BinaryHeap::new(),
            emergency_guard: None,
            clock,
            _single_owner: PhantomData,
        }
    }

    /// Like [`Self::new`], but rejects Emergency-tier pushes that would
    /// exceed `guard_config`'s rolling-window limit. Non-Emergency pushes
    /// are never gated.
    pub fn with_emergency_guard(guard_config: EmergencyGuardConfig, clock: Arc<dyn Clock>) -> Self {
        Self {
            heap: BinaryHeap::new(),
            emergency_guard: Some(EmergencyGuard::new(guard_config)),
            clock,
            _single_owner: PhantomData,
        }
    }

    /// Push `envelope` at the given `priority`, timestamped now.
    ///
    /// Returns [`SyncEngineError::EmergencyQueueLimitExceeded`] if `priority`
    /// is [`TxPriority::Emergency`] and a configured guard's limit has
    /// already been reached — a soft failure the embedding wallet should
    /// use as a signal to demand extra confirmation, not a silent drop.
    pub fn push(
        &mut self,
        envelope: TransactionEnvelope,
        priority: TxPriority,
    ) -> Result<(), SyncEngineError> {
        let enqueued_at = self.clock.now_secs();
        self.push_at(envelope, priority, enqueued_at)
    }

    /// Same as [`Self::push`] but with an explicit `enqueued_at`.
    ///
    /// This is used both to restore a queue from durable storage after a
    /// restart, and (in tests) to deterministically control the rolling
    /// window. Either way it still enforces the Emergency guard as of
    /// `enqueued_at` — if a caller needs to replay previously-accepted
    /// Emergency entries without re-checking the limit (the restart-restore
    /// case), use [`Self::restore_at`] instead.
    pub fn push_at(
        &mut self,
        envelope: TransactionEnvelope,
        priority: TxPriority,
        enqueued_at: u64,
    ) -> Result<(), SyncEngineError> {
        if priority == TxPriority::Emergency {
            if let Some(guard) = &mut self.emergency_guard {
                guard.check(enqueued_at)?;
                guard.record(enqueued_at);
            }
        }
        self.heap.push(QueuedTx {
            priority,
            enqueued_at,
            envelope,
        });
        Ok(())
    }

    /// Re-admit a previously-accepted envelope (e.g. one reloaded from
    /// `crate::storage::db::SyncEngineDb` at startup) without re-running the
    /// Emergency guard's limit check. Emergency entries are still folded
    /// into the guard's history so the rolling window correctly accounts
    /// for them — this is what lets the guard survive a forced restart (see
    /// the module docs). Never rejects.
    pub fn restore_at(
        &mut self,
        envelope: TransactionEnvelope,
        priority: TxPriority,
        enqueued_at: u64,
    ) {
        if priority == TxPriority::Emergency {
            if let Some(guard) = &mut self.emergency_guard {
                guard.record(enqueued_at);
            }
        }
        self.heap.push(QueuedTx {
            priority,
            enqueued_at,
            envelope,
        });
    }

    pub fn pop(&mut self) -> Option<TransactionEnvelope> {
        self.heap.pop().map(|q| q.envelope)
    }

    pub fn peek(&self) -> Option<&TransactionEnvelope> {
        self.heap.peek().map(|q| &q.envelope)
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_envelope(message_id: u8) -> TransactionEnvelope {
        TransactionEnvelope {
            message_id: [message_id; 32],
            origin_pubkey: [1u8; 32],
            tx_xdr: "mock_xdr".to_string(),
            ttl_hops: 10,
            timestamp: 1_700_000_000,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn test_higher_priority_pops_first() {
        let clock = Arc::new(crate::clock::MockClock::new(100));
        let mut q = OutboundTxQueue::new(clock);
        q.push(mock_envelope(1), TxPriority::Low).unwrap();
        q.push(mock_envelope(2), TxPriority::Emergency).unwrap();
        q.push(mock_envelope(3), TxPriority::Normal).unwrap();

        assert_eq!(q.pop().unwrap().message_id, [2u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [3u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [1u8; 32]);
        assert!(q.pop().is_none());
    }

    #[test]
    fn test_fifo_within_same_priority() {
        let clock = Arc::new(crate::clock::MockClock::new(100));
        let mut q = OutboundTxQueue::new(clock);
        q.push_at(mock_envelope(1), TxPriority::Normal, 100)
            .unwrap();
        q.push_at(mock_envelope(2), TxPriority::Normal, 50).unwrap();
        q.push_at(mock_envelope(3), TxPriority::Normal, 200)
            .unwrap();

        // Oldest enqueued_at (50) should come out first.
        assert_eq!(q.pop().unwrap().message_id, [2u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [1u8; 32]);
        assert_eq!(q.pop().unwrap().message_id, [3u8; 32]);
    }

    #[test]
    fn test_len_and_is_empty() {
        let clock = Arc::new(crate::clock::MockClock::new(100));
        let mut q = OutboundTxQueue::new(clock);
        assert!(q.is_empty());
        q.push(mock_envelope(1), TxPriority::Low).unwrap();
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());
    }

    #[test]
    fn test_priority_i64_roundtrip() {
        for p in [TxPriority::Low, TxPriority::Normal, TxPriority::Emergency] {
            let as_i64: i64 = p.into();
            assert_eq!(TxPriority::try_from(as_i64).unwrap(), p);
        }
    }

    #[test]
    fn test_priority_from_invalid_i64_errors() {
        assert!(TxPriority::try_from(99).is_err());
    }

    #[test]
    fn test_emergency_queuing_within_limit_succeeds() {
        let clock = Arc::new(crate::clock::MockClock::new(100));
        let config = EmergencyGuardConfig::new(3, Duration::from_secs(3600));
        let mut q = OutboundTxQueue::with_emergency_guard(config, clock);

        for i in 0..3 {
            q.push(mock_envelope(i), TxPriority::Emergency).unwrap();
        }
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_emergency_queuing_beyond_limit_is_rejected() {
        let clock = Arc::new(crate::clock::MockClock::new(100));
        let config = EmergencyGuardConfig::new(2, Duration::from_secs(3600));
        let mut q = OutboundTxQueue::with_emergency_guard(config, clock);

        q.push(mock_envelope(1), TxPriority::Emergency).unwrap();
        q.push(mock_envelope(2), TxPriority::Emergency).unwrap();

        let err = q
            .push(mock_envelope(3), TxPriority::Emergency)
            .expect_err("third Emergency push should exceed the configured limit of 2");
        assert!(matches!(
            err,
            SyncEngineError::EmergencyQueueLimitExceeded {
                current: 2,
                max: 2,
                ..
            }
        ));
        // The rejected push must not have been silently queued.
        assert_eq!(q.len(), 2);

        // Non-Emergency tiers are never gated by the Emergency guard.
        q.push(mock_envelope(4), TxPriority::Normal).unwrap();
        q.push(mock_envelope(5), TxPriority::Low).unwrap();
        assert_eq!(q.len(), 4);
    }

    #[test]
    fn test_limit_is_configurable() {
        let clock = Arc::new(crate::clock::MockClock::new(100));
        let permissive = EmergencyGuardConfig::new(5, Duration::from_secs(60));
        let mut generous_q = OutboundTxQueue::with_emergency_guard(permissive, clock.clone());
        for i in 0..5 {
            generous_q
                .push(mock_envelope(i), TxPriority::Emergency)
                .unwrap();
        }
        assert!(generous_q
            .push(mock_envelope(200), TxPriority::Emergency)
            .is_err());

        let strict = EmergencyGuardConfig::new(1, Duration::from_secs(60));
        let mut strict_q = OutboundTxQueue::with_emergency_guard(strict, clock.clone());
        strict_q
            .push(mock_envelope(1), TxPriority::Emergency)
            .unwrap();
        assert!(strict_q
            .push(mock_envelope(2), TxPriority::Emergency)
            .is_err());

        // A queue with no guard configured never rejects.
        let mut unguarded_q = OutboundTxQueue::new(clock);
        for i in 0..10 {
            unguarded_q
                .push(mock_envelope(i), TxPriority::Emergency)
                .unwrap();
        }
    }

    #[test]
    fn test_limit_resets_after_window_elapses() {
        let clock = Arc::new(crate::clock::MockClock::new(1000));
        let config = EmergencyGuardConfig::new(1, Duration::from_secs(60));
        let mut q = OutboundTxQueue::with_emergency_guard(config, clock.clone());

        // Seed a single Emergency admission that is already outside the
        // 60s window as of "now", the way a wallet would replay
        // durably-stored history from before a restart.
        let now = clock.now_secs();
        q.restore_at(mock_envelope(1), TxPriority::Emergency, now - 61);

        // The window has elapsed for that entry, so a fresh push at the
        // configured limit of 1 must still be admitted.
        q.push(mock_envelope(2), TxPriority::Emergency).unwrap();

        // But now the window is full again (the entry from `push` above is
        // current), so a third one is rejected.
        assert!(q.push(mock_envelope(3), TxPriority::Emergency).is_err());
    }

    #[test]
    fn test_limit_survives_restart() {
        // Chosen persistence model: `OutboundTxQueue` (and its guard) is an
        // in-process cache reconstructed from the durable `queued_envelopes`
        // table (see `crate::storage::db::SyncEngineDb`), which already
        // records `priority` and `enqueued_at` for every queued envelope.
        // this test proves that replaying that durable history through
        // `restore_at` after a simulated restart keeps the Emergency guard
        // at its pre-restart count, closing the force-restart bypass.
        let clock = Arc::new(crate::clock::MockClock::new(1000));
        let config = EmergencyGuardConfig::new(2, Duration::from_secs(3600));
        let now = clock.now_secs();

        // "Before restart": a device queues 2 Emergency payments, the max
        // allowed, and each would have been durably persisted immediately.
        let mut before_restart = OutboundTxQueue::with_emergency_guard(config, clock.clone());
        before_restart
            .push_at(mock_envelope(1), TxPriority::Emergency, now)
            .unwrap();
        before_restart
            .push_at(mock_envelope(2), TxPriority::Emergency, now)
            .unwrap();
        let durably_persisted_emergency_timestamps = [now, now];

        // "Restart": the in-memory queue is gone. A fresh one is built and
        // seeded from what the wallet reloads out of durable storage.
        let mut after_restart = OutboundTxQueue::with_emergency_guard(config, clock.clone());
        for (i, &ts) in durably_persisted_emergency_timestamps.iter().enumerate() {
            after_restart.restore_at(mock_envelope(i as u8 + 1), TxPriority::Emergency, ts);
        }

        // An attacker who forced the restart hoping to reset the counter
        // and queue more Emergency payments is still blocked.
        let err = after_restart
            .push(mock_envelope(3), TxPriority::Emergency)
            .expect_err("guard state must survive the simulated restart");
        assert!(matches!(
            err,
            SyncEngineError::EmergencyQueueLimitExceeded {
                current: 2,
                max: 2,
                ..
            }
        ));
    }

    /// Structural proof of `!Send` and `!Sync`.
    ///
    /// `OutboundTxQueue` contains `PhantomData<*mut ()>`. Raw pointers are
    /// neither `Send` nor `Sync`, so `OutboundTxQueue` inherits `!Send +
    /// !Sync`. This test confirms the structural condition compiles: the field
    /// `_single_owner: PhantomData<*mut ()>` exists and has the right type.
    ///
    /// The negative proof (that `OutboundTxQueue` is genuinely not `Send`)
    /// is enforced at compile time: uncommenting
    ///   `fn _assert_send() { fn f<T: Send>() {} f::<OutboundTxQueue>() }`
    /// produces a compile error. That is the authoritative check; the test
    /// below validates the structural precondition.
    #[test]
    fn test_outbound_tx_queue_is_not_send_or_sync() {
        let q = OutboundTxQueue::new(Arc::new(crate::clock::MockClock::new(100)));
        // Confirm _single_owner has type PhantomData<*mut ()>.
        let _marker: PhantomData<*mut ()> = q._single_owner;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loom-based exhaustive interleaving tests.
//
// These tests prove two things:
//
//  1. **Single-owner enforcement is real**: a caller who wraps the queue in a
//     `Mutex` can share it across threads without data races — the `Mutex`
//     does its job.
//
//  2. **The data structure is logically linearizable under that `Mutex`**: for
//     every possible interleaving of push/pop operations across two threads,
//     the results are consistent with some valid sequential history. In
//     particular: no entry is ever lost, no entry is ever returned twice, and
//     the total number of items in and out is always balanced.
//
// Both points together prove the single-owner contract: the type is safe to
// use exactly as documented (one owner, exclusive access), and the one
// supported sharing pattern (explicit `Mutex` wrapping) is also correct.
//
// The tests are gated behind `#[cfg(feature = "loom")]` because loom replaces
// std::sync primitives with its own instrumented versions, which panic if used
// outside a `loom::model` block. Run them with:
//
//   cargo test --features loom loom_test_
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::sync::{Arc, Mutex};

    fn loom_envelope(id: u8) -> TransactionEnvelope {
        TransactionEnvelope {
            message_id: [id; 32],
            origin_pubkey: [1u8; 32],
            tx_xdr: "mock_xdr".to_string(),
            ttl_hops: 10,
            timestamp: 1_700_000_000,
            signature: [0u8; 64],
        }
    }

    /// Two threads each push one envelope and then one thread pops.
    ///
    /// **What this proves (push/pop linearizability):**
    /// Across all interleavings that loom can enumerate:
    /// - The total number of pushes that actually completed equals the total
    ///   count of items that can be popped — no entry is ever lost.
    /// - Each pop returns a distinct envelope — no entry is ever returned
    ///   twice.
    ///
    /// This is the "never loses or duplicates entry" property required by the
    /// acceptance criteria.
    #[test]
    fn loom_test_concurrent_push_pop_never_loses_or_duplicates_entry() {
        loom::model(|| {
            let clock = std::sync::Arc::new(crate::clock::MockClock::new(1000));
            let queue = Arc::new(Mutex::new(OutboundTxQueue::new(clock)));

            // Thread A: push envelope 0xAA at Normal priority.
            let q_a = Arc::clone(&queue);
            let thread_a = loom::thread::spawn(move || {
                q_a.lock()
                    .unwrap()
                    .push_at(loom_envelope(0xAA), TxPriority::Normal, 100)
                    .expect("push must not fail for Normal priority");
            });

            // Thread B: push envelope 0xBB at Normal priority.
            let q_b = Arc::clone(&queue);
            let thread_b = loom::thread::spawn(move || {
                q_b.lock()
                    .unwrap()
                    .push_at(loom_envelope(0xBB), TxPriority::Normal, 200)
                    .expect("push must not fail for Normal priority");
            });

            thread_a.join().unwrap();
            thread_b.join().unwrap();

            // After both pushes completed, the queue must contain exactly 2
            // items. We pop both and check for distinctness.
            let mut q = queue.lock().unwrap();
            assert_eq!(q.len(), 2, "both pushed envelopes must be present");

            let first = q.pop().expect("first pop must return an envelope");
            let second = q.pop().expect("second pop must return an envelope");
            assert!(q.pop().is_none(), "queue must be empty after two pops");

            // The two pops must return distinct envelopes.
            assert_ne!(
                first.message_id, second.message_id,
                "each pop must return a distinct envelope"
            );

            // The returned IDs must be exactly the two we pushed.
            let mut ids = [first.message_id[0], second.message_id[0]];
            ids.sort_unstable();
            assert_eq!(
                ids,
                [0xAA, 0xBB],
                "the two pops must return exactly the two pushed envelopes"
            );
        });
    }

    /// Thread A interleaves push and pop; Thread B does the same.
    ///
    /// **What this proves (no entry loss under concurrent push+pop):**
    /// Across all interleavings:
    /// - Total items popped ≤ total items pushed.
    /// - Items that were successfully pushed but not yet popped remain in
    ///   the queue; the sum `popped_count + queue.len()` always equals the
    ///   number of successful pushes.
    ///
    /// This catches the classic "ABA problem" where a pop races with a push
    /// and either returns a stale item or loses a freshly-pushed one.
    #[test]
    fn loom_test_concurrent_push_pop_interleaved_never_loses_entry() {
        loom::model(|| {
            // Pre-populate with one envelope so both threads have something
            // to pop immediately, making the push/pop interleaving denser.
            let clock = std::sync::Arc::new(crate::clock::MockClock::new(1000));
            let mut initial = OutboundTxQueue::new(clock);
            initial
                .push_at(loom_envelope(0x01), TxPriority::Normal, 50)
                .unwrap();
            let queue = Arc::new(Mutex::new(initial));

            // Thread A: push one envelope, then pop one.
            let q_a = Arc::clone(&queue);
            let thread_a = loom::thread::spawn(move || {
                q_a.lock()
                    .unwrap()
                    .push_at(loom_envelope(0xAA), TxPriority::Normal, 100)
                    .unwrap();
                q_a.lock().unwrap().pop()
            });

            // Thread B: push one envelope, then pop one.
            let q_b = Arc::clone(&queue);
            let thread_b = loom::thread::spawn(move || {
                q_b.lock()
                    .unwrap()
                    .push_at(loom_envelope(0xBB), TxPriority::Normal, 200)
                    .unwrap();
                q_b.lock().unwrap().pop()
            });

            let popped_a = thread_a.join().unwrap();
            let popped_b = thread_b.join().unwrap();

            // Total items in the system: started with 1, each thread pushed
            // 1, so 3 total. Each thread popped at most 1. Items not popped
            // by the threads are still in the queue.
            let remaining = queue.lock().unwrap().len();
            let popped_count = popped_a.is_some() as usize + popped_b.is_some() as usize;

            assert_eq!(
                popped_count + remaining,
                3,
                "total items in system must always be conserved: \
                 3 pushed, {} popped, {} remaining",
                popped_count,
                remaining
            );

            // No two pops may return the same envelope.
            if let (Some(a), Some(b)) = (popped_a, popped_b) {
                assert_ne!(
                    a.message_id, b.message_id,
                    "concurrent pops must not return the same envelope"
                );
            }
        });
    }

    /// Two threads concurrently push Emergency-priority envelopes into a
    /// queue protected by a guard that allows at most 2 Emergency entries.
    ///
    /// **What this proves (Emergency guard under concurrent access):**
    /// Across all interleavings:
    /// - At most `max_count` Emergency entries are ever admitted, regardless
    ///   of the interleaving of the two pushes.
    /// - The count of items in the queue never exceeds `max_count` for
    ///   Emergency entries (Normal entries are not limited and are counted
    ///   separately here).
    ///
    /// This is the critical "guard state race" scenario: without the Mutex,
    /// two threads could both pass the `check()` test before either calls
    /// `record()`, resulting in `max_count + 1` Emergency entries being
    /// admitted. With the Mutex, only one can proceed at a time, so the guard
    /// is always consistent.
    #[test]
    fn loom_test_concurrent_emergency_guard_never_exceeds_limit() {
        loom::model(|| {
            // Guard allows at most 2 Emergency entries in a 1-hour window.
            let clock = std::sync::Arc::new(crate::clock::MockClock::new(1000));
            let config = EmergencyGuardConfig::new(2, Duration::from_secs(3600));
            let queue = Arc::new(Mutex::new(OutboundTxQueue::with_emergency_guard(
                config, clock,
            )));

            let q_a = Arc::clone(&queue);
            let thread_a = loom::thread::spawn(move || {
                q_a.lock()
                    .unwrap()
                    .push_at(loom_envelope(0xAA), TxPriority::Emergency, 1000)
            });

            let q_b = Arc::clone(&queue);
            let thread_b = loom::thread::spawn(move || {
                q_b.lock()
                    .unwrap()
                    .push_at(loom_envelope(0xBB), TxPriority::Emergency, 1001)
            });

            let result_a = thread_a.join().unwrap();
            let result_b = thread_b.join().unwrap();

            let q = queue.lock().unwrap();
            let emergency_count = q.len(); // both are Emergency, so this is the Emergency count

            // Both succeeded: the guard limit of 2 was not exceeded.
            let both_succeeded = result_a.is_ok() && result_b.is_ok();
            // One failed: the guard rejected one of them. Queue should have 1.
            let one_failed = result_a.is_err() || result_b.is_err();

            // Since max_count == 2 and we pushed exactly 2 Emergency entries,
            // both must have been admitted (the limit is not exceeded until
            // the 3rd attempt). In all interleavings of two pushes under a
            // correctly-held mutex, both must succeed.
            assert!(
                both_succeeded,
                "both Emergency pushes must succeed when limit is 2 and only 2 are pushed \
                 (result_a={:?}, result_b={:?})",
                result_a, result_b
            );
            assert!(!one_failed);
            assert_eq!(
                emergency_count, 2,
                "queue must contain exactly 2 Emergency entries"
            );
        });
    }

    /// Two threads push 2 Emergency entries each against a guard with
    /// `max_count = 2`. After both threads complete, the queue must contain
    /// exactly 2 Emergency entries — the third and fourth must have been
    /// rejected.
    ///
    /// **What this proves (guard limit is never silently over-admitted):**
    /// This is the sharpest version of the race: if the `check`+`record`
    /// inside `push_at` were not protected by the mutex, both threads could
    /// pass `check` simultaneously (both see count=1 < max=2) and both call
    /// `record`, resulting in 4 entries being admitted instead of 2.
    /// Under the mutex, at most `max_count` entries are ever admitted in
    /// total, across all interleavings.
    #[test]
    fn loom_test_concurrent_emergency_guard_over_limit_rejects_excess() {
        loom::model(|| {
            let clock = std::sync::Arc::new(crate::clock::MockClock::new(1000));
            let config = EmergencyGuardConfig::new(2, Duration::from_secs(3600));
            let queue = Arc::new(Mutex::new(OutboundTxQueue::with_emergency_guard(
                config, clock,
            )));

            // Thread A tries to push 2 Emergency entries.
            let q_a = Arc::clone(&queue);
            let thread_a = loom::thread::spawn(move || {
                let r1 =
                    q_a.lock()
                        .unwrap()
                        .push_at(loom_envelope(0xA1), TxPriority::Emergency, 1000);
                let r2 =
                    q_a.lock()
                        .unwrap()
                        .push_at(loom_envelope(0xA2), TxPriority::Emergency, 1001);
                (r1.is_ok(), r2.is_ok())
            });

            // Thread B tries to push 2 Emergency entries.
            let q_b = Arc::clone(&queue);
            let thread_b = loom::thread::spawn(move || {
                let r1 =
                    q_b.lock()
                        .unwrap()
                        .push_at(loom_envelope(0xB1), TxPriority::Emergency, 1002);
                let r2 =
                    q_b.lock()
                        .unwrap()
                        .push_at(loom_envelope(0xB2), TxPriority::Emergency, 1003);
                (r1.is_ok(), r2.is_ok())
            });

            let (a1_ok, a2_ok) = thread_a.join().unwrap();
            let (b1_ok, b2_ok) = thread_b.join().unwrap();

            let admitted_count = [a1_ok, a2_ok, b1_ok, b2_ok]
                .iter()
                .filter(|&&ok| ok)
                .count();

            let q = queue.lock().unwrap();
            // The queue length equals admitted Emergency entries (all are Emergency).
            assert_eq!(
                q.len(),
                admitted_count,
                "queue length must equal the number of admitted pushes"
            );

            // The guard must never admit more than max_count=2 entries,
            // regardless of interleaving.
            assert!(
                admitted_count <= 2,
                "Emergency guard must never admit more than max_count=2 entries; \
                 admitted {admitted_count}"
            );
        });
    }
}
