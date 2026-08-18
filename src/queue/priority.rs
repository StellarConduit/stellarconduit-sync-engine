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

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use stellarconduit_core::message::types::TransactionEnvelope;

use crate::errors::SyncEngineError;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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
#[derive(Debug, Default)]
pub struct OutboundTxQueue {
    heap: BinaryHeap<QueuedTx>,
    emergency_guard: Option<EmergencyGuard>,
}

impl OutboundTxQueue {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            emergency_guard: None,
        }
    }

    /// Like [`Self::new`], but rejects Emergency-tier pushes that would
    /// exceed `guard_config`'s rolling-window limit. Non-Emergency pushes
    /// are never gated.
    pub fn with_emergency_guard(guard_config: EmergencyGuardConfig) -> Self {
        Self {
            heap: BinaryHeap::new(),
            emergency_guard: Some(EmergencyGuard::new(guard_config)),
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
        let enqueued_at = now_secs();
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
        let span = tracing::info_span!(
            "envelope_queued",
            message_id = %hex::encode(envelope.message_id),
            priority = ?priority,
            enqueued_at
        );
        let _entered = span.enter();
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
        let span = tracing::info_span!(
            "envelope_restored_to_queue",
            message_id = %hex::encode(envelope.message_id),
            priority = ?priority,
            enqueued_at
        );
        let _entered = span.enter();
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
        let envelope = self.heap.pop().map(|q| q.envelope);
        if let Some(envelope) = &envelope {
            tracing::info!(
                message_id = %hex::encode(envelope.message_id),
                "envelope dispatched from queue"
            );
        }
        envelope
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
        let mut q = OutboundTxQueue::new();
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
        let mut q = OutboundTxQueue::new();
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
        let mut q = OutboundTxQueue::new();
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
        let config = EmergencyGuardConfig::new(3, Duration::from_secs(3600));
        let mut q = OutboundTxQueue::with_emergency_guard(config);

        for i in 0..3 {
            q.push(mock_envelope(i), TxPriority::Emergency).unwrap();
        }
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn test_emergency_queuing_beyond_limit_is_rejected() {
        let config = EmergencyGuardConfig::new(2, Duration::from_secs(3600));
        let mut q = OutboundTxQueue::with_emergency_guard(config);

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
        let permissive = EmergencyGuardConfig::new(5, Duration::from_secs(60));
        let mut generous_q = OutboundTxQueue::with_emergency_guard(permissive);
        for i in 0..5 {
            generous_q
                .push(mock_envelope(i), TxPriority::Emergency)
                .unwrap();
        }
        assert!(generous_q
            .push(mock_envelope(200), TxPriority::Emergency)
            .is_err());

        let strict = EmergencyGuardConfig::new(1, Duration::from_secs(60));
        let mut strict_q = OutboundTxQueue::with_emergency_guard(strict);
        strict_q
            .push(mock_envelope(1), TxPriority::Emergency)
            .unwrap();
        assert!(strict_q
            .push(mock_envelope(2), TxPriority::Emergency)
            .is_err());

        // A queue with no guard configured never rejects.
        let mut unguarded_q = OutboundTxQueue::new();
        for i in 0..10 {
            unguarded_q
                .push(mock_envelope(i), TxPriority::Emergency)
                .unwrap();
        }
    }

    #[test]
    fn test_limit_resets_after_window_elapses() {
        let config = EmergencyGuardConfig::new(1, Duration::from_secs(60));
        let mut q = OutboundTxQueue::with_emergency_guard(config);

        // Seed a single Emergency admission that is already outside the
        // 60s window as of "now", the way a wallet would replay
        // durably-stored history from before a restart.
        let now = now_secs();
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
        // This test proves that replaying that durable history through
        // `restore_at` after a simulated restart keeps the Emergency guard
        // at its pre-restart count, closing the force-restart bypass.
        let config = EmergencyGuardConfig::new(2, Duration::from_secs(3600));
        let now = now_secs();

        // "Before restart": a device queues 2 Emergency payments, the max
        // allowed, and each would have been durably persisted immediately.
        let mut before_restart = OutboundTxQueue::with_emergency_guard(config);
        before_restart
            .push_at(mock_envelope(1), TxPriority::Emergency, now)
            .unwrap();
        before_restart
            .push_at(mock_envelope(2), TxPriority::Emergency, now)
            .unwrap();
        let durably_persisted_emergency_timestamps = [now, now];

        // "Restart": the in-memory queue is gone. A fresh one is built and
        // seeded from what the wallet reloads out of durable storage.
        let mut after_restart = OutboundTxQueue::with_emergency_guard(config);
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
}
