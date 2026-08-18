//! `SyncEngine` — the restart-safe driver that wires together the queue,
//! sequence reservation, offline signing, durable storage, and settlement
//! tracking components into a single API a wallet or relay node can embed.
//!
//! ## Crash-consistency contract
//!
//! StellarConduit devices stay offline for long stretches and can be killed at
//! any instant — battery death, OS eviction, reboot. The engine's central
//! guarantee is that [`SyncEngine::open`] on the next launch reconstructs
//! exactly the state a fully-completed previous call would have produced, and
//! that a crash mid-call can never silently lose a queued payment, reuse a
//! sequence number, or re-dispatch an envelope that was already handed to the
//! mesh.
//!
//! To deliver that, durable SQLite storage is the single source of truth. All
//! in-memory state — the [`OutboundTxQueue`], the [`SequenceReservationManager`],
//! and the [`SettlementTracker`] — is *rehydrated* from it on every `open`, so
//! ephemeral memory can be discarded freely.
//!
//! Per-method write ordering:
//!
//! - **`queue_payment`**: the sequence reservation, the signed envelope, and
//!   its initial `Queued` settlement status are written to SQLite in **one
//!   atomic transaction** (`SyncEngineDb::enqueue_transaction`), and only then
//!   is the in-memory queue/tracker touched. A crash during the call therefore
//!   leaves the database either fully written (the call completed) or
//!   completely untouched (as if it never ran) — never half-written. This
//!   matters because a Stellar sequence number cannot be skipped on-chain:
//!   persisting the reservation without the envelope (or the envelope without
//!   the reservation) would either burn an unrecoverable gap or invite a reuse,
//!   and both are real double-spend hazards against the user's own account.
//!
//! - **`next_to_dispatch`**: the envelope's settlement status is advanced to
//!   `Propagating` and **persisted before** the envelope leaves the in-memory
//!   queue. If the device dies between dispatch and settlement, the next
//!   `open` sees `Propagating` (not `Queued`) and so never re-queues the
//!   envelope — no duplicate handoff to the mesh.
//!
//! - **`mark_settlement`**: the transition is validated (via
//!   [`SettlementStatus::can_transition_to`]) first; the new status is
//!   persisted, and only then is the in-memory tracker advanced, so the two
//!   never disagree.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use stellarconduit_core::message::types::TransactionEnvelope;

use crate::envelope::OfflineEnvelopeBuilder;
use crate::errors::SyncEngineError;
use crate::queue::{OutboundTxQueue, SequenceReservationManager, TxPriority};
use crate::settlement::{SettlementStatus, SettlementTracker};
use crate::storage::SyncEngineDb;

/// Restart-safe driver combining durable storage with the in-memory queue,
/// sequence reservations, and settlement tracker.
pub struct SyncEngine {
    db: SyncEngineDb,
    queue: OutboundTxQueue,
    sequences: SequenceReservationManager,
    settlement: SettlementTracker,
    /// Dedicated *synchronous* SQLite connection used only by
    /// [`next_to_dispatch`](SyncEngine::next_to_dispatch), whose signature is
    /// synchronous and therefore cannot `.await` an async DB call. It opens the
    /// same database file as `db`, so dispatch markers it writes are visible to
    /// `open` after a restart. The engine is driven sequentially (`&mut self`
    /// everywhere), so this connection never contends with `db`'s writes.
    dispatch_conn: rusqlite::Connection,
}

impl SyncEngine {
    /// Open (or create) the database at `db_path` and rehydrate all in-memory
    /// state from it. Safe to call after an unclean shutdown at any point
    /// during a previous `queue_payment` or `mark_settlement` call.
    ///
    /// Use a real on-disk path for any workflow that needs to survive a
    /// restart; a `:memory:` path produces an ephemeral engine that cannot be
    /// reopened.
    pub async fn open(db_path: &str) -> Result<Self, SyncEngineError> {
        let db = SyncEngineDb::init(db_path).await?;

        // --- Rehydrate sequence reservations for every known account. ---
        let mut sequences = SequenceReservationManager::new();
        let reservations = db.list_all_sequence_reservations().await?;
        for (account, last_reserved) in reservations {
            sequences.seed(account, last_reserved);
        }

        // --- Rehydrate the settlement tracker and the dispatchable queue. ---
        let mut queue = OutboundTxQueue::new();
        let mut settlement = SettlementTracker::new();
        for record in db.list_queued_envelopes().await? {
            let status = db
                .get_settlement_status(record.envelope.message_id)
                .await?
                .unwrap_or(SettlementStatus::Queued);

            // Seed the tracker at the envelope's true (persisted) status so a
            // resumed lifecycle (e.g. mark_settlement after dispatch) works.
            settlement.restore(record.envelope.message_id, status);

            // Only still-`Queued` envelopes are dispatchable. Anything already
            // handed to the mesh (Propagating) or beyond is intentionally left
            // out of the queue, so it is never dispatched a second time after a
            // restart.
            if status == SettlementStatus::Queued {
                queue.restore_at(record.envelope, record.priority, record.enqueued_at);
            }
        }

        // --- Synchronous connection for next_to_dispatch's durable marker. ---
        let dispatch_conn = open_dispatch_connection(db_path)?;

        Ok(Self {
            db,
            queue,
            sequences,
            settlement,
            dispatch_conn,
        })
    }

    /// Seed (or re-seed) `source_account`'s sequence baseline from its
    /// last-known on-chain sequence number, as observed while the device still
    /// had connectivity.
    ///
    /// A production wallet should call this once per account before queuing any
    /// payment for it; the baseline is durably persisted so it survives
    /// restarts. Accounts left unseeded are auto-seeded at `0` by
    /// [`queue_payment`](SyncEngine::queue_payment) as a self-contained
    /// fallback.
    pub async fn seed_account(
        &mut self,
        source_account: &str,
        current_chain_sequence: i64,
    ) -> Result<(), SyncEngineError> {
        self.sequences.seed(source_account, current_chain_sequence);
        self.db
            .save_sequence_reservation(source_account, current_chain_sequence)
            .await?;
        Ok(())
    }

    /// Read the last-reserved sequence number for `source_account` from durable
    /// storage. Returns `None` if the account has never been seeded or queued.
    pub async fn last_reserved_sequence(
        &self,
        source_account: &str,
    ) -> Result<Option<i64>, SyncEngineError> {
        self.db.load_sequence_reservation(source_account).await
    }

    /// Look up the current settlement status of a queued envelope by its
    /// `message_id`.
    ///
    /// Reads the in-memory tracker, which is rehydrated from durable storage
    /// on [`open`](SyncEngine::open) and kept in lock-step with it by every
    /// [`queue_payment`](SyncEngine::queue_payment),
    /// [`next_to_dispatch`](SyncEngine::next_to_dispatch), and
    /// [`mark_settlement`](SyncEngine::mark_settlement) call — so this is a
    /// cheap, synchronous lookup rather than a database round-trip. Returns
    /// `None` if `message_id` is not (or no longer) tracked.
    ///
    /// Exposed as a thin pass-through — same shape as
    /// [`last_reserved_sequence`](SyncEngine::last_reserved_sequence) above —
    /// primarily so callers that only have a `SyncEngine` handle (e.g.
    /// `crate::ffi`) don't need direct access to the private `settlement`
    /// field.
    pub fn settlement_status(&self, message_id: [u8; 32]) -> Option<SettlementStatus> {
        self.settlement.status(&message_id)
    }

    /// Durably record a newly-detected double-spend conflict as unresolved.
    ///
    /// Conflict *detection* (via [`crate::conflict::detect_conflicts`]) and
    /// wiring that detection into the queue/dispatch lifecycle are tracked as
    /// follow-up work and not yet performed automatically by this engine;
    /// this method is the durable-storage half of that pipeline, exposed
    /// today so callers that detect a conflict by other means (or the FFI
    /// layer in `crate::ffi`, for testing) have a supported way to record and
    /// later list it via [`list_unresolved_conflicts`](SyncEngine::list_unresolved_conflicts).
    pub async fn record_conflict(
        &self,
        conflict: &crate::conflict::Conflict,
        detected_at: u64,
    ) -> Result<(), SyncEngineError> {
        self.db.record_conflict(conflict, detected_at).await
    }

    /// List every unresolved (not yet arbitrated) double-spend conflict
    /// currently recorded in durable storage.
    pub async fn list_unresolved_conflicts(
        &self,
    ) -> Result<Vec<crate::conflict::Conflict>, SyncEngineError> {
        self.db.list_unresolved_conflicts().await
    }

    /// Reserve a sequence number, sign, and durably queue a new payment.
    ///
    /// Crash-safety: see the [module docs](self). In short, the reservation +
    /// envelope + initial settlement status are written atomically to storage
    /// before any in-memory state changes, so a crash here is indistinguishable
    /// from the call never having run.
    pub async fn queue_payment(
        &mut self,
        source_account: &str,
        signing_key: &SigningKey,
        tx_xdr: impl Into<String>,
        priority: TxPriority,
        ttl_hops: u8,
    ) -> Result<TransactionEnvelope, SyncEngineError> {
        // Ensure a baseline exists. A brand-new account that was never seeded or
        // queued before falls back to a `0` baseline so queue_payment is
        // self-contained; production callers should prefer seed_account().
        if self.sequences.last_reserved(source_account).is_none() {
            self.sequences.seed(source_account, 0);
        }

        // Reserve the sequence and build + sign the envelope fully offline.
        let (envelope, sequence) = OfflineEnvelopeBuilder::build_and_sign(
            &mut self.sequences,
            source_account,
            signing_key,
            tx_xdr,
            ttl_hops,
        )?;

        let enqueued_at = unix_now();

        // === Durable persistence, atomically, BEFORE any in-memory update. ===
        if let Err(err) = self
            .db
            .enqueue_transaction(&envelope, source_account, sequence, priority, enqueued_at)
            .await
        {
            // Roll back the in-memory reservation so a failed (and retried)
            // queue_payment does not silently skip a sequence number.
            let _ = self.sequences.release(source_account, sequence);
            return Err(err);
        }

        // === In-memory update, only once durability succeeded. ===
        self.queue
            .push_at(envelope.clone(), priority, enqueued_at)?;
        self.settlement.track(envelope.message_id);

        Ok(envelope)
    }

    /// Pop the highest-priority envelope ready for handoff to the mesh.
    ///
    /// The dispatch is recorded durably (settlement status advanced to
    /// `Propagating`) *before* the envelope leaves the in-memory queue, so a
    /// restart after dispatch but before settlement never re-dispatches the
    /// same envelope.
    ///
    /// This is a synchronous method by design: it performs one short, durable
    /// SQLite write via the engine's dedicated synchronous connection and then
    /// returns. It does not need an `.await`.
    pub fn next_to_dispatch(&mut self) -> Option<TransactionEnvelope> {
        let message_id = self.queue.peek()?.message_id;
        let updated_at = unix_now();

        // Persist the `Propagating` marker FIRST. If it fails, leave the
        // envelope queued and report nothing dispatchable so the caller can
        // retry — we never hand out an envelope whose dispatch wasn't recorded.
        if let Err(err) = self.persist_dispatch_status(message_id, updated_at) {
            tracing::error!(
                "failed to persist dispatch status for {}: {err}; leaving envelope queued",
                hex::encode(message_id)
            );
            return None;
        }

        // Durable marker written; safe to remove from the in-memory queue and
        // advance the tracker. `peek` then `pop` yield the same envelope
        // because nothing else mutates the queue in between (single &mut self).
        let envelope = self
            .queue
            .pop()
            .expect("peek reported a queued envelope; pop must return it");

        // In-memory Queued -> Propagating. The queue only ever holds Queued
        // envelopes, so this is legal; the durable marker is authoritative.
        if let Err(err) = self
            .settlement
            .transition(envelope.message_id, SettlementStatus::Propagating)
        {
            tracing::warn!(
                "in-memory tracker did not advance to Propagating for {}: {err} \
                 (durable marker already persisted)",
                hex::encode(envelope.message_id)
            );
        }

        Some(envelope)
    }

    /// Validate and apply a settlement state transition, in memory and in
    /// storage. Rejects illegal transitions (reuses
    /// [`SettlementStatus::can_transition_to`]) and keeps the in-memory tracker
    /// and durable storage in agreement.
    pub async fn mark_settlement(
        &mut self,
        message_id: [u8; 32],
        next: SettlementStatus,
        updated_at: u64,
    ) -> Result<(), SyncEngineError> {
        // 1. Validate the transition before mutating anything.
        let current = self
            .settlement
            .status(&message_id)
            .ok_or_else(|| SyncEngineError::EnvelopeNotFound(hex::encode(message_id)))?;
        if !current.can_transition_to(next) {
            return Err(SyncEngineError::InvalidStateTransition {
                from: current.as_str().to_string(),
                to: next.as_str().to_string(),
            });
        }

        // 2. Persist first; only on success...
        self.db
            .set_settlement_status(message_id, next, updated_at)
            .await?;

        // 3. ...advance the in-memory tracker. Validated above, so infallible.
        self.settlement.transition(message_id, next)?;
        Ok(())
    }

    /// Synchronous, durable write of the dispatch marker via the engine's
    /// dedicated (non-async) SQLite connection. Mirrors the
    /// `settlement_status` insert performed by `SyncEngineDb` but on the
    /// synchronous connection so it can run inside `next_to_dispatch`.
    fn persist_dispatch_status(
        &self,
        message_id: [u8; 32],
        updated_at: u64,
    ) -> Result<(), rusqlite::Error> {
        self.dispatch_conn.execute(
            "INSERT OR REPLACE INTO settlement_status \
             (message_id, status, updated_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                message_id.to_vec(),
                SettlementStatus::Propagating.as_str(),
                updated_at as i64,
            ],
        )?;
        Ok(())
    }
}

/// Open the synchronous dispatch connection onto the same database the async
/// `SyncEngineDb` uses. A short busy timeout lets it cooperate gracefully in
/// the rare event of overlap (the engine is normally driven sequentially, so
/// contention is not expected in practice).
fn open_dispatch_connection(db_path: &str) -> Result<rusqlite::Connection, SyncEngineError> {
    let conn = if db_path == ":memory:" {
        // A second `:memory:` connection is an isolated database. That is
        // harmless here: an in-memory engine can never be reopened, so the
        // dispatch marker is only consulted within the same session, where the
        // in-memory tracker is already authoritative.
        rusqlite::Connection::open_in_memory()?
    } else {
        let conn = rusqlite::Connection::open(Path::new(db_path))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn
    };
    Ok(conn)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
