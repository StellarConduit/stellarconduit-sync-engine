//! Durable, on-device storage for queued envelopes, sequence reservations,
//! settlement status, and detected conflicts — so none of it is lost if the
//! device restarts before settlement completes. Mirrors the SQLite-via-
//! `tokio-rusqlite` pattern used in `stellarconduit_core::persistence::db`.

use std::path::Path;

use tokio_rusqlite::Connection;

use stellarconduit_core::message::relay_proof::RelayChainProof;
use stellarconduit_core::message::types::TransactionEnvelope;

use crate::conflict::{Conflict, DisputeEscalation};
use crate::errors::SyncEngineError;
use crate::queue::TxPriority;
use crate::settlement::SettlementStatus;

pub struct SyncEngineDb {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueuedEnvelopeRecord {
    pub envelope: TransactionEnvelope,
    pub source_account: String,
    pub sequence: i64,
    pub priority: TxPriority,
    pub enqueued_at: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HistoryEntry {
    pub message_id: [u8; 32],
    pub from_status: String,
    pub to_status: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BatchUpdateReport {
    pub applied: Vec<[u8; 32]>,
    pub rejected: Vec<([u8; 32], String)>,
}

/// A [`DisputeEscalation`] as durably stored, along with the row id used by
/// [`SyncEngineDb::mark_escalation_submitted`] and the originating
/// [`Conflict`]'s account/sequence/envelope bookkeeping.
#[derive(Debug, Clone, PartialEq)]
pub struct PersistedEscalation {
    pub id: i64,
    pub source_account: String,
    pub sequence: i64,
    pub envelope_a: [u8; 32],
    pub envelope_b: [u8; 32],
    pub escalation: DisputeEscalation,
    pub created_at: u64,
}

impl SyncEngineDb {
    /// Initialize the embedded SQLite database, creating tables if needed.
    /// Pass `":memory:"` for an ephemeral, test-only database.
    pub async fn init(db_path: &str) -> Result<Self, SyncEngineError> {
        let conn = if db_path == ":memory:" {
            Connection::open_in_memory().await?
        } else {
            Connection::open(Path::new(db_path)).await?
        };

        conn.call(|conn| {
            conn.execute_batch(
                "CREATE TABLE IF NOT EXISTS queued_envelopes (
                    message_id      BLOB PRIMARY KEY,
                    source_account  TEXT NOT NULL,
                    sequence        INTEGER NOT NULL,
                    priority        INTEGER NOT NULL,
                    enqueued_at     INTEGER NOT NULL,
                    envelope_bytes  BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settlement_status (
                    message_id  BLOB PRIMARY KEY,
                    status      TEXT NOT NULL,
                    updated_at  INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sequence_reservations (
                    source_account  TEXT PRIMARY KEY,
                    last_reserved   INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS conflicts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_account  TEXT NOT NULL,
                    sequence        INTEGER NOT NULL,
                    envelope_a      BLOB NOT NULL,
                    envelope_b      BLOB NOT NULL,
                    detected_at     INTEGER NOT NULL,
                    resolved        INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settlement_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id  BLOB NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status   TEXT NOT NULL,
                    timestamp   INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS dispute_escalations (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_account  TEXT NOT NULL,
                    sequence        INTEGER NOT NULL,
                    envelope_a      BLOB NOT NULL,
                    envelope_b      BLOB NOT NULL,
                    initiator       TEXT NOT NULL,
                    respondent      TEXT NOT NULL,
                    tx_id           BLOB NOT NULL,
                    proof_bytes     BLOB NOT NULL,
                    created_at      INTEGER NOT NULL,
                    submitted       INTEGER NOT NULL DEFAULT 0
                );",
            )?;
            Ok(())
        })
        .await?;

        Ok(Self { conn })
    }

    pub async fn enqueue_envelope(
        &self,
        envelope: &TransactionEnvelope,
        source_account: &str,
        sequence: i64,
        priority: TxPriority,
        enqueued_at: u64,
    ) -> Result<(), SyncEngineError> {
        let span = tracing::info_span!(
            "envelope_storage_write",
            message_id = %hex::encode(envelope.message_id),
            operation = "enqueue_envelope"
        );
        let _entered = span.enter();
        let message_id = envelope.message_id.to_vec();
        let envelope_bytes = rmp_serde::to_vec(envelope)?;
        let source_account = source_account.to_string();
        let priority: i64 = priority.into();

        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO queued_envelopes
                        (message_id, source_account, sequence, priority, enqueued_at, envelope_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        message_id,
                        source_account,
                        sequence,
                        priority,
                        enqueued_at as i64,
                        envelope_bytes
                    ],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Atomically persist a newly-signed payment in a single SQLite
    /// transaction: its sequence reservation, the queued envelope, and its
    /// initial `Queued` settlement status.
    ///
    /// All three rows share one transaction so that a crash at any instant
    /// leaves the database either fully updated (the call completed) or
    /// entirely unchanged (as if the call never happened) — never a
    /// half-written state. This is what lets [`crate::engine::SyncEngine`] be
    /// restart-safe: a Stellar sequence number cannot be skipped on-chain, so
    /// writing the reservation without the envelope (or the envelope without
    /// the reservation) would either burn a gap or invite a reuse, both of
    /// which are double-spend hazards against the user's own account.
    pub async fn enqueue_transaction(
        &self,
        envelope: &TransactionEnvelope,
        source_account: &str,
        sequence: i64,
        priority: TxPriority,
        enqueued_at: u64,
    ) -> Result<(), SyncEngineError> {
        let span = tracing::info_span!(
            "envelope_storage_write",
            message_id = %hex::encode(envelope.message_id),
            operation = "enqueue_transaction"
        );
        let _entered = span.enter();
        let message_id = envelope.message_id.to_vec();
        let envelope_bytes = rmp_serde::to_vec(envelope)?;
        let source_account = source_account.to_string();
        let priority: i64 = priority.into();
        let status = SettlementStatus::Queued.as_str().to_string();

        self.conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.execute(
                    "INSERT OR REPLACE INTO sequence_reservations
                        (source_account, last_reserved) VALUES (?1, ?2)",
                    rusqlite::params![source_account, sequence],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO queued_envelopes
                        (message_id, source_account, sequence, priority, enqueued_at, envelope_bytes)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![
                        message_id,
                        source_account,
                        sequence,
                        priority,
                        enqueued_at as i64,
                        envelope_bytes
                    ],
                )?;
                tx.execute(
                    "INSERT OR REPLACE INTO settlement_status (message_id, status, updated_at)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![message_id, status, enqueued_at as i64],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn get_queued_envelope(
        &self,
        message_id: [u8; 32],
    ) -> Result<Option<QueuedEnvelopeRecord>, SyncEngineError> {
        let id = message_id.to_vec();
        let row = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT source_account, sequence, priority, enqueued_at, envelope_bytes
                     FROM queued_envelopes WHERE message_id = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![id])?;
                if let Some(row) = rows.next()? {
                    let source_account: String = row.get(0)?;
                    let sequence: i64 = row.get(1)?;
                    let priority: i64 = row.get(2)?;
                    let enqueued_at: i64 = row.get(3)?;
                    let envelope_bytes: Vec<u8> = row.get(4)?;
                    Ok(Some((
                        source_account,
                        sequence,
                        priority,
                        enqueued_at,
                        envelope_bytes,
                    )))
                } else {
                    Ok(None)
                }
            })
            .await?;

        match row {
            None => Ok(None),
            Some((source_account, sequence, priority, enqueued_at, envelope_bytes)) => {
                let envelope: TransactionEnvelope = rmp_serde::from_slice(&envelope_bytes)?;
                Ok(Some(QueuedEnvelopeRecord {
                    envelope,
                    source_account,
                    sequence,
                    priority: TxPriority::try_from(priority)?,
                    enqueued_at: enqueued_at as u64,
                }))
            }
        }
    }

    pub async fn list_queued_envelopes(
        &self,
    ) -> Result<Vec<QueuedEnvelopeRecord>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT source_account, sequence, priority, enqueued_at, envelope_bytes
                     FROM queued_envelopes",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        let source_account: String = row.get(0)?;
                        let sequence: i64 = row.get(1)?;
                        let priority: i64 = row.get(2)?;
                        let enqueued_at: i64 = row.get(3)?;
                        let envelope_bytes: Vec<u8> = row.get(4)?;
                        Ok((
                            source_account,
                            sequence,
                            priority,
                            enqueued_at,
                            envelope_bytes,
                        ))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        rows.into_iter()
            .map(
                |(source_account, sequence, priority, enqueued_at, envelope_bytes)| {
                    let envelope: TransactionEnvelope = rmp_serde::from_slice(&envelope_bytes)?;
                    Ok(QueuedEnvelopeRecord {
                        envelope,
                        source_account,
                        sequence,
                        priority: TxPriority::try_from(priority)?,
                        enqueued_at: enqueued_at as u64,
                    })
                },
            )
            .collect()
    }

    pub async fn remove_queued_envelope(
        &self,
        message_id: [u8; 32],
    ) -> Result<(), SyncEngineError> {
        let id = message_id.to_vec();
        self.conn
            .call(move |conn| {
                conn.execute("DELETE FROM queued_envelopes WHERE message_id = ?1", [id])?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn set_settlement_status(
        &self,
        message_id: [u8; 32],
        status: SettlementStatus,
        updated_at: u64,
    ) -> Result<(), SyncEngineError> {
        let span = tracing::info_span!(
            "settlement_storage_write",
            message_id = %hex::encode(message_id),
            to_status = status.as_str()
        );
        let _entered = span.enter();
        let id = message_id.to_vec();
        let status_str = status.as_str().to_string();
        self.conn
            .call(move |conn| {
                let from_status: String = conn
                    .query_row(
                        "SELECT status FROM settlement_status WHERE message_id = ?1",
                        rusqlite::params![id],
                        |row| row.get(0),
                    )
                    .unwrap_or_default();

                conn.execute(
                    "INSERT OR REPLACE INTO settlement_status (message_id, status, updated_at)
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params![id, status_str, updated_at as i64],
                )?;

                conn.execute(
                    "INSERT INTO settlement_history (message_id, from_status, to_status, timestamp)
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![id, from_status, status_str, updated_at as i64],
                )?;

                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Update settlement statuses in bulk inside a single database transaction.
    /// Uses a Best-Effort policy: valid transitions are committed while illegal
    /// transitions (or untracked envelopes) are skipped and reported as `rejected`
    /// in the returned `BatchUpdateReport`.
    /// This prevents a single stale message in a large relayed batch from
    /// rejecting the entire batch and causing massive network re-transmission.
    pub async fn set_settlement_status_batch(
        &self,
        updates: &[([u8; 32], SettlementStatus, u64)],
    ) -> Result<BatchUpdateReport, SyncEngineError> {
        let updates = updates.to_vec();

        let report = self
            .conn
            .call(move |conn| {
                let tx = conn.transaction()?;
                let mut applied = Vec::new();
                let mut rejected = Vec::new();

                for (message_id, to_status, updated_at) in updates {
                    let id = message_id.to_vec();

                    let from_status_res: rusqlite::Result<String> = tx
                        .query_row(
                            "SELECT status FROM settlement_status WHERE message_id = ?1",
                            rusqlite::params![id],
                            |row| row.get(0),
                        );

                    let from_status_str = match from_status_res {
                        Ok(s) => s,
                        Err(rusqlite::Error::QueryReturnedNoRows) => {
                            rejected.push((message_id, "Untracked envelope".to_string()));
                            continue;
                        }
                        Err(e) => return Err(e.into()),
                    };

                    let is_valid = match from_status_str.parse::<SettlementStatus>() {
                        Ok(current_status) => current_status.can_transition_to(to_status),
                        Err(_) => false,
                    };

                    if !is_valid {
                        rejected.push((
                            message_id,
                            format!("Illegal transition from '{}' to '{}'", from_status_str, to_status.as_str()),
                        ));
                        continue;
                    }

                    let to_status_str = to_status.as_str().to_string();
                    tx.execute(
                        "UPDATE settlement_status SET status = ?1, updated_at = ?2 WHERE message_id = ?3",
                        rusqlite::params![to_status_str, updated_at as i64, id],
                    )?;

                    tx.execute(
                        "INSERT INTO settlement_history (message_id, from_status, to_status, timestamp)
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![id, from_status_str, to_status_str, updated_at as i64],
                    )?;

                    applied.push(message_id);
                }

                tx.commit()?;
                Ok(BatchUpdateReport { applied, rejected })
            })
            .await?;

        Ok(report)
    }

    pub async fn get_settlement_status(
        &self,
        message_id: [u8; 32],
    ) -> Result<Option<SettlementStatus>, SyncEngineError> {
        let id = message_id.to_vec();
        let status: Option<String> = self
            .conn
            .call(move |conn| {
                let mut stmt =
                    conn.prepare("SELECT status FROM settlement_status WHERE message_id = ?1")?;
                let mut rows = stmt.query(rusqlite::params![id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(row.get::<_, String>(0)?))
                } else {
                    Ok(None)
                }
            })
            .await?;

        status.map(|s| s.parse()).transpose()
    }

    pub async fn history_for(
        &self,
        message_id: [u8; 32],
    ) -> Result<Vec<HistoryEntry>, SyncEngineError> {
        let id = message_id.to_vec();
        let rows = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT message_id, from_status, to_status, timestamp
                     FROM settlement_history
                     WHERE message_id = ?1
                     ORDER BY id",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![id], |row| {
                        let message_id: Vec<u8> = row.get(0)?;
                        let from_status: String = row.get(1)?;
                        let to_status: String = row.get(2)?;
                        let timestamp: i64 = row.get(3)?;
                        Ok(HistoryEntry {
                            message_id: message_id.try_into().unwrap_or([0u8; 32]),
                            from_status,
                            to_status,
                            timestamp: timestamp as u64,
                        })
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn save_sequence_reservation(
        &self,
        source_account: &str,
        last_reserved: i64,
    ) -> Result<(), SyncEngineError> {
        let source_account = source_account.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR REPLACE INTO sequence_reservations (source_account, last_reserved)
                     VALUES (?1, ?2)",
                    rusqlite::params![source_account, last_reserved],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn load_sequence_reservation(
        &self,
        source_account: &str,
    ) -> Result<Option<i64>, SyncEngineError> {
        let source_account = source_account.to_string();
        let value = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT last_reserved FROM sequence_reservations WHERE source_account = ?1",
                )?;
                let mut rows = stmt.query(rusqlite::params![source_account])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(row.get::<_, i64>(0)?))
                } else {
                    Ok(None)
                }
            })
            .await?;
        Ok(value)
    }

    /// Load every known account's last-reserved sequence number. Used by
    /// [`crate::engine::SyncEngine::open`] to rehydrate all in-memory sequence
    /// state in one pass after a restart; the per-account
    /// [`Self::load_sequence_reservation`] is for single-account lookups.
    pub async fn list_all_sequence_reservations(
        &self,
    ) -> Result<std::collections::HashMap<String, i64>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn
                    .prepare("SELECT source_account, last_reserved FROM sequence_reservations")?;
                let rows = stmt
                    .query_map([], |row| {
                        let source_account: String = row.get(0)?;
                        let last_reserved: i64 = row.get(1)?;
                        Ok((source_account, last_reserved))
                    })?
                    .collect::<Result<std::collections::HashMap<_, _>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows)
    }

    pub async fn record_conflict(
        &self,
        conflict: &Conflict,
        detected_at: u64,
    ) -> Result<(), SyncEngineError> {
        let source_account = conflict.source_account.clone();
        let sequence = conflict.sequence;
        let envelope_a = conflict.envelope_a.to_vec();
        let envelope_b = conflict.envelope_b.to_vec();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO conflicts (source_account, sequence, envelope_a, envelope_b, detected_at, resolved)
                     VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                    rusqlite::params![source_account, sequence, envelope_a, envelope_b, detected_at as i64],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn list_unresolved_conflicts(&self) -> Result<Vec<Conflict>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT source_account, sequence, envelope_a, envelope_b
                     FROM conflicts WHERE resolved = 0",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        let source_account: String = row.get(0)?;
                        let sequence: i64 = row.get(1)?;
                        let envelope_a: Vec<u8> = row.get(2)?;
                        let envelope_b: Vec<u8> = row.get(3)?;
                        Ok((source_account, sequence, envelope_a, envelope_b))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(source_account, sequence, envelope_a, envelope_b)| Conflict {
                    source_account,
                    sequence,
                    envelope_a: envelope_a.try_into().unwrap_or([0u8; 32]),
                    envelope_b: envelope_b.try_into().unwrap_or([0u8; 32]),
                },
            )
            .collect())
    }

    /// Durably persist `escalation` (built by
    /// `crate::conflict::escalation::build_escalation` for `conflict`) and
    /// set [`SettlementStatus::Disputed`] on both of `conflict`'s envelopes —
    /// per the architecture, an escalated conflict's envelopes are neither
    /// settled nor failed until on-chain arbitration resolves them.
    ///
    /// Returns the new row's id, which `mark_escalation_submitted` uses to
    /// identify it later.
    pub async fn save_escalation(
        &self,
        conflict: &Conflict,
        escalation: &DisputeEscalation,
        created_at: u64,
    ) -> Result<i64, SyncEngineError> {
        let source_account = conflict.source_account.clone();
        let sequence = conflict.sequence;
        let envelope_a = conflict.envelope_a.to_vec();
        let envelope_b = conflict.envelope_b.to_vec();
        let initiator = escalation.initiator.clone();
        let respondent = escalation.respondent.clone();
        let tx_id = escalation.tx_id.to_vec();
        let proof_bytes = rmp_serde::to_vec(&escalation.proof)?;

        let id = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO dispute_escalations
                        (source_account, sequence, envelope_a, envelope_b, initiator, respondent, tx_id, proof_bytes, created_at, submitted)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                    rusqlite::params![
                        source_account,
                        sequence,
                        envelope_a,
                        envelope_b,
                        initiator,
                        respondent,
                        tx_id,
                        proof_bytes,
                        created_at as i64
                    ],
                )?;
                Ok(conn.last_insert_rowid())
            })
            .await?;

        self.set_settlement_status(conflict.envelope_a, SettlementStatus::Disputed, created_at)
            .await?;
        self.set_settlement_status(conflict.envelope_b, SettlementStatus::Disputed, created_at)
            .await?;

        Ok(id)
    }

    /// List every escalation not yet marked submitted (`submitted = 0`) —
    /// i.e. still awaiting pickup by a relay node with live Soroban RPC
    /// connectivity.
    pub async fn list_pending_escalations(
        &self,
    ) -> Result<Vec<PersistedEscalation>, SyncEngineError> {
        let rows = self
            .conn
            .call(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT id, source_account, sequence, envelope_a, envelope_b, initiator,
                            respondent, tx_id, proof_bytes, created_at
                     FROM dispute_escalations WHERE submitted = 0",
                )?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                            row.get::<_, Vec<u8>>(8)?,
                            row.get::<_, i64>(9)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        rows.into_iter()
            .map(
                |(
                    id,
                    source_account,
                    sequence,
                    envelope_a,
                    envelope_b,
                    initiator,
                    respondent,
                    tx_id,
                    proof_bytes,
                    created_at,
                )| {
                    let proof: RelayChainProof = rmp_serde::from_slice(&proof_bytes)?;
                    Ok(PersistedEscalation {
                        id,
                        source_account,
                        sequence,
                        envelope_a: envelope_a.try_into().unwrap_or([0u8; 32]),
                        envelope_b: envelope_b.try_into().unwrap_or([0u8; 32]),
                        escalation: DisputeEscalation {
                            initiator,
                            respondent,
                            tx_id: tx_id.try_into().unwrap_or([0u8; 32]),
                            proof,
                        },
                        created_at: created_at as u64,
                    })
                },
            )
            .collect()
    }

    /// Mark the escalation with row id `id` as submitted, excluding it from
    /// future [`list_pending_escalations`](Self::list_pending_escalations)
    /// results. Called by a relay node once it has successfully submitted
    /// the payload to `raise_dispute` on-chain.
    pub async fn mark_escalation_submitted(&self, id: i64) -> Result<(), SyncEngineError> {
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE dispute_escalations SET submitted = 1 WHERE id = ?1",
                    rusqlite::params![id],
                )?;
                Ok(())
            })
            .await?;
        Ok(())
    }

    pub async fn sweep_stale_envelopes(
        &self,
        max_age_secs: u64,
        now: u64,
    ) -> Result<Vec<[u8; 32]>, SyncEngineError> {
        let cutoff = now.saturating_sub(max_age_secs) as i64;
        let stale_id_bytes: Vec<Vec<u8>> = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT q.message_id
                     FROM queued_envelopes q
                     JOIN settlement_status s ON s.message_id = q.message_id
                     WHERE q.enqueued_at < ?1
                       AND s.status IN ('queued', 'propagating')",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![cutoff], |row| {
                        let message_id: Vec<u8> = row.get(0)?;
                        Ok(message_id)
                    })?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?;
                Ok(rows)
            })
            .await?;

        let stale_ids: Vec<[u8; 32]> = stale_id_bytes
            .into_iter()
            .filter_map(|v| v.try_into().ok())
            .collect();

        for &mid in &stale_ids {
            self.set_settlement_status(mid, SettlementStatus::Failed, now)
                .await?;
        }

        Ok(stale_ids)
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

    #[tokio::test]
    async fn test_enqueue_and_get_queued_envelope() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let envelope = mock_envelope(1);
        db.enqueue_envelope(&envelope, "GABC", 101, TxPriority::Emergency, 1000)
            .await
            .unwrap();

        let record = db.get_queued_envelope([1u8; 32]).await.unwrap().unwrap();
        assert_eq!(record.envelope, envelope);
        assert_eq!(record.source_account, "GABC");
        assert_eq!(record.sequence, 101);
        assert_eq!(record.priority, TxPriority::Emergency);
        assert_eq!(record.enqueued_at, 1000);
    }

    #[tokio::test]
    async fn test_get_missing_envelope_returns_none() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        assert!(db.get_queued_envelope([9u8; 32]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_list_queued_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();
        db.enqueue_envelope(&mock_envelope(2), "GABC", 102, TxPriority::Low, 1001)
            .await
            .unwrap();

        let records = db.list_queued_envelopes().await.unwrap();
        assert_eq!(records.len(), 2);
    }

    #[tokio::test]
    async fn test_remove_queued_envelope() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();
        db.remove_queued_envelope([1u8; 32]).await.unwrap();
        assert!(db.get_queued_envelope([1u8; 32]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_settlement_status_roundtrip() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.set_settlement_status([1u8; 32], SettlementStatus::Propagating, 2000)
            .await
            .unwrap();
        let status = db.get_settlement_status([1u8; 32]).await.unwrap();
        assert_eq!(status, Some(SettlementStatus::Propagating));
    }

    #[tokio::test]
    async fn test_sequence_reservation_roundtrip() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        assert_eq!(db.load_sequence_reservation("GABC").await.unwrap(), None);
        db.save_sequence_reservation("GABC", 101).await.unwrap();
        assert_eq!(
            db.load_sequence_reservation("GABC").await.unwrap(),
            Some(101)
        );
    }

    #[tokio::test]
    async fn test_batch_applies_all_valid_transitions() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        // Insert initial queued status
        db.set_settlement_status([1u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();
        db.set_settlement_status([2u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();

        let report = db
            .set_settlement_status_batch(&[
                ([1u8; 32], SettlementStatus::Propagating, 1001),
                ([2u8; 32], SettlementStatus::Failed, 1001),
            ])
            .await
            .unwrap();

        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.rejected.len(), 0);

        assert_eq!(
            db.get_settlement_status([1u8; 32]).await.unwrap(),
            Some(SettlementStatus::Propagating)
        );
        assert_eq!(
            db.get_settlement_status([2u8; 32]).await.unwrap(),
            Some(SettlementStatus::Failed)
        );
    }

    #[tokio::test]
    async fn test_batch_handles_mixed_valid_and_invalid_per_documented_policy() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.set_settlement_status([1u8; 32], SettlementStatus::Settled, 1000)
            .await
            .unwrap();
        db.set_settlement_status([2u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();

        let report = db
            .set_settlement_status_batch(&[
                // Invalid: Settled -> Propagating
                ([1u8; 32], SettlementStatus::Propagating, 1001),
                // Valid: Queued -> Propagating
                ([2u8; 32], SettlementStatus::Propagating, 1001),
                // Invalid: Untracked envelope
                ([3u8; 32], SettlementStatus::Propagating, 1001),
            ])
            .await
            .unwrap();

        // Best effort: only valid ones are applied
        assert_eq!(report.applied, vec![[2u8; 32]]);
        assert_eq!(report.rejected.len(), 2);

        // Status unchanged for invalid transition
        assert_eq!(
            db.get_settlement_status([1u8; 32]).await.unwrap(),
            Some(SettlementStatus::Settled)
        );
        // Status changed for valid transition
        assert_eq!(
            db.get_settlement_status([2u8; 32]).await.unwrap(),
            Some(SettlementStatus::Propagating)
        );
    }

    #[tokio::test]
    async fn test_batch_report_accurately_reflects_outcomes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        db.set_settlement_status([1u8; 32], SettlementStatus::Queued, 1000)
            .await
            .unwrap();

        let report = db
            .set_settlement_status_batch(&[
                ([1u8; 32], SettlementStatus::Propagating, 1001),
                ([9u8; 32], SettlementStatus::Propagating, 1001),
            ])
            .await
            .unwrap();

        assert_eq!(report.applied, vec![[1u8; 32]]);
        assert_eq!(report.rejected[0].0, [9u8; 32]);
        assert_eq!(report.rejected[0].1, "Untracked envelope");
    }

    #[tokio::test]
    async fn test_batch_is_faster_than_sequential() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let count = 500;

        for i in 0..count {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            db.set_settlement_status(id, SettlementStatus::Queued, 1000)
                .await
                .unwrap();
        }

        let mut sequential_updates = Vec::new();
        let mut batch_updates = Vec::new();
        for i in 0..count {
            let mut id = [0u8; 32];
            id[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            if i % 2 == 0 {
                sequential_updates.push((id, SettlementStatus::Propagating, 1001));
            } else {
                batch_updates.push((id, SettlementStatus::Propagating, 1001));
            }
        }

        let start_seq = std::time::Instant::now();
        for (id, status, time) in sequential_updates {
            db.set_settlement_status(id, status, time).await.unwrap();
        }
        let seq_duration = start_seq.elapsed();

        let start_batch = std::time::Instant::now();
        db.set_settlement_status_batch(&batch_updates)
            .await
            .unwrap();
        let batch_duration = start_batch.elapsed();

        assert!(
            batch_duration < seq_duration,
            "Batch: {:?}, Seq: {:?}",
            batch_duration,
            seq_duration
        );
    }

    #[tokio::test]
    async fn test_conflict_record_and_list_unresolved() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let conflict = Conflict {
            source_account: "GABC".to_string(),
            sequence: 101,
            envelope_a: [1u8; 32],
            envelope_b: [2u8; 32],
        };
        db.record_conflict(&conflict, 3000).await.unwrap();

        let unresolved = db.list_unresolved_conflicts().await.unwrap();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0], conflict);
    }

    // ── Issue 2: settlement_history tests ──

    #[tokio::test]
    async fn test_successful_transitions_are_recorded_in_order() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [1u8; 32];

        db.set_settlement_status(id, SettlementStatus::Queued, 1000)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Propagating, 1001)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Settled, 1002)
            .await
            .unwrap();

        let history = db.history_for(id).await.unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].from_status, "");
        assert_eq!(history[0].to_status, "queued");
        assert_eq!(history[0].timestamp, 1000);
        assert_eq!(history[1].from_status, "queued");
        assert_eq!(history[1].to_status, "propagating");
        assert_eq!(history[1].timestamp, 1001);
        assert_eq!(history[2].from_status, "propagating");
        assert_eq!(history[2].to_status, "settled");
        assert_eq!(history[2].timestamp, 1002);
    }

    #[tokio::test]
    async fn test_history_for_unknown_envelope_is_empty() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let history = db.history_for([99u8; 32]).await.unwrap();
        assert!(history.is_empty());
    }

    #[tokio::test]
    async fn test_full_lifecycle_produces_complete_history() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [2u8; 32];

        db.set_settlement_status(id, SettlementStatus::Queued, 1000)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Propagating, 1001)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Disputed, 1002)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Settled, 1003)
            .await
            .unwrap();

        let history = db.history_for(id).await.unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[0].to_status, "queued");
        assert_eq!(history[1].to_status, "propagating");
        assert_eq!(history[2].to_status, "disputed");
        assert_eq!(history[3].to_status, "settled");
    }

    // ── Issue 3: staleness sweep tests ──

    #[tokio::test]
    async fn test_sweep_identifies_stale_queued_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let stale_id = [1u8; 32];
        let fresh_id = [2u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(stale_id, SettlementStatus::Queued, 100)
            .await
            .unwrap();

        db.enqueue_envelope(&mock_envelope(2), "GABC", 102, TxPriority::Normal, 900)
            .await
            .unwrap();
        db.set_settlement_status(fresh_id, SettlementStatus::Queued, 900)
            .await
            .unwrap();

        // now=1000, max_age=500 => cutoff=500; stale (enqueued_at=100) is past, fresh (900) is not
        let stale = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert_eq!(stale, vec![stale_id]);
    }

    #[tokio::test]
    async fn test_sweep_ignores_fresh_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [1u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 800)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Queued, 800)
            .await
            .unwrap();

        let stale = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(stale.is_empty());
    }

    #[tokio::test]
    async fn test_sweep_ignores_already_terminal_envelopes() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let settled_id = [1u8; 32];
        let failed_id = [2u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(settled_id, SettlementStatus::Settled, 100)
            .await
            .unwrap();

        db.enqueue_envelope(&mock_envelope(2), "GABC", 102, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(failed_id, SettlementStatus::Failed, 100)
            .await
            .unwrap();

        let stale = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(stale.is_empty());
    }

    #[tokio::test]
    async fn test_sweep_is_idempotent() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let id = [1u8; 32];

        db.enqueue_envelope(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 100)
            .await
            .unwrap();
        db.set_settlement_status(id, SettlementStatus::Queued, 100)
            .await
            .unwrap();

        let first = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(!first.is_empty());

        let second = db.sweep_stale_envelopes(500, 1000).await.unwrap();
        assert!(second.is_empty());
    }

    // ── Issue 2: dispute escalation tests ──

    use crate::conflict::escalation::{build_escalation, EscalationInput};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn temp_db_path() -> (TempDir, String) {
        let dir = TempDir::new().expect("create temp dir");
        let path = dir.path().join("escalation-test.sqlite3");
        (dir, path.to_string_lossy().into_owned())
    }

    fn escalation_input(
        message_id: [u8; 32],
        origin_pubkey: [u8; 32],
        seen_at: u64,
    ) -> EscalationInput {
        let key = SigningKey::generate(&mut OsRng);
        EscalationInput {
            message_id,
            origin_pubkey,
            first_seen_locally_at: seen_at,
            proof: RelayChainProof::sign(&key, &message_id, &[9u8; 32], 101),
        }
    }

    fn sample_conflict() -> Conflict {
        Conflict {
            source_account: "GABC".to_string(),
            sequence: 101,
            envelope_a: [1u8; 32],
            envelope_b: [2u8; 32],
        }
    }

    #[tokio::test]
    async fn test_escalation_persists_across_restart() {
        let (_dir, path) = temp_db_path();
        let conflict = sample_conflict();
        let escalation = {
            let db = SyncEngineDb::init(&path).await.unwrap();
            let envelope_a = escalation_input(conflict.envelope_a, [10u8; 32], 1000);
            let envelope_b = escalation_input(conflict.envelope_b, [20u8; 32], 2000);
            let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();
            db.save_escalation(&conflict, &escalation, 3000)
                .await
                .unwrap();
            escalation
            // `db` dropped here, closing the connection -- simulates a restart.
        };

        let reopened = SyncEngineDb::init(&path).await.unwrap();
        let pending = reopened.list_pending_escalations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_account, conflict.source_account);
        assert_eq!(pending[0].sequence, conflict.sequence);
        assert_eq!(pending[0].envelope_a, conflict.envelope_a);
        assert_eq!(pending[0].envelope_b, conflict.envelope_b);
        assert_eq!(pending[0].escalation, escalation);

        // Escalating both envelopes must have set them Disputed too.
        assert_eq!(
            reopened
                .get_settlement_status(conflict.envelope_a)
                .await
                .unwrap(),
            Some(SettlementStatus::Disputed)
        );
        assert_eq!(
            reopened
                .get_settlement_status(conflict.envelope_b)
                .await
                .unwrap(),
            Some(SettlementStatus::Disputed)
        );
    }

    #[tokio::test]
    async fn test_mark_submitted_excludes_from_pending_list() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let conflict = sample_conflict();
        let envelope_a = escalation_input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = escalation_input(conflict.envelope_b, [20u8; 32], 2000);
        let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();

        let id = db
            .save_escalation(&conflict, &escalation, 3000)
            .await
            .unwrap();

        assert_eq!(db.list_pending_escalations().await.unwrap().len(), 1);

        db.mark_escalation_submitted(id).await.unwrap();

        assert!(db.list_pending_escalations().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_pending_escalations_excludes_only_submitted() {
        let db = SyncEngineDb::init(":memory:").await.unwrap();

        let conflict_1 = sample_conflict();
        let envelope_a_1 = escalation_input(conflict_1.envelope_a, [10u8; 32], 1000);
        let envelope_b_1 = escalation_input(conflict_1.envelope_b, [20u8; 32], 2000);
        let escalation_1 = build_escalation(&conflict_1, &envelope_a_1, &envelope_b_1).unwrap();
        let id_1 = db
            .save_escalation(&conflict_1, &escalation_1, 3000)
            .await
            .unwrap();

        let conflict_2 = Conflict {
            source_account: "GXYZ".to_string(),
            sequence: 202,
            envelope_a: [3u8; 32],
            envelope_b: [4u8; 32],
        };
        let envelope_a_2 = escalation_input(conflict_2.envelope_a, [30u8; 32], 1500);
        let envelope_b_2 = escalation_input(conflict_2.envelope_b, [40u8; 32], 2500);
        let escalation_2 = build_escalation(&conflict_2, &envelope_a_2, &envelope_b_2).unwrap();
        db.save_escalation(&conflict_2, &escalation_2, 3500)
            .await
            .unwrap();

        db.mark_escalation_submitted(id_1).await.unwrap();

        let pending = db.list_pending_escalations().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].source_account, "GXYZ");
    }

    #[tokio::test]
    async fn test_escalation_survives_conflicting_concurrent_writes() {
        // Two conflicting escalations for the same tx_id, written concurrently,
        // must both land intact -- tokio_rusqlite serializes calls through a
        // single connection actor, so this must never corrupt storage.
        let db = std::sync::Arc::new(SyncEngineDb::init(":memory:").await.unwrap());

        let conflict = sample_conflict();
        let envelope_a = escalation_input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = escalation_input(conflict.envelope_b, [20u8; 32], 2000);
        let escalation_1 = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();
        let escalation_2 = escalation_1.clone();

        let conflict_1 = conflict.clone();
        let conflict_2 = conflict.clone();
        let db_1 = db.clone();
        let db_2 = db.clone();

        let (r1, r2) = tokio::join!(
            tokio::spawn(
                async move { db_1.save_escalation(&conflict_1, &escalation_1, 3000).await }
            ),
            tokio::spawn(
                async move { db_2.save_escalation(&conflict_2, &escalation_2, 3001).await }
            ),
        );
        r1.unwrap().unwrap();
        r2.unwrap().unwrap();

        let pending = db.list_pending_escalations().await.unwrap();
        assert_eq!(
            pending.len(),
            2,
            "both concurrent writes must be durably recorded, not corrupted"
        );
    }
}
