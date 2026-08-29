//! Restart-safety tests for `SyncEngine`.
//!
//! These deliberately use a real **temp-file-backed** SQLite database rather
//! than `:memory:`, because an in-memory database does not survive being
//! reopened and therefore cannot exercise *any* restart behavior — which is
//! the whole point of the crash-consistency contract. Each simulated "crash"
//! is modelled by dropping the `SyncEngine` (closing both of its SQLite
//! connections) and then calling `SyncEngine::open` again on the same path.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tempfile::TempDir;

use stellarconduit_core::message::envelope::validate_envelope;

use stellarconduit_sync_engine::engine::SyncEngine;
use stellarconduit_sync_engine::errors::SyncEngineError;
use stellarconduit_sync_engine::queue::TxPriority;
use stellarconduit_sync_engine::settlement::SettlementStatus;

/// Real, valid `TransactionEnvelope` XDR, one fixed ed25519 seed byte per
/// account (`0x44`..`0x99`), generated with the `stellar-xdr` crate — the
/// same approach as `tests/fixtures/*.b64` (see that directory's README),
/// just inlined here since each test below needs its own account and, in
/// some cases, several successive sequence numbers rather than the one or two
/// shared structural variants `tests/fixtures` provides. `SyncEngine::queue_payment`
/// (via `OfflineEnvelopeBuilder::build_and_sign`) parses this XDR and requires
/// its embedded source account and sequence to agree with the caller-claimed
/// `source_account` and the locally-reserved sequence — see
/// `src/envelope/xdr.rs` — so a placeholder string no longer works here.
mod fixtures {
    pub const QUEUED_ACCOUNT: &str = "GBCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIZCA";
    pub const QUEUED_SEQ_1: &str = "AAAAAgAAAABERERERERERERERERERERERERERERERERERERERERERAAAAGQAAAAAAAAAAQAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    pub const SEQ_ACCOUNT: &str = "GBKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKK3J";
    pub const SEQ_SEQ_1: &str = "AAAAAgAAAABVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQAAAGQAAAAAAAAAAQAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    pub const SEQ_SEQ_2: &str = "AAAAAgAAAABVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQAAAGQAAAAAAAAAAgAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    pub const SEQ_SEQ_3: &str = "AAAAAgAAAABVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQAAAGQAAAAAAAAAAwAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    pub const SEQ_SEQ_4: &str = "AAAAAgAAAABVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVQAAAGQAAAAAAAAABAAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    pub const REUSE_ACCOUNT: &str = "GBTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGN6QS";
    pub const REUSE_SEQ_1: &str = "AAAAAgAAAABmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZgAAAGQAAAAAAAAAAQAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    pub const REUSE_SEQ_2: &str = "AAAAAgAAAABmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZgAAAGQAAAAAAAAAAgAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    pub const DISP_ACCOUNT: &str = "GB3XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XPNJ3";
    pub const DISP_SEQ_1: &str = "AAAAAgAAAAB3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3dwAAAGQAAAAAAAAAAQAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    pub const SETTLE_ACCOUNT: &str = "GCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIQAN7";
    pub const SETTLE_SEQ_1: &str = "AAAAAgAAAACIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiAAAAGQAAAAAAAAAAQAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    pub const PERSIST_ACCOUNT: &str = "GCMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZSTUW";
    pub const PERSIST_SEQ_1: &str = "AAAAAgAAAACZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmQAAAGQAAAAAAAAAAQAAAAAAAAABAAAADHJlc3RhcnQtdGVzdAAAAAEAAAAAAAAAAQAAAACqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqgAAAAAAAAAABfXhAAAAAAAAAAABAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
}

fn signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

/// Each test gets its own temp directory; the SQLite file lives inside it and
/// is cleaned up automatically when the returned `TempDir` (kept alive for the
/// test's scope) is dropped.
fn temp_db_path() -> (TempDir, String) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("syncengine.sqlite3");
    let path_str = path.to_string_lossy().into_owned();
    (dir, path_str)
}

#[tokio::test]
async fn test_open_empty_db_is_empty() {
    let (_dir, path) = temp_db_path();
    let mut engine = SyncEngine::open(&path).await.expect("open a fresh db");

    // No payments queued, so nothing to dispatch.
    assert!(
        engine.next_to_dispatch().is_none(),
        "a freshly-opened engine on an empty db has nothing to dispatch"
    );
    // No reservations for any account.
    assert_eq!(
        engine.last_reserved_sequence("GSOMEACCOUNT").await.unwrap(),
        None,
        "a freshly-opened engine on an empty db has no reservations"
    );
}

#[tokio::test]
async fn test_queue_payment_survives_restart() {
    let (_dir, path) = temp_db_path();
    let key = signing_key();
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(key.clone());
    let account = fixtures::QUEUED_ACCOUNT;

    // Queue one payment, then drop the engine (simulated crash) immediately.
    let envelope = {
        let mut engine = SyncEngine::open(&path).await.unwrap();
        engine
            .queue_payment(
                account,
                &signer,
                fixtures::QUEUED_SEQ_1,
                TxPriority::Emergency,
                10,
            )
            .await
            .expect("queue a payment")
    };
    assert!(validate_envelope(&envelope).is_ok());

    // Reopen the same file-backed database: the payment must still be queued
    // with the exact same envelope and sequence reservation.
    let mut engine = SyncEngine::open(&path).await.expect("reopen after drop");

    let dispatched = engine
        .next_to_dispatch()
        .expect("the queued payment survived the restart and is dispatchable");
    assert_eq!(
        dispatched, envelope,
        "the same envelope (byte-for-byte) is recovered after restart"
    );
    assert_eq!(
        engine.last_reserved_sequence(account).await.unwrap(),
        Some(1),
        "the sequence reservation survived the restart"
    );
}

#[tokio::test]
async fn test_sequence_reservations_survive_restart() {
    let (_dir, path) = temp_db_path();
    let key = signing_key();
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(key.clone());
    let account = fixtures::SEQ_ACCOUNT;

    // Queue several payments from the same account in one session.
    {
        let mut engine = SyncEngine::open(&path).await.unwrap();
        for tx_xdr in [
            fixtures::SEQ_SEQ_1,
            fixtures::SEQ_SEQ_2,
            fixtures::SEQ_SEQ_3,
        ] {
            engine
                .queue_payment(account, &signer, tx_xdr, TxPriority::Normal, 10)
                .await
                .unwrap();
        }
        assert_eq!(
            engine.last_reserved_sequence(account).await.unwrap(),
            Some(3)
        );
    }

    // Restart, then queue one more: the sequence must continue strictly
    // upward with no reuse and no skip.
    let mut engine = SyncEngine::open(&path).await.unwrap();
    assert_eq!(
        engine.last_reserved_sequence(account).await.unwrap(),
        Some(3),
        "the reservation survived the restart"
    );

    engine
        .queue_payment(
            account,
            &signer,
            fixtures::SEQ_SEQ_4,
            TxPriority::Normal,
            10,
        )
        .await
        .unwrap();

    assert_eq!(
        engine.last_reserved_sequence(account).await.unwrap(),
        Some(4),
        "the next sequence continues after restart with no reuse or skip"
    );
}

#[tokio::test]
async fn test_no_sequence_reuse_after_restart() {
    // Crash-consistency for the sequence window: even if a crash occurs in the
    // gap between the durable write of an envelope and the in-memory sequence
    // update, reopening must not let a later queue_payment reuse that sequence.
    let (_dir, path) = temp_db_path();
    let key = signing_key();
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(key.clone());
    let account = fixtures::REUSE_ACCOUNT;

    // First session: queue one payment. Because the reservation + envelope +
    // initial status are written atomically, the database is fully consistent
    // the instant queue_payment returns.
    {
        let mut engine = SyncEngine::open(&path).await.unwrap();
        engine
            .queue_payment(
                account,
                &signer,
                fixtures::REUSE_SEQ_1,
                TxPriority::Normal,
                10,
            )
            .await
            .unwrap();
        // Dropping here models the process being killed right after the
        // durable write; any in-memory state is discarded.
    }

    // Reopen: the reservation must be rehydrated from storage so the next
    // queued payment takes the *next* sequence, never the same one again.
    let mut engine = SyncEngine::open(&path).await.unwrap();
    assert_eq!(
        engine.last_reserved_sequence(account).await.unwrap(),
        Some(1),
        "the reservation was durably persisted despite the simulated crash"
    );
    engine
        .queue_payment(
            account,
            &signer,
            fixtures::REUSE_SEQ_2,
            TxPriority::Normal,
            10,
        )
        .await
        .unwrap();
    assert_eq!(
        engine.last_reserved_sequence(account).await.unwrap(),
        Some(2),
        "no sequence number is reused after a restart"
    );
}

#[tokio::test]
async fn test_no_double_dispatch_after_restart_post_dispatch() {
    let (_dir, path) = temp_db_path();
    let key = signing_key();
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(key.clone());
    let account = fixtures::DISP_ACCOUNT;

    let envelope = {
        let mut engine = SyncEngine::open(&path).await.unwrap();
        engine
            .queue_payment(
                account,
                &signer,
                fixtures::DISP_SEQ_1,
                TxPriority::Normal,
                10,
            )
            .await
            .unwrap()
    };

    // Dispatch the payment, then "crash" (drop) before it is settled.
    {
        let mut engine = SyncEngine::open(&path).await.unwrap();
        let dispatched = engine
            .next_to_dispatch()
            .expect("dispatch the payment for the first time");
        assert_eq!(dispatched, envelope);
        assert!(
            engine.next_to_dispatch().is_none(),
            "no second envelope to dispatch in the same session"
        );
    }

    // Reopen after the crash: the already-dispatched envelope must NOT be
    // handed out a second time.
    let mut engine = SyncEngine::open(&path).await.unwrap();
    assert!(
        engine.next_to_dispatch().is_none(),
        "an already-dispatched envelope must not be re-dispatched after a restart"
    );
}

#[tokio::test]
async fn test_mark_settlement_rejects_illegal_transition() {
    let (_dir, path) = temp_db_path();
    let key = signing_key();
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(key.clone());
    let account = fixtures::SETTLE_ACCOUNT;

    let mut engine = SyncEngine::open(&path).await.unwrap();
    let envelope = engine
        .queue_payment(
            account,
            &signer,
            fixtures::SETTLE_SEQ_1,
            TxPriority::Normal,
            10,
        )
        .await
        .unwrap();

    // Queued -> Settled is illegal (must pass through Propagating first).
    let err = engine
        .mark_settlement(envelope.message_id, SettlementStatus::Settled, 1)
        .await
        .expect_err("an illegal transition must be rejected");
    assert!(
        matches!(err, SyncEngineError::InvalidStateTransition { .. }),
        "expected InvalidStateTransition, got {err:?}"
    );

    // The legal path still works after the rejected attempt.
    engine
        .mark_settlement(envelope.message_id, SettlementStatus::Propagating, 2)
        .await
        .expect("a legal transition is accepted");
    engine
        .mark_settlement(envelope.message_id, SettlementStatus::Settled, 3)
        .await
        .expect("a legal transition is accepted");
}

#[tokio::test]
async fn test_mark_settlement_persists_across_restart() {
    let (_dir, path) = temp_db_path();
    let key = signing_key();
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(key.clone());
    let account = fixtures::PERSIST_ACCOUNT;

    // Carry an envelope all the way to Settled, then drop the engine.
    let message_id = {
        let mut engine = SyncEngine::open(&path).await.unwrap();
        let envelope = engine
            .queue_payment(
                account,
                &signer,
                fixtures::PERSIST_SEQ_1,
                TxPriority::Normal,
                10,
            )
            .await
            .unwrap();
        engine
            .mark_settlement(envelope.message_id, SettlementStatus::Propagating, 100)
            .await
            .unwrap();
        engine
            .mark_settlement(envelope.message_id, SettlementStatus::Settled, 200)
            .await
            .unwrap();
        envelope.message_id
    };

    // Restart. The persisted Settled status must have been rehydrated into the
    // in-memory tracker, which we prove by attempting an illegal transition
    // *out* of Settled: it must be rejected (not treated as untracked, which
    // would yield EnvelopeNotFound).
    let mut engine = SyncEngine::open(&path).await.unwrap();
    let err = engine
        .mark_settlement(message_id, SettlementStatus::Propagating, 300)
        .await
        .expect_err("Settled is terminal; the persisted Settled state must block this");
    assert!(
        matches!(err, SyncEngineError::InvalidStateTransition { .. }),
        "expected InvalidStateTransition proving Settled was rehydrated, got {err:?}"
    );
}
