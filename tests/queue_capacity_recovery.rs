//! Verify the queue cap never silently loses a payment from durable storage.
use tempfile::TempDir;

use stellarconduit_core::message::types::TransactionEnvelope;
use stellarconduit_sync_engine::engine::SyncEngine;
use stellarconduit_sync_engine::queue::priority::LOW_CAPACITY;
use stellarconduit_sync_engine::queue::TxPriority;
use stellarconduit_sync_engine::settlement::SettlementStatus;
use stellarconduit_sync_engine::storage::SyncEngineDb;

fn fake_envelope(index: usize) -> TransactionEnvelope {
    let mut message_id = [0u8; 32];
    message_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
    TransactionEnvelope {
        message_id,
        origin_pubkey: [1u8; 32],
        tx_xdr: "unused-in-storage-replay".to_string(),
        ttl_hops: 10,
        timestamp: 1_700_000_000,
        signature: [0u8; 64],
    }
}

#[tokio::test]
async fn over_capacity_restart_marks_displaced_oldest_failed() {
    let directory = TempDir::new().unwrap();
    let db_path = directory.path().join("queue.sqlite");
    let db_file = db_path.to_string_lossy().to_string();
    let db = SyncEngineDb::init(&db_file).await.unwrap();

    // Emulate an old unlimited queue persisted before capacity limits existed.
    for index in 1..=LOW_CAPACITY + 2 {
        db.enqueue_transaction(
            &fake_envelope(index),
            "unused-in-replay",
            index as i64,
            TxPriority::Low,
            index as u64,
        )
        .await
        .unwrap();
    }
    drop(db);

    let engine = SyncEngine::open(&db_file).await.unwrap();
    assert_eq!(engine.queue_metrics().snapshot().queue_evictions, 2);
    assert_eq!(
        engine.settlement_status(fake_envelope(1).message_id),
        Some(SettlementStatus::Failed)
    );
    assert_eq!(
        engine.settlement_status(fake_envelope(2).message_id),
        Some(SettlementStatus::Failed)
    );
    assert_eq!(
        engine.settlement_status(fake_envelope(3).message_id),
        Some(SettlementStatus::Queued)
    );
    drop(engine);

    // Crash/reopen should not requeue displaced entries or double-count them.
    let reopened = SyncEngine::open(&db_file).await.unwrap();
    assert_eq!(reopened.queue_metrics().snapshot().queue_evictions, 0);
    assert_eq!(
        reopened.settlement_status(fake_envelope(1).message_id),
        Some(SettlementStatus::Failed)
    );
    let db = SyncEngineDb::init(&db_file).await.unwrap();
    assert_eq!(
        db.get_settlement_status(fake_envelope(2).message_id)
            .await
            .unwrap(),
        Some(SettlementStatus::Failed)
    );
}

#[tokio::test]
async fn enqueue_with_eviction_records_both_changes_atomically() {
    let db = SyncEngineDb::init(":memory:").await.unwrap();
    let old = fake_envelope(1);
    let new = fake_envelope(2);
    db.enqueue_transaction(&old, "source", 1, TxPriority::Low, 100)
        .await
        .unwrap();
    db.enqueue_transaction_with_eviction(
        &new,
        "source",
        2,
        TxPriority::Low,
        101,
        Some(old.message_id),
    )
    .await
    .unwrap();
    assert_eq!(
        db.get_settlement_status(old.message_id).await.unwrap(),
        Some(SettlementStatus::Failed)
    );
    assert_eq!(
        db.get_settlement_status(new.message_id).await.unwrap(),
        Some(SettlementStatus::Queued)
    );

    // A nonexistent victim must rollback the *entire* next enqueue.
    let third = fake_envelope(3);
    assert!(db
        .enqueue_transaction_with_eviction(
            &third,
            "source",
            3,
            TxPriority::Low,
            102,
            Some(fake_envelope(999).message_id),
        )
        .await
        .is_err());
    assert!(db
        .get_queued_envelope(third.message_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.get_settlement_status(third.message_id).await.unwrap(),
        None
    );
}
