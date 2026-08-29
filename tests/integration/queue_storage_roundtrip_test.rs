//! End-to-end test wiring the pieces of the sync engine together the way a
//! wallet would: reserve a sequence number, sign an envelope offline, persist
//! it durably, hand it to the mesh, and mark it settled once a relay node
//! confirms it.
//!
//! The source account and sequence number are derived from the transaction XDR
//! (see `stellarconduit_sync_engine::envelope::xdr`), so these tests drive
//! `build_and_sign` with real, valid XDR fixtures whose embedded values are
//! known ahead of time (see `tests/fixtures`).

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellarconduit_core::message::envelope::validate_envelope;
use stellarconduit_sync_engine::envelope::pq::SigningPolicy;
use stellarconduit_sync_engine::envelope::OfflineEnvelopeBuilder;
use stellarconduit_sync_engine::queue::SequenceReservationManager;
use stellarconduit_sync_engine::settlement::SettlementStatus;
use stellarconduit_sync_engine::storage::SyncEngineDb;

/// Source account (`G...`) and sequence embedded in the fixtures below.
const SOURCE_G: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
const SEQ: i64 = 103_720_918_407_610_369;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
        .trim()
        .to_string()
}

#[tokio::test]
async fn test_reserve_sign_persist_and_settle() {
    let db = SyncEngineDb::init(":memory:").await.unwrap();
    let mut sequences = SequenceReservationManager::new();
    let signing_key = SigningKey::generate(&mut OsRng);
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(signing_key.clone());
    let source_account = SOURCE_G;

    // A device that last saw connectivity knows the account's on-chain
    // sequence number; seed from there before queuing anything offline. The
    // wallet's Stellar SDK built the transaction against the next sequence, so
    // reserving here must produce exactly what the XDR encodes.
    sequences.seed(source_account, SEQ - 1);

    let (hybrid, sequence) = OfflineEnvelopeBuilder::build_and_sign(
        &mut sequences,
        source_account,
        &signer,
        &SigningPolicy::ClassicalOnly,
        fixture("transaction_v1_envelope.b64"),
        10,
    )
    .unwrap();
    let envelope = hybrid.classical_envelope;

    // The sequence is derived from the XDR, not merely the caller's claim.
    assert_eq!(sequence, SEQ);
    assert!(validate_envelope(&envelope).is_ok());

    db.enqueue_envelope(
        &envelope,
        source_account,
        sequence,
        stellarconduit_sync_engine::queue::TxPriority::Emergency,
        1_700_000_000,
    )
    .await
    .unwrap();
    db.save_sequence_reservation(source_account, sequence)
        .await
        .unwrap();
    db.set_settlement_status(envelope.message_id, SettlementStatus::Queued, 1_700_000_000)
        .await
        .unwrap();

    // Simulate a restart: everything needed to resume must be recoverable
    // from durable storage alone.
    let restored = db
        .get_queued_envelope(envelope.message_id)
        .await
        .unwrap()
        .expect("envelope should survive a simulated restart");
    assert_eq!(restored.envelope, envelope);
    assert_eq!(restored.source_account, SOURCE_G);
    assert_eq!(restored.sequence, SEQ);
    assert_eq!(
        db.load_sequence_reservation(source_account).await.unwrap(),
        Some(SEQ)
    );

    // Hand off to the mesh, then confirm settlement once a relay reports back.
    db.set_settlement_status(
        envelope.message_id,
        SettlementStatus::Propagating,
        1_700_000_100,
    )
    .await
    .unwrap();
    db.set_settlement_status(
        envelope.message_id,
        SettlementStatus::Settled,
        1_700_000_200,
    )
    .await
    .unwrap();

    let status = db.get_settlement_status(envelope.message_id).await.unwrap();
    assert_eq!(status, Some(SettlementStatus::Settled));

    db.remove_queued_envelope(envelope.message_id)
        .await
        .unwrap();
    assert!(db
        .get_queued_envelope(envelope.message_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_conflicting_envelopes_for_same_slot_are_detected_and_recorded() {
    use stellarconduit_sync_engine::conflict::{conflicts_between, QueuedSlot};

    let db = SyncEngineDb::init(":memory:").await.unwrap();
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let signer_a = stellarconduit_sync_engine::envelope::InMemorySigner::new(key_a.clone());
    let signer_b = stellarconduit_sync_engine::envelope::InMemorySigner::new(key_b.clone());
    let source_account = SOURCE_G;

    // Two devices sharing the same account, both offline, each builds a
    // different payment against the same reserved sequence before either learns
    // about the other — a classic split-mesh double-spend setup. Each device
    // has its own independent, stale view of the account, so each seeds and
    // reserves separately.
    let mut sequences_a = SequenceReservationManager::new();
    sequences_a.seed(source_account, SEQ - 1);
    let (hybrid_a, seq_a) = OfflineEnvelopeBuilder::build_and_sign(
        &mut sequences_a,
        source_account,
        &signer_a,
        &SigningPolicy::ClassicalOnly,
        fixture("transaction_v1_envelope.b64"),
        10,
    )
    .unwrap();
    let envelope_a = hybrid_a.classical_envelope;

    let mut sequences_b = SequenceReservationManager::new();
    sequences_b.seed(source_account, SEQ - 1);
    let (hybrid_b, seq_b) = OfflineEnvelopeBuilder::build_and_sign(
        &mut sequences_b,
        source_account,
        &signer_b,
        &SigningPolicy::ClassicalOnly,
        // Same source and sequence, different payment: a genuinely conflicting
        // envelope, not a duplicate.
        fixture("transaction_v1_envelope_conflict.b64"),
        10,
    )
    .unwrap();
    let envelope_b = hybrid_b.classical_envelope;

    // Both occupy the same (account, sequence) slot, derived from the XDR.
    assert_eq!(seq_a, SEQ);
    assert_eq!(seq_b, SEQ);
    assert_ne!(envelope_a.message_id, envelope_b.message_id);

    let slot_a = QueuedSlot {
        source_account: source_account.to_string(),
        sequence: seq_a,
        message_id: envelope_a.message_id,
    };
    let slot_b = QueuedSlot {
        source_account: source_account.to_string(),
        sequence: seq_b,
        message_id: envelope_b.message_id,
    };

    let conflict = conflicts_between(&slot_a, &slot_b).expect("should detect a conflict");
    db.record_conflict(&conflict, 1_700_000_300).await.unwrap();

    let unresolved = db.list_unresolved_conflicts().await.unwrap();
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0], conflict);
}
