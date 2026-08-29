//! End-to-end test for the VRF-based deterministic tie-break (issue #067),
//! wired the way the mesh would use it: two devices double-spend a slot while
//! offline, the conflict is detected and **persisted durably**, then read back
//! and run through issue #001's full resolution order — relay quorum first,
//! and, because that comes out an exact tie, the VRF tie-break as the
//! last-resort step before on-chain escalation.
//!
//! The tie-break outcome is then re-verified from nothing but public inputs,
//! standing in for any third party (or the `dispute-resolver` contract) that
//! needs to check the decision without trusting the evaluator.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellarconduit_core::message::relay_proof::RelayChainProof;
use stellarconduit_sync_engine::conflict::{
    conflicts_between, quorum_standing, resolve_conflict_with_tiebreak, select_tiebreak_evaluator,
    verify_tiebreak, verify_tiebreak_with_evaluator, vrf_tiebreak, Conflict, ConflictEvidence,
    QueuedSlot, QuorumStanding, RelayObservation, RelayVrfIdentity,
};
use stellarconduit_sync_engine::envelope::pq::SigningPolicy;
use stellarconduit_sync_engine::envelope::OfflineEnvelopeBuilder;
use stellarconduit_sync_engine::queue::SequenceReservationManager;
use stellarconduit_sync_engine::storage::SyncEngineDb;

const SOURCE_G: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
const SEQ: i64 = 103_720_918_407_610_369;

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
        .trim()
        .to_string()
}

/// Build one signed envelope's `message_id` for the shared slot.
fn build_message_id(key: &SigningKey, xdr_fixture: &str) -> [u8; 32] {
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(key.clone());
    let mut sequences = SequenceReservationManager::new();
    sequences.seed(SOURCE_G, SEQ - 1);
    let (hybrid, seq) = OfflineEnvelopeBuilder::build_and_sign(
        &mut sequences,
        SOURCE_G,
        &signer,
        &SigningPolicy::ClassicalOnly,
        fixture(xdr_fixture),
        10,
    )
    .unwrap();
    assert_eq!(seq, SEQ);
    hybrid.classical_envelope.message_id
}

/// A relay observation from `relay` corroborating `tx_id` on this slot.
fn observation(relay: &SigningKey, tx_id: &[u8; 32]) -> RelayObservation {
    RelayObservation {
        relay_pubkey: relay.verifying_key().to_bytes(),
        proof: RelayChainProof::sign(relay, tx_id, &[3u8; 32], SEQ as u64),
    }
}

#[tokio::test]
async fn test_vrf_tiebreak_resolves_a_persisted_quorum_met_tie_end_to_end() {
    // 1. Two offline devices double-spend the same (account, sequence) slot.
    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);
    let id_a = build_message_id(&key_a, "transaction_v1_envelope.b64");
    let id_b = build_message_id(&key_b, "transaction_v1_envelope_conflict.b64");
    assert_ne!(id_a, id_b);

    let slot_a = QueuedSlot {
        source_account: SOURCE_G.to_string(),
        sequence: SEQ,
        message_id: id_a,
    };
    let slot_b = QueuedSlot {
        source_account: SOURCE_G.to_string(),
        sequence: SEQ,
        message_id: id_b,
    };

    // 2. Detect the conflict and persist it durably, then read it back.
    let db = SyncEngineDb::init(":memory:").await.unwrap();
    let detected = conflicts_between(&slot_a, &slot_b).expect("should detect a conflict");
    db.record_conflict(&detected, 1_700_000_300).await.unwrap();

    let unresolved = db.list_unresolved_conflicts().await.unwrap();
    assert_eq!(unresolved, vec![detected]);
    let conflict: Conflict = unresolved.into_iter().next().unwrap();

    // 3. Each side is corroborated by three distinct relays: every
    //    deterministic criterion the resolver has comes out exactly even.
    let relays: Vec<SigningKey> = (0..6).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let committed: Vec<RelayVrfIdentity> = relays.iter().map(RelayVrfIdentity::derive).collect();

    let evidence = ConflictEvidence {
        envelope_a_timestamp: 1_700_000_100,
        envelope_b_timestamp: 1_700_000_105,
        envelope_a_observations: relays[..3]
            .iter()
            .map(|r| observation(r, &conflict.envelope_a))
            .collect(),
        envelope_b_observations: relays[3..]
            .iter()
            .map(|r| observation(r, &conflict.envelope_b))
            .collect(),
    };

    assert!(matches!(
        quorum_standing(&conflict, &evidence),
        QuorumStanding::QuorumTie {
            distinct_relays_each: 3
        }
    ));

    // Without a tie-break, a quorum-met tie escalates on-chain.
    assert!(resolve_conflict_with_tiebreak(&conflict, &evidence, None, &committed).is_err());

    // 4. The deterministically selected evaluator (a relay, never either
    //    conflicting party) evaluates the VRF.
    let selected_identity = select_tiebreak_evaluator(&conflict, &committed)
        .expect("a candidate relay is selected")
        .identity;
    assert_ne!(selected_identity, key_a.verifying_key().to_bytes());
    assert_ne!(selected_identity, key_b.verifying_key().to_bytes());

    let evaluator_key = relays
        .iter()
        .find(|k| k.verifying_key().to_bytes() == selected_identity)
        .expect("the selected evaluator is one of the candidate relays");

    let outcome = vrf_tiebreak(&conflict, evaluator_key).unwrap();

    // 5. The resolution flow accepts the verified tie-break and returns one
    //    winner.
    let winner =
        resolve_conflict_with_tiebreak(&conflict, &evidence, Some(&outcome), &committed).unwrap();
    assert_eq!(winner, outcome.winner);
    assert!(winner == conflict.envelope_a || winner == conflict.envelope_b);

    // 6. A third party re-verifies from public inputs alone.
    verify_tiebreak(&conflict, &outcome).unwrap();
    verify_tiebreak_with_evaluator(&conflict, &outcome, &committed).unwrap();

    // 7. Deterministic: a second evaluation picks the same winner.
    let again = vrf_tiebreak(&conflict, evaluator_key).unwrap();
    assert_eq!(again.winner, outcome.winner);
    assert_eq!(again.vrf_output, outcome.vrf_output);
}
