use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellarconduit_sync_engine::queue::reputation::ReputationTracker;

fn random_peer_id() -> [u8; 32] {
    let key = SigningKey::generate(&mut OsRng);
    key.verifying_key().to_bytes()
}

fn random_message_id() -> [u8; 32] {
    let key = SigningKey::generate(&mut OsRng);
    key.verifying_key().to_bytes()
}

#[test]
fn test_reputation_score_increases_with_honest_relay_participation() {
    let mut tracker = ReputationTracker::new();
    let honest_mule = random_peer_id();

    // The mule relays a transaction for someone else.
    let tx1 = random_message_id();
    tracker.record_submission(honest_mule, tx1);

    // Initial score should be 0, not yet priority.
    assert_eq!(tracker.score(&honest_mule), 0);
    assert!(!tracker.is_priority(&honest_mule));

    // The transaction settles successfully on the Stellar network (paid L1 fee).
    tracker.apply_settlement_result(tx1, true);

    // The mule's reputation increases.
    assert!(tracker.score(&honest_mule) > 0);
    assert!(tracker.is_priority(&honest_mule));

    // Relaying more successful transactions increases the score further.
    let tx2 = random_message_id();
    tracker.record_submission(honest_mule, tx2);
    tracker.apply_settlement_result(tx2, true);

    assert_eq!(tracker.score(&honest_mule), 20);
}

#[test]
fn test_new_device_cold_start_is_not_unfairly_penalized() {
    let tracker = ReputationTracker::new();
    let new_device = random_peer_id();

    // A brand new device starts with a score of 0.
    assert_eq!(tracker.score(&new_device), 0);

    // It is not in the "priority" bucket.
    assert!(!tracker.is_priority(&new_device));

    // However, the score is not negative. In the relay's outbound queue (OutboundTxQueue),
    // a non-priority peer would draw from the Fair-Share bucket rather than being ignored entirely.
    // The explicit design is that score <= 0 still gets service, just rate-limited or round-robin,
    // ensuring the cold start is fair and does not lock them out.
}

#[test]
fn test_simple_sybil_strategy_does_not_trivially_outperform_honest_participation() {
    let mut tracker = ReputationTracker::new();
    let honest_mule = random_peer_id();
    let sybil_attacker = random_peer_id();

    // Honest mule participates properly.
    for _ in 0..5 {
        let tx = random_message_id();
        tracker.record_submission(honest_mule, tx);
        tracker.apply_settlement_result(tx, true);
    }
    let honest_score = tracker.score(&honest_mule); // +50

    // Sybil Attacker tries to flood invalid transactions (Garbage Spam)
    // They can generate thousands of fake, invalid transactions for free.
    for _ in 0..10 {
        let tx = random_message_id();
        tracker.record_submission(sybil_attacker, tx);
        // The network rejects them (bad signature/sequence).
        tracker.apply_settlement_result(tx, false);
    }

    let attacker_score = tracker.score(&sybil_attacker);

    // The attacker's score plunges below 0 due to heavy penalties for invalid transactions.
    assert!(attacker_score < 0);
    assert!(!tracker.is_priority(&sybil_attacker));

    // The attacker's only way to get a positive score is to submit *valid* transactions
    // that actually settle on L1. If they do that, they must pay real XLM base fees,
    // which turns a free Sybil attack into an economically bounded paid action, identical
    // to honest participation from the network's perspective.
    // Therefore, the Sybil strategy (free spam) does not trivially outperform honest participation.
    assert!(honest_score > attacker_score);
}
