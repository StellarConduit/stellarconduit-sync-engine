//! End-to-end test for recursive relay-chain proof compression (issue #63),
//! exercised the way the mesh would use it:
//!
//! 1. An envelope propagates hop-by-hop across a long, sparse chain. Each relay
//!    folds its own hop into the constant-size [`CompressedChainProof`] it
//!    received and forwards the result — no relay ever holds or re-signs the
//!    whole chain.
//! 2. The proof is serialized between hops (a relay goes offline / hands off),
//!    round-tripped through MessagePack, and folding resumes.
//! 3. At the escalation point the accumulated proof is verified the way the
//!    `dispute-resolver` Soroban contract would — against only the disputed
//!    slot's `(origin_tx_id, sequence)` — and the verification cost is checked
//!    to be independent of how long the chain grew.
//! 4. A chain carrying a tampered intermediate hop is shown to be
//!    unforgeable: compression does not launder a bad hop into a valid proof.

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellarconduit_core::message::relay_proof::RelayChainProof;
use stellarconduit_sync_engine::conflict::proof_compression::{
    compose, fold_hop, genesis, verification_cost, verify_compressed, CompressedChainProof,
    TAIL_WINDOW,
};
use stellarconduit_sync_engine::errors::SyncEngineError;

const ORIGIN_TX_ID: [u8; 32] = [0x7c; 32];
const SEQUENCE: u64 = 103_720_918_407_610_369;

/// Simulate a relay receiving a compressed proof, folding its own hop, and
/// producing the proof it forwards downstream. The relay signs over the
/// accumulator it observed — the module's chain-linking rule.
fn relay_forwards(incoming: &CompressedChainProof, relay: &SigningKey) -> CompressedChainProof {
    let hop = RelayChainProof::sign(
        relay,
        &incoming.origin_tx_id,
        &incoming.acc,
        incoming.sequence,
    );
    fold_hop(incoming, relay.verifying_key().to_bytes(), hop).expect("honest hop must fold")
}

#[test]
fn test_long_chain_folds_incrementally_and_verifies_at_escalation() {
    let hops = 200usize;
    let relays: Vec<SigningKey> = (0..hops)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect();

    // The origin device starts the fold; each relay folds one hop.
    let mut proof = genesis(ORIGIN_TX_ID, SEQUENCE);
    for (i, relay) in relays.iter().enumerate() {
        proof = relay_forwards(&proof, relay);

        // Halfway, a relay serializes and hands the proof off before the next
        // one picks it up.
        if i == hops / 2 {
            let bytes = rmp_serde::to_vec(&proof).expect("proof serializes");
            proof = rmp_serde::from_slice(&bytes).expect("proof deserializes");
        }
    }

    assert_eq!(proof.length, hops as u64);
    assert_eq!(proof.tail.len(), TAIL_WINDOW);

    // The escalation point verifies against nothing but the disputed slot.
    let verified = verify_compressed(&proof, &ORIGIN_TX_ID, SEQUENCE)
        .expect("a fully honest chain must verify");
    assert_eq!(verified.length, hops as u64);
    assert_eq!(verified.distinct_tail_relays, TAIL_WINDOW);

    // Folding the same hops in one batch is byte-identical to the incremental
    // walk above.
    let batch_hops: Vec<([u8; 32], RelayChainProof)> = {
        let mut acc_proof = genesis(ORIGIN_TX_ID, SEQUENCE);
        let mut out = Vec::new();
        for relay in &relays {
            let hop = RelayChainProof::sign(relay, &ORIGIN_TX_ID, &acc_proof.acc, SEQUENCE);
            acc_proof =
                fold_hop(&acc_proof, relay.verifying_key().to_bytes(), hop.clone()).unwrap();
            out.push((relay.verifying_key().to_bytes(), hop));
        }
        out
    };
    let batch = compose(ORIGIN_TX_ID, SEQUENCE, &batch_hops).unwrap();
    assert_eq!(batch, proof);
}

#[test]
fn test_verification_cost_does_not_grow_with_chain_length() {
    let build = |n: usize| {
        let mut proof = genesis(ORIGIN_TX_ID, SEQUENCE);
        for _ in 0..n {
            proof = relay_forwards(&proof, &SigningKey::generate(&mut OsRng));
        }
        proof
    };

    let costs: Vec<_> = [8usize, 50, 400, 2000]
        .iter()
        .map(|&n| verification_cost(&build(n)))
        .collect();

    // Every length costs the same fixed number of signature checks.
    for c in &costs {
        assert_eq!(c, &costs[0]);
        assert_eq!(c.signature_checks, TAIL_WINDOW);
    }
}

#[test]
fn test_tampered_intermediate_hop_cannot_be_compressed_into_a_valid_proof() {
    let hops = 80usize;
    let relays: Vec<SigningKey> = (0..hops)
        .map(|_| SigningKey::generate(&mut OsRng))
        .collect();

    // Build the honest hop list first.
    let mut acc_proof = genesis(ORIGIN_TX_ID, SEQUENCE);
    let mut hop_list: Vec<([u8; 32], RelayChainProof)> = Vec::new();
    for relay in &relays {
        let hop = RelayChainProof::sign(relay, &ORIGIN_TX_ID, &acc_proof.acc, SEQUENCE);
        acc_proof = fold_hop(&acc_proof, relay.verifying_key().to_bytes(), hop.clone()).unwrap();
        hop_list.push((relay.verifying_key().to_bytes(), hop));
    }
    // Sanity: the honest chain compresses and verifies.
    let honest = compose(ORIGIN_TX_ID, SEQUENCE, &hop_list).unwrap();
    verify_compressed(&honest, &ORIGIN_TX_ID, SEQUENCE).unwrap();

    // An attacker rewrites hop 30 with their own relay key. They cannot know
    // the real accumulator at that point without replaying the honest prefix
    // to that hop with the honest keys — and even the closest they can get
    // (guessing / using a stale value) fails to link.
    let attacker = SigningKey::generate(&mut OsRng);
    hop_list[30] = (
        attacker.verifying_key().to_bytes(),
        RelayChainProof::sign(&attacker, &ORIGIN_TX_ID, &[0x99; 32], SEQUENCE),
    );

    let err = compose(ORIGIN_TX_ID, SEQUENCE, &hop_list).unwrap_err();
    assert!(matches!(err, SyncEngineError::CompressedProofInvalid(_)));
    assert_eq!(
        err.classify(),
        stellarconduit_sync_engine::errors::ErrorClass::Permanent
    );
}
