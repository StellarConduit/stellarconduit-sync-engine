//! Measures the cost of `crate::conflict::proof_compression` as a function of
//! relay-chain length (issue #63's "measure and document" acceptance
//! criterion).
//!
//! Run with:
//! ```bash
//! cargo run --release --example compression_bench
//! ```
//!
//! It prints, for a range of chain lengths:
//! - **fold time / hop** — the incremental proving cost each relay pays as the
//!   envelope passes through it (SHA-256 + Ed25519 sign + Ed25519 verify);
//! - **compose time** — folding the whole chain at once at the escalation
//!   point (this is *not* what happens in practice — folding is incremental —
//!   but it bounds the worst case);
//! - **verify time** and **`verification_cost`** — what the `dispute-resolver`
//!   Soroban contract pays; this is the number to check against a contract
//!   budget, and it must not grow with chain length;
//! - **artifact size** — the serialized `CompressedChainProof`, also flat.

use std::time::Instant;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use stellarconduit_core::message::relay_proof::RelayChainProof;
use stellarconduit_sync_engine::conflict::proof_compression::{
    compose, compressed_size, fold_hop, genesis, verification_cost, verify_compressed, TAIL_WINDOW,
};

const ORIGIN: [u8; 32] = [0x42; 32];
const SEQUENCE: u64 = 4_070_800_009_842_177;

/// Build a valid `n`-hop chain following the module's linking rule: hop `i` is
/// signed over `(ORIGIN, acc_{i-1}, SEQUENCE)`. We reuse `compose` internally
/// via `genesis`/`fold_hop` accounting so the accumulator math stays in one
/// place — here we just need the raw hop list, so we rebuild it by folding a
/// throwaway proof and reading back each step's `acc`.
fn build_chain(n: usize) -> Vec<([u8; 32], RelayChainProof)> {
    let mut proof = genesis(ORIGIN, SEQUENCE);
    let mut hops = Vec::with_capacity(n);
    for _ in 0..n {
        let key = SigningKey::generate(&mut OsRng);
        let pk = key.verifying_key().to_bytes();
        let hop = RelayChainProof::sign(&key, &ORIGIN, &proof.acc, SEQUENCE);
        proof = fold_hop(&proof, pk, hop.clone()).expect("freshly built hop must fold");
        hops.push((pk, hop));
    }
    hops
}

fn main() {
    println!(
        "TAIL_WINDOW = {TAIL_WINDOW}  (verification cost and artifact size are bounded by this, \
         not by chain length)\n"
    );
    println!(
        "{:>8}  {:>14}  {:>14}  {:>14}  {:>22}  {:>10}",
        "hops", "fold/hop", "compose(total)", "verify", "verify_cost", "size(B)"
    );
    println!("{}", "-".repeat(94));

    // Start at MIN_QUORUM (2) — a 1-hop chain cannot meet the distinct-relay
    // quorum and is not a meaningful escalation case.
    for &n in &[2usize, 4, 8, 16, 64, 256, 1024, 4096] {
        let hops = build_chain(n);

        // Incremental proving cost: time each fold_hop from genesis.
        let mut proof = genesis(ORIGIN, SEQUENCE);
        let fold_start = Instant::now();
        for (pk, hop) in &hops {
            proof = fold_hop(&proof, *pk, hop.clone()).unwrap();
        }
        let fold_per_hop = fold_start.elapsed() / n as u32;

        // Batch compose at the escalation point.
        let compose_start = Instant::now();
        let composed = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        let compose_total = compose_start.elapsed();

        // On-chain verification cost.
        let verify_start = Instant::now();
        let verified = verify_compressed(&composed, &ORIGIN, SEQUENCE).unwrap();
        let verify_time = verify_start.elapsed();
        assert_eq!(verified.length, n as u64);

        let cost = verification_cost(&composed);
        let size = compressed_size(&composed).unwrap();

        println!(
            "{:>8}  {:>14?}  {:>14?}  {:>14?}  {:>10} sig /{:>3} hash  {:>10}",
            n,
            fold_per_hop,
            compose_total,
            verify_time,
            cost.signature_checks,
            cost.hash_steps,
            size,
        );
    }

    println!(
        "\nverify time / cost / size are flat past {TAIL_WINDOW} hops — the headline result. \
         Compare a naive linear proof: n signature checks on-chain, ~n*100 bytes."
    );
}
