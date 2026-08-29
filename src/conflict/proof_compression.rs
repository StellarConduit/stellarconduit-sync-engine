//! Recursive compression of a long relay-chain proof into a constant-size
//! artifact for on-chain dispute escalation (issue #63).
//!
//! # The problem this solves
//!
//! `crate::conflict::resolver` weighs a *set* of independent
//! [`RelayChainProof`]s per conflicting envelope, and
//! `crate::conflict::escalation` carries exactly one such proof into the
//! `dispute-resolver` Soroban contract. Neither addresses what happens when a
//! payment bounced through *many* hops across a large, sparse mesh over a long
//! offline period: the natural evidence for "this envelope really did traverse
//! a legitimate `n`-hop chain from its origin" is `n` separate signatures, and
//! both the artifact size and the on-chain verification cost then grow
//! **linearly in `n`**. Soroban calls have hard instruction/fee budgets, so a
//! long-but-entirely-legitimate chain can become too expensive to verify
//! on-chain — an availability failure for exactly the remote, poorly-connected
//! users the mesh exists to serve.
//!
//! # The scheme: an attested recursive fold
//!
//! This is a hash-based *incrementally verifiable computation* (IVC) accumulator
//! — the same shape as a folding scheme (Nova) but instantiated with a hash and
//! a signature per step instead of an in-circuit SNARK verifier. It uses only
//! primitives already in this crate's dependency graph (`sha2`,
//! `ed25519-dalek`); see the "Where this stops scaling" section for the honest
//! cost of that choice.
//!
//! ## Fold state
//!
//! ```text
//! acc_0 = SHA-256( "SCRC-v1/genesis" ‖ origin_tx_id ‖ sequence_be )
//! acc_i = SHA-256( "SCRC-v1/fold"    ‖ acc_{i-1} ‖ relay_pubkey_i ‖ i_be )   (i ≥ 1)
//! ```
//!
//! `acc_i` is a 32-byte commitment to the entire length-`i` prefix of the
//! chain. The state carried between hops is *constant size* regardless of `i`.
//!
//! ## Chain-linking rule imposed on relays
//!
//! Issue #046 (hop-by-hop chain integrity) is not yet merged, so this module
//! states the linking rule it needs, consistent with #046's issue description:
//! **hop `i`'s [`RelayChainProof`] MUST be signed by relay `r_i` over
//! `tx_id = origin_tx_id`, `chain_hash = acc_{i-1}`, `sequence`.** In words:
//! each relay signs *the accumulator it observed* and is extending. That single
//! rule is what makes the fold recursive — verifying hop `i` needs only
//! `acc_{i-1}` and `r_i`'s public key, never hops `1..i-1` — and it is what a
//! tampered intermediate hop cannot satisfy (see
//! `test_tampered_hop_is_rejected_even_after_compression`).
//!
//! ## The compressed artifact
//!
//! [`CompressedChainProof`] is `origin_tx_id`, `sequence`, `length` (`= n`),
//! `acc` (`= acc_n`), and a **bounded** tail of the last [`TAIL_WINDOW`] hops'
//! attestations. Its serialized size is a small constant — roughly 1 KB at
//! `TAIL_WINDOW = 4` under this crate's MessagePack encoding — for any `n`.
//!
//! ## What a valid `CompressedChainProof` attests to
//!
//! That there exists a chain of `length` hops, rooted at `acc_0` (which binds
//! `origin_tx_id` and `sequence`), in which:
//!
//! - every one of the last [`TAIL_WINDOW`] hops carries a [`RelayChainProof`]
//!   that verifies against its relay's public key over the accumulator that hop
//!   extends, and those hops fold forward to exactly `acc`;
//! - for `length ≤ TAIL_WINDOW`, the tail is re-rooted at the recomputed
//!   `acc_0`, so the *entire* chain is checked;
//! - for `length > TAIL_WINDOW`, the pre-tail prefix is accepted **on the
//!   strength of the tail relays' recursive attestations** — this is the
//!   sub-linearity, and the trust shift is spelled out below;
//! - at least [`MIN_QUORUM`] *distinct* relays appear in the tail (Sybil
//!   backstop, mirroring `resolver`).
//!
//! ## Incremental composition
//!
//! [`fold_hop`] folds one new hop into an existing [`CompressedChainProof`] in
//! O(1) work — this is the "a relay chain grows one hop at a time" story: each
//! relay folds its own hop as the envelope passes through and forwards the
//! updated constant-size proof, so nothing is ever re-proven from scratch at
//! escalation time. [`compose`] is the batch equivalent and produces a
//! byte-identical result (`test_incremental_fold_matches_full_reproof`).
//!
//! # Measured cost (`cargo run --release --example compression_bench`)
//!
//! Numbers below are from a dev laptop (x86-64); mobile-class hardware is
//! roughly 3–5× slower but the *shape* — flat verification — is what matters.
//!
//! - **Proving, per hop:** one SHA-256 over ~84 bytes + one Ed25519 sign + one
//!   Ed25519 verify ≈ **80 µs/hop, constant** from 2 to 4096 hops. **O(1) per
//!   hop**, and incremental — never an O(n) reprove.
//! - **Verification:** exactly [`TAIL_WINDOW`] Ed25519 verifies + `TAIL_WINDOW`
//!   (+1 for short chains) SHA-256 ≈ **300 µs, flat** across the same range
//!   (see [`verification_cost`] and `test_verification_cost_is_flat`). On
//!   Soroban that is roughly 1–2 M instructions, comfortably inside the ~100 M
//!   budget. A naive linear proof of `n ≈ 1000` would be ~400 M+ and simply
//!   would not verify.
//! - **Artifact:** ~1.1 KB regardless of `n` (vs ~`n`·100 B for a linear
//!   proof).
//!
//! # Where this stops scaling / breaks down (the honest deliverable)
//!
//! Per the issue, this is a *working but not-yet-production* scheme:
//!
//! 1. **Trust shift, not trust elimination.** For `n > TAIL_WINDOW` the
//!    verifier no longer independently re-checks hops `1..n-TAIL_WINDOW`; it
//!    trusts that the last [`TAIL_WINDOW`] distinct relays each verified the
//!    accumulator they signed (which they did, recursively). A *collusion of
//!    those `TAIL_WINDOW` relays* can therefore attest to a fabricated or
//!    shorter prefix. `resolver`'s equivalent exposure is any 2 relays; this
//!    raises the bar to `TAIL_WINDOW` but does not remove it. Mitigations left
//!    for follow-up work: a larger window, relay stake/reputation weighting
//!    (`crate::queue::reputation`), and an optional full-transcript
//!    challenge/fraud-proof path that falls back to linear verification only
//!    when a dispute is itself disputed.
//! 2. **Not succinct in the cryptographic sense.** Verification is O(TAIL_WINDOW),
//!    not O(1), and soundness rests on a signature quorum rather than a single
//!    verified computation. A real recursive SNARK (Nova/Groth16-rec) would
//!    remove the trust shift in (1); it was rejected here for dependency size
//!    (hostile to the mobile-wallet binary-size constraint) and proving cost on
//!    mobile hardware.
//! 3. **Requires the linking rule above.** Legacy relays that put an arbitrary
//!    `chain_hash` in their [`RelayChainProof`] produce proofs this scheme
//!    cannot fold; adoption needs the relay-side change.
//! 4. **`length` is attested, not enforced.** The fold commits to the relay
//!    identities and their order, but the verifier cannot tell a genuine
//!    50-hop chain from one where a colluding tail asserts `length = 50` over a
//!    prefix it fabricated — same root cause as (1).
//! 5. **No unlinkability.** Tail relay public keys are in the clear.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use stellarconduit_core::message::relay_proof::RelayChainProof;

use crate::errors::SyncEngineError;

/// Number of trailing hops whose full attestations a [`CompressedChainProof`]
/// carries. This is the knob that trades artifact size / verification cost
/// (both linear in `TAIL_WINDOW`) against the size of the tail coalition that
/// would have to collude to forge a prefix (see the module docs, point 1).
///
/// Must be `≥ MIN_QUORUM` so a fully-populated tail can always meet quorum.
pub const TAIL_WINDOW: usize = 4;

/// Minimum number of *distinct* relays that must appear in a compressed
/// proof's tail before [`verify_compressed`] will accept it. Mirrors
/// `crate::conflict::resolver`'s constant of the same name and purpose: a
/// single relay keypair, honest or compromised, can never carry an escalation
/// on its own.
const MIN_QUORUM: usize = 2;

const GENESIS_DOMAIN: &[u8] = b"SCRC-v1/genesis";
const FOLD_DOMAIN: &[u8] = b"SCRC-v1/fold";

/// `acc_0` — the fold's genesis commitment, binding the chain's origin
/// transaction id and Stellar sequence number.
fn acc_genesis(origin_tx_id: &[u8; 32], sequence: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GENESIS_DOMAIN);
    h.update(origin_tx_id);
    h.update(sequence.to_be_bytes());
    h.finalize().into()
}

/// `acc_i = SHA-256( "SCRC-v1/fold" ‖ acc_{i-1} ‖ relay_pubkey_i ‖ i_be )`.
///
/// `hop_index` is 1-based (the first hop folded onto genesis is hop 1).
fn acc_step(prev_acc: &[u8; 32], relay_pubkey: &[u8; 32], hop_index: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(FOLD_DOMAIN);
    h.update(prev_acc);
    h.update(relay_pubkey);
    h.update(hop_index.to_be_bytes());
    h.finalize().into()
}

fn invalid(msg: impl Into<String>) -> SyncEngineError {
    SyncEngineError::CompressedProofInvalid(msg.into())
}

/// One hop's attestation, retained in a [`CompressedChainProof`]'s bounded
/// tail: the relay's public key, the accumulator value that hop extended
/// (`acc_{i-1}`), and the relay's [`RelayChainProof`] signed over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailHop {
    pub relay_pubkey: [u8; 32],
    /// `acc_{i-1}` — the fold state this hop was folded onto. Equals
    /// `proof.chain_hash` for a well-formed hop.
    pub prev_acc: [u8; 32],
    pub proof: RelayChainProof,
}

/// A constant-size, incrementally-foldable commitment to an arbitrarily long
/// relay chain. See the module docs for what a verified instance attests to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedChainProof {
    /// The origin envelope's `message_id` (`tx_id`), bound into `acc_0`.
    pub origin_tx_id: [u8; 32],
    /// The Stellar sequence number the disputed slot is on, bound into
    /// `acc_0` and re-checked against every hop proof.
    pub sequence: u64,
    /// Number of hops folded so far (`n`).
    pub length: u64,
    /// `acc_n` — the running fold commitment over the whole chain.
    pub acc: [u8; 32],
    /// The last `min(length, TAIL_WINDOW)` hops' attestations, oldest first.
    pub tail: Vec<TailHop>,
}

/// The result of a successful [`verify_compressed`]: the facts the
/// `dispute-resolver` contract (or any third party) may now rely on without
/// having processed the chain hop-by-hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    pub origin_tx_id: [u8; 32],
    pub sequence: u64,
    /// The attested hop count. See module docs point 4 on what "attested"
    /// buys you here.
    pub length: u64,
    /// Distinct relays in the verified tail (always `≥ MIN_QUORUM`).
    pub distinct_tail_relays: usize,
}

/// The work [`verify_compressed`] performs, for budgeting against a Soroban
/// resource limit and for asserting (in tests / the bench) that it does not
/// grow with chain length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationCost {
    pub signature_checks: usize,
    pub hash_steps: usize,
}

/// The cost [`verify_compressed`] *will* incur for `proof`, without running it.
/// Depends only on `proof.tail.len()` and whether the chain is short enough to
/// re-root at genesis — never on `proof.length` beyond that threshold.
pub fn verification_cost(proof: &CompressedChainProof) -> VerificationCost {
    let tail_len = proof.tail.len();
    VerificationCost {
        signature_checks: tail_len,
        hash_steps: tail_len + usize::from(proof.length <= TAIL_WINDOW as u64),
    }
}

/// Serialized size of `proof` in bytes (MessagePack, the crate's storage
/// encoding). Does not scale with `proof.length` — only the handful of bytes
/// the `length` varint itself needs — since the tail is bounded by
/// [`TAIL_WINDOW`]. Provided for the bench / docs.
pub fn compressed_size(proof: &CompressedChainProof) -> Result<usize, SyncEngineError> {
    Ok(rmp_serde::to_vec(proof)?.len())
}

/// Start an empty fold for `(origin_tx_id, sequence)` — a length-0 chain whose
/// accumulator is `acc_0`. Feed hops in with [`fold_hop`].
pub fn genesis(origin_tx_id: [u8; 32], sequence: u64) -> CompressedChainProof {
    CompressedChainProof {
        origin_tx_id,
        sequence,
        length: 0,
        acc: acc_genesis(&origin_tx_id, sequence),
        tail: Vec::new(),
    }
}

/// Fold one hop into `proof`, returning the extended proof.
///
/// This is O(1): it does not touch `proof.tail`'s existing entries beyond
/// pushing one and dropping at most one from the front. Errors (all
/// [`SyncEngineError::CompressedProofInvalid`]) if the hop's proof is for the
/// wrong sequence, does not link to `proof.acc`, or does not verify against
/// `relay_pubkey` over `proof.origin_tx_id`.
pub fn fold_hop(
    proof: &CompressedChainProof,
    relay_pubkey: [u8; 32],
    hop: RelayChainProof,
) -> Result<CompressedChainProof, SyncEngineError> {
    if hop.sequence != proof.sequence {
        return Err(invalid(format!(
            "hop proof sequence {} does not match chain sequence {}",
            hop.sequence, proof.sequence
        )));
    }
    if hop.chain_hash != proof.acc {
        return Err(invalid(format!(
            "hop does not link to the current fold state: proof.chain_hash {} != acc {}",
            hex::encode(hop.chain_hash),
            hex::encode(proof.acc),
        )));
    }
    let key = VerifyingKey::from_bytes(&relay_pubkey)
        .map_err(|e| invalid(format!("relay pubkey is not a valid ed25519 key: {e}")))?;
    if !hop.verify(&key, &proof.origin_tx_id) {
        return Err(invalid(
            "hop proof signature does not verify against the paired relay pubkey over the \
             chain's origin tx id",
        ));
    }

    let hop_index = proof.length + 1;
    let new_acc = acc_step(&proof.acc, &relay_pubkey, hop_index);

    let mut tail = proof.tail.clone();
    tail.push(TailHop {
        relay_pubkey,
        prev_acc: proof.acc,
        proof: hop,
    });
    if tail.len() > TAIL_WINDOW {
        let excess = tail.len() - TAIL_WINDOW;
        tail.drain(0..excess);
    }

    Ok(CompressedChainProof {
        origin_tx_id: proof.origin_tx_id,
        sequence: proof.sequence,
        length: hop_index,
        acc: new_acc,
        tail,
    })
}

/// Fold a whole ordered hop list at once. Equivalent to [`genesis`] followed
/// by one [`fold_hop`] per hop — see `test_incremental_fold_matches_full_reproof`.
pub fn compose(
    origin_tx_id: [u8; 32],
    sequence: u64,
    hops: &[([u8; 32], RelayChainProof)],
) -> Result<CompressedChainProof, SyncEngineError> {
    let mut proof = genesis(origin_tx_id, sequence);
    for (relay_pubkey, hop) in hops {
        proof = fold_hop(&proof, *relay_pubkey, hop.clone())?;
    }
    Ok(proof)
}

/// Verify a [`CompressedChainProof`] against the slot it claims to be about.
///
/// Cost is [`verification_cost`] — flat in `proof.length`. See the module docs
/// for precisely what a returned [`VerifiedChain`] does and does not attest to.
pub fn verify_compressed(
    proof: &CompressedChainProof,
    expected_origin_tx_id: &[u8; 32],
    expected_sequence: u64,
) -> Result<VerifiedChain, SyncEngineError> {
    if proof.origin_tx_id != *expected_origin_tx_id {
        return Err(invalid(format!(
            "compressed proof origin tx id {} does not match the expected {}",
            hex::encode(proof.origin_tx_id),
            hex::encode(expected_origin_tx_id),
        )));
    }
    if proof.sequence != expected_sequence {
        return Err(invalid(format!(
            "compressed proof sequence {} does not match the expected {}",
            proof.sequence, expected_sequence
        )));
    }
    if proof.length == 0 {
        return Err(invalid(
            "compressed proof attests to a zero-length chain; nothing to escalate",
        ));
    }

    let expected_tail = std::cmp::min(proof.length, TAIL_WINDOW as u64) as usize;
    if proof.tail.len() != expected_tail {
        return Err(invalid(format!(
            "compressed proof tail holds {} hop(s) but a chain of length {} must carry {}",
            proof.tail.len(),
            proof.length,
            expected_tail,
        )));
    }

    // 1-based index of the first hop retained in the tail.
    let first_tail_index = proof.length - proof.tail.len() as u64 + 1;

    let mut running = proof.tail[0].prev_acc;
    let mut distinct: HashSet<[u8; 32]> = HashSet::new();
    for (offset, hop) in proof.tail.iter().enumerate() {
        if hop.prev_acc != running {
            return Err(invalid(format!(
                "tail hop {offset} does not chain: its prev_acc breaks the fold from the \
                 previous hop"
            )));
        }
        if hop.proof.sequence != expected_sequence {
            return Err(invalid(format!(
                "tail hop {offset} proof is for sequence {}, not {expected_sequence}",
                hop.proof.sequence
            )));
        }
        if hop.proof.chain_hash != hop.prev_acc {
            return Err(invalid(format!(
                "tail hop {offset} proof was not signed over the accumulator it extends"
            )));
        }
        let key = VerifyingKey::from_bytes(&hop.relay_pubkey)
            .map_err(|e| invalid(format!("tail hop {offset} relay pubkey is invalid: {e}")))?;
        if !hop.proof.verify(&key, &proof.origin_tx_id) {
            return Err(invalid(format!(
                "tail hop {offset} proof signature does not verify against its relay pubkey"
            )));
        }
        running = acc_step(
            &hop.prev_acc,
            &hop.relay_pubkey,
            first_tail_index + offset as u64,
        );
        distinct.insert(hop.relay_pubkey);
    }

    if running != proof.acc {
        return Err(invalid(
            "tail attestations do not fold up to the compressed proof's accumulator",
        ));
    }

    // Short chain: the tail *is* the whole chain, so it must re-root at a
    // freshly recomputed genesis. Long chain: `proof.tail[0].prev_acc`
    // (= acc_{n-TAIL_WINDOW}) is accepted on the tail relays' recursive
    // attestations — the documented trust shift (module docs, point 1).
    if proof.length <= TAIL_WINDOW as u64 {
        let g = acc_genesis(&proof.origin_tx_id, proof.sequence);
        if proof.tail[0].prev_acc != g {
            return Err(invalid(
                "short chain's first tail hop does not root at the recomputed genesis \
                 accumulator",
            ));
        }
    }

    if distinct.len() < MIN_QUORUM {
        return Err(invalid(format!(
            "compressed proof tail carries only {} distinct relay(s); at least {MIN_QUORUM} are \
             required",
            distinct.len(),
        )));
    }

    Ok(VerifiedChain {
        origin_tx_id: proof.origin_tx_id,
        sequence: proof.sequence,
        length: proof.length,
        distinct_tail_relays: distinct.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    const ORIGIN: [u8; 32] = [0x11; 32];
    const SEQUENCE: u64 = 101;

    fn relay_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// Build a valid `n`-hop chain: hop `i` is signed by a fresh relay over
    /// `(ORIGIN, acc_{i-1}, SEQUENCE)`, exactly as the linking rule requires.
    /// Returns the hop list plus the signing keys (index `i-1` signed hop `i`).
    fn build_chain(n: usize) -> (Vec<([u8; 32], RelayChainProof)>, Vec<SigningKey>) {
        build_chain_for(ORIGIN, SEQUENCE, n)
    }

    fn build_chain_for(
        origin: [u8; 32],
        sequence: u64,
        n: usize,
    ) -> (Vec<([u8; 32], RelayChainProof)>, Vec<SigningKey>) {
        let mut hops = Vec::with_capacity(n);
        let mut keys = Vec::with_capacity(n);
        let mut acc = acc_genesis(&origin, sequence);
        for i in 1..=n as u64 {
            let key = relay_key();
            let pk = key.verifying_key().to_bytes();
            let proof = RelayChainProof::sign(&key, &origin, &acc, sequence);
            acc = acc_step(&acc, &pk, i);
            hops.push((pk, proof));
            keys.push(key);
        }
        (hops, keys)
    }

    #[test]
    fn test_compose_empty_is_genesis() {
        let composed = compose(ORIGIN, SEQUENCE, &[]).unwrap();
        assert_eq!(composed, genesis(ORIGIN, SEQUENCE));
        assert_eq!(composed.length, 0);
        assert!(composed.tail.is_empty());
    }

    #[test]
    fn test_compressed_proof_verifies_for_short_chain() {
        let (hops, _keys) = build_chain(3);
        let proof = compose(ORIGIN, SEQUENCE, &hops).unwrap();

        assert_eq!(proof.length, 3);
        assert_eq!(proof.tail.len(), 3); // whole chain fits in the tail

        let verified = verify_compressed(&proof, &ORIGIN, SEQUENCE).unwrap();
        assert_eq!(verified.length, 3);
        assert_eq!(verified.distinct_tail_relays, 3);
    }

    #[test]
    fn test_compressed_proof_verifies_for_long_chain() {
        let (hops, _keys) = build_chain(512);
        let proof = compose(ORIGIN, SEQUENCE, &hops).unwrap();

        assert_eq!(proof.length, 512);
        assert_eq!(proof.tail.len(), TAIL_WINDOW); // bounded regardless of length

        let verified = verify_compressed(&proof, &ORIGIN, SEQUENCE).unwrap();
        assert_eq!(verified.length, 512);
        assert_eq!(verified.distinct_tail_relays, TAIL_WINDOW);
    }

    #[test]
    fn test_incremental_fold_matches_full_reproof() {
        let (hops, _keys) = build_chain(40);

        // (a) fold hop-by-hop, as each relay would as the envelope passes it.
        let mut incremental = genesis(ORIGIN, SEQUENCE);
        for (pk, hop) in &hops {
            incremental = fold_hop(&incremental, *pk, hop.clone()).unwrap();
        }

        // (b) compose the whole chain at the escalation point.
        let full = compose(ORIGIN, SEQUENCE, &hops).unwrap();

        assert_eq!(incremental, full);

        // (c) fold in two sessions (serialize the partial proof in between,
        // as a relay that goes offline mid-chain would) — still identical.
        let (first, second) = hops.split_at(17);
        let mut partial = genesis(ORIGIN, SEQUENCE);
        for (pk, hop) in first {
            partial = fold_hop(&partial, *pk, hop.clone()).unwrap();
        }
        let round_tripped: CompressedChainProof =
            rmp_serde::from_slice(&rmp_serde::to_vec(&partial).unwrap()).unwrap();
        let mut resumed = round_tripped;
        for (pk, hop) in second {
            resumed = fold_hop(&resumed, *pk, hop.clone()).unwrap();
        }
        assert_eq!(resumed, full);
    }

    #[test]
    fn test_tampered_hop_is_rejected_even_after_compression() {
        let (hops, keys) = build_chain(64);
        let good = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        verify_compressed(&good, &ORIGIN, SEQUENCE).unwrap();

        // (a) An intermediate hop is tampered: relay 20 is swapped for an
        // attacker's key that re-signs over whatever it likes. Compression
        // must not launder this — the fold refuses it because the attacker
        // could not have signed over the real running accumulator.
        let mut tampered = hops.clone();
        let attacker = relay_key();
        tampered[20] = (
            attacker.verifying_key().to_bytes(),
            RelayChainProof::sign(&attacker, &ORIGIN, &[0xAB; 32], SEQUENCE),
        );
        let err = compose(ORIGIN, SEQUENCE, &tampered).unwrap_err();
        assert!(matches!(err, SyncEngineError::CompressedProofInvalid(_)));

        // (b) The compressed accumulator itself is bit-flipped after the fact.
        let mut flipped = good.clone();
        flipped.acc[0] ^= 0x01;
        assert!(matches!(
            verify_compressed(&flipped, &ORIGIN, SEQUENCE),
            Err(SyncEngineError::CompressedProofInvalid(_))
        ));

        // (c) A tail attestation is replaced with one the same relay signed
        // over a *different* origin tx id — a genuine signature, wrong chain.
        let mut spliced = good.clone();
        let victim_hop_index = good.length as usize - TAIL_WINDOW + 1; // 1-based
        let victim_key = &keys[victim_hop_index - 1];
        spliced.tail[1].proof =
            RelayChainProof::sign(victim_key, &[0xCD; 32], &spliced.tail[1].prev_acc, SEQUENCE);
        assert!(matches!(
            verify_compressed(&spliced, &ORIGIN, SEQUENCE),
            Err(SyncEngineError::CompressedProofInvalid(_))
        ));
    }

    #[test]
    fn test_verification_cost_is_flat() {
        let (short_hops, _) = build_chain(8);
        let (long_hops, _) = build_chain(1024);
        let short = compose(ORIGIN, SEQUENCE, &short_hops).unwrap();
        let long = compose(ORIGIN, SEQUENCE, &long_hops).unwrap();

        // The claim that matters: identical verification work regardless of
        // how many hops the chain actually has.
        assert_eq!(verification_cost(&short), verification_cost(&long));
        assert_eq!(verification_cost(&long).signature_checks, TAIL_WINDOW);

        // The serialized artifact does not scale with chain length either. It
        // is not byte-for-byte identical — MessagePack varint-encodes the
        // `length` field and its per-byte array encoding depends on the random
        // key/hash/signature bytes — but the gap between an 8-hop and a
        // 1024-hop proof is a small constant, not linear in hop count.
        let short_size = compressed_size(&short).unwrap() as i64;
        let long_size = compressed_size(&long).unwrap() as i64;
        assert!(
            (short_size - long_size).abs() < 128,
            "artifact size grew with chain length: {short_size} vs {long_size}"
        );
    }

    #[test]
    fn test_fold_rejects_wrong_sequence() {
        let start = genesis(ORIGIN, SEQUENCE);
        let key = relay_key();
        let wrong_seq_hop = RelayChainProof::sign(&key, &ORIGIN, &start.acc, SEQUENCE + 1);
        let err = fold_hop(&start, key.verifying_key().to_bytes(), wrong_seq_hop).unwrap_err();
        assert!(matches!(err, SyncEngineError::CompressedProofInvalid(_)));
    }

    #[test]
    fn test_fold_rejects_unlinked_hop() {
        let start = genesis(ORIGIN, SEQUENCE);
        let key = relay_key();
        // Signed over a chain_hash that isn't the current accumulator.
        let unlinked = RelayChainProof::sign(&key, &ORIGIN, &[0x00; 32], SEQUENCE);
        let err = fold_hop(&start, key.verifying_key().to_bytes(), unlinked).unwrap_err();
        assert!(matches!(err, SyncEngineError::CompressedProofInvalid(_)));
    }

    #[test]
    fn test_fold_rejects_wrong_signer() {
        let start = genesis(ORIGIN, SEQUENCE);
        let signer = relay_key();
        let hop = RelayChainProof::sign(&signer, &ORIGIN, &start.acc, SEQUENCE);
        // Pair the proof with a *different* relay's pubkey.
        let other_pubkey = relay_key().verifying_key().to_bytes();
        let err = fold_hop(&start, other_pubkey, hop).unwrap_err();
        assert!(matches!(err, SyncEngineError::CompressedProofInvalid(_)));
    }

    #[test]
    fn test_verify_rejects_below_quorum_tail() {
        // A one-hop chain: valid fold, but only one distinct relay in the
        // tail — below MIN_QUORUM, so it cannot carry an escalation alone.
        let (hops, _keys) = build_chain(1);
        let proof = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        assert!(matches!(
            verify_compressed(&proof, &ORIGIN, SEQUENCE),
            Err(SyncEngineError::CompressedProofInvalid(_))
        ));
    }

    #[test]
    fn test_verify_rejects_wrong_slot() {
        let (hops, _keys) = build_chain(10);
        let proof = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        assert!(matches!(
            verify_compressed(&proof, &[0x22; 32], SEQUENCE),
            Err(SyncEngineError::CompressedProofInvalid(_))
        ));
        assert!(matches!(
            verify_compressed(&proof, &ORIGIN, SEQUENCE + 1),
            Err(SyncEngineError::CompressedProofInvalid(_))
        ));
    }

    #[test]
    fn test_verify_rejects_forged_length_claim() {
        // Take a valid long chain and inflate its claimed length without
        // touching the tail. The tail no longer folds up to `acc` under the
        // shifted hop indices, so verification fails.
        let (hops, _keys) = build_chain(100);
        let mut proof = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        proof.length += 50;
        assert!(matches!(
            verify_compressed(&proof, &ORIGIN, SEQUENCE),
            Err(SyncEngineError::CompressedProofInvalid(_))
        ));
    }

    #[test]
    fn test_composition_is_deterministic() {
        let (hops, _keys) = build_chain(32);
        let a = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        let b = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            rmp_serde::to_vec(&a).unwrap(),
            rmp_serde::to_vec(&b).unwrap()
        );
    }

    #[test]
    fn test_serde_roundtrip() {
        let (hops, _keys) = build_chain(20);
        let proof = compose(ORIGIN, SEQUENCE, &hops).unwrap();
        let bytes = rmp_serde::to_vec(&proof).unwrap();
        let back: CompressedChainProof = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(proof, back);
        verify_compressed(&back, &ORIGIN, SEQUENCE).unwrap();
    }

    #[test]
    fn test_distinct_relay_reuse_across_tail_counts_once() {
        // A relay that appears twice in the tail must count once for quorum.
        // Build a 3-hop chain where hop 2 reuses hop 1's key, then a fresh
        // hop 3; tail = all three, distinct relays = 2 == MIN_QUORUM.
        let origin = [0x33; 32];
        let seq = 7;
        let mut acc = acc_genesis(&origin, seq);
        let k1 = relay_key();
        let k3 = relay_key();
        let signers = [&k1, &k1, &k3];
        let mut hops = Vec::new();
        for (i, k) in signers.iter().enumerate() {
            let pk = k.verifying_key().to_bytes();
            let proof = RelayChainProof::sign(k, &origin, &acc, seq);
            acc = acc_step(&acc, &pk, i as u64 + 1);
            hops.push((pk, proof));
        }
        let proof = compose(origin, seq, &hops).unwrap();
        let verified = verify_compressed(&proof, &origin, seq).unwrap();
        assert_eq!(verified.distinct_tail_relays, 2);
    }
}
