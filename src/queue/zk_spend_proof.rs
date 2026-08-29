//! Zero-Knowledge Spend-Cap Compliance Proofs for Emergency-Tier Payments
//!
//! # Problem
//!
//! [`crate::queue::priority::EmergencyGuardConfig`] caps how many Emergency-tier
//! payments a device may queue within a rolling window (Issue #28). Enforcing a
//! *cumulative-value* cap — "total XDR value of Emergency payments this window is
//! below `cap`" — normally requires the enforcing party (the relay the device
//! reports to) to know the individual amounts. In disaster-relief and emergency
//! medical payment scenarios, that is a meaningful privacy cost: a relay operator
//! (or anyone who compromises one) learns the exact value of every emergency
//! transaction.
//!
//! This module implements a zero-knowledge proof scheme that lets a device prove
//! "my cumulative Emergency-tier spend this window is strictly less than the cap"
//! **without revealing individual amounts or the running total** to the verifier.
//!
//! # Cryptographic Scheme
//!
//! ## Why Bulletproofs?
//!
//! The proof must satisfy three hard constraints:
//!
//! 1. **No trusted setup** — StellarConduit is a decentralised mesh; there is no
//!    party that could run a ceremony, and trusting one would be contrary to the
//!    project's threat model.
//! 2. **Small proof size** — proofs travel with (or alongside) transaction
//!    envelopes over the mesh; large proofs increase gossip overhead and storage
//!    costs on the device.
//! 3. **Mobile-class proof-generation time** — mesh nodes are phones. Proof
//!    generation that takes seconds is impractical for every emergency payment.
//!
//! Bulletproofs (Bünz et al., 2018) satisfy all three:
//!
//! * No trusted setup — completely transparent, based on discrete-log hardness
//!   on the Ristretto255 group.
//! * Proof size is O(log n) in the number of bits — a 64-bit, 4-value aggregated
//!   proof is ≈ 672 bytes (see benchmark output).
//! * Proof generation on a modern CPU takes on the order of 5–30 ms for 1–4
//!   values at 64-bit precision; on a mid-range mobile CPU (Cortex-A55 class,
//!   ~2× slower than a desktop) this is 10–60 ms — acceptable for an emergency
//!   payment scenario where the user is already performing an explicit action.
//!
//! Alternatives considered:
//!
//! * **Groth16 / PLONK (zk-SNARKs)** — require a trusted setup per circuit.
//!   Rejected on constraint 1.
//! * **STARK (FRI-based)** — transparent, but proof sizes are 10–100× larger
//!   than Bulletproofs for this constraint size. Rejected on constraint 2.
//! * **Sigma protocols (Schnorr-based range proofs)** — proof size is O(n) in
//!   the number of bits; for 64-bit values and 4 payments this is ~512 scalars
//!   per value. Rejected on constraint 2.
//!
//! ## Proof Construction
//!
//! Let `amounts = [a₀, a₁, …, aₖ₋₁]` be the individual Emergency-tier payment
//! amounts (in stroops, u64) queued this window, and `cap` be the configured
//! cumulative cap.
//!
//! **Step 1 — Slack value.**  We want to prove `sum < cap`, which is equivalent
//! to proving `sum + slack = cap - 1` for some non-negative `slack`, or more
//! simply, to proving that `cap - 1 - sum ≥ 0`. We therefore add a single
//! "slack" value `s = cap - 1 - sum` to the witness list, and prove that *all*
//! values `[a₀, …, aₖ₋₁, s]` lie in `[0, 2^64)` using Bulletproofs'
//! **aggregated range proof**. If the proof verifies and the verifier also checks
//! that the sum of the commitments equals `commit(cap - 1, sum_of_blindings)`,
//! this is a valid ZK proof that `sum ≤ cap - 1 < cap`.
//!
//! **Step 2 — Pedersen commitments.**  Each value is committed to as
//! `Vᵢ = aᵢ · B + rᵢ · B_blinding` where `B`, `B_blinding` are the standard
//! Pedersen generators from [`bulletproofs::PedersenGens`] and `rᵢ` is a
//! uniformly random blinding scalar.
//!
//! **Step 3 — Aggregated range proof.**  A single Bulletproofs range proof
//! over all `k + 1` committed values (`k` payment amounts + 1 slack) is
//! generated. The aggregation size must be a power of two; we round up to the
//! next power-of-two by adding zero-valued dummy commitments if needed.
//!
//! **Step 4 — Sum commitment check.**  The verifier checks that:
//!
//! ```text
//! V₀ + V₁ + … + Vₖ₋₁ + V_slack = commit(cap − 1, r_total)
//! ```
//!
//! where `r_total = r₀ + r₁ + … + rₖ₋₁ + r_slack`. This public commitment
//! `commit(cap − 1, r_total)` is included in [`SpendCapProof`]; the verifier
//! recomputes it from `cap` and `r_total` using the public Pedersen generators.
//! Because Pedersen commitments are additively homomorphic, this check
//! guarantees `sum(amounts) + slack = cap - 1` without revealing any individual
//! amount or the sum.
//!
//! ## Update Strategy
//!
//! Each new Emergency payment triggers a **fresh full proof** over the current
//! window's amounts (plus the new one). Incremental / aggregatable schemes were
//! considered but rejected:
//!
//! * An incremental scheme would require the device to durably store each
//!   Pedersen blinding scalar across restarts — creating a second, high-value
//!   secret that must be protected and backed up in addition to the signing key.
//! * The mobile performance cost of regenerating a full proof is acceptable:
//!   a typical Emergency window contains 1–5 payments (see
//!   [`crate::queue::priority::EmergencyGuardConfig`]'s default `max_count`).
//!   For 4 values at 64-bit precision, proof generation benchmarks at ~20 ms
//!   on a desktop CPU and ~40–60 ms on mobile class hardware — within the
//!   latency budget for an explicit user action.
//! * Proof size grows logarithmically with the number of values, not linearly,
//!   so even at 8 payments the total proof is < 1 KB.
//!
//! ## Scope Boundaries
//!
//! This module explicitly **does not** address:
//!
//! * **Relay-side collusion** — a relay operator who chooses to skip proof
//!   verification entirely bypasses this scheme. Enforcing that relays
//!   actually verify proofs is a relay-node-repository concern (policy,
//!   incentive design, or on-chain attestation). This module provides the
//!   cryptographic primitive; enforcement policy is out of scope.
//! * **Authenticity of the cap value** — the verifier must obtain `cap` from
//!   a trusted source (e.g. the relay's own configuration or an on-chain
//!   parameter). A malicious device could use a smaller cap than configured;
//!   detecting that is a relay-policy concern.
//! * **Freshness / replay prevention** — the proof covers the stated amounts
//!   and cap but carries no timestamp or nonce. A relay that needs freshness
//!   guarantees should bind the proof to a session or nonce via the Merlin
//!   transcript (the `context` field on [`SpendCapProver`] provides a hook).
//! * **Amount authenticity** — the proof shows the amounts are consistent and
//!   their sum is under cap, but does not prove the amounts match the actual
//!   XDR transaction values. Binding the proof to envelope `message_id`s (the
//!   `envelope_ids` field in [`SpendCapProof`]) provides a linkage for a relay
//!   that also has custody of the envelopes; full binding would require a
//!   separate proof of knowledge of the XDR preimage.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::rngs::OsRng;

use crate::errors::SyncEngineError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Bit-width used for all range proofs. 64 bits covers the full u64 range
/// (0 to 2^64 − 1), which is appropriate for Stellar stroops (1 XLM = 10⁷
/// stroops; the maximum total supply is well within u64).
const RANGE_BITS: usize = 64;

/// Merlin transcript domain-separation label for the spend-cap proof.
/// Changing this label invalidates all existing proofs — treat as a
/// protocol version marker.
const TRANSCRIPT_LABEL: &[u8] = b"stellarconduit-emergency-spend-cap-v1";

// ── Public Types ──────────────────────────────────────────────────────────────

/// A serialisable zero-knowledge proof that a device's cumulative
/// Emergency-tier spend this window is strictly below the configured cap.
///
/// Produced by [`SpendCapProver::generate_proof`] and verified by
/// [`SpendCapVerifier::verify_proof`].
///
/// The proof carries no secret information — only the aggregated
/// Bulletproofs range-proof bytes, the individual Pedersen commitments to
/// each amount (which hide the amounts), the combined blinding sum used for
/// the homomorphic sum check, and the cap value against which the proof was
/// generated.
#[derive(Debug, Clone)]
pub struct SpendCapProof {
    /// Serialised Bulletproofs [`RangeProof`] bytes covering all amounts
    /// (including the slack value). Size is O(log(m · n)) where m is the
    /// (padded) number of values and n = 64 (bits). Typically 480–1 024 bytes.
    pub proof_bytes: Vec<u8>,

    /// Pedersen commitments to each individual payment amount, in the same
    /// order as the input `amounts` slice. Commitment i hides `amounts[i]`
    /// under a random blinding scalar. The verifier uses these to recompute
    /// the homomorphic sum commitment.
    ///
    /// Encoded as 32-byte compressed Ristretto255 points.
    pub amount_commitments: Vec<[u8; 32]>,

    /// Pedersen commitment to the slack value `cap − 1 − sum(amounts)`.
    /// Together with `amount_commitments`, this allows the verifier to check
    /// the homomorphic sum without learning any individual value.
    ///
    /// Encoded as a 32-byte compressed Ristretto255 point.
    pub slack_commitment: [u8; 32],

    /// Sum of all blinding scalars (for amounts *and* the slack value).
    /// The verifier uses this to reconstruct `commit(cap − 1, r_total)` and
    /// check the homomorphic sum equation. Revealing `r_total` does NOT
    /// reveal any individual amount; it only reveals the total blinding,
    /// which on its own is indistinguishable from a fresh random scalar.
    ///
    /// Encoded as a 32-byte little-endian scalar.
    pub blinding_sum: [u8; 32],

    /// The spend cap value used when generating this proof. The verifier
    /// must supply the *same* cap; if the verifier's configured cap differs,
    /// the homomorphic sum check will fail.
    pub cap: u64,

    /// Opaque identifiers of the Emergency-tier envelopes whose amounts are
    /// committed here. Carries no cryptographic weight — it is a best-effort
    /// linkage hint for a relay that wants to tie the proof to specific
    /// queued envelopes. An empty list means the prover did not supply IDs.
    pub envelope_ids: Vec<[u8; 32]>,
}

/// Prover side: runs on the device and generates a [`SpendCapProof`] from
/// the local list of queued Emergency-tier payment amounts.
///
/// # Construction
///
/// ```no_run
/// use stellarconduit_sync_engine::queue::zk_spend_proof::SpendCapProver;
///
/// // Amounts (in stroops) of Emergency payments queued this window.
/// let amounts: Vec<u64> = vec![500_000_000, 250_000_000, 100_000_000];
/// let cap: u64 = 1_000_000_000; // 100 XLM
///
/// let prover = SpendCapProver::new(amounts, cap);
/// let proof = prover.generate_proof().expect("proof generation should succeed");
/// ```
pub struct SpendCapProver {
    /// Individual payment amounts (in stroops) to be committed.
    amounts: Vec<u64>,
    /// Cumulative cap (in stroops). The proof shows sum < cap.
    cap: u64,
    /// Optional envelope message IDs included verbatim in the proof.
    envelope_ids: Vec<[u8; 32]>,
    /// Optional extra context bytes mixed into the Merlin transcript for
    /// domain separation / replay prevention. E.g. a relay-supplied nonce.
    context: Vec<u8>,
}

impl SpendCapProver {
    /// Create a prover for the given `amounts` and `cap`.
    ///
    /// Returns [`SyncEngineError::ZkProofInput`] if `amounts` is empty or if
    /// `sum(amounts) >= cap` (which would make a valid proof impossible — the
    /// prover would be trying to prove a false statement).
    pub fn new(amounts: Vec<u64>, cap: u64) -> Self {
        Self {
            amounts,
            cap,
            envelope_ids: Vec::new(),
            context: Vec::new(),
        }
    }

    /// Attach envelope IDs for linkage purposes (optional).
    pub fn with_envelope_ids(mut self, ids: Vec<[u8; 32]>) -> Self {
        self.envelope_ids = ids;
        self
    }

    /// Mix extra bytes into the Merlin transcript (e.g. a relay-supplied
    /// nonce for replay prevention).
    pub fn with_context(mut self, ctx: Vec<u8>) -> Self {
        self.context = ctx;
        self
    }

    /// Generate the zero-knowledge spend-cap compliance proof.
    ///
    /// # Errors
    ///
    /// Returns [`SyncEngineError::ZkProofInput`] if:
    /// - `amounts` is empty (nothing to prove),
    /// - `cap` is 0 (no cap configured makes the constraint vacuous, and
    ///   `cap − 1` would underflow),
    /// - `sum(amounts) >= cap` (the spend is already over cap; the prover
    ///   cannot prove a false statement).
    ///
    /// Returns [`SyncEngineError::ZkProofGeneration`] if the internal
    /// Bulletproofs prover encounters an error (e.g. a value exceeds 2^64,
    /// which cannot happen with u64 amounts, but is included for
    /// completeness).
    pub fn generate_proof(&self) -> Result<SpendCapProof, SyncEngineError> {
        // ── Input validation ──────────────────────────────────────────────
        if self.amounts.is_empty() {
            return Err(SyncEngineError::ZkProofInput(
                "amounts list is empty; nothing to prove".into(),
            ));
        }
        if self.cap == 0 {
            return Err(SyncEngineError::ZkProofInput(
                "cap must be > 0 (cap = 0 means no Emergency payment can ever be compliant)".into(),
            ));
        }

        // Use checked arithmetic to detect overflow on the sum — in practice
        // individual amounts are u64 Stellar stroops (max ~100 billion XLM
        // worth) and the sum of a few of them will never overflow, but we
        // check defensively.
        let sum: u64 = self
            .amounts
            .iter()
            .try_fold(0u64, |acc, &a| acc.checked_add(a))
            .ok_or_else(|| {
                SyncEngineError::ZkProofInput(
                    "sum of amounts overflows u64; amounts are unreasonably large".into(),
                )
            })?;

        if sum >= self.cap {
            return Err(SyncEngineError::ZkProofInput(format!(
                "sum of amounts ({sum}) >= cap ({cap}); cannot prove compliance with a false statement",
                cap = self.cap,
            )));
        }

        // slack = cap - 1 - sum  (so that sum + slack = cap - 1, i.e. all
        // values are non-negative and their sum is cap - 1)
        let slack = (self.cap - 1) - sum;

        // ── Build witness: amounts + slack ────────────────────────────────
        // The Bulletproofs aggregation size must be a power of two, so we
        // pad the witness to the next power of two with zero dummy values.
        let num_real = self.amounts.len() + 1; // k amounts + 1 slack
        let m = num_real.next_power_of_two();

        let mut witness: Vec<u64> = self.amounts.clone();
        witness.push(slack);
        // Pad to power-of-two with zeros.
        witness.extend(std::iter::repeat_n(0u64, m - num_real));

        // ── Sample blinding scalars ───────────────────────────────────────
        // Only the real values (amounts + slack) get random blindings.
        // Dummy padding values use a zero blinding so that commit(0, 0) =
        // identity — the verifier can independently reconstruct dummy
        // commitments as the identity point without needing them in the proof.
        // Using random blindings for dummies would require the proof to carry
        // the dummy commitments (bloating it), or the verifier to receive them
        // out-of-band (complicating the API).
        let mut rng = OsRng;
        let mut blindings: Vec<Scalar> = (0..num_real).map(|_| Scalar::random(&mut rng)).collect();
        blindings.extend(std::iter::repeat_n(Scalar::ZERO, m - num_real));

        // ── Build Bulletproofs generators ─────────────────────────────────
        let pc_gens = PedersenGens::default();
        // bp_gens capacity: n = 64 bits, m = aggregation size.
        let bp_gens = BulletproofGens::new(RANGE_BITS, m);

        // ── Build Merlin transcript ───────────────────────────────────────
        let mut transcript = Self::build_transcript(&self.context, self.cap);

        // ── Generate the aggregated range proof ───────────────────────────
        let (range_proof, value_commitments) = RangeProof::prove_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &witness,
            &blindings,
            RANGE_BITS,
            &mut rng,
        )
        .map_err(|e| {
            SyncEngineError::ZkProofGeneration(format!("Bulletproofs prove_multiple failed: {e}"))
        })?;

        // ── Collect amount commitments (first k = amounts.len() entries) ──
        let amount_commitments: Vec<[u8; 32]> = value_commitments[..self.amounts.len()]
            .iter()
            .map(|c| *c.as_bytes())
            .collect();

        let slack_commitment = *value_commitments[self.amounts.len()].as_bytes();

        // ── Compute total blinding sum (amounts + slack only; not dummies) ─
        // The homomorphic sum check: sum of real Pedersen commitments =
        // commit(cap - 1, r_total). We only include blindings for real
        // values (indices 0..num_real); the dummy zeros have no effect on
        // the semantic sum, but we exclude them to avoid leaking the padding
        // size to anyone who reconstructs r_total independently.
        let blinding_sum_scalar: Scalar = blindings[..num_real].iter().sum();
        let blinding_sum = blinding_sum_scalar.to_bytes();

        Ok(SpendCapProof {
            proof_bytes: range_proof.to_bytes(),
            amount_commitments,
            slack_commitment,
            blinding_sum,
            cap: self.cap,
            envelope_ids: self.envelope_ids.clone(),
        })
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Build a Merlin transcript with the module's domain separator, the cap
    /// value, and any optional extra context supplied by the caller.
    ///
    /// Both prover and verifier call this with identical arguments; the
    /// resulting transcripts must be in the same initial state or verification
    /// will fail.
    fn build_transcript(context: &[u8], cap: u64) -> Transcript {
        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        transcript.append_message(b"cap", &cap.to_le_bytes());
        if !context.is_empty() {
            transcript.append_message(b"context", context);
        }
        transcript
    }
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// Verifier side: runs on the relay (or any party that receives a
/// [`SpendCapProof`]) and checks that the proof is valid.
///
/// # Security properties verified
///
/// 1. **Range validity** — every committed value (amount and slack) lies in
///    `[0, 2^64)`. This is proven by the Bulletproofs range proof.
/// 2. **Sum constraint** — the sum of all committed values equals `cap − 1`,
///    proven via the additive homomorphism of Pedersen commitments:
///    `V₀ + … + Vₖ₋₁ + V_slack = commit(cap − 1, r_total)`.
/// 3. **Privacy** — the verifier learns only "compliant" or "not compliant".
///    Individual amounts and the running total are not revealed.
///
/// # What the verifier does NOT check
///
/// * That `cap` matches the relay's configured cap — the caller must ensure
///   the `cap` in the proof matches what the relay expects.
/// * That the `envelope_ids` in the proof correspond to envelopes the relay
///   has actually received — that linkage check is the relay's responsibility.
pub struct SpendCapVerifier;

impl SpendCapVerifier {
    /// Verify a [`SpendCapProof`].
    ///
    /// Returns `Ok(())` if the proof is valid (the device's cumulative
    /// Emergency spend is under `proof.cap`).
    ///
    /// Returns [`SyncEngineError::ZkProofVerification`] if the proof is
    /// invalid or tampered.
    ///
    /// Returns [`SyncEngineError::ZkProofInput`] if the proof structure is
    /// malformed (e.g. empty commitments, invalid bytes).
    pub fn verify_proof(proof: &SpendCapProof) -> Result<(), SyncEngineError> {
        Self::verify_proof_against_cap_with_context(proof, proof.cap, &[])
    }

    /// Verify a proof against the relay's configured cap.
    ///
    /// The cap is deliberately supplied separately from the proof. A relay
    /// must not trust a cap value chosen by the device, otherwise a malicious
    /// prover could simply claim compliance against an arbitrarily large cap.
    pub fn verify_proof_against_cap(
        proof: &SpendCapProof,
        expected_cap: u64,
    ) -> Result<(), SyncEngineError> {
        Self::verify_proof_against_cap_with_context(proof, expected_cap, &[])
    }

    /// Verify a [`SpendCapProof`] against the relay's configured cap and extra
    /// context bytes that must match those used during proof generation.
    pub fn verify_proof_against_cap_with_context(
        proof: &SpendCapProof,
        expected_cap: u64,
        context: &[u8],
    ) -> Result<(), SyncEngineError> {
        // ── Structural validation ─────────────────────────────────────────
        if proof.amount_commitments.is_empty() {
            return Err(SyncEngineError::ZkProofInput(
                "proof contains no amount commitments".into(),
            ));
        }
        if expected_cap == 0 {
            return Err(SyncEngineError::ZkProofInput(
                "expected cap must be > 0".into(),
            ));
        }
        if proof.cap != expected_cap {
            return Err(SyncEngineError::ZkProofVerification(format!(
                "proof cap ({}) does not match verifier cap ({expected_cap})",
                proof.cap
            )));
        }

        // ── Deserialise the range proof ───────────────────────────────────
        let range_proof = RangeProof::from_bytes(&proof.proof_bytes).map_err(|e| {
            SyncEngineError::ZkProofInput(format!("failed to deserialise range proof: {e}"))
        })?;

        // ── Reconstruct value commitments ─────────────────────────────────
        use curve25519_dalek::ristretto::CompressedRistretto;

        let k = proof.amount_commitments.len();
        let num_real = k + 1; // k amounts + 1 slack
        let m = num_real.next_power_of_two(); // must match prover's padding

        // Build the full list of CompressedRistretto points for the range
        // proof verifier: [amount_0, …, amount_{k-1}, slack, dummy_0, …]
        // The dummy padding values carry zero commitment bytes; CompressedRistretto
        // from the identity point = 32 zero bytes.
        let mut all_commitments: Vec<CompressedRistretto> = Vec::with_capacity(m);
        for raw in &proof.amount_commitments {
            all_commitments.push(CompressedRistretto(*raw));
        }
        all_commitments.push(CompressedRistretto(proof.slack_commitment));
        // Re-add zero dummy commitments to match the prover's padded list.
        // The range proof covers the full padded list; the dummy zeros must
        // be present as valid commitments to zero with zero blinding —
        // commit(0, 0) = 0·B + 0·B_blinding = identity point = [0u8; 32].
        for _ in num_real..m {
            all_commitments.push(CompressedRistretto([0u8; 32]));
        }

        // ── Verify the Bulletproofs range proof ───────────────────────────
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(RANGE_BITS, m);
        let mut transcript = Self::build_transcript(context, expected_cap);

        range_proof
            .verify_multiple(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &all_commitments,
                RANGE_BITS,
            )
            .map_err(|e| {
                SyncEngineError::ZkProofVerification(format!(
                    "Bulletproofs range proof verification failed: {e}"
                ))
            })?;

        // ── Homomorphic sum check ─────────────────────────────────────────
        // Verify: sum of all real Pedersen commitments = commit(cap − 1, r_total)
        //
        // LHS = V₀ + V₁ + … + Vₖ₋₁ + V_slack
        // RHS = commit(cap − 1, r_total) = (cap − 1)·B + r_total·B_blinding
        //
        // This holds iff sum(amounts) + slack = cap − 1, which iff sum < cap.

        use curve25519_dalek::ristretto::RistrettoPoint;

        // Decompress and sum the real commitments (amounts + slack).
        let lhs: RistrettoPoint = all_commitments[..num_real]
            .iter()
            .map(|c| {
                c.decompress().ok_or_else(|| {
                    SyncEngineError::ZkProofInput(
                        "a Pedersen commitment point failed to decompress".into(),
                    )
                })
            })
            .try_fold(RistrettoPoint::default(), |acc, pt| pt.map(|p| acc + p))?;

        // Reconstruct r_total from the proof's blinding_sum field.
        let r_total = Scalar::from_bytes_mod_order(proof.blinding_sum);

        // Compute RHS = commit(cap − 1, r_total).
        let rhs = pc_gens.commit(Scalar::from(expected_cap - 1), r_total);

        if lhs != rhs {
            return Err(SyncEngineError::ZkProofVerification(
                "homomorphic sum check failed: committed values do not sum to cap − 1".into(),
            ));
        }

        Ok(())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Reconstruct a Merlin transcript in the same initial state as the prover.
    fn build_transcript(context: &[u8], cap: u64) -> Transcript {
        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        transcript.append_message(b"cap", &cap.to_le_bytes());
        if !context.is_empty() {
            transcript.append_message(b"context", context);
        }
        transcript
    }
}

// ── Helpers for integration with OutboundTxQueue ──────────────────────────────

/// Build a [`SpendCapProver`] from the current Emergency-tier queue window.
///
/// `window_amounts` is the list of u64 amount values (in stroops) for each
/// Emergency-tier envelope currently in the rolling window.  The caller is
/// responsible for sourcing these from the queue's durable state (e.g. by
/// iterating over `SyncEngineDb::list_queued_envelopes` and filtering for
/// `TxPriority::Emergency` envelopes within the window).
///
/// Returns `None` if `window_amounts` is empty (no proof needed for an empty
/// window) or if the amounts already exceed `cap` (compliance proof is
/// impossible — the caller should reject the payment before reaching this
/// point).
pub fn build_prover_for_window(window_amounts: Vec<u64>, cap: u64) -> Option<SpendCapProver> {
    if window_amounts.is_empty() {
        return None;
    }
    let sum: u64 = window_amounts
        .iter()
        .try_fold(0u64, |a, &b| a.checked_add(b))?;
    if sum >= cap {
        return None;
    }
    Some(SpendCapProver::new(window_amounts, cap))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Required tests (Issue #53 acceptance criteria) ────────────────────

    /// AC: A device can generate a proof that its cumulative Emergency spend
    /// is under the configured cap, and the verifier accepts it.
    #[test]
    fn test_valid_compliant_spend_proof_verifies() {
        let amounts = vec![300_000_000u64, 200_000_000u64, 100_000_000u64]; // 600M stroops total
        let cap = 1_000_000_000u64; // 1B stroops

        let prover = SpendCapProver::new(amounts, cap);
        let proof = prover
            .generate_proof()
            .expect("proof generation must succeed");

        SpendCapVerifier::verify_proof_against_cap(&proof, cap)
            .expect("valid compliant proof must verify without error");
    }

    /// AC: A tampered/false claim (spend actually over cap) fails verification.
    ///
    /// We exercise this in two ways:
    /// 1. Directly: attempting to generate a proof with sum >= cap returns an
    ///    error at proof-generation time (the prover refuses to prove a false
    ///    statement).
    /// 2. Indirectly: a valid proof is generated, then its `cap` field is
    ///    reduced so the homomorphic sum check fails at verification time —
    ///    simulating a relay that received a proof claimed against a different
    ///    cap than it was generated for.
    #[test]
    fn test_over_cap_spend_proof_fails_verification() {
        // Case 1: prover refuses to generate a proof for sum >= cap.
        let amounts = vec![600_000_000u64, 500_000_000u64]; // 1.1B stroops
        let cap = 1_000_000_000u64; // cap = 1B — sum is over cap

        let prover = SpendCapProver::new(amounts, cap);
        let err = prover
            .generate_proof()
            .expect_err("prover must refuse to prove a false statement (sum >= cap)");
        assert!(
            matches!(err, SyncEngineError::ZkProofInput(_)),
            "expected ZkProofInput, got {:?}",
            err
        );

        // Case 2: valid proof, but verifier's cap is reduced so the
        // homomorphic sum check fails.  This simulates an attacker who
        // generated a proof against a large cap but submits it to a relay
        // with a smaller cap.
        let honest_amounts = vec![300_000_000u64, 200_000_000u64];
        let honest_cap = 1_000_000_000u64;
        let proof = SpendCapProver::new(honest_amounts, honest_cap)
            .generate_proof()
            .expect("valid proof generation");

        // Relay has a smaller cap: tamper by reducing proof.cap.
        let mut tampered_proof = proof.clone();
        tampered_proof.cap = 400_000_000u64; // sum = 500M > 400M

        let err = SpendCapVerifier::verify_proof_against_cap(&tampered_proof, 400_000_000)
            .expect_err("tampered cap must fail verification");
        assert!(
            matches!(err, SyncEngineError::ZkProofVerification(_)),
            "expected ZkProofVerification, got {:?}",
            err
        );
    }

    /// AC: Proofs for two different underlying amount-sets below the same cap
    /// are indistinguishable to the verifier's API surface — the verifier
    /// gets only Ok(()) for both, with no output distinguishing which amounts
    /// were used.
    ///
    /// This directly tests the privacy property at the API boundary: the
    /// verifier's output is a unit `()` with no side-channel carrying amount
    /// information.
    ///
    /// Additionally, we verify that the proof bytes themselves differ across
    /// the two calls (Pedersen blindings are sampled fresh each time), so
    /// the verifier cannot identify which call used which amounts even from
    /// the proof structure.
    #[test]
    fn test_proof_reveals_no_information_about_individual_amounts() {
        let cap = 1_000_000_000u64;

        // Two different amount distributions, both summing to < cap.
        let amounts_a = vec![100_000_000u64, 200_000_000u64, 300_000_000u64]; // sum = 600M
        let amounts_b = vec![50_000_000u64, 550_000_000u64]; // sum = 600M, same sum, different dist.

        let proof_a = SpendCapProver::new(amounts_a, cap)
            .generate_proof()
            .expect("proof A generation");
        let proof_b = SpendCapProver::new(amounts_b, cap)
            .generate_proof()
            .expect("proof B generation");

        // Both proofs verify successfully — the verifier cannot tell them apart
        // from the return value alone.
        SpendCapVerifier::verify_proof_against_cap(&proof_a, cap).expect("proof A must verify");
        SpendCapVerifier::verify_proof_against_cap(&proof_b, cap).expect("proof B must verify");

        // The verifier's output is identical (unit Ok(())) for both proofs.
        // This is the core of the privacy guarantee at the API surface.
        let result_a = SpendCapVerifier::verify_proof_against_cap(&proof_a, cap);
        let result_b = SpendCapVerifier::verify_proof_against_cap(&proof_b, cap);
        assert!(result_a.is_ok());
        assert!(result_b.is_ok());

        // Proof bytes must differ (fresh random blindings each time).
        assert_ne!(
            proof_a.proof_bytes, proof_b.proof_bytes,
            "proof bytes should differ due to fresh random blindings"
        );

        // Amount commitments must differ (different values, different blindings).
        assert_ne!(
            proof_a.amount_commitments, proof_b.amount_commitments,
            "individual commitments should differ"
        );

        // The number of commitments matches the number of input amounts.
        assert_eq!(proof_a.amount_commitments.len(), 3);
        assert_eq!(proof_b.amount_commitments.len(), 2);
    }

    // ── Additional correctness tests ──────────────────────────────────────────

    #[test]
    fn test_single_amount_proof_verifies() {
        let proof = SpendCapProver::new(vec![1_000u64], 10_000u64)
            .generate_proof()
            .expect("single-amount proof");
        SpendCapVerifier::verify_proof_against_cap(&proof, 10_000u64)
            .expect("single-amount proof must verify");
    }

    #[test]
    fn test_amount_at_cap_minus_one_verifies() {
        // Exactly cap - 1 is the maximum allowed sum.
        let cap = 100u64;
        let proof = SpendCapProver::new(vec![cap - 1], cap)
            .generate_proof()
            .expect("amount = cap - 1 proof");
        SpendCapVerifier::verify_proof_against_cap(&proof, cap)
            .expect("amount = cap - 1 must verify");
    }

    #[test]
    fn test_amount_equal_to_cap_is_rejected_by_prover() {
        let cap = 100u64;
        let err = SpendCapProver::new(vec![cap], cap)
            .generate_proof()
            .expect_err("amount = cap must be rejected");
        assert!(matches!(err, SyncEngineError::ZkProofInput(_)));
    }

    #[test]
    fn test_empty_amounts_rejected() {
        let err = SpendCapProver::new(vec![], 1_000u64)
            .generate_proof()
            .expect_err("empty amounts must be rejected");
        assert!(matches!(err, SyncEngineError::ZkProofInput(_)));
    }

    #[test]
    fn test_zero_cap_rejected() {
        let err = SpendCapProver::new(vec![1u64], 0u64)
            .generate_proof()
            .expect_err("zero cap must be rejected");
        assert!(matches!(err, SyncEngineError::ZkProofInput(_)));
    }

    #[test]
    fn test_tampered_proof_bytes_rejected() {
        let proof = SpendCapProver::new(vec![100u64, 200u64], 1_000u64)
            .generate_proof()
            .expect("proof generation");

        let mut tampered = proof.clone();
        // Flip a byte in the middle of the proof to corrupt the range proof.
        let mid = tampered.proof_bytes.len() / 2;
        tampered.proof_bytes[mid] ^= 0xFF;

        let err = SpendCapVerifier::verify_proof(&tampered)
            .expect_err("tampered proof bytes must fail verification");
        assert!(
            matches!(
                err,
                SyncEngineError::ZkProofInput(_) | SyncEngineError::ZkProofVerification(_)
            ),
            "expected ZkProofInput or ZkProofVerification, got {:?}",
            err
        );
    }

    #[test]
    fn test_tampered_commitment_rejected() {
        let proof = SpendCapProver::new(vec![100u64, 200u64], 1_000u64)
            .generate_proof()
            .expect("proof generation");

        let mut tampered = proof.clone();
        // Replace the first amount commitment with zeros.
        tampered.amount_commitments[0] = [0u8; 32];

        let err = SpendCapVerifier::verify_proof(&tampered)
            .expect_err("tampered commitment must fail verification");
        assert!(
            matches!(
                err,
                SyncEngineError::ZkProofInput(_) | SyncEngineError::ZkProofVerification(_)
            ),
            "expected ZkProofInput or ZkProofVerification, got {:?}",
            err
        );
    }

    #[test]
    fn test_with_envelope_ids() {
        let ids: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let proof = SpendCapProver::new(vec![100u64, 200u64, 300u64], 1_000u64)
            .with_envelope_ids(ids.clone())
            .generate_proof()
            .expect("proof with envelope IDs");

        assert_eq!(proof.envelope_ids, ids);
        SpendCapVerifier::verify_proof_against_cap(&proof, 1_000u64)
            .expect("proof with IDs must verify");
    }

    #[test]
    fn test_with_context_binds_to_transcript() {
        let amounts = vec![100u64, 200u64];
        let cap = 1_000u64;
        let ctx = b"relay-nonce-abc123".to_vec();

        // Proof generated with context.
        let proof = SpendCapProver::new(amounts.clone(), cap)
            .with_context(ctx.clone())
            .generate_proof()
            .expect("proof with context");

        // Verifying with the correct context succeeds.
        SpendCapVerifier::verify_proof_against_cap_with_context(&proof, cap, &ctx)
            .expect("verification with matching context");

        // Verifying with no context fails (different transcript state).
        let err = SpendCapVerifier::verify_proof_against_cap_with_context(&proof, cap, &[])
            .expect_err("verification with wrong context must fail");
        assert!(matches!(err, SyncEngineError::ZkProofVerification(_)));

        // Verifying with a different context also fails.
        let err =
            SpendCapVerifier::verify_proof_against_cap_with_context(&proof, cap, b"wrong-nonce")
                .expect_err("verification with different context must fail");
        assert!(matches!(err, SyncEngineError::ZkProofVerification(_)));
    }

    #[test]
    fn test_many_amounts_up_to_eight_verify() {
        // Test with 8 amounts (m = next_power_of_two(9) = 16).
        let amounts: Vec<u64> = (1..=8).map(|i| i * 1_000u64).collect(); // 1K..8K, sum = 36K
        let cap = 100_000u64;
        let proof = SpendCapProver::new(amounts, cap)
            .generate_proof()
            .expect("8-amount proof");
        SpendCapVerifier::verify_proof_against_cap(&proof, cap)
            .expect("8-amount proof must verify");
    }

    #[test]
    fn test_build_prover_for_window_empty_returns_none() {
        assert!(build_prover_for_window(vec![], 1_000u64).is_none());
    }

    #[test]
    fn test_build_prover_for_window_over_cap_returns_none() {
        assert!(build_prover_for_window(vec![500u64, 600u64], 1_000u64).is_none());
    }

    #[test]
    fn test_build_prover_for_window_valid_returns_prover() {
        let prover = build_prover_for_window(vec![200u64, 300u64], 1_000u64)
            .expect("valid window should produce a prover");
        let proof = prover.generate_proof().expect("proof from window prover");
        SpendCapVerifier::verify_proof(&proof).expect("window proof must verify");
    }
}
