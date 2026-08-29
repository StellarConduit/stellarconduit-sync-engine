//! Offline construction and signing of `TransactionEnvelope`s.
//!
//! Building the actual Stellar transaction XDR (setting operations, fee, and
//! embedding the reserved sequence number into it) is the wallet layer's
//! responsibility, same as in `stellarconduit-core` — this crate treats
//! `tx_xdr` as an already-built base64 XDR string. What this module adds on top
//! of `stellarconduit_core::message::envelope::EnvelopeBuilder` is coupling that
//! signing step to sequence-number reservation, so a caller cannot accidentally
//! sign two envelopes for the same account without first reserving distinct
//! sequence numbers.
//!
//! Crucially, the source account and sequence number are **derived from the XDR
//! itself** (see [`crate::envelope::xdr`]) rather than taken on trust from the
//! caller. The caller still passes the account it *believes* it is signing for,
//! but that claim is cross-checked against what the transaction actually
//! encodes: a mismatch is rejected instead of being propagated into storage and
//! conflict detection, where it could mask a double-spend.

use std::collections::HashMap;

use sha2::{Digest, Sha256};
use stellarconduit_core::message::types::TransactionEnvelope;

use crate::envelope::secure_signing::KeySigner;
use crate::envelope::xdr::{extract_source_account_and_sequence, with_updated_sequence};
use crate::errors::SyncEngineError;
use crate::queue::{MultisigAccountRegistry, SequenceReservationManager};

pub struct OfflineEnvelopeBuilder;

impl OfflineEnvelopeBuilder {
    /// Derive the source account and sequence number from `tx_xdr`, reserve
    /// that sequence, and build and sign an envelope wrapping `tx_xdr`.
    ///
    /// The flow deliberately parses first and trusts the XDR over the caller:
    ///
    /// 1. Parse `tx_xdr` to recover the source account and sequence the wallet's
    ///    Stellar SDK layer actually embedded when it built the transaction.
    /// 2. Cross-check the caller-supplied `source_account` against it, rejecting
    ///    a [`SyncEngineError::SourceAccountMismatch`] if they disagree.
    /// 3. Reserve the next sequence number for that account and verify it equals
    ///    the sequence embedded in the XDR, rejecting a
    ///    [`SyncEngineError::SequenceMismatch`] (and rolling the reservation
    ///    back) if the wallet's bookkeeping has drifted from ours.
    ///
    /// Returns the signed envelope along with the sequence number it occupies —
    /// the one taken straight from the XDR — so the caller can correlate this
    /// envelope with its sequence slot (e.g. for conflict detection in
    /// `crate::conflict`).
    ///
    /// [`SyncEngineError::SourceAccountMismatch`]: crate::errors::SyncEngineError::SourceAccountMismatch
    /// [`SyncEngineError::SequenceMismatch`]: crate::errors::SyncEngineError::SequenceMismatch
    pub fn build_and_sign(
        sequences: &mut SequenceReservationManager,
        source_account: &str,
        signer: &dyn KeySigner,
        policy: &crate::envelope::pq::SigningPolicy,
        tx_xdr: impl Into<String>,
        ttl_hops: u8,
    ) -> Result<(crate::envelope::pq::HybridSignedEnvelope, i64), SyncEngineError> {
        let tx_xdr = tx_xdr.into();

        // Trust the XDR, not the caller: the true source account and sequence
        // are encoded in the already-built transaction.
        let (xdr_account, xdr_sequence) = extract_source_account_and_sequence(&tx_xdr)?;

        if source_account != xdr_account {
            return Err(SyncEngineError::SourceAccountMismatch {
                claimed: source_account.to_string(),
                actual: xdr_account,
            });
        }

        let reserved = sequences.reserve_next(&xdr_account)?;
        if reserved != xdr_sequence {
            // Nothing got signed, so roll the reservation back to keep the
            // manager consistent with what actually occupies each slot.
            let _ = sequences.release(&xdr_account, reserved);
            return Err(SyncEngineError::SequenceMismatch {
                account: xdr_account,
                reserved,
                actual: xdr_sequence,
            });
        }

        let origin_pubkey = signer.public_key();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let message_id = stellarconduit_core::message::envelope::compute_message_id(
            &origin_pubkey,
            &tx_xdr,
            timestamp,
        );
        let signature = signer.sign(&message_id)?;

        let classical_envelope = TransactionEnvelope {
            message_id,
            origin_pubkey,
            tx_xdr,
            ttl_hops,
            timestamp,
            signature,
        };

        let mut hybrid_envelope = crate::envelope::pq::HybridSignedEnvelope {
            classical_envelope,
            pq_signature: None,
            pq_public_key: None,
        };

        if let crate::envelope::pq::SigningPolicy::Hybrid(pq_pk, pq_sk) = policy {
            let payload = hybrid_envelope.canonical_payload();
            let pq_sig = pqcrypto_dilithium::dilithium2::detached_sign(&payload, pq_sk);
            use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
            hybrid_envelope.pq_signature = Some(pq_sig.as_bytes().to_vec());
            hybrid_envelope.pq_public_key = Some(pq_pk.as_bytes().to_vec());
        }

        Ok((hybrid_envelope, xdr_sequence))
    }
}

/// Parses the old envelope's `tx_xdr`, rewrites its sequence number, re-serializes it,
/// and produces a freshly-signed `TransactionEnvelope` (with a new `message_id`) via
/// the existing `EnvelopeBuilder` machinery.
///
/// Ensures that the other transaction semantics (operations, fee, memo if present)
/// are preserved unchanged.
pub fn resequence_and_resign(
    old_envelope: &TransactionEnvelope,
    new_sequence: i64,
    signer: &dyn KeySigner,
    policy: &crate::envelope::pq::SigningPolicy,
) -> Result<crate::envelope::pq::HybridSignedEnvelope, SyncEngineError> {
    let new_tx_xdr = with_updated_sequence(&old_envelope.tx_xdr, new_sequence)?;

    let origin_pubkey = signer.public_key();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let message_id = stellarconduit_core::message::envelope::compute_message_id(
        &origin_pubkey,
        &new_tx_xdr,
        timestamp,
    );
    let signature = signer.sign(&message_id)?;

    let classical_envelope = TransactionEnvelope {
        message_id,
        origin_pubkey,
        tx_xdr: new_tx_xdr,
        ttl_hops: old_envelope.ttl_hops,
        timestamp,
        signature,
    };

    let mut hybrid_envelope = crate::envelope::pq::HybridSignedEnvelope {
        classical_envelope,
        pq_signature: None,
        pq_public_key: None,
    };

    if let crate::envelope::pq::SigningPolicy::Hybrid(pq_pk, pq_sk) = policy {
        let payload = hybrid_envelope.canonical_payload();
        let pq_sig = pqcrypto_dilithium::dilithium2::detached_sign(&payload, pq_sk);
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
        hybrid_envelope.pq_signature = Some(pq_sig.as_bytes().to_vec());
        hybrid_envelope.pq_public_key = Some(pq_pk.as_bytes().to_vec());
    }

    Ok(hybrid_envelope)
}

/// ## Multi-signature source accounts
///
/// Real Stellar accounts routinely have multiple signers with weighted
/// thresholds (e.g. a family or small-business account requiring 2-of-3
/// signatures for payments above a threshold) — Stellar's native
/// multisig, entirely independent of Soroban. Offline, in a mesh with no
/// connectivity to coordinate, gathering enough weighted signatures before
/// an envelope is even queueable is a genuinely hard sub-problem: signers
/// may be on different devices that are never in range of each other, and
/// the mesh is the only channel available to coordinate partial
/// signatures.
///
/// ### Design: a new type, not an extension of `TransactionEnvelope`
///
/// [`TransactionEnvelope`] (defined in `stellarconduit-core`) has exactly
/// one `origin_pubkey` and one `signature` field — it is shaped for a
/// single mesh-transport signer, and that shape lives in a crate this repo
/// doesn't own. Rather than overload those fields to also carry N Stellar
/// signer contributions, [`PartiallySignedEnvelope`] is a distinct type
/// that can only become a `TransactionEnvelope` via [`try_promote`], and
/// only once the account's cached threshold is met. This means "below
/// threshold can't reach `OutboundTxQueue`" is enforced by the type system
/// (only `TransactionEnvelope` can be pushed there), not merely by a
/// runtime check that something could bypass.
///
/// ### Two distinct signing concerns, kept separate
///
/// A promoted envelope's single mesh-transport signature (produced by
/// `try_promote`'s `mesh_signing_key`, the same role
/// [`OfflineEnvelopeBuilder::build_and_sign`] plays for the single-signer
/// case) is **not** one of the Stellar account's multisig signatures. It
/// authenticates which mesh device relayed/finalized the message, same as
/// every other envelope in this crate. The Stellar-account-level signer
/// contributions tracked in `PartiallySignedEnvelope::contributions` are a
/// separate authorization concern layered on top. Splicing those signer
/// contributions into the actual Stellar transaction's own on-chain
/// signature list (inside `tx_xdr`) is XDR-format work this crate
/// deliberately doesn't do — consistent with the existing rule that this
/// crate treats `tx_xdr` as an opaque, already-built string (see the module
/// docs above). The contributions tracked here are this crate's *local
/// coordination record* of who has authorized dispatch, used to gate
/// promotion; the wallet layer remains responsible for actually assembling
/// a valid signed `tx_xdr` before/independently of that gate.
///
/// ### Where signer weights/threshold come from
///
/// Stellar's live signer list and thresholds aren't fetchable without
/// connectivity, so — mirroring how [`SequenceReservationManager::seed`]
/// caches an account's last-known sequence number — they must be cached
/// ahead of time via [`MultisigAccountRegistry::seed`] while the device
/// last had connectivity.
///
/// ### Mesh propagation: flagged as a cross-repo follow-up
///
/// This module defines the data structure and local logic for
/// accumulating signatures, but says nothing about how a
/// `PartiallySignedEnvelope` actually moves hop-to-hop through the mesh so
/// other signers' devices can add their contribution. `stellarconduit-core`'s
/// `ProtocolMessage` enum (`Transaction | TopologyUpdate | SyncRequest |
/// SyncResponse`) has no variant that can carry a partial-signature
/// payload today. Wiring that up is out of scope for this repo and should
/// be filed as a follow-up issue against `stellarconduit-core` — this PR
/// intentionally stops at the boundary of this crate.
fn multisig_payload_hash(source_account: &str, sequence: i64, tx_xdr: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(source_account.as_bytes());
    hasher.update(sequence.to_le_bytes());
    hasher.update(tx_xdr.as_bytes());
    hasher.finalize().into()
}

/// An envelope for a Stellar multisig source account that has accumulated
/// some, but not yet enough, weighted signer authorizations to be
/// dispatched. See the module docs above for the full design rationale.
#[derive(Debug, Clone)]
pub struct PartiallySignedEnvelope {
    pub source_account: String,
    pub sequence: i64,
    pub tx_xdr: String,
    /// Signer pubkey -> that signer's authorization signature over this
    /// envelope's coordination payload. Keyed by pubkey so a signer
    /// re-signing overwrites their own prior contribution instead of being
    /// counted twice.
    contributions: HashMap<[u8; 32], [u8; 64]>,
}

impl PartiallySignedEnvelope {
    pub fn new(
        source_account: impl Into<String>,
        sequence: i64,
        tx_xdr: impl Into<String>,
    ) -> Self {
        Self {
            source_account: source_account.into(),
            sequence,
            tx_xdr: tx_xdr.into(),
            contributions: HashMap::new(),
        }
    }

    /// Number of distinct signers who have contributed so far.
    pub fn contributor_count(&self) -> usize {
        self.contributions.len()
    }

    /// Sum of `registry`-cached weights for every contributing signer.
    /// Contributors not found in `registry` (e.g. the registry was seeded
    /// for a different account) contribute no weight.
    pub fn accumulated_weight(&self, registry: &MultisigAccountRegistry) -> u32 {
        self.contributions
            .keys()
            .filter_map(|pubkey| registry.signer_weight(&self.source_account, pubkey))
            .sum()
    }

    /// Whether the accumulated weight has reached `registry`'s cached
    /// threshold for this envelope's source account. `false` if the
    /// account hasn't been seeded in `registry`.
    pub fn meets_threshold(&self, registry: &MultisigAccountRegistry) -> bool {
        registry
            .threshold(&self.source_account)
            .is_some_and(|required| self.accumulated_weight(registry) >= required)
    }
}

/// Add `signing_key`'s authorization to `partial`.
///
/// Rejects with [`SyncEngineError::UnknownMultisigSigner`] if
/// `signing_key`'s public key is not among `registry`'s cached signers for
/// `partial.source_account` — a signature from an unauthorized key must
/// never count toward the threshold. The same signer contributing twice
/// overwrites its own prior entry rather than counting twice, since
/// contributions are keyed by pubkey.
pub fn add_signature(
    partial: &mut PartiallySignedEnvelope,
    registry: &MultisigAccountRegistry,
    signer: &dyn KeySigner,
) -> Result<(), SyncEngineError> {
    let pubkey = signer.public_key();
    if !registry.is_known_signer(&partial.source_account, &pubkey) {
        return Err(SyncEngineError::UnknownMultisigSigner {
            account: partial.source_account.clone(),
        });
    }
    let hash = multisig_payload_hash(&partial.source_account, partial.sequence, &partial.tx_xdr);
    let signature = signer.sign(&hash)?;
    partial.contributions.insert(pubkey, signature);
    Ok(())
}

/// Promote `partial` into a mesh-dispatchable [`TransactionEnvelope`] once
/// its accumulated signer weight meets the account's cached threshold.
///
/// Returns [`SyncEngineError::MultisigThresholdNotMet`] otherwise — this is
/// the only path from [`PartiallySignedEnvelope`] to [`TransactionEnvelope`],
/// so an envelope below threshold cannot reach [`crate::queue::OutboundTxQueue`]
/// no matter what else goes wrong.
///
/// `mesh_signing_key` signs the resulting envelope at the mesh-transport
/// layer only (see the module docs' "two distinct signing concerns"
/// section) — it does not need to be one of the account's Stellar signers.
pub fn try_promote(
    partial: &PartiallySignedEnvelope,
    registry: &MultisigAccountRegistry,
    mesh_signer: &dyn KeySigner,
    policy: &crate::envelope::pq::SigningPolicy,
    ttl_hops: u8,
) -> Result<crate::envelope::pq::HybridSignedEnvelope, SyncEngineError> {
    if !partial.meets_threshold(registry) {
        return Err(SyncEngineError::MultisigThresholdNotMet {
            account: partial.source_account.clone(),
            accumulated_weight: partial.accumulated_weight(registry),
            required_threshold: registry.threshold(&partial.source_account).unwrap_or(0),
        });
    }
    let origin_pubkey = mesh_signer.public_key();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tx_xdr = partial.tx_xdr.clone();
    let message_id = stellarconduit_core::message::envelope::compute_message_id(
        &origin_pubkey,
        &tx_xdr,
        timestamp,
    );
    let signature = mesh_signer.sign(&message_id)?;

    let classical_envelope = TransactionEnvelope {
        message_id,
        origin_pubkey,
        tx_xdr,
        ttl_hops,
        timestamp,
        signature,
    };

    let mut hybrid_envelope = crate::envelope::pq::HybridSignedEnvelope {
        classical_envelope,
        pq_signature: None,
        pq_public_key: None,
    };

    if let crate::envelope::pq::SigningPolicy::Hybrid(pq_pk, pq_sk) = policy {
        let payload = hybrid_envelope.canonical_payload();
        let pq_sig = pqcrypto_dilithium::dilithium2::detached_sign(&payload, pq_sk);
        use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
        hybrid_envelope.pq_signature = Some(pq_sig.as_bytes().to_vec());
        hybrid_envelope.pq_public_key = Some(pq_pk.as_bytes().to_vec());
    }

    Ok(hybrid_envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellarconduit_core::message::envelope::validate_envelope;

    // Real, valid XDR fixtures whose embedded source account and sequence are
    // known; see `src/envelope/xdr.rs` and `tests/fixtures`.
    const SOURCE_G: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
    const FEE_SOURCE_G: &str = "GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6";
    const SEQ: i64 = 103_720_918_407_610_369;

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
            .trim()
            .to_string()
    }

    #[test]
    fn test_build_and_sign_produces_valid_envelope() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let (hybrid_env, sequence) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();

        // The returned sequence is the one embedded in the XDR, not merely the
        // next reservation.
        assert_eq!(sequence, SEQ);
        assert!(validate_envelope(&hybrid_env.classical_envelope).is_ok());
        assert_eq!(
            hybrid_env.classical_envelope.origin_pubkey,
            key.verifying_key().to_bytes()
        );
    }

    #[test]
    fn test_successive_builds_consume_successive_sequences() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let (_, seq_a) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();
        let (_, seq_b) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            fixture("transaction_v1_envelope_seq_next.b64"),
            10,
        )
        .unwrap();

        assert_eq!(seq_a, SEQ);
        assert_eq!(seq_b, SEQ + 1);
    }

    #[test]
    fn test_build_without_seed_errors() {
        let mut sequences = SequenceReservationManager::new();
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());
        // Correct account (matches the XDR), but never seeded.
        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            fixture("transaction_v1_envelope.b64"),
            10,
        );
        assert!(matches!(
            result,
            Err(SyncEngineError::NoSequenceReserved(_))
        ));
    }

    #[test]
    fn test_mismatched_caller_claim_is_rejected() {
        // Caller claims account A (the fee source), but the XDR actually encodes
        // account B (the source): the mismatch must be caught, not accepted.
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(FEE_SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            FEE_SOURCE_G,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            fixture("transaction_v1_envelope.b64"),
            10,
        );

        match result {
            Err(SyncEngineError::SourceAccountMismatch { claimed, actual }) => {
                assert_eq!(claimed, FEE_SOURCE_G);
                assert_eq!(actual, SOURCE_G);
            }
            other => panic!("expected SourceAccountMismatch, got {other:?}"),
        }
        // The reservation must be untouched: we rejected before reserving.
        assert_eq!(sequences.last_reserved(FEE_SOURCE_G), Some(SEQ - 1));
    }

    #[test]
    fn test_sequence_mismatch_is_rejected_and_rolled_back() {
        // The manager's view of the account has drifted from the XDR: reserving
        // hands out a sequence that does not match what actually got built.
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, 50);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            fixture("transaction_v1_envelope.b64"),
            10,
        );

        match result {
            Err(SyncEngineError::SequenceMismatch {
                account,
                reserved,
                actual,
            }) => {
                assert_eq!(account, SOURCE_G);
                assert_eq!(reserved, 51);
                assert_eq!(actual, SEQ);
            }
            other => panic!("expected SequenceMismatch, got {other:?}"),
        }
        // The failed reservation must have been rolled back.
        assert_eq!(sequences.last_reserved(SOURCE_G), Some(50));
    }

    #[test]
    fn test_malformed_xdr_is_rejected() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let result = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            "not-valid-xdr !!!",
            10,
        );
        assert!(matches!(result, Err(SyncEngineError::XdrParse(_))));
    }

    #[test]
    fn test_resequence_updates_embedded_sequence() {
        let old_xdr = fixture("transaction_v1_envelope.b64");
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());
        let old_env = stellarconduit_core::message::envelope::EnvelopeBuilder::new(
            key.verifying_key().to_bytes(),
            old_xdr,
        )
        .ttl(10)
        .build(&key);

        let new_env = resequence_and_resign(
            &old_env,
            SEQ + 5,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
        )
        .unwrap();

        let (_, new_seq) =
            extract_source_account_and_sequence(&new_env.classical_envelope.tx_xdr).unwrap();
        assert_eq!(new_seq, SEQ + 5);
    }

    #[test]
    fn test_resequence_produces_new_message_id() {
        let old_xdr = fixture("transaction_v1_envelope.b64");
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());
        let old_env = stellarconduit_core::message::envelope::EnvelopeBuilder::new(
            key.verifying_key().to_bytes(),
            old_xdr,
        )
        .ttl(10)
        .build(&key);

        let new_env = resequence_and_resign(
            &old_env,
            SEQ + 5,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
        )
        .unwrap();
        assert_ne!(old_env.message_id, new_env.classical_envelope.message_id);
    }

    #[test]
    fn test_resequence_preserves_other_transaction_fields() {
        let old_xdr = fixture("transaction_v1_envelope.b64");
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());
        let old_env = stellarconduit_core::message::envelope::EnvelopeBuilder::new(
            key.verifying_key().to_bytes(),
            old_xdr,
        )
        .ttl(10)
        .build(&key);

        let new_env = resequence_and_resign(
            &old_env,
            SEQ + 5,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
        )
        .unwrap();

        let (old_account, _) = extract_source_account_and_sequence(&old_env.tx_xdr).unwrap();
        let (new_account, _) =
            extract_source_account_and_sequence(&new_env.classical_envelope.tx_xdr).unwrap();
        assert_eq!(old_account, new_account);
    }

    #[test]
    fn test_resequence_produces_validly_signed_envelope() {
        let old_xdr = fixture("transaction_v1_envelope.b64");
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());
        let old_env = stellarconduit_core::message::envelope::EnvelopeBuilder::new(
            key.verifying_key().to_bytes(),
            old_xdr,
        )
        .ttl(10)
        .build(&key);

        let new_env = resequence_and_resign(
            &old_env,
            SEQ + 5,
            &signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
        )
        .unwrap();
        assert!(validate_envelope(&new_env.classical_envelope).is_ok());
    }
}

#[cfg(test)]
mod multisig_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellarconduit_core::message::envelope::validate_envelope;

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    /// A 2-of-3 registry: three equally-weighted signers, threshold 2.
    fn registry_2_of_3(signers: &[SigningKey]) -> MultisigAccountRegistry {
        let mut registry = MultisigAccountRegistry::new();
        registry.seed(
            "GMULTISIG",
            signers.iter().map(|k| (k.verifying_key().to_bytes(), 1)),
            2,
        );
        registry
    }

    #[test]
    fn test_single_signature_below_threshold_not_promotable() {
        let signers: Vec<SigningKey> = (0..3).map(|_| signing_key()).collect();
        let registry = registry_2_of_3(&signers);
        let mut partial = PartiallySignedEnvelope::new("GMULTISIG", 101, "tx_xdr");

        let signer0 = crate::envelope::secure_signing::InMemorySigner::new(signers[0].clone());
        add_signature(&mut partial, &registry, &signer0).unwrap();

        assert_eq!(partial.accumulated_weight(&registry), 1);
        assert!(!partial.meets_threshold(&registry));

        let mesh_key = signing_key();
        let mesh_signer = crate::envelope::secure_signing::InMemorySigner::new(mesh_key.clone());
        let err = try_promote(
            &partial,
            &registry,
            &mesh_signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            10,
        )
        .expect_err("one of two required signatures must not be promotable");
        assert!(matches!(
            err,
            SyncEngineError::MultisigThresholdNotMet {
                accumulated_weight: 1,
                required_threshold: 2,
                ..
            }
        ));
    }

    #[test]
    fn test_threshold_met_promotes_to_dispatchable() {
        let signers: Vec<SigningKey> = (0..3).map(|_| signing_key()).collect();
        let registry = registry_2_of_3(&signers);
        let mut partial = PartiallySignedEnvelope::new("GMULTISIG", 101, "tx_xdr");

        let signer0 = crate::envelope::secure_signing::InMemorySigner::new(signers[0].clone());
        let signer1 = crate::envelope::secure_signing::InMemorySigner::new(signers[1].clone());
        add_signature(&mut partial, &registry, &signer0).unwrap();
        add_signature(&mut partial, &registry, &signer1).unwrap();
        assert!(partial.meets_threshold(&registry));

        let mesh_key = signing_key();
        let mesh_signer = crate::envelope::secure_signing::InMemorySigner::new(mesh_key.clone());
        let hybrid_env = try_promote(
            &partial,
            &registry,
            &mesh_signer,
            &crate::envelope::pq::SigningPolicy::ClassicalOnly,
            10,
        )
        .expect("threshold met, envelope should be promotable");

        assert!(validate_envelope(&hybrid_env.classical_envelope).is_ok());
        assert_eq!(
            hybrid_env.classical_envelope.origin_pubkey,
            mesh_key.verifying_key().to_bytes()
        );
        assert_eq!(hybrid_env.classical_envelope.tx_xdr, "tx_xdr");

        // A promoted envelope is a genuine TransactionEnvelope and is
        // therefore eligible for OutboundTxQueue — an envelope below
        // threshold has no way to produce one to push here at all.
        let clock = std::sync::Arc::new(crate::clock::HybridClock::new());
        let mut queue = crate::queue::OutboundTxQueue::new(clock);
        queue
            .push(
                hybrid_env.classical_envelope,
                crate::queue::TxPriority::Emergency,
            )
            .unwrap();
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn test_duplicate_signer_does_not_double_count_weight() {
        let signers: Vec<SigningKey> = (0..3).map(|_| signing_key()).collect();
        let registry = registry_2_of_3(&signers);
        let mut partial = PartiallySignedEnvelope::new("GMULTISIG", 101, "tx_xdr");

        let signer0 = crate::envelope::secure_signing::InMemorySigner::new(signers[0].clone());
        add_signature(&mut partial, &registry, &signer0).unwrap();
        add_signature(&mut partial, &registry, &signer0).unwrap();
        add_signature(&mut partial, &registry, &signer0).unwrap();

        assert_eq!(partial.contributor_count(), 1);
        assert_eq!(partial.accumulated_weight(&registry), 1);
        assert!(!partial.meets_threshold(&registry));
    }

    #[test]
    fn test_unknown_signer_is_rejected() {
        let signers: Vec<SigningKey> = (0..3).map(|_| signing_key()).collect();
        let registry = registry_2_of_3(&signers);
        let mut partial = PartiallySignedEnvelope::new("GMULTISIG", 101, "tx_xdr");

        let outsider = signing_key();
        let outsider_signer =
            crate::envelope::secure_signing::InMemorySigner::new(outsider.clone());
        let err = add_signature(&mut partial, &registry, &outsider_signer)
            .expect_err("a key outside the account's signer set must be rejected");
        assert!(matches!(err, SyncEngineError::UnknownMultisigSigner { .. }));

        // The rejected contribution must not have been silently counted.
        assert_eq!(partial.contributor_count(), 0);
        assert_eq!(partial.accumulated_weight(&registry), 0);
    }
}
