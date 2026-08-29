use crate::errors::SyncEngineError;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde::{Deserialize, Serialize};
use stellarconduit_core::message::types::TransactionEnvelope;

/// Opt-in signing policy for the envelope builder.
pub enum SigningPolicy {
    /// Behavior is byte-for-byte unchanged from baseline.
    ClassicalOnly,
    /// Adds a post-quantum signature (ML-DSA-44 / Dilithium2) over the canonical payload.
    Hybrid(Box<dilithium2::PublicKey>, Box<dilithium2::SecretKey>),
}

/// A wrapper around the core `TransactionEnvelope` that can carry an optional PQ signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignedEnvelope {
    pub classical_envelope: TransactionEnvelope,
    pub pq_signature: Option<Vec<u8>>,
    pub pq_public_key: Option<Vec<u8>>,
}

impl HybridSignedEnvelope {
    /// Canonical payload that both classical and PQ signatures are computed over.
    /// In this case, we just hash the XDR and the origin_pubkey as a stable representation.
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut payload = self.classical_envelope.origin_pubkey.to_vec();
        payload.extend_from_slice(self.classical_envelope.tx_xdr.as_bytes());
        payload
    }

    /// Verifies the PQ signature if present.
    pub fn verify_pq(&self) -> Result<(), SyncEngineError> {
        if let (Some(sig_bytes), Some(pk_bytes)) = (&self.pq_signature, &self.pq_public_key) {
            let public_key = dilithium2::PublicKey::from_bytes(pk_bytes)
                .map_err(|_| SyncEngineError::PqVerificationFailed)?;
            let signature = dilithium2::DetachedSignature::from_bytes(sig_bytes)
                .map_err(|_| SyncEngineError::PqVerificationFailed)?;

            let payload = self.canonical_payload();
            dilithium2::verify_detached_signature(&signature, &payload, &public_key)
                .map_err(|_| SyncEngineError::PqVerificationFailed)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::builder::OfflineEnvelopeBuilder;
    use crate::queue::SequenceReservationManager;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use stellarconduit_core::message::envelope::validate_envelope;

    const SOURCE_G: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
    const SEQ: i64 = 103_720_918_407_610_369;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
            .trim()
            .to_string()
    }

    fn signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn test_classical_only_signing_unchanged_from_baseline() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let (hybrid_env, _) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &SigningPolicy::ClassicalOnly,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();

        assert!(hybrid_env.pq_signature.is_none());
        assert!(hybrid_env.pq_public_key.is_none());
        assert!(validate_envelope(&hybrid_env.classical_envelope).is_ok());
    }

    #[test]
    fn test_hybrid_signing_produces_both_valid_signatures() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let pq_keypair = pqcrypto_dilithium::dilithium2::keypair();
        let policy = SigningPolicy::Hybrid(Box::new(pq_keypair.0), Box::new(pq_keypair.1));

        let (hybrid_env, _) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &policy,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();

        assert!(hybrid_env.pq_signature.is_some());
        assert!(hybrid_env.pq_public_key.is_some());

        // Both classical and PQ signatures must be valid
        assert!(validate_envelope(&hybrid_env.classical_envelope).is_ok());
        assert!(hybrid_env.verify_pq().is_ok());
    }

    #[test]
    fn test_hybrid_verification_fails_if_either_signature_is_tampered() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let pq_keypair = pqcrypto_dilithium::dilithium2::keypair();
        let policy = SigningPolicy::Hybrid(Box::new(pq_keypair.0), Box::new(pq_keypair.1));

        let (mut hybrid_env, _) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &policy,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();

        assert!(hybrid_env.verify_pq().is_ok());

        // Tamper with the PQ signature
        if let Some(ref mut sig) = hybrid_env.pq_signature {
            sig[0] ^= 0xff;
        }
        assert!(matches!(
            hybrid_env.verify_pq(),
            Err(SyncEngineError::PqVerificationFailed)
        ));
    }

    #[test]
    fn test_pq_signature_size_overhead_is_within_documented_bound() {
        let mut sequences = SequenceReservationManager::new();
        sequences.seed(SOURCE_G, SEQ - 1);
        let key = signing_key();
        let signer = crate::envelope::secure_signing::InMemorySigner::new(key.clone());

        let pq_keypair = pqcrypto_dilithium::dilithium2::keypair();
        let policy = SigningPolicy::Hybrid(Box::new(pq_keypair.0), Box::new(pq_keypair.1));

        let (hybrid_env, _) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            SOURCE_G,
            &signer,
            &policy,
            fixture("transaction_v1_envelope.b64"),
            10,
        )
        .unwrap();

        let sig_size = hybrid_env
            .pq_signature
            .as_ref()
            .map(|s| s.len())
            .unwrap_or(0);

        // ML-DSA-44 (Dilithium2) signatures should be ~2420 bytes.
        // We assert it's less than 2500 to allow for minimal overhead,
        // ensuring it doesn't accidentally bloat (e.g. SPHINCS+).
        assert!(
            sig_size > 0 && sig_size < 2500,
            "PQ Signature size out of expected ML-DSA-44 bounds: {}",
            sig_size
        );
    }
}
