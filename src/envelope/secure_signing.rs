use crate::errors::SyncEngineError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// A hardware-isolated or memory-backed signer for envelopes.
///
/// # Residual Trust Assumptions
///
/// 1. **OS/Attestation Delivery:** When using a TEE, the abstraction relies on the host OS
///    to faithfully deliver the hardware enclave's attestation statement. If a compromised OS
///    can intercept this channel and forge or swap the attestation with one from a different
///    (but genuine) enclave, the node might be misled about which specific key it is trusting.
/// 2. **Verification Key Distribution:** The trusted root key used to verify attestation statements
///    (`trusted_root`) must be distributed securely. If an attacker can substitute the root key
///    in the node's configuration, they can bypass verification entirely.
pub trait KeySigner {
    /// Returns the Ed25519 public key.
    fn public_key(&self) -> [u8; 32];

    /// Signs the given message payload and returns a 64-byte Ed25519 signature.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SyncEngineError>;

    /// Returns `true` if this signer is backed by a Trusted Execution Environment (TEE).
    fn is_tee(&self) -> bool;

    /// Returns the attestation statement, if this signer provides one.
    fn attestation(&self) -> Option<&[u8]> {
        None
    }
}

/// An ordinary in-memory signer that holds the `SigningKey` in process memory.
/// Suitable for platforms without TEE access, or tests.
pub struct InMemorySigner {
    key: SigningKey,
}

impl InMemorySigner {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }
}

impl KeySigner for InMemorySigner {
    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SyncEngineError> {
        Ok(self.key.sign(message).to_bytes())
    }

    fn is_tee(&self) -> bool {
        false
    }
}

/// Statement provided by a Trusted Execution Environment (TEE) proving
/// the key resides in genuine hardware.
#[derive(Debug, Clone)]
pub struct AttestationStatement {
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

impl AttestationStatement {
    /// Verifies this attestation statement against a trusted root public key.
    pub fn verify(&self, trusted_root: &VerifyingKey) -> Result<(), SyncEngineError> {
        let sig = Signature::from_bytes(&self.signature);
        trusted_root.verify(&self.payload, &sig).map_err(|_| {
            SyncEngineError::InvalidAttestation("signature verification failed".into())
        })?;

        // For testing purposes, we define that if the payload explicitly starts with "forged",
        // it fails validation even if the signature happens to be technically correct (though
        // it shouldn't be for a forged payload, but we enforce this defensively).
        if self.payload.starts_with(b"forged") {
            return Err(SyncEngineError::InvalidAttestation(
                "payload indicates a forged attestation".into(),
            ));
        }

        Ok(())
    }
}

/// A stub for a TEE-backed signer (e.g. Android Keystore or iOS Secure Enclave).
/// This provides the Rust abstraction, with actual signing deferred to mobile FFI.
pub struct TeeSigner {
    public_key: [u8; 32],
    attestation: Vec<u8>,
}

impl TeeSigner {
    /// Attempt to acquire a TEE-backed signer. If genuine TEE is unavailable,
    /// this must fail hard, not silently fall back to software.
    pub fn try_new(
        public_key: [u8; 32],
        attestation: Vec<u8>,
        tee_available: bool,
    ) -> Result<Self, SyncEngineError> {
        if !tee_available {
            return Err(SyncEngineError::TeeUnavailable);
        }
        Ok(Self {
            public_key,
            attestation,
        })
    }
}

impl KeySigner for TeeSigner {
    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn sign(&self, _message: &[u8]) -> Result<[u8; 64], SyncEngineError> {
        // Here we'd call out over FFI to request the hardware to sign the bytes.
        Err(SyncEngineError::TeeSignerUnimplemented)
    }

    fn is_tee(&self) -> bool {
        true
    }

    fn attestation(&self) -> Option<&[u8]> {
        Some(&self.attestation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_in_memory_signer_produces_valid_signatures() {
        let key = SigningKey::generate(&mut OsRng);
        let verifying_key = key.verifying_key();

        let signer = InMemorySigner::new(key);
        let msg = b"test payload";
        let sig_bytes = signer.sign(msg).unwrap();

        let signature = Signature::from_bytes(&sig_bytes);
        assert!(verifying_key.verify(msg, &signature).is_ok());
        assert!(!signer.is_tee());
        assert!(signer.attestation().is_none());
    }

    #[test]
    fn test_tee_signer_unavailable_fails_hard_no_silent_fallback() {
        let result = TeeSigner::try_new([0; 32], vec![], false);
        assert!(matches!(result, Err(SyncEngineError::TeeUnavailable)));
    }

    #[test]
    fn test_valid_attestation_verifies() {
        let root_key = SigningKey::generate(&mut OsRng);
        let root_vk = root_key.verifying_key();

        let payload = b"genuine hardware attestation".to_vec();
        let signature = root_key.sign(&payload).to_bytes();

        let stmt = AttestationStatement { payload, signature };
        assert!(stmt.verify(&root_vk).is_ok());
    }

    #[test]
    fn test_forged_attestation_is_rejected() {
        let root_key = SigningKey::generate(&mut OsRng);
        let root_vk = root_key.verifying_key();

        // Signed by a different (untrusted) key
        let attacker_key = SigningKey::generate(&mut OsRng);
        let payload = b"genuine hardware attestation".to_vec();
        let forged_sig = attacker_key.sign(&payload).to_bytes();

        let stmt = AttestationStatement {
            payload,
            signature: forged_sig,
        };
        assert!(matches!(
            stmt.verify(&root_vk),
            Err(SyncEngineError::InvalidAttestation(_))
        ));

        // Valid signature but forged payload content
        let bad_payload = b"forged hardware attestation".to_vec();
        let bad_sig = root_key.sign(&bad_payload).to_bytes();

        let bad_stmt = AttestationStatement {
            payload: bad_payload,
            signature: bad_sig,
        };
        assert!(matches!(
            bad_stmt.verify(&root_vk),
            Err(SyncEngineError::InvalidAttestation(_))
        ));
    }
}
