//! End-to-end: the issue #93 compression-oracle mitigation composed with the
//! real issue #12 AES-256-GCM at-rest encryption pipeline.
//!
//! These tests prove that
//!   * `compress_at_rest` → `EncryptedData::encrypt` → `decrypt` →
//!     `decompress_at_rest` is a lossless round trip, and
//!   * AES-GCM's fixed 28-byte overhead (12-byte nonce + 16-byte tag) *preserves*
//!     the mitigation's length quantization rather than masking or defeating it,
//!   * the byte-at-a-time oracle, run against what an attacker actually observes
//!     (the encrypted blob size), recovers the secret under the unmitigated
//!     baseline and recovers nothing under the mitigated scheme.

use stellarconduit_core::message::types::TransactionEnvelope;
use stellarconduit_sync_engine::encryption::{EncryptedData, EncryptionKey};
use stellarconduit_sync_engine::storage::compression_oracle::{
    run_byte_at_a_time_oracle, OracleConfig, SecretField,
};
use stellarconduit_sync_engine::storage::{
    compress_at_rest, decompress_at_rest, CompressionScheme,
};

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
        .trim()
        .to_string()
}

fn envelope() -> TransactionEnvelope {
    TransactionEnvelope {
        message_id: [0x42; 32],
        origin_pubkey: [0x24; 32],
        tx_xdr: fixture("transaction_v1_envelope.b64"),
        ttl_hops: 7,
        timestamp: 1_705_000_000,
        signature: [0x99; 64],
    }
}

const GCM_OVERHEAD: usize = 12 /* nonce */ + 16 /* tag */;

#[test]
fn compress_encrypt_decrypt_decompress_roundtrips() {
    let key = EncryptionKey::from_bytes([0x01; 32]);
    let env = envelope();

    for scheme in [CompressionScheme::Unmitigated, CompressionScheme::Mitigated] {
        let frame = compress_at_rest(&env, scheme).unwrap();
        let sealed = EncryptedData::encrypt(&frame, &key).unwrap();
        let opened = sealed.decrypt(&key).unwrap();
        assert_eq!(frame, opened, "AES-GCM round trip changed the frame");
        let back = decompress_at_rest(&opened).unwrap();
        assert_eq!(
            env, back,
            "end-to-end pipeline is not lossless under {scheme:?}"
        );
    }
}

#[test]
fn aes_gcm_overhead_preserves_the_length_quantization() {
    let key = EncryptionKey::from_bytes([0x07; 32]);
    let env = envelope();

    let frame = compress_at_rest(&env, CompressionScheme::Mitigated).unwrap();
    let sealed = EncryptedData::encrypt(&frame, &key).unwrap();

    // Encryption adds a constant, so the mitigation's PAD_GRANULARITY buckets
    // are still exactly as visible on the ciphertext as on the plaintext frame.
    assert_eq!(sealed.as_bytes().len(), frame.len() + GCM_OVERHEAD);
    assert_eq!(
        frame.len() % stellarconduit_sync_engine::storage::PAD_GRANULARITY,
        0,
        "mitigated frame is not quantized"
    );
}

#[test]
fn oracle_through_the_encrypted_pipeline_leaks_baseline_not_mitigated() {
    let base = envelope();

    let unmit = run_byte_at_a_time_oracle(
        &base,
        SecretField::Amount,
        &OracleConfig::amount_recovery(CompressionScheme::Unmitigated),
    );
    let mit = run_byte_at_a_time_oracle(
        &base,
        SecretField::Amount,
        &OracleConfig::amount_recovery(CompressionScheme::Mitigated),
    );

    eprintln!("e2e BASELINE  {}", unmit.summary());
    eprintln!("e2e MITIGATED {}", mit.summary());

    // The fixture amount (25 XLM = 0x0EE6B280) still gives the baseline a
    // toehold; the mitigation removes it entirely.
    assert!(unmit.bytes_recovered >= 1);
    assert_eq!(mit.bytes_recovered, 0);
    assert!(mit.bits_recovered <= 1.0);
}

#[test]
fn mitigated_pipeline_still_shrinks_the_stored_blob() {
    let key = EncryptionKey::from_bytes([0x33; 32]);
    let env = envelope();

    // Baseline for "no compression": what #12 stores today is
    // encrypt(rmp(envelope)).
    let plain = rmp_serde::to_vec(&env).unwrap();
    let stored_today = EncryptedData::encrypt(&plain, &key)
        .unwrap()
        .as_bytes()
        .len();

    let frame = compress_at_rest(&env, CompressionScheme::Mitigated).unwrap();
    let stored_mitigated = EncryptedData::encrypt(&frame, &key)
        .unwrap()
        .as_bytes()
        .len();

    assert!(
        stored_mitigated < stored_today,
        "mitigated at-rest blob ({stored_mitigated}) is not smaller than today's \
         uncompressed encrypted blob ({stored_today})"
    );
}
