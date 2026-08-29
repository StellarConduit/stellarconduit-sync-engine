use thiserror::Error;

/// Classifies a [`SyncEngineError`] into one of three recovery buckets.
///
/// This is the single source of truth for retry/recovery policy across the
/// crate. Every future issue that needs to decide "is this worth retrying?"
/// (#008, #016, #017, #018) should call [`SyncEngineError::classify()`]
/// rather than duplicating ad-hoc judgements.
///
/// # Variants
///
/// - **`Permanent`** — the error is a caller-code bug or an irrecoverable
///   logical invariant violation. No amount of retrying will help; the caller
///   must fix the root cause (e.g. pass a valid sequence number, supply an
///   authorized signer).
///
/// - **`Transient`** — the error is likely caused by environmental conditions
///   (disk contention, lock conflicts, I/O races) that may resolve on their
///   own. A short retry with exponential back-off is appropriate.
///
/// - **`RequiresEscalation`** — neither retry nor give-up is the right move.
///   The error signals a situation that requires human intervention or an
///   off-chain → on-chain escalation path (see issue #002's dispute-resolver
///   contract). The embedding wallet should surface this to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Permanent,
    Transient,
    RequiresEscalation,
}

#[derive(Error, Debug)]
pub enum SyncEngineError {
    #[error("no sequence number reserved for account {0}")]
    NoSequenceReserved(String),

    #[error("sequence number {requested} is not greater than last reserved {last_reserved} for account {account}")]
    SequenceOutOfOrder {
        account: String,
        requested: i64,
        last_reserved: i64,
    },

    #[error("envelope validation failed: {0}")]
    InvalidEnvelope(String),

    #[error("failed to parse transaction XDR: {0}")]
    XdrParse(String),

    #[error("caller-claimed source account {claimed} does not match the source account {actual} encoded in the transaction XDR")]
    SourceAccountMismatch { claimed: String, actual: String },

    #[error("reserved sequence {reserved} does not match the sequence {actual} encoded in the transaction XDR for account {account}")]
    SequenceMismatch {
        account: String,
        reserved: i64,
        actual: i64,
    },

    #[error("no queued envelope found for message_id {0}")]
    EnvelopeNotFound(String),

    #[error("invalid settlement state transition from {from:?} to {to:?}")]
    InvalidStateTransition { from: String, to: String },

    #[error("dispatch backpressure window is full ({max_in_flight} in flight); wait for acknowledgments or timeouts before dispatching more")]
    BackpressureWindowFull { max_in_flight: usize },

    #[error("message is already in flight in the dispatch window")]
    DuplicateInFlight,

    #[error("invalid dispatch window configuration: {0}")]
    InvalidDispatchWindow(String),

    #[error("conflict between envelopes could not be resolved off-chain: {0}")]
    UnresolvedConflict(String),

    /// Returned by `crate::conflict::vrf_tiebreak` when a VRF tie-break proof
    /// is malformed, fails verification, or was produced by a party other than
    /// the deterministically selected evaluator. The tie-break is the
    /// last-resort step of conflict resolution (issue #067); a bad one is a
    /// caller-data / protocol-deviation failure, not something to retry.
    #[error("VRF conflict tie-break is invalid: {0}")]
    VrfTiebreak(String),

    /// Returned by `crate::conflict::proof_compression` when a compressed
    /// relay-chain proof (issue #63) is malformed, fails to fold, or fails
    /// verification — a hop that doesn't link to the running accumulator, a
    /// tail attestation whose signature doesn't verify, a tail that doesn't
    /// fold up to the proof's accumulator, or a tail below the distinct-relay
    /// quorum. A bad proof is bad on every attempt; the caller must obtain a
    /// well-formed one (or escalate with the raw per-hop proofs instead).
    #[error("compressed relay-chain proof is invalid: {0}")]
    CompressedProofInvalid(String),

    /// Returned when queuing an Emergency-tier envelope would push the
    /// device past its configured spending guard (see
    /// `crate::queue::priority::EmergencyGuardConfig`). This is a soft,
    /// informative failure: the embedding wallet should catch this variant
    /// specifically and prompt the user for extra confirmation (e.g. a
    /// biometric re-auth) rather than treating it as an ordinary queuing
    /// failure or silently dropping the payment.
    #[error(
        "emergency-tier queue limit exceeded: {current}/{max} Emergency payments already \
         queued within the last {window_secs}s; extra confirmation is required before \
         queuing another"
    )]
    EmergencyQueueLimitExceeded {
        current: usize,
        max: usize,
        window_secs: u64,
    },

    /// Returned by `crate::envelope::builder::add_signature` when the
    /// signing key presented does not belong to the account's cached signer
    /// set (see `crate::queue::sequence::MultisigAccountRegistry`). A
    /// signature from an unauthorized key must never count toward the
    /// multisig threshold.
    #[error("signing key is not a known/authorized signer for account {account}")]
    UnknownMultisigSigner { account: String },

    /// Returned by `crate::envelope::builder::try_promote` when a
    /// `PartiallySignedEnvelope`'s accumulated signer weight has not yet
    /// reached the account's cached threshold — it must not be promoted to
    /// a dispatchable `TransactionEnvelope` while this holds.
    #[error(
        "multisig threshold not met for account {account}: accumulated weight \
         {accumulated_weight} < required threshold {required_threshold}"
    )]
    MultisigThresholdNotMet {
        account: String,
        accumulated_weight: u32,
        required_threshold: u32,
    },

    /// Returned when a [`crate::queue::zk_spend_proof::SpendCapProver`] is
    /// given invalid inputs — empty amounts list, zero cap, or a spend that
    /// already exceeds the cap (a proof of a false statement is impossible).
    /// This is a permanent, caller-code error.
    #[error("invalid input for ZK spend-cap proof generation: {0}")]
    ZkProofInput(String),

    /// Returned when the Bulletproofs prover itself fails internally (e.g.
    /// a generator-capacity mismatch or a library-level error). Distinguishing
    /// this from `ZkProofInput` lets callers decide whether to surface a user
    /// error message vs. log an internal fault.
    #[error("ZK spend-cap proof generation failed: {0}")]
    ZkProofGeneration(String),

    /// Returned when [`crate::queue::zk_spend_proof::SpendCapVerifier`]
    /// rejects a proof — either the Bulletproofs range proof is invalid or
    /// the homomorphic sum check fails (meaning the claimed spend is not
    /// actually under the cap, or the proof has been tampered with).
    #[error("ZK spend-cap proof verification failed: {0}")]
    ZkProofVerification(String),

    #[error("SQLite connection error: {0}")]
    ConnectionError(#[from] tokio_rusqlite::Error),

    #[error("SQLite database error: {0}")]
    SqliteError(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    SerializationError(#[from] rmp_serde::encode::Error),

    #[error("deserialization error: {0}")]
    DeserializationError(#[from] rmp_serde::decode::Error),

    #[error("post-quantum signature verification failed")]
    PqVerificationFailed,

    /// Returned when encryption or decryption operations fail.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Returned when attempting to open an encrypted database without
    /// providing the correct key, or when attempting to open an unencrypted
    /// database as if it were encrypted.
    #[error("database encryption key mismatch or missing key")]
    EncryptionKeyMismatch,

    /// Returned when an encrypted database is opened with a key that doesn't
    /// match the one used to create it.
    #[error("decryption failed: wrong key or corrupted data")]
    DecryptionFailed,

    /// Returned by `SyncEngineDb::import_snapshot` when the target database
    /// already contains rows in any of its tables. Import is documented and
    /// implemented as reject-if-nonempty (see that function's doc comment for
    /// the full rationale) rather than merge or overwrite, so this is not a
    /// bug to retry past — the caller must import into a fresh database.
    #[error(
        "cannot import snapshot: target database is not empty (import_snapshot requires an \
         empty database — see SyncEngineDb::import_snapshot's documented policy)"
    )]
    ImportTargetNotEmpty,

    /// Returned by `SyncEngineDb::import_snapshot` when a snapshot's embedded
    /// schema version does not match [`crate::storage::db::DB_SNAPSHOT_SCHEMA_VERSION`].
    /// A structurally-valid snapshot produced by an incompatible version must
    /// never be silently imported, since its row shapes may not match what
    /// this build expects.
    #[error(
        "snapshot schema version {found} is incompatible with this build's expected version {expected}"
    )]
    IncompatibleSnapshotSchemaVersion { found: u32, expected: u32 },

    #[error("TEE signing is requested but no genuine TEE is available on this device")]
    TeeUnavailable,

    #[error("TEE signing is currently a stub waiting for FFI integration")]
    TeeSignerUnimplemented,

    #[error("invalid or forged TEE attestation statement: {0}")]
    InvalidAttestation(String),
}

impl SyncEngineError {
    /// Classify this error into a recovery bucket.
    ///
    /// The match is intentionally exhaustive with **no wildcard arm**. This
    /// means that adding a new [`SyncEngineError`] variant without also
    /// updating this function is a **compile error**, not a silent gap.
    /// `#[deny(unreachable_patterns)]` is also applied to make that guarantee
    /// even harder to accidentally break.
    ///
    /// # Classification rationale
    ///
    /// | Variant | Class | Why |
    /// |---------|-------|-----|
    /// | `NoSequenceReserved` | Permanent | The caller never called `seed()`/`reserve()` before attempting to build an envelope. This is a programming error; retrying the same call without fixing the caller will always fail. |
    /// | `SequenceOutOfOrder` | Permanent | The caller passed a sequence number that regresses or equals `last_reserved`. This is a logical invariant violation in caller code; the sequence must be corrected before any retry makes sense. |
    /// | `InvalidEnvelope` | Permanent | Envelope validation failed because the payload itself is malformed. The same invalid bytes will fail validation on every attempt. |
    /// | `XdrParse` | Permanent | The transaction XDR itself could not be parsed. The same bytes will fail to parse on every attempt; the caller must supply a well-formed transaction. |
    /// | `SourceAccountMismatch` | Permanent | The caller-claimed source account doesn't match the one encoded in the transaction XDR. This is a caller bug (wrong account supplied); retrying with the same mismatched inputs will always fail. |
    /// | `SequenceMismatch` | Permanent | The reserved sequence number doesn't match the one encoded in the transaction XDR. Retrying without correcting the sequence or the XDR will reproduce the same mismatch. |
    /// | `EnvelopeNotFound` | Permanent | A lookup by `message_id` returned nothing. The envelope was never enqueued, or has already been removed. Retrying the same lookup against the same DB will not materialise it. |
    /// | `InvalidStateTransition` | Permanent | A state-machine transition was attempted that is not in the legal transition graph. Retrying the same transition will never become legal; the caller has a logic bug. |
    /// | `BackpressureWindowFull` | Transient | The per-relay dispatch window is at capacity. Acks landing or timeout releases will free slots; retrying after a short back-off is exactly the intended behaviour. |
    /// | `DuplicateInFlight` | Permanent | The same message was acquired into the dispatch window twice without an intervening release. This is a caller bug; retrying identical inputs reproduces it. |
    /// | `InvalidDispatchWindow` | Permanent | The window configuration violates an invariant (zero capacity or zero timeout). Fix the configuration and construct again. |
    /// | `UnresolvedConflict` | RequiresEscalation | Two envelopes compete for the same account/sequence slot and could not be resolved off-chain. Neither retrying nor giving up is correct — the dispute must be escalated to the on-chain `dispute-resolver` contract (see issue #002). |
    /// | `VrfTiebreak` | Permanent | A supplied VRF tie-break proof is malformed, fails verification, or came from the wrong evaluator. The same bytes will fail the same way on every attempt; the resolution flow treats a tie with no valid tie-break as an ordinary `UnresolvedConflict` and escalates. |
    /// | `CompressedProofInvalid` | Permanent | A compressed relay-chain proof (issue #63) failed to fold or verify. The same artifact fails identically on every attempt; a well-formed proof must be produced, or the escalation must fall back to the raw per-hop proofs. |
    /// | `EmergencyQueueLimitExceeded` | RequiresEscalation | The spending guard has tripped. A simple retry without user re-confirmation would be a security bypass. The embedding wallet must surface this to the user (biometric re-auth or explicit override) before queuing is retried. |
    /// | `UnknownMultisigSigner` | Permanent | The presented signing key is not in the account's authorised signer set. No retry will change the signer registry without an explicit key-management operation. |
    /// | `MultisigThresholdNotMet` | Permanent | The accumulated signer weight is below the required threshold. In this context the error means promotion was attempted prematurely; more signatures are needed, which is a caller flow issue, not a transient I/O problem. |
    /// | `ZkProofInput` | Permanent | Invalid inputs for ZK proof generation (empty amounts, zero cap, sum >= cap). These are caller-code bugs that will never succeed on retry. |
    /// | `ZkProofGeneration` | Permanent | The Bulletproofs prover failed internally. Retrying the same inputs will produce the same failure; the caller must investigate the root cause. |
    /// | `ZkProofVerification` | Permanent | A ZK proof failed verification. The proof is invalid or tampered; retrying will not make an invalid proof valid. |
    /// | `ConnectionError` | Transient | `tokio_rusqlite` errors typically arise from thread-pool contention, busy-timeout, or a momentary lock on the WAL file. These conditions usually resolve within milliseconds and are appropriate to retry with back-off. |
    /// | `SqliteError` | Transient | Raw `rusqlite` errors (e.g. `SQLITE_BUSY`, `SQLITE_LOCKED`) are similarly caused by disk/locking contention and are generally safe to retry. Callers that need to distinguish truly fatal SQLite errors (e.g. corruption) may inspect the inner `rusqlite::Error` further, but the default classification is Transient. |
    /// | `SerializationError` | Permanent | A value could not be encoded to MessagePack. This reflects a type-system mismatch or an unencodable value; retrying the same data will produce the same error. |
    /// | `DeserializationError` | Permanent | Stored bytes could not be decoded. The bytes are corrupted or were written by an incompatible schema version. Retrying the same read will not repair the data. |
    /// | `ImportTargetNotEmpty` | Permanent | `import_snapshot`'s documented policy refuses a non-empty target. Retrying the identical call against the same database will always hit the same refusal; the caller must choose a fresh database. |
    /// | `IncompatibleSnapshotSchemaVersion` | Permanent | The snapshot was produced by a different schema version than this build expects. Retrying the same import will reproduce the same mismatch; a migration path is needed instead. |
    #[deny(unreachable_patterns)]
    pub fn classify(&self) -> ErrorClass {
        match self {
            // ── Permanent: caller-code bugs and irrecoverable logical failures ──
            SyncEngineError::NoSequenceReserved(_) => ErrorClass::Permanent,
            SyncEngineError::SequenceOutOfOrder { .. } => ErrorClass::Permanent,
            SyncEngineError::InvalidEnvelope(_) => ErrorClass::Permanent,
            SyncEngineError::VrfTiebreak(_) => ErrorClass::Permanent,
            SyncEngineError::CompressedProofInvalid(_) => ErrorClass::Permanent,
            SyncEngineError::XdrParse(_) => ErrorClass::Permanent,
            SyncEngineError::SourceAccountMismatch { .. } => ErrorClass::Permanent,
            SyncEngineError::SequenceMismatch { .. } => ErrorClass::Permanent,
            SyncEngineError::EnvelopeNotFound(_) => ErrorClass::Permanent,
            SyncEngineError::InvalidStateTransition { .. } => ErrorClass::Permanent,
            SyncEngineError::BackpressureWindowFull { .. } => ErrorClass::Transient,
            SyncEngineError::DuplicateInFlight => ErrorClass::Permanent,
            SyncEngineError::InvalidDispatchWindow(_) => ErrorClass::Permanent,
            SyncEngineError::UnknownMultisigSigner { .. } => ErrorClass::Permanent,
            SyncEngineError::MultisigThresholdNotMet { .. } => ErrorClass::Permanent,
            SyncEngineError::SerializationError(_) => ErrorClass::Permanent,
            SyncEngineError::DeserializationError(_) => ErrorClass::Permanent,
            SyncEngineError::PqVerificationFailed => ErrorClass::Permanent,
            SyncEngineError::ZkProofInput(_) => ErrorClass::Permanent,
            SyncEngineError::ZkProofGeneration(_) => ErrorClass::Permanent,
            SyncEngineError::ZkProofVerification(_) => ErrorClass::Permanent,
            SyncEngineError::ImportTargetNotEmpty => ErrorClass::Permanent,
            SyncEngineError::IncompatibleSnapshotSchemaVersion { .. } => ErrorClass::Permanent,
            SyncEngineError::TeeUnavailable => ErrorClass::Permanent,
            SyncEngineError::TeeSignerUnimplemented => ErrorClass::Permanent,
            SyncEngineError::InvalidAttestation(_) => ErrorClass::Permanent,

            // ── RequiresEscalation: needs human/on-chain intervention ──
            SyncEngineError::UnresolvedConflict(_) => ErrorClass::RequiresEscalation,
            SyncEngineError::EmergencyQueueLimitExceeded { .. } => ErrorClass::RequiresEscalation,

            // ── Transient: environmental failures worth retrying with back-off ──
            SyncEngineError::ConnectionError(_) => ErrorClass::Transient,
            SyncEngineError::SqliteError(_) => ErrorClass::Transient,
            SyncEngineError::EncryptionError(_) => ErrorClass::Permanent,
            SyncEngineError::EncryptionKeyMismatch => ErrorClass::Permanent,
            SyncEngineError::DecryptionFailed => ErrorClass::Permanent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers to construct every variant ──────────────────────────────────

    fn all_variants() -> Vec<SyncEngineError> {
        vec![
            SyncEngineError::NoSequenceReserved("GTEST".into()),
            SyncEngineError::SequenceOutOfOrder {
                account: "GTEST".into(),
                requested: 5,
                last_reserved: 10,
            },
            SyncEngineError::InvalidEnvelope("bad payload".into()),
            SyncEngineError::XdrParse("bad xdr".into()),
            SyncEngineError::SourceAccountMismatch {
                claimed: "GCLAIMED".into(),
                actual: "GACTUAL".into(),
            },
            SyncEngineError::SequenceMismatch {
                account: "GTEST".into(),
                reserved: 5,
                actual: 6,
            },
            SyncEngineError::EnvelopeNotFound("deadbeef".into()),
            SyncEngineError::InvalidStateTransition {
                from: "queued".into(),
                to: "settled".into(),
            },
            SyncEngineError::UnresolvedConflict("slot 42".into()),
            SyncEngineError::VrfTiebreak("bad proof".into()),
            SyncEngineError::CompressedProofInvalid("bad fold".into()),
            SyncEngineError::EmergencyQueueLimitExceeded {
                current: 3,
                max: 3,
                window_secs: 60,
            },
            SyncEngineError::UnknownMultisigSigner {
                account: "GTEST".into(),
            },
            SyncEngineError::MultisigThresholdNotMet {
                account: "GTEST".into(),
                accumulated_weight: 1,
                required_threshold: 2,
            },
            SyncEngineError::ConnectionError(tokio_rusqlite::Error::Rusqlite(
                rusqlite::Error::InvalidQuery,
            )),
            SyncEngineError::SqliteError(rusqlite::Error::InvalidQuery),
            SyncEngineError::SerializationError(rmp_serde::encode::Error::UnknownLength),
            SyncEngineError::DeserializationError(rmp_serde::decode::Error::Syntax("test".into())),
            SyncEngineError::PqVerificationFailed,
            SyncEngineError::ZkProofInput("empty amounts".into()),
            SyncEngineError::ZkProofGeneration("prover fault".into()),
            SyncEngineError::ZkProofVerification("invalid range proof".into()),
            SyncEngineError::ImportTargetNotEmpty,
            SyncEngineError::IncompatibleSnapshotSchemaVersion {
                found: 1,
                expected: 2,
            },
            SyncEngineError::TeeUnavailable,
            SyncEngineError::TeeSignerUnimplemented,
            SyncEngineError::InvalidAttestation("forged".into()),
        ]
    }

    /// Living checklist: every variant must be constructible here and must
    /// return one of the three defined classes without panicking.
    /// A new variant added to `SyncEngineError` without a corresponding entry
    /// in `all_variants()` is a sign the classification audit is incomplete.
    #[test]
    fn test_every_variant_has_a_classification() {
        let valid_classes = [
            ErrorClass::Permanent,
            ErrorClass::Transient,
            ErrorClass::RequiresEscalation,
        ];
        for variant in all_variants() {
            let class = variant.classify();
            assert!(
                valid_classes.contains(&class),
                "classify() returned an unexpected value for {:?}",
                variant
            );
        }
    }

    // ── Per-class tests ─────────────────────────────────────────────────────

    #[test]
    fn test_sequence_errors_are_permanent() {
        assert_eq!(
            SyncEngineError::NoSequenceReserved("GTEST".into()).classify(),
            ErrorClass::Permanent
        );
        assert_eq!(
            SyncEngineError::SequenceOutOfOrder {
                account: "GTEST".into(),
                requested: 1,
                last_reserved: 5,
            }
            .classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_storage_errors_are_transient() {
        assert_eq!(
            SyncEngineError::ConnectionError(tokio_rusqlite::Error::Rusqlite(
                rusqlite::Error::InvalidQuery
            ))
            .classify(),
            ErrorClass::Transient
        );
        assert_eq!(
            SyncEngineError::SqliteError(rusqlite::Error::InvalidQuery).classify(),
            ErrorClass::Transient
        );
    }

    #[test]
    fn test_unresolved_conflict_requires_escalation() {
        assert_eq!(
            SyncEngineError::UnresolvedConflict("slot conflict".into()).classify(),
            ErrorClass::RequiresEscalation
        );
    }

    #[test]
    fn test_emergency_queue_limit_requires_escalation() {
        assert_eq!(
            SyncEngineError::EmergencyQueueLimitExceeded {
                current: 3,
                max: 3,
                window_secs: 60,
            }
            .classify(),
            ErrorClass::RequiresEscalation
        );
    }

    #[test]
    fn test_invalid_envelope_is_permanent() {
        assert_eq!(
            SyncEngineError::InvalidEnvelope("malformed".into()).classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_vrf_tiebreak_is_permanent() {
        assert_eq!(
            SyncEngineError::VrfTiebreak("proof failed verification".into()).classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_compressed_proof_invalid_is_permanent() {
        assert_eq!(
            SyncEngineError::CompressedProofInvalid("tail does not fold to acc".into()).classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_xdr_derivation_errors_are_permanent() {
        assert_eq!(
            SyncEngineError::XdrParse("bad xdr".into()).classify(),
            ErrorClass::Permanent
        );
        assert_eq!(
            SyncEngineError::SourceAccountMismatch {
                claimed: "GCLAIMED".into(),
                actual: "GACTUAL".into(),
            }
            .classify(),
            ErrorClass::Permanent
        );
        assert_eq!(
            SyncEngineError::SequenceMismatch {
                account: "GTEST".into(),
                reserved: 5,
                actual: 6,
            }
            .classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_envelope_not_found_is_permanent() {
        assert_eq!(
            SyncEngineError::EnvelopeNotFound("deadbeef".into()).classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_invalid_state_transition_is_permanent() {
        assert_eq!(
            SyncEngineError::InvalidStateTransition {
                from: "queued".into(),
                to: "settled".into(),
            }
            .classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_multisig_errors_are_permanent() {
        assert_eq!(
            SyncEngineError::UnknownMultisigSigner {
                account: "GTEST".into()
            }
            .classify(),
            ErrorClass::Permanent
        );
        assert_eq!(
            SyncEngineError::MultisigThresholdNotMet {
                account: "GTEST".into(),
                accumulated_weight: 1,
                required_threshold: 2,
            }
            .classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_serde_errors_are_permanent() {
        let enc_err = SyncEngineError::SerializationError(rmp_serde::encode::Error::UnknownLength);
        assert_eq!(enc_err.classify(), ErrorClass::Permanent);

        let dec_err =
            SyncEngineError::DeserializationError(rmp_serde::decode::Error::Syntax("test".into()));
        assert_eq!(dec_err.classify(), ErrorClass::Permanent);

        assert_eq!(
            SyncEngineError::PqVerificationFailed.classify(),
            ErrorClass::Permanent
        );
    }

    #[test]
    fn test_zk_proof_errors_are_permanent() {
        assert_eq!(
            SyncEngineError::ZkProofInput("empty amounts".into()).classify(),
            ErrorClass::Permanent
        );
        assert_eq!(
            SyncEngineError::ZkProofGeneration("prover fault".into()).classify(),
            ErrorClass::Permanent
        );
        assert_eq!(
            SyncEngineError::ZkProofVerification("invalid range proof".into()).classify(),
            ErrorClass::Permanent
        );
    }
}
