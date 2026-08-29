//! Stellar sequence-number reservation for offline-queued transactions.
//!
//! A Stellar account's sequence number must increase by exactly 1 per
//! transaction, with no gaps. When several transactions from the same source
//! account are queued while offline, each must be assigned a distinct,
//! strictly-increasing sequence number *before* signing — otherwise two
//! envelopes signed against the same sequence become mutually exclusive
//! (only one can ever settle), which is one of the ways a double-spend
//! conflict enters the mesh in the first place. See `crate::conflict` for
//! detection/resolution of that scenario.

use std::collections::HashMap;

use crate::errors::SyncEngineError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconciliationOutcome {
    /// No drift detected: the observed chain sequence equals the local baseline sequence.
    NoDrift,
    /// Local baseline was behind reality: the observed chain sequence has advanced past the local baseline.
    /// Contains any in-flight reserved sequence numbers that are now provably stale (`<= observed_chain_sequence`)
    /// and the updated baseline sequence number.
    BehindReality {
        stale_sequences: Vec<i64>,
        new_baseline: i64,
    },
    /// Local baseline was ahead of reality: the observed chain sequence is lower than the local baseline.
    /// Handled gracefully to prevent state corruption or invalidation of valid reservations.
    AheadOfReality { observed: i64, baseline: i64 },
}

#[derive(Debug, Default)]
pub struct SequenceReservationManager {
    /// Baseline sequence number per Stellar source account as last observed on-chain.
    baseline: HashMap<String, i64>,
    /// Last reserved sequence number per Stellar source account (G... strkey).
    reserved: HashMap<String, i64>,
}

impl SequenceReservationManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed the manager with an account's current on-chain sequence number,
    /// as last observed while the device had connectivity. Reservations for
    /// that account build on top of this baseline.
    pub fn seed(&mut self, account: impl Into<String>, current_chain_sequence: i64) {
        let acc = account.into();
        self.baseline.insert(acc.clone(), current_chain_sequence);
        self.reserved.insert(acc, current_chain_sequence);
    }

    /// Reserve and return the next sequence number for `account`. The account
    /// must have been seeded first.
    pub fn reserve_next(&mut self, account: &str) -> Result<i64, SyncEngineError> {
        let last = self
            .reserved
            .get(account)
            .copied()
            .ok_or_else(|| SyncEngineError::NoSequenceReserved(account.to_string()))?;
        let next = last + 1;
        self.reserved.insert(account.to_string(), next);
        Ok(next)
    }

    pub fn last_reserved(&self, account: &str) -> Option<i64> {
        self.reserved.get(account).copied()
    }

    pub fn baseline(&self, account: &str) -> Option<i64> {
        self.baseline.get(account).copied()
    }

    /// Roll back the most recent reservation for `account`, e.g. when
    /// envelope construction fails after a sequence number was reserved.
    /// `sequence` must equal the most recently reserved value.
    pub fn release(&mut self, account: &str, sequence: i64) -> Result<(), SyncEngineError> {
        let last = self
            .reserved
            .get(account)
            .copied()
            .ok_or_else(|| SyncEngineError::NoSequenceReserved(account.to_string()))?;
        if last != sequence {
            return Err(SyncEngineError::SequenceOutOfOrder {
                account: account.to_string(),
                requested: sequence,
                last_reserved: last,
            });
        }
        self.reserved.insert(account.to_string(), last - 1);
        Ok(())
    }

    /// Reconcile local baseline and reservations against a fresh on-chain observation.
    ///
    /// Identifies any in-flight reserved sequences that are now provably stale
    /// (`<= observed_chain_sequence`) and updates the local baseline.
    pub fn reconcile(
        &mut self,
        account: &str,
        observed_chain_sequence: i64,
    ) -> ReconciliationOutcome {
        let current_baseline = match self.baseline.get(account).copied() {
            Some(b) => b,
            None => {
                self.seed(account, observed_chain_sequence);
                return ReconciliationOutcome::NoDrift;
            }
        };

        if observed_chain_sequence == current_baseline {
            ReconciliationOutcome::NoDrift
        } else if observed_chain_sequence < current_baseline {
            ReconciliationOutcome::AheadOfReality {
                observed: observed_chain_sequence,
                baseline: current_baseline,
            }
        } else {
            let current_reserved = self
                .reserved
                .get(account)
                .copied()
                .unwrap_or(current_baseline);

            let stale_end = observed_chain_sequence.min(current_reserved);
            let stale_sequences = if stale_end > current_baseline {
                (current_baseline + 1..=stale_end).collect()
            } else {
                Vec::new()
            };

            self.baseline
                .insert(account.to_string(), observed_chain_sequence);

            if observed_chain_sequence > current_reserved {
                self.reserved
                    .insert(account.to_string(), observed_chain_sequence);
            }

            ReconciliationOutcome::BehindReality {
                stale_sequences,
                new_baseline: observed_chain_sequence,
            }
        }
    }
}

/// A Stellar account's cached multisig signer set: which Ed25519 public keys
/// are authorized signers, their weights, and the weight threshold a
/// transaction must accumulate before it may be dispatched.
///
/// Like an account's on-chain sequence number, its live signer list and
/// thresholds aren't fetchable without connectivity, so — mirroring
/// [`SequenceReservationManager::seed`] — this must be seeded from a
/// snapshot taken while the device last had connectivity. A stale cache
/// (e.g. a signer removed on-chain after the last sync) is a real risk or a
/// legitimate wallet is expected to re-sync and re-seed opportunistically;
/// this crate only provides the offline cache, not staleness detection.
///
/// Real Stellar accounts have three threshold levels (low/medium/high)
/// depending on operation type. This cache simplifies that to a single
/// effective `threshold` per account — documented here as a first version,
/// same simplification style as the count-only Emergency spending guard.
/// Callers should seed whichever of the three thresholds applies to the
/// operations they intend to queue.
#[derive(Debug, Default)]
pub struct MultisigAccountRegistry {
    accounts: HashMap<String, AccountSigners>,
}

#[derive(Debug, Clone)]
struct AccountSigners {
    /// Signer pubkey -> weight.
    signers: HashMap<[u8; 32], u32>,
    threshold: u32,
}

impl MultisigAccountRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache `account`'s signer set and threshold. Replaces any previous
    /// entry for the same account.
    pub fn seed(
        &mut self,
        account: impl Into<String>,
        signers: impl IntoIterator<Item = ([u8; 32], u32)>,
        threshold: u32,
    ) {
        self.accounts.insert(
            account.into(),
            AccountSigners {
                signers: signers.into_iter().collect(),
                threshold,
            },
        );
    }

    /// The cached weight for `pubkey` on `account`, or `None` if `account`
    /// hasn't been seeded or `pubkey` isn't one of its known signers.
    pub fn signer_weight(&self, account: &str, pubkey: &[u8; 32]) -> Option<u32> {
        self.accounts.get(account)?.signers.get(pubkey).copied()
    }

    /// The cached signing threshold for `account`, or `None` if it hasn't
    /// been seeded.
    pub fn threshold(&self, account: &str) -> Option<u32> {
        self.accounts.get(account).map(|a| a.threshold)
    }

    /// Whether `pubkey` is among `account`'s cached authorized signers.
    pub fn is_known_signer(&self, account: &str, pubkey: &[u8; 32]) -> bool {
        self.signer_weight(account, pubkey).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserve_without_seed_errors() {
        let mut mgr = SequenceReservationManager::new();
        assert!(matches!(
            mgr.reserve_next("GABC"),
            Err(SyncEngineError::NoSequenceReserved(_))
        ));
    }

    #[test]
    fn test_reserve_increments_from_seed() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 101);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 102);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 103);
        assert_eq!(mgr.last_reserved("GABC"), Some(103));
        assert_eq!(mgr.baseline("GABC"), Some(100));
    }

    #[test]
    fn test_accounts_are_independent() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        mgr.seed("GXYZ", 5);
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 101);
        assert_eq!(mgr.reserve_next("GXYZ").unwrap(), 6);
    }

    #[test]
    fn test_release_rolls_back_last_reservation() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        let seq = mgr.reserve_next("GABC").unwrap();
        mgr.release("GABC", seq).unwrap();
        assert_eq!(mgr.last_reserved("GABC"), Some(100));
        // Reserving again should hand out the same sequence number.
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 101);
    }

    #[test]
    fn test_release_rejects_non_matching_sequence() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        mgr.reserve_next("GABC").unwrap(); // 101
        mgr.reserve_next("GABC").unwrap(); // 102
        assert!(matches!(
            mgr.release("GABC", 101),
            Err(SyncEngineError::SequenceOutOfOrder { .. })
        ));
    }

    #[test]
    fn test_reconcile_no_drift_is_noop() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        let outcome = mgr.reconcile("GABC", 100);
        assert_eq!(outcome, ReconciliationOutcome::NoDrift);
        assert_eq!(mgr.baseline("GABC"), Some(100));
        assert_eq!(mgr.last_reserved("GABC"), Some(100));
    }

    #[test]
    fn test_reconcile_identifies_stale_reservations() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        let seq1 = mgr.reserve_next("GABC").unwrap(); // 101
        let seq2 = mgr.reserve_next("GABC").unwrap(); // 102
        let seq3 = mgr.reserve_next("GABC").unwrap(); // 103

        let outcome = mgr.reconcile("GABC", 103);
        assert_eq!(
            outcome,
            ReconciliationOutcome::BehindReality {
                stale_sequences: vec![seq1, seq2, seq3],
                new_baseline: 103,
            }
        );
        assert_eq!(mgr.baseline("GABC"), Some(103));
        assert_eq!(mgr.last_reserved("GABC"), Some(103));
    }

    #[test]
    fn test_reconcile_does_not_invalidate_valid_future_reservations() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        let seq1 = mgr.reserve_next("GABC").unwrap(); // 101
        let seq2 = mgr.reserve_next("GABC").unwrap(); // 102
        let seq3 = mgr.reserve_next("GABC").unwrap(); // 103
        let seq4 = mgr.reserve_next("GABC").unwrap(); // 104
        assert_eq!(seq3, 103);
        assert_eq!(seq4, 104);

        let outcome = mgr.reconcile("GABC", 102);
        assert_eq!(
            outcome,
            ReconciliationOutcome::BehindReality {
                stale_sequences: vec![seq1, seq2],
                new_baseline: 102,
            }
        );
        assert_eq!(mgr.baseline("GABC"), Some(102));
        assert_eq!(mgr.last_reserved("GABC"), Some(104));

        assert_eq!(mgr.reserve_next("GABC").unwrap(), 105);
    }

    #[test]
    fn test_reconcile_behind_reality_does_not_corrupt_state() {
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        let _seq1 = mgr.reserve_next("GABC").unwrap(); // 101
        let _seq2 = mgr.reserve_next("GABC").unwrap(); // 102

        let outcome = mgr.reconcile("GABC", 95);
        assert_eq!(
            outcome,
            ReconciliationOutcome::AheadOfReality {
                observed: 95,
                baseline: 100,
            }
        );
        assert_eq!(mgr.baseline("GABC"), Some(100));
        assert_eq!(mgr.last_reserved("GABC"), Some(102));
        assert_eq!(mgr.reserve_next("GABC").unwrap(), 103);
    }

    #[tokio::test]
    async fn test_reconciled_baseline_persists_via_storage() {
        use crate::storage::SyncEngineDb;

        let db = SyncEngineDb::init(":memory:").await.unwrap();
        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GABC", 100);
        mgr.reserve_next("GABC").unwrap(); // 101
        mgr.reserve_next("GABC").unwrap(); // 102

        let outcome = mgr.reconcile("GABC", 105);
        assert!(matches!(
            outcome,
            ReconciliationOutcome::BehindReality { .. }
        ));

        db.save_sequence_reservation("GABC", mgr.last_reserved("GABC").unwrap())
            .await
            .unwrap();

        let loaded = db.load_sequence_reservation("GABC").await.unwrap();
        assert_eq!(loaded, Some(105));
    }

    /// Issue #51: a lookup for a *present* account must not be
    /// distinguishable, by timing, from a lookup for an *absent* one.
    ///
    /// `#[ignore]` by default — wall-clock timing is machine- and
    /// load-dependent, so this belongs in a dedicated, repeated timing job
    /// (see `docs/design/side-channel-resistant-signing.md`), not the
    /// ordinary `cargo test` run. The statistical method it relies on
    /// ([`crate::timing::mann_whitney_u`]) is itself covered by
    /// deterministic unit tests that do run in CI. Run this one explicitly
    /// with `cargo test -- --ignored does_not_correlate_with_account_presence`.
    #[test]
    #[ignore = "timing-sensitive; run in a dedicated timing job (see docs/design/side-channel-resistant-signing.md)"]
    fn test_sequence_lookup_timing_does_not_correlate_with_account_presence() {
        use crate::timing::mann_whitney_u;
        use std::hint::black_box;
        use std::time::Instant;

        let mut mgr = SequenceReservationManager::new();
        mgr.seed("GPRESENT", 100);

        const TRIALS: usize = 20_000;
        let mut present = Vec::with_capacity(TRIALS);
        let mut absent = Vec::with_capacity(TRIALS);

        for _ in 0..TRIALS {
            let start = Instant::now();
            let _ = black_box(mgr.last_reserved(black_box("GPRESENT")));
            present.push(start.elapsed().as_nanos() as f64);

            let start = Instant::now();
            let _ = black_box(mgr.last_reserved(black_box("GMISSING")));
            absent.push(start.elapsed().as_nanos() as f64);
        }

        let result = mann_whitney_u(&present, &absent);
        // Two-sided alpha = 1e-3 corresponds to a |z| threshold of 3.2905.
        assert!(
            !result.differs_at(3.2905),
            "sequence-lookup timing correlates with account presence: z = {:.3}",
            result.z_score
        );
    }

    #[test]
    fn test_multisig_registry_seed_and_lookup() {
        let mut registry = MultisigAccountRegistry::new();
        let signer_a = [1u8; 32];
        let signer_b = [2u8; 32];
        registry.seed("GMULTISIG", [(signer_a, 1), (signer_b, 2)], 2);

        assert_eq!(registry.signer_weight("GMULTISIG", &signer_a), Some(1));
        assert_eq!(registry.signer_weight("GMULTISIG", &signer_b), Some(2));
        assert_eq!(registry.threshold("GMULTISIG"), Some(2));
        assert!(registry.is_known_signer("GMULTISIG", &signer_a));
    }

    #[test]
    fn test_multisig_registry_unknown_account_and_signer() {
        let registry = MultisigAccountRegistry::new();
        assert_eq!(registry.signer_weight("GUNKNOWN", &[9u8; 32]), None);
        assert_eq!(registry.threshold("GUNKNOWN"), None);
        assert!(!registry.is_known_signer("GUNKNOWN", &[9u8; 32]));

        let mut registry = MultisigAccountRegistry::new();
        registry.seed("GMULTISIG", [([1u8; 32], 1)], 1);
        assert!(!registry.is_known_signer("GMULTISIG", &[9u8; 32]));
    }
}
