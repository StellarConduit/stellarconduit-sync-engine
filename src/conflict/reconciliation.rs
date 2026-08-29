//! Deterministic reconvergence for independently-resolved conflicts.
//!
//! When two mesh partitions reconcile after a long split (see
//! `docs/design/proof-carrying-reconciliation.md`), most divergence is
//! trivially mergeable: a record present on only one side, or byte-identical
//! on both. The hard case is when *both* sides already resolved the *same*
//! logical conflict (per [`crate::conflict::resolver`]) while partitioned,
//! and resolved it to *different* outcomes.
//!
//! This module provides the two pure, side-effect-free primitives that case
//! needs:
//!
//! - [`classify`] — bucket a single record's divergence.
//! - [`reconverge`] — pick the winning resolution from two competing ones
//!   with a rule that is **order-independent**: `reconverge(a, b)` and
//!   `reconverge(b, a)` name the same underlying resolution as the winner, so
//!   both partitions reach the same final state regardless of which side
//!   initiates reconciliation.
//!
//! Neither function performs I/O or touches [`crate::storage`]. Wiring the
//! Merkle-range anti-entropy exchange and the journaled, resumable session on
//! top of them is tracked separately in the design doc.

use sha2::{Digest, Sha256};

/// A compact, comparable summary of one conflict resolution as recorded by a
/// single partition.
///
/// `causal_depth` is the length of the causal history behind the resolution
/// decision: a smaller value means the decision was made earlier in logical
/// time. It is the primary tie-break key because the earliest decision is the
/// one more peers are likely to have already observed and built on.
///
/// `payload_hash` is a SHA-256 hash of the canonical serialization of the
/// resolution payload. It is used only as a final, total-order tie-break when
/// two resolutions share a `causal_depth`, so the outcome stays deterministic
/// even in that pathological case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionSummary {
    /// Length of the causal history behind this resolution decision.
    pub causal_depth: u64,
    /// SHA-256 of the canonical resolution payload.
    pub payload_hash: [u8; 32],
}

impl ResolutionSummary {
    /// Build a summary from a causal depth and the raw canonical bytes of the
    /// resolution payload. The bytes are hashed with SHA-256 and are not
    /// retained.
    pub fn from_payload(causal_depth: u64, canonical_payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(canonical_payload);
        let digest = hasher.finalize();
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&digest);
        Self {
            causal_depth,
            payload_hash,
        }
    }

    /// The total order used for reconvergence: earliest causal decision
    /// first, then lowest payload hash. Keeping the key in one place makes it
    /// obvious the order is total.
    fn ordering_key(&self) -> (u64, [u8; 32]) {
        (self.causal_depth, self.payload_hash)
    }
}

/// How a single record differs between the local and remote partition, once
/// both sides are known to hold that record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DivergenceClass {
    /// Neither side has recorded a resolution yet, or both recorded the same
    /// one — nothing for this module to do.
    Converged,
    /// Exactly one side has recorded a resolution. Propagate it to the other
    /// side (verifying its causal history first).
    OneSidedResolution,
    /// Both sides independently recorded a resolution for the same logical
    /// conflict, and the two disagree. Feed both summaries to [`reconverge`].
    DoublyResolved,
}

/// Bucket the divergence of a record that both partitions hold, given each
/// side's recorded resolution (if any).
pub fn classify(
    local: Option<ResolutionSummary>,
    remote: Option<ResolutionSummary>,
) -> DivergenceClass {
    match (local, remote) {
        (None, None) => DivergenceClass::Converged,
        (Some(_), None) | (None, Some(_)) => DivergenceClass::OneSidedResolution,
        (Some(a), Some(b)) => {
            if a == b {
                DivergenceClass::Converged
            } else {
                DivergenceClass::DoublyResolved
            }
        }
    }
}

/// The outcome of reconverging two competing resolutions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconvergence {
    /// Both sides already hold the same resolution; no state change.
    AlreadyConverged,
    /// The local resolution wins; the remote side must adopt it.
    LocalWins,
    /// The remote resolution wins; the local side must adopt it.
    RemoteWins,
}

/// Pick the winner of two independently-recorded resolutions for the same
/// logical conflict.
///
/// The rule is a pure function of the *unordered pair* `{local, remote}`: the
/// resolution with the smaller [`ResolutionSummary::ordering_key`] wins
/// (earliest causal decision, then lowest payload hash). Because that key is
/// a total order and the comparison does not depend on argument position,
/// `reconverge(a, b)` and `reconverge(b, a)` always name the same underlying
/// resolution as the winner — see `test_reconverge_is_order_independent`.
///
/// "Proof-carrying" in the design sense lives one layer up: the winning side
/// transmits the causal-history segment that justifies its `causal_depth`,
/// and the losing side recomputes this comparison locally before adopting
/// the change rather than trusting a bare assertion.
pub fn reconverge(local: ResolutionSummary, remote: ResolutionSummary) -> Reconvergence {
    use std::cmp::Ordering;

    match local.ordering_key().cmp(&remote.ordering_key()) {
        Ordering::Less => Reconvergence::LocalWins,
        Ordering::Greater => Reconvergence::RemoteWins,
        Ordering::Equal => Reconvergence::AlreadyConverged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn summary(causal_depth: u64, first_hash_byte: u8) -> ResolutionSummary {
        let mut payload_hash = [0u8; 32];
        payload_hash[0] = first_hash_byte;
        ResolutionSummary {
            causal_depth,
            payload_hash,
        }
    }

    #[test]
    fn test_from_payload_is_stable_and_hides_payload() {
        let a = ResolutionSummary::from_payload(7, b"resolution-payload");
        let b = ResolutionSummary::from_payload(7, b"resolution-payload");
        assert_eq!(a, b);
        assert_eq!(a.causal_depth, 7);
        // The 32-byte hash never equals the 18-byte input.
        assert_ne!(&a.payload_hash[..], b"resolution-payload".as_slice());
    }

    #[test]
    fn test_classify_buckets() {
        let s1 = summary(1, 1);
        let s2 = summary(2, 2);
        assert_eq!(classify(None, None), DivergenceClass::Converged);
        assert_eq!(classify(Some(s1), Some(s1)), DivergenceClass::Converged);
        assert_eq!(
            classify(Some(s1), None),
            DivergenceClass::OneSidedResolution
        );
        assert_eq!(
            classify(None, Some(s2)),
            DivergenceClass::OneSidedResolution
        );
        assert_eq!(
            classify(Some(s1), Some(s2)),
            DivergenceClass::DoublyResolved
        );
    }

    #[test]
    fn test_reconverge_prefers_earlier_causal_depth() {
        let earlier = summary(3, 9);
        let later = summary(10, 1);
        assert_eq!(reconverge(earlier, later), Reconvergence::LocalWins);
        assert_eq!(reconverge(later, earlier), Reconvergence::RemoteWins);
    }

    #[test]
    fn test_reconverge_breaks_causal_depth_tie_by_hash() {
        let low_hash = summary(5, 1);
        let high_hash = summary(5, 200);
        assert_eq!(reconverge(low_hash, high_hash), Reconvergence::LocalWins);
        assert_eq!(reconverge(high_hash, low_hash), Reconvergence::RemoteWins);
    }

    #[test]
    fn test_reconverge_identical_is_already_converged() {
        let s = summary(5, 42);
        assert_eq!(reconverge(s, s), Reconvergence::AlreadyConverged);
    }

    proptest! {
        /// The named winner (as a concrete summary) is identical no matter
        /// which side is passed first — the property both partitions rely on
        /// to converge regardless of who initiates reconciliation.
        #[test]
        fn test_reconverge_is_order_independent(
            d1 in any::<u64>(),
            h1 in proptest::array::uniform32(any::<u8>()),
            d2 in any::<u64>(),
            h2 in proptest::array::uniform32(any::<u8>()),
        ) {
            let a = ResolutionSummary { causal_depth: d1, payload_hash: h1 };
            let b = ResolutionSummary { causal_depth: d2, payload_hash: h2 };

            let winner_ab = match reconverge(a, b) {
                Reconvergence::LocalWins => Some(a),
                Reconvergence::RemoteWins => Some(b),
                Reconvergence::AlreadyConverged => None,
            };
            let winner_ba = match reconverge(b, a) {
                Reconvergence::LocalWins => Some(b),
                Reconvergence::RemoteWins => Some(a),
                Reconvergence::AlreadyConverged => None,
            };

            prop_assert_eq!(winner_ab, winner_ba);
        }
    }
}
