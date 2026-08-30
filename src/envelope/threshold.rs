//! FROST threshold-signing session model (feasibility slice).
//!
//! Full design, crate selection, and the comparison against issue #029's
//! weighted-multisig accumulation live in
//! `docs/design/frost-threshold-signing.md`. This module is the first bounded
//! slice: the parameter and session-state types a FROST `t`-of-`n` signing
//! coordinator needs, plus the validation rules the harder
//! transport-adaptation work builds on.
//!
//! It deliberately does **not** pull in a FROST implementation yet —
//! integrating `frost-ed25519` (RFC 9591) is its own reviewable step, called
//! out in the design doc. Nothing here performs cryptography.

use std::collections::BTreeSet;

/// A signing participant, identified by its FROST participant index.
///
/// FROST participant indices are 1-based; `ParticipantId(0)` is never a valid
/// participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantId(pub u16);

/// Why a `t`-of-`n` configuration was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ThresholdConfigError {
    /// `n` was zero — a group needs at least one participant.
    #[error("threshold group needs at least one participant")]
    NoParticipants,
    /// `t` was zero — a threshold of zero would let anyone sign.
    #[error("threshold must be at least 1")]
    ZeroThreshold,
    /// `t > n` — the threshold could never be met.
    #[error("threshold {threshold} exceeds participant count {participants}")]
    ThresholdExceedsParticipants { threshold: u16, participants: u16 },
}

/// A validated `t`-of-`n` FROST configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdParams {
    threshold: u16,
    participants: u16,
}

impl ThresholdParams {
    /// Validate and construct a `t`-of-`n` configuration.
    ///
    /// # Errors
    /// Returns [`ThresholdConfigError`] if `participants == 0`,
    /// `threshold == 0`, or `threshold > participants`.
    pub fn new(threshold: u16, participants: u16) -> Result<Self, ThresholdConfigError> {
        if participants == 0 {
            return Err(ThresholdConfigError::NoParticipants);
        }
        if threshold == 0 {
            return Err(ThresholdConfigError::ZeroThreshold);
        }
        if threshold > participants {
            return Err(ThresholdConfigError::ThresholdExceedsParticipants {
                threshold,
                participants,
            });
        }
        Ok(Self {
            threshold,
            participants,
        })
    }

    /// The number of signature shares required to produce a signature (`t`).
    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    /// The total number of participants in the group (`n`).
    pub fn participants(&self) -> u16 {
        self.participants
    }

    /// Whether `present` contains enough *distinct* participants to produce a
    /// signature. Duplicate ids are counted once, so a caller cannot reach
    /// threshold by submitting the same participant's share twice.
    pub fn has_signing_quorum(&self, present: &[ParticipantId]) -> bool {
        let distinct: BTreeSet<ParticipantId> = present.iter().copied().collect();
        distinct.len() >= usize::from(self.threshold)
    }
}

/// Where a signing session sits in the two-round FROST protocol, as adapted
/// to asynchronous mesh delivery (see the design doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningRound {
    /// Round 1: collecting per-participant nonce commitments.
    Commitment,
    /// Round 2: a signing package has been assembled from `t` commitments;
    /// collecting signature shares.
    SignatureShare,
    /// `t` shares have been aggregated into a final signature.
    Aggregated,
    /// The session was abandoned (e.g. a participant dropped and the epoch
    /// was bumped for a retry).
    Abandoned,
}

/// A monotonic per-session epoch.
///
/// Bumping it on retry invalidates every Round-1 commitment from the previous
/// attempt, which is what stops a stalled-then-retried session from reusing a
/// signing nonce (see the design doc's "nonce reuse under retry" gap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionEpoch(pub u64);

impl SessionEpoch {
    /// The next epoch. Retrying a session always moves strictly forward.
    pub fn bump(self) -> Self {
        Self(self.0 + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threshold_params_reject_zero_participants() {
        assert_eq!(
            ThresholdParams::new(1, 0),
            Err(ThresholdConfigError::NoParticipants)
        );
    }

    #[test]
    fn test_threshold_params_reject_zero_threshold() {
        assert_eq!(
            ThresholdParams::new(0, 3),
            Err(ThresholdConfigError::ZeroThreshold)
        );
    }

    #[test]
    fn test_threshold_params_reject_threshold_above_participants() {
        assert_eq!(
            ThresholdParams::new(4, 3),
            Err(ThresholdConfigError::ThresholdExceedsParticipants {
                threshold: 4,
                participants: 3,
            })
        );
    }

    #[test]
    fn test_threshold_params_accept_valid() {
        let params = ThresholdParams::new(2, 3).expect("2-of-3 is valid");
        assert_eq!(params.threshold(), 2);
        assert_eq!(params.participants(), 3);
    }

    #[test]
    fn test_signing_below_threshold_participants_fails() {
        let params = ThresholdParams::new(3, 5).expect("3-of-5 is valid");
        let two_present = [ParticipantId(1), ParticipantId(2)];
        assert!(!params.has_signing_quorum(&two_present));

        let three_present = [ParticipantId(1), ParticipantId(2), ParticipantId(4)];
        assert!(params.has_signing_quorum(&three_present));
    }

    #[test]
    fn test_has_signing_quorum_deduplicates_participants() {
        let params = ThresholdParams::new(3, 5).expect("3-of-5 is valid");
        // Same participant repeated must not count three times.
        let repeated = [ParticipantId(1), ParticipantId(1), ParticipantId(1)];
        assert!(!params.has_signing_quorum(&repeated));
    }

    #[test]
    fn test_session_epoch_bump_is_strictly_monotonic() {
        let e0 = SessionEpoch(0);
        let e1 = e0.bump();
        let e2 = e1.bump();
        assert!(e0 < e1 && e1 < e2);
        assert_eq!(e2, SessionEpoch(2));
    }
}
