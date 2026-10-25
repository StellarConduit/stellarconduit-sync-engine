//! Classification of Stellar transaction submission results.
//!
//! Keep this mapping separate from the durable `SettlementStatus` state
//! machine: a rejected transaction can need a *new* envelope (new sequence,
//! fee, or time bounds) without proving that the original payment intent is
//! safe to resend. In particular, never automatically dispatch a replacement
//! after receiving a non-terminal classification; reconcile chain state first.

use stellar_xdr::curr::TransactionResultCode;

use super::SettlementStatus;

/// Outcome of submitting a Stellar transaction, before any retry policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementOutcome {
    /// Confirmed successful transaction, including a successful fee-bump inner.
    Settled,
    /// The submitted bytes cannot be retried successfully without correction.
    PermanentFailure,
    /// The account sequence must be reconciled and the envelope re-signed.
    NeedsResequencing,
    /// Potentially recoverable, but not evidence that re-sending is safe.
    /// Callers must check chain state and any necessary fee/time/account change.
    TransientFailure,
}

impl SettlementOutcome {
    /// Only definitive outcomes are safe to persist as terminal status.
    /// Other outcomes retain `Propagating` (or `Disputed`) until a caller
    /// deliberately reconciles and chooses a legal next transition.
    pub const fn terminal_status(self) -> Option<SettlementStatus> {
        match self {
            Self::Settled => Some(SettlementStatus::Settled),
            Self::PermanentFailure => Some(SettlementStatus::Failed),
            Self::NeedsResequencing | Self::TransientFailure => None,
        }
    }
}

/// Classify *every* known Stellar XDR transaction result code.
///
/// This match intentionally has no wildcard: a future `stellar-xdr` upgrade
/// introducing a result code must force an explicit policy decision.
///
/// A transient outcome is *not* permission to replay unchanged signed bytes:
/// `TxTooLate` requires fresh time bounds and a new signature;
/// `TxInsufficientFee` requires a fee change/bump; and `TxNoAccount` and
/// `TxInsufficientBalance` need external account state to change. Even
/// `TxInternalError` requires on-chain reconciliation before any retry.
/// `TxFeeBumpInnerFailed` is terminal for the submitted fee-bump transaction;
/// callers wishing to retry the payment must examine its inner result.
#[must_use]
pub const fn classify_result(code: TransactionResultCode) -> SettlementOutcome {
    use SettlementOutcome::*;
    use TransactionResultCode::*;

    match code {
        TxSuccess | TxFeeBumpInnerSuccess => Settled,
        TxBadSeq => NeedsResequencing,
        TxTooEarly
        | TxTooLate
        | TxInsufficientBalance
        | TxNoAccount
        | TxInsufficientFee
        | TxInternalError
        | TxBadMinSeqAgeOrGap => TransientFailure,
        TxFailed | TxMissingOperation | TxBadAuth | TxBadAuthExtra | TxNotSupported
        | TxFeeBumpInnerFailed | TxBadSponsorship | TxMalformed | TxSorobanInvalid => {
            PermanentFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SettlementOutcome::*;
    use TransactionResultCode::*;

    #[test]
    fn test_success_maps_to_settled() {
        assert_eq!(classify_result(TxSuccess), Settled);
        assert_eq!(classify_result(TxFeeBumpInnerSuccess), Settled);
        assert_eq!(Settled.terminal_status(), Some(SettlementStatus::Settled));
    }

    #[test]
    fn test_bad_seq_maps_to_needs_resequencing() {
        assert_eq!(classify_result(TxBadSeq), NeedsResequencing);
        assert_eq!(NeedsResequencing.terminal_status(), None);
    }

    #[test]
    fn test_bad_auth_maps_to_permanent_failure() {
        assert_eq!(classify_result(TxBadAuth), PermanentFailure);
        assert_eq!(
            PermanentFailure.terminal_status(),
            Some(SettlementStatus::Failed)
        );
    }

    #[test]
    fn test_every_known_result_code_is_classified() {
        // Independent expectation table: does not derive its expected values
        // from classify_result(), and the XDR enum exposes exactly 19 codes.
        let expected = [
            (TxFeeBumpInnerSuccess, Settled),
            (TxSuccess, Settled),
            (TxFailed, PermanentFailure),
            (TxTooEarly, TransientFailure),
            (TxTooLate, TransientFailure),
            (TxMissingOperation, PermanentFailure),
            (TxBadSeq, NeedsResequencing),
            (TxBadAuth, PermanentFailure),
            (TxInsufficientBalance, TransientFailure),
            (TxNoAccount, TransientFailure),
            (TxInsufficientFee, TransientFailure),
            (TxBadAuthExtra, PermanentFailure),
            (TxInternalError, TransientFailure),
            (TxNotSupported, PermanentFailure),
            (TxFeeBumpInnerFailed, PermanentFailure),
            (TxBadSponsorship, PermanentFailure),
            (TxBadMinSeqAgeOrGap, TransientFailure),
            (TxMalformed, PermanentFailure),
            (TxSorobanInvalid, PermanentFailure),
        ];
        assert_eq!(expected.len(), TransactionResultCode::VARIANTS.len());
        for (code, outcome) in expected {
            assert_eq!(classify_result(code), outcome, "{}", code.name());
        }
        for code in TransactionResultCode::VARIANTS {
            assert!(expected.iter().any(|(candidate, _)| *candidate == code));
        }
    }

    #[test]
    fn test_retryable_outcomes_cannot_finalize_a_payment() {
        assert_eq!(TransientFailure.terminal_status(), None);
        assert_eq!(NeedsResequencing.terminal_status(), None);
    }
}
