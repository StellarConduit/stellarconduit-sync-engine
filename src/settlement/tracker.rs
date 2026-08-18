//! Settlement state machine for a queued envelope, from the moment it's
//! signed offline to final on-chain confirmation (or failure).

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

use crate::errors::SyncEngineError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettlementStatus {
    /// Signed and durably stored on-device; not yet handed to the mesh.
    Queued,
    /// Handed to the gossip layer; propagating toward a relay node.
    Propagating,
    /// A relay node submitted it to Stellar and it was confirmed.
    Settled,
    /// Propagation or submission failed (TTL expired, relay rejected it, etc).
    Failed,
    /// A conflicting envelope was detected for the same account/sequence and
    /// the conflict could not be resolved off-chain — see `crate::conflict`.
    /// Awaiting on-chain arbitration via the `dispute-resolver` contract.
    Disputed,
}

impl SettlementStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SettlementStatus::Queued => "queued",
            SettlementStatus::Propagating => "propagating",
            SettlementStatus::Settled => "settled",
            SettlementStatus::Failed => "failed",
            SettlementStatus::Disputed => "disputed",
        }
    }

    /// Whether transitioning from `self` to `next` is a legal state change.
    pub fn can_transition_to(&self, next: SettlementStatus) -> bool {
        use SettlementStatus::*;
        matches!(
            (self, next),
            (Queued, Propagating)
                | (Queued, Failed)
                | (Propagating, Settled)
                | (Propagating, Failed)
                | (Propagating, Disputed)
                | (Disputed, Settled)
                | (Disputed, Failed)
                | (Failed, Propagating)
        )
    }
}

impl FromStr for SettlementStatus {
    type Err = SyncEngineError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "queued" => Ok(SettlementStatus::Queued),
            "propagating" => Ok(SettlementStatus::Propagating),
            "settled" => Ok(SettlementStatus::Settled),
            "failed" => Ok(SettlementStatus::Failed),
            "disputed" => Ok(SettlementStatus::Disputed),
            other => Err(SyncEngineError::InvalidStateTransition {
                from: other.to_string(),
                to: "<unknown>".to_string(),
            }),
        }
    }
}

/// In-memory tracker enforcing legal [`SettlementStatus`] transitions per
/// envelope. Durable persistence of status is handled separately by
/// `crate::storage::db::SyncEngineDb` — callers that need both should update
/// the tracker and the DB together.
#[derive(Debug, Default)]
pub struct SettlementTracker {
    statuses: HashMap<[u8; 32], SettlementStatus>,
    state_spans: HashMap<[u8; 32], tracing::Span>,
    state_started_at: HashMap<[u8; 32], Instant>,
}

impl SettlementTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a newly-queued envelope. Fresh entries always start `Queued`.
    pub fn track(&mut self, message_id: [u8; 32]) {
        self.statuses.insert(message_id, SettlementStatus::Queued);
        let span = tracing::info_span!(
            "envelope_state",
            message_id = %hex::encode(message_id),
            state = SettlementStatus::Queued.as_str()
        );
        self.state_spans.insert(message_id, span);
        self.state_started_at.insert(message_id, Instant::now());
        tracing::info!(
            message_id = %hex::encode(message_id),
            state = SettlementStatus::Queued.as_str(),
            "envelope entered settlement state"
        );
    }

    /// Restore an envelope directly to `status`, bypassing transition
    /// validation. Used when rehydrating the tracker from durable storage on
    /// restart — the persisted status is ground truth and must be taken as-is
    /// rather than re-derived through a (possibly impossible) chain of legal
    /// transitions.
    pub fn restore(&mut self, message_id: [u8; 32], status: SettlementStatus) {
        self.statuses.insert(message_id, status);
        let span = tracing::info_span!(
            "envelope_state",
            message_id = %hex::encode(message_id),
            state = status.as_str(),
            restored = true
        );
        self.state_spans.insert(message_id, span);
        self.state_started_at.insert(message_id, Instant::now());
    }

    pub fn status(&self, message_id: &[u8; 32]) -> Option<SettlementStatus> {
        self.statuses.get(message_id).copied()
    }

    /// Attempt to move `message_id` to `next`. Fails if no such envelope is
    /// tracked, or if the transition is not legal from its current status.
    pub fn transition(
        &mut self,
        message_id: [u8; 32],
        next: SettlementStatus,
    ) -> Result<(), SyncEngineError> {
        let current = self
            .statuses
            .get(&message_id)
            .copied()
            .ok_or_else(|| SyncEngineError::EnvelopeNotFound(hex::encode(message_id)))?;

        if !current.can_transition_to(next) {
            return Err(SyncEngineError::InvalidStateTransition {
                from: current.as_str().to_string(),
                to: next.as_str().to_string(),
            });
        }

        let elapsed = self
            .state_started_at
            .remove(&message_id)
            .map(|started| started.elapsed());
        self.state_spans.remove(&message_id);
        self.statuses.insert(message_id, next);
        let next_span = tracing::info_span!(
            "envelope_state",
            message_id = %hex::encode(message_id),
            state = next.as_str()
        );
        self.state_spans.insert(message_id, next_span);
        self.state_started_at.insert(message_id, Instant::now());
        tracing::info!(
            message_id = %hex::encode(message_id),
            from_status = current.as_str(),
            to_status = next.as_str(),
            state_duration_ms = elapsed.map_or(0, |duration| duration.as_millis() as u64),
            "settlement transition"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::{Context, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;

    #[derive(Clone, Default)]
    struct Capture {
        spans: Arc<Mutex<Vec<(String, String)>>>,
        events: Arc<Mutex<Vec<(String, String)>>>,
    }

    struct FieldVisitor(String);

    impl tracing::field::Visit for FieldVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={field} {value:?}"));
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.push_str(&format!(" {}={field} {value}"));
        }
    }

    impl<S> tracing_subscriber::Layer<S> for Capture
    where
        S: tracing::Subscriber + for<'span> LookupSpan<'span>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: Context<'_, S>,
        ) {
            let mut fields = FieldVisitor(String::new());
            attrs.record(&mut fields);
            self.spans.lock().unwrap().push((
                attrs.metadata().name().to_string(),
                fields.0,
            ));
        }

        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = FieldVisitor(String::new());
            event.record(&mut fields);
            self.events.lock().unwrap().push((
                event.metadata().name().to_string(),
                fields.0,
            ));
        }
    }

    fn captured_subscriber(capture: &Capture) -> impl tracing::Subscriber {
        tracing_subscriber::registry().with(capture.clone())
    }

    #[test]
    fn test_full_lifecycle_emits_correlated_spans_for_single_message_id() {
        let capture = Capture::default();
        let message_id = [0xabu8; 32];

        tracing::subscriber::with_default(captured_subscriber(&capture), || {
            let mut tracker = SettlementTracker::new();
            tracker.track(message_id);
            tracker
                .transition(message_id, SettlementStatus::Propagating)
                .unwrap();
            tracker
                .transition(message_id, SettlementStatus::Settled)
                .unwrap();
        });

        let spans = capture.spans.lock().unwrap();
        let events = capture.events.lock().unwrap();
        assert_eq!(
            spans.iter().filter(|(name, _)| name == "envelope_state").count(),
            3
        );
        assert!(spans.iter().all(|(_, fields)| fields.contains("message_id")));
        assert!(events.iter().any(|(name, fields)| {
            name.contains("envelope entered settlement state") && fields.contains("message_id")
        }));
        assert!(events.iter().any(|(name, fields)| {
            name.contains("settlement transition") && fields.contains("message_id")
        }));
    }

    #[test]
    fn test_span_timing_reflects_actual_elapsed_state_duration() {
        let capture = Capture::default();
        let message_id = [0xcdu8; 32];

        tracing::subscriber::with_default(captured_subscriber(&capture), || {
            let mut tracker = SettlementTracker::new();
            tracker.track(message_id);
            tracker
                .transition(message_id, SettlementStatus::Propagating)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
            tracker
                .transition(message_id, SettlementStatus::Settled)
                .unwrap();
        });

        assert!(capture.events.lock().unwrap().iter().any(|(name, fields)| {
            name.contains("settlement transition")
                && fields.contains("state_duration_ms")
                && fields.contains("20")
        }));
    }

    #[test]
    fn test_happy_path_queued_to_settled() {
        let mut tracker = SettlementTracker::new();
        let id = [1u8; 32];
        tracker.track(id);
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Queued));

        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        tracker.transition(id, SettlementStatus::Settled).unwrap();
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Settled));
    }

    #[test]
    fn test_disputed_can_recover_to_settled() {
        let mut tracker = SettlementTracker::new();
        let id = [2u8; 32];
        tracker.track(id);
        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        tracker.transition(id, SettlementStatus::Disputed).unwrap();
        tracker.transition(id, SettlementStatus::Settled).unwrap();
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Settled));
    }

    #[test]
    fn test_failed_can_retry_to_propagating() {
        let mut tracker = SettlementTracker::new();
        let id = [3u8; 32];
        tracker.track(id);
        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        tracker.transition(id, SettlementStatus::Failed).unwrap();
        tracker
            .transition(id, SettlementStatus::Propagating)
            .unwrap();
        assert_eq!(tracker.status(&id), Some(SettlementStatus::Propagating));
    }

    #[test]
    fn test_illegal_transition_rejected() {
        let mut tracker = SettlementTracker::new();
        let id = [4u8; 32];
        tracker.track(id);
        // Cannot jump straight from Queued to Settled.
        let result = tracker.transition(id, SettlementStatus::Settled);
        assert!(matches!(
            result,
            Err(SyncEngineError::InvalidStateTransition { .. })
        ));
    }

    #[test]
    fn test_transition_on_untracked_envelope_errors() {
        let mut tracker = SettlementTracker::new();
        let result = tracker.transition([9u8; 32], SettlementStatus::Propagating);
        assert!(matches!(result, Err(SyncEngineError::EnvelopeNotFound(_))));
    }

    #[test]
    fn test_settlement_transition_matrix_is_exhaustive() {
        use SettlementStatus::*;

        // Hand-written ground truth reachability graph, kept independent of
        // `can_transition_to`'s own match arms so this test can actually
        // catch a divergence between the two instead of restating the same
        // logic. Any (from, to) pair not listed here is expected to be illegal.
        let allowed: &[(SettlementStatus, SettlementStatus)] = &[
            (Queued, Propagating),
            (Queued, Failed),
            (Propagating, Settled),
            (Propagating, Failed),
            (Propagating, Disputed),
            (Disputed, Settled),
            (Disputed, Failed),
            (Failed, Propagating),
        ];

        let all_states = [Queued, Propagating, Settled, Failed, Disputed];

        let mut checked = 0;
        for &from in &all_states {
            for &to in &all_states {
                let expected = allowed.contains(&(from, to));
                assert_eq!(
                    from.can_transition_to(to),
                    expected,
                    "mismatch for transition {:?} -> {:?}: expected {}",
                    from,
                    to,
                    expected
                );
                checked += 1;
            }
        }
        assert_eq!(
            checked, 25,
            "expected all 25 (from, to) pairs across 5 states"
        );
    }

    #[test]
    fn test_status_roundtrip_via_str() {
        for status in [
            SettlementStatus::Queued,
            SettlementStatus::Propagating,
            SettlementStatus::Settled,
            SettlementStatus::Failed,
            SettlementStatus::Disputed,
        ] {
            let parsed: SettlementStatus = status.as_str().parse().unwrap();
            assert_eq!(parsed, status);
        }
    }
}
