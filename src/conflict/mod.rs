pub mod causal;
pub mod detector;
pub mod escalation;
pub mod resolver;

pub use causal::{
    causal_relation, CausalClock, CausalEnvelope, CausalRelation, DeviceId, MAX_CLOCK_ENTRIES,
};
pub use detector::{
    conflicts_between, detect_conflicts, detect_nway_conflicts, Conflict, NWayConflict, QueuedSlot,
};
pub use escalation::{build_escalation, DisputeEscalation, EscalationInput};
pub use resolver::{
    resolve_conflict, resolve_nway_conflict, CandidateEvidence, ConflictEvidence, RelayObservation,
};
