//! Structural double-spend detection.
//!
//! `TransactionEnvelope.tx_xdr` is an opaque, already-built Stellar XDR blob
//! (see `stellarconduit_core::message::envelope`) — this crate does not parse
//! XDR. Instead, the source account and reserved sequence number for each
//! queued envelope are tracked explicitly at enqueue time (see
//! `crate::storage::db`), and conflicts are detected structurally: two
//! *different* envelopes claiming the same (account, sequence) slot can never
//! both settle on-chain, since Stellar accepts only one transaction per
//! sequence number.
//!
//! Deciding *which* of the two is valid is the hard part — see
//! `crate::conflict::resolver`.
//!
//! # Beyond two envelopes
//!
//! A slot can be claimed by three or more distinct envelopes at once (e.g.
//! independent multi-sig cosigners, or a badly-partitioned mesh cluster with
//! several stale views). [`detect_conflicts`] still reports that case as
//! every pairwise [`Conflict`] within the group — kept as-is so existing
//! callers and tests are untouched. But resolving those pairs independently
//! can produce a non-transitive outcome (A beats B, B beats C, C beats A) that
//! no single deterministic pass can reconcile. [`detect_nway_conflicts`] is
//! the migration path: it groups the *same* underlying slots into one
//! [`NWayConflict`] per contested slot, carrying the full candidate set so
//! `crate::conflict::resolver::resolve_nway_conflict` can make one coherent
//! decision instead of many independent ones. New call sites that need to
//! *resolve* conflicts (rather than just log/report them) should prefer
//! `detect_nway_conflicts` over `detect_conflicts`.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSlot {
    pub source_account: String,
    pub sequence: i64,
    pub message_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub source_account: String,
    pub sequence: i64,
    pub envelope_a: [u8; 32],
    pub envelope_b: [u8; 32],
}

/// Returns a conflict if `a` and `b` occupy the same (account, sequence) slot
/// but are different envelopes. Returns `None` if they're the same envelope
/// (e.g. seen twice via different gossip paths) or occupy different slots.
pub fn conflicts_between(a: &QueuedSlot, b: &QueuedSlot) -> Option<Conflict> {
    let span = tracing::info_span!(
        "conflict_detection",
        message_id = %hex::encode(a.message_id),
        other_message_id = %hex::encode(b.message_id)
    );
    let _entered = span.enter();
    if a.source_account != b.source_account || a.sequence != b.sequence {
        return None;
    }
    if a.message_id == b.message_id {
        return None;
    }
    Some(Conflict {
        source_account: a.source_account.clone(),
        sequence: a.sequence,
        envelope_a: a.message_id,
        envelope_b: b.message_id,
    })
}

/// Scan a batch of queued slots (e.g. everything currently durably queued)
/// for double-spend conflicts.
pub fn detect_conflicts(slots: &[QueuedSlot]) -> Vec<Conflict> {
    let mut groups: HashMap<(String, i64), Vec<[u8; 32]>> = HashMap::new();
    for slot in slots {
        groups
            .entry((slot.source_account.clone(), slot.sequence))
            .or_default()
            .push(slot.message_id);
    }

    let mut conflicts = Vec::new();
    for ((account, sequence), mut ids) in groups {
        ids.sort();
        ids.dedup();
        for message_id in &ids {
            tracing::info_span!(
                "conflict_candidate",
                message_id = %hex::encode(message_id),
                source_account = %account,
                sequence
            )
            .in_scope(|| tracing::info!("candidate inspected"));
        }
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                conflicts.push(Conflict {
                    source_account: account.clone(),
                    sequence,
                    envelope_a: ids[i],
                    envelope_b: ids[j],
                });
            }
        }
    }
    conflicts
}

/// The full set of distinct envelopes competing for a single (account,
/// sequence) slot.
///
/// Unlike [`Conflict`], which names exactly two envelopes, this carries every
/// contender at once so a resolver can pick a single winner (or declare the
/// whole slot unresolved) in one coherent pass — see
/// `crate::conflict::resolver::resolve_nway_conflict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NWayConflict {
    pub source_account: String,
    pub sequence: i64,
    /// Every distinct envelope claiming this slot, sorted ascending.
    /// Always has at least 2 elements.
    pub message_ids: Vec<[u8; 32]>,
}

/// Scan a batch of queued slots for double-spend conflicts, grouping every
/// distinct envelope claiming the same (account, sequence) slot into a single
/// [`NWayConflict`] instead of one [`Conflict`] per pair.
///
/// This is the N-way counterpart to [`detect_conflicts`]; use it when the
/// result will be fed into `resolver::resolve_nway_conflict`, since resolving
/// the pairwise conflicts independently can produce a non-transitive outcome.
/// `detect_conflicts` is left unchanged for existing callers — see the module
/// docs for the migration note.
pub fn detect_nway_conflicts(slots: &[QueuedSlot]) -> Vec<NWayConflict> {
    let mut groups: HashMap<(String, i64), Vec<[u8; 32]>> = HashMap::new();
    for slot in slots {
        groups
            .entry((slot.source_account.clone(), slot.sequence))
            .or_default()
            .push(slot.message_id);
    }

    let mut conflicts = Vec::new();
    for ((source_account, sequence), mut ids) in groups {
        ids.sort();
        ids.dedup();
        for message_id in &ids {
            tracing::info_span!(
                "conflict_candidate",
                message_id = %hex::encode(message_id),
                source_account = %source_account,
                sequence
            )
            .in_scope(|| tracing::info!("candidate inspected"));
        }
        if ids.len() >= 2 {
            conflicts.push(NWayConflict {
                source_account,
                sequence,
                message_ids: ids,
            });
        }
    }
    conflicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::BTreeSet;

    fn slot(account: &str, sequence: i64, message_id: u8) -> QueuedSlot {
        QueuedSlot {
            source_account: account.to_string(),
            sequence,
            message_id: [message_id; 32],
        }
    }

    #[test]
    fn test_same_slot_different_envelopes_conflicts() {
        let a = slot("GABC", 101, 1);
        let b = slot("GABC", 101, 2);
        let conflict = conflicts_between(&a, &b).unwrap();
        assert_eq!(conflict.source_account, "GABC");
        assert_eq!(conflict.sequence, 101);
    }

    #[test]
    fn test_same_envelope_seen_twice_is_not_a_conflict() {
        let a = slot("GABC", 101, 1);
        let b = slot("GABC", 101, 1);
        assert!(conflicts_between(&a, &b).is_none());
    }

    #[test]
    fn test_different_sequence_is_not_a_conflict() {
        let a = slot("GABC", 101, 1);
        let b = slot("GABC", 102, 2);
        assert!(conflicts_between(&a, &b).is_none());
    }

    #[test]
    fn test_different_account_is_not_a_conflict() {
        let a = slot("GABC", 101, 1);
        let b = slot("GXYZ", 101, 2);
        assert!(conflicts_between(&a, &b).is_none());
    }

    #[test]
    fn test_detect_conflicts_in_batch() {
        let slots = vec![
            slot("GABC", 101, 1),
            slot("GABC", 101, 2), // conflicts with the above
            slot("GABC", 102, 3), // no conflict, different sequence
            slot("GXYZ", 101, 4), // no conflict, different account
        ];
        let conflicts = detect_conflicts(&slots);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].source_account, "GABC");
        assert_eq!(conflicts[0].sequence, 101);
    }

    #[test]
    fn test_no_conflicts_in_clean_batch() {
        let slots = vec![slot("GABC", 101, 1), slot("GABC", 102, 2)];
        assert!(detect_conflicts(&slots).is_empty());
    }

    #[test]
    fn test_three_way_collision_reports_every_pair() {
        // Three distinct envelopes on the same (account, sequence) slot must
        // yield all three pairwise conflicts, not just the ones adjacent in
        // sorted order.
        let slots = vec![
            slot("GABC", 101, 1),
            slot("GABC", 101, 2),
            slot("GABC", 101, 3),
        ];
        let conflicts = detect_conflicts(&slots);
        assert_eq!(conflicts.len(), 3);
    }

    #[test]
    fn test_detect_nway_conflicts_groups_three_way_collision_into_one() {
        let slots = vec![
            slot("GABC", 101, 1),
            slot("GABC", 101, 2),
            slot("GABC", 101, 3),
        ];
        let conflicts = detect_nway_conflicts(&slots);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].source_account, "GABC");
        assert_eq!(conflicts[0].sequence, 101);
        assert_eq!(
            conflicts[0].message_ids,
            vec![[1u8; 32], [2u8; 32], [3u8; 32]]
        );
    }

    #[test]
    fn test_detect_nway_conflicts_ignores_clean_slots() {
        let slots = vec![slot("GABC", 101, 1), slot("GABC", 102, 2)];
        assert!(detect_nway_conflicts(&slots).is_empty());
    }

    #[test]
    fn test_existing_two_way_behavior_preserved() {
        // The old pairwise API (`detect_conflicts` / `conflicts_between`)
        // must keep behaving exactly as before after adding the N-way path.
        let slots = vec![slot("GABC", 101, 1), slot("GABC", 101, 2)];

        let pairwise = detect_conflicts(&slots);
        assert_eq!(pairwise.len(), 1);
        assert_eq!(pairwise[0].envelope_a, [1u8; 32]);
        assert_eq!(pairwise[0].envelope_b, [2u8; 32]);

        // The N-way view of the same 2-envelope slot must describe the exact
        // same candidate set, just carried in one struct instead of a pair.
        let nway = detect_nway_conflicts(&slots);
        assert_eq!(nway.len(), 1);
        assert_eq!(nway[0].source_account, pairwise[0].source_account);
        assert_eq!(nway[0].sequence, pairwise[0].sequence);
        assert_eq!(
            nway[0].message_ids,
            vec![pairwise[0].envelope_a, pairwise[0].envelope_b]
        );
    }

    /// Naive O(n^2) reference: every distinct pair of slots is checked
    /// independently via `conflicts_between`, so it can't share a bug with
    /// `detect_conflicts`'s grouping logic.
    fn naive_detect_conflicts(slots: &[QueuedSlot]) -> Vec<Conflict> {
        let mut out = Vec::new();
        for i in 0..slots.len() {
            for j in (i + 1)..slots.len() {
                if let Some(c) = conflicts_between(&slots[i], &slots[j]) {
                    out.push(c);
                }
            }
        }
        out
    }

    /// Order-independent view of a conflict set: (account, sequence, sorted envelope pair).
    fn normalize(conflicts: Vec<Conflict>) -> BTreeSet<(String, i64, [u8; 32], [u8; 32])> {
        conflicts
            .into_iter()
            .map(|c| {
                let (a, b) = if c.envelope_a <= c.envelope_b {
                    (c.envelope_a, c.envelope_b)
                } else {
                    (c.envelope_b, c.envelope_a)
                };
                (c.source_account, c.sequence, a, b)
            })
            .collect()
    }

    fn arb_account() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("GABC".to_string()),
            Just("GXYZ".to_string()),
            Just("GDEF".to_string()),
        ]
    }

    fn arb_slot() -> impl Strategy<Value = QueuedSlot> {
        (arb_account(), 0i64..6, 0u8..6).prop_map(|(source_account, sequence, message_id)| {
            QueuedSlot {
                source_account,
                sequence,
                message_id: [message_id; 32],
            }
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        #[test]
        fn proptest_detect_conflicts_matches_naive_reference(
            slots in prop::collection::vec(arb_slot(), 0..40)
        ) {
            let actual = normalize(detect_conflicts(&slots));
            let expected = normalize(naive_detect_conflicts(&slots));
            prop_assert_eq!(actual, expected);
        }
    }
}
