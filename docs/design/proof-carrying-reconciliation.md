# Design: Proof-Carrying Reconciliation for Long-Diverged Mesh Partitions

Design discussion for [#52](https://github.com/StellarConduit/stellarconduit-sync-engine/issues/52).
Opened per the issue's note and `CONTRIBUTING.md`'s rule that
`conflict::resolver`-adjacent work starts with a design issue. Components:
`src/storage/db.rs`, `src/conflict/detector.rs`. Builds on #001, #020, #047.

## Problem restated

When two partitions that have been split for days/weeks reconnect, each
`SyncEngineDb` has independently evolved: new queued envelopes, changed
settlement statuses, and *already-resolved* conflicts. Re-running pairwise
detection on the union is insufficient because it (a) is O(records)
over a BLE-bandwidth link, (b) says nothing about *why* the peer's state is
trustworthy, and (c) does not handle both sides having resolved the same
logical conflict differently.

## Proposed protocol

### Phase 0 — causal context

Assumes #047's causal history (per-record logical clock / hash-linked
history). Each record carries `(origin_partition, causal_hash, prev_hash)`.
Reconciliation reasons over history, not wall-clock.

### Phase 1 — divergence discovery (anti-entropy)

Range-based set reconciliation over a Merkle summary of the record-id space:

- Each side builds a balanced Merkle tree keyed by record id; interior nodes
  hash their children, leaves hash `(id, causal_hash, resolution_state)`.
- Exchange the root; recurse only into subtrees whose hashes differ.
- Bandwidth is O(d · log n) where d = number of differing records, not O(n).
  Chosen over IBLT because d can be large (weeks of divergence) and IBLT
  sizing needs an a-priori estimate of d that we do not have.

### Phase 2 — classification

Each differing record is one of:

1. **Present on one side only** — non-conflicting; transfer with its causal
   history so the receiver can verify `prev_hash` chains to a known root.
2. **Present both sides, same `causal_hash`** — identical; no action.
3. **Present both sides, divergent content, no shared resolution** — a
   normal conflict; hand to the existing `conflict::detector` /
   `resolver` path.
4. **Both sides resolved the *same* logical conflict differently** — the
   hard case, below.

### Phase 3 — deterministic reconvergence of case 4

Tie-break rule, applied identically on both sides, order-independent:

```
winner = argmin over {A_resolution, B_resolution} of:
    (1) causal_depth_at_resolution        # earlier causal decision wins
    (2) then: blake3(resolution_payload)  # total order, deterministic
```

- **Order-independence proof obligation.** The rule is a pure function of
  the unordered pair `{A_resolution, B_resolution}` — no input depends on
  who initiates. Property test: run reconciliation A→B and B→A on the same
  fixtures, assert byte-identical final `SyncEngineDb` state.
- **Proof-carrying.** The winning side transmits the resolution payload plus
  the causal history segment that justifies its `causal_depth`. The losing
  side recomputes the tie-break locally from that data and only then commits
  the switch — it never accepts a bare "I win" assertion.

### Phase 4 — resumability

- Reconciliation runs as a single storage transaction per batch of ≤ N
  records, journaled to a `reconciliation_session` table:
  `(session_id, peer, last_acked_merkle_range, phase)`.
- A dropped link leaves the last committed batch durable and the session row
  pointing at the next unprocessed range. Resumption re-sends the Merkle
  root for the remaining range; already-applied batches are idempotent
  (keyed by `causal_hash`).
- Rollback is never needed mid-protocol because no partial batch is
  committed; the invariant is "the local DB is always a valid prefix of the
  reconciled state".

## Acceptance-criteria mapping

| Criterion | Addressed by |
| --- | --- |
| Non-conflicting divergence identified and merged | Phase 1 + Phase 2 cases 1–2 |
| Independently-resolved conflicts converge regardless of initiator | Phase 3 tie-break + order-independence proof |
| Interrupted reconciliation leaves valid partial state | Phase 4 journaling + prefix invariant |
| Bandwidth measured vs. naive full-diff baseline | Bench below |
| `fmt` / `clippy` / `test` pass | Implementation PR |

## Test plan

- `test_non_conflicting_divergence_merges_cleanly`
- `test_independently_resolved_conflict_converges_regardless_of_initiator`
  — both directions, assert identical final state hash.
- `test_interrupted_reconciliation_leaves_valid_partial_state` — kill the
  session at each phase boundary; assert DB validity and successful resume.
- `test_reconciliation_bandwidth_scales_sublinearly_with_matching_state` —
  bench in `benches/`, vary shared-state fraction, compare bytes-on-wire to
  a full-table-diff baseline.

## Open questions

- Merkle tree rebalancing cost on each side per session vs. maintaining an
  incremental Merkle index in `storage` continuously (#047 overlap).
- Does the `causal_depth` tie-break interact badly with #020's escalation
  path when a case-4 winner was itself an escalated resolution?
- Bounding `reconciliation_session` retention so an abandoned peer session
  does not pin storage forever.
