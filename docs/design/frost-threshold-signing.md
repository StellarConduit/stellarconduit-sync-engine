# Design: FROST Threshold Signing vs. Weighted Multisig Accumulation

Design discussion for [#55](https://github.com/StellarConduit/stellarconduit-sync-engine/issues/55).
Opened per the issue's note and `CONTRIBUTING.md`. New component:
`src/envelope/threshold.rs`. Alternative to #029; the project likely
standardizes on one.

## What FROST buys us

FROST (Flexible Round-Optimized Schnorr Threshold signatures) lets a
`t`-of-`n` group jointly produce **one** signature that is, on-chain,
indistinguishable from an ordinary single-signer ed25519 signature:

- **On-chain footprint:** one signature, one signer key on the account —
  vs. #029's N separately-visible weighted signatures.
- **Coordination:** two signing rounds regardless of N, vs. N independent
  full signing operations that each must reach the coordinator.
- **Privacy:** the set of participating signers is not revealed on-chain.

## Crate evaluation

| Option | Status | Assessment |
| --- | --- | --- |
| `frost-ed25519` (ZF FROST, RFC 9591) | Audited (NCC 2023), maintained | **Preferred.** RFC-tracked, ed25519 ciphersuite, supports dealerless keygen via `frost-ed25519`'s DKG module. |
| `frost-dalek` | Unmaintained, pre-RFC | Rejected — API drift, no audit of current form. |
| Hand-rolled | — | Rejected — the issue explicitly warns against naive implementation; a from-scratch Schnorr threshold impl is not justifiable against an audited RFC crate. |

Recommendation: integrate `frost-ed25519` (RFC 9591), wrap its
`Identifier`/`SigningPackage`/`SignatureShare` types behind
`src/envelope/threshold.rs`, and keep the DKG and signing round state in
this crate's storage so it survives process restarts.

## The hard part: async, partition-prone transport

FROST assumes synchronous rounds with all `t` participants reachable within
a round. `stellarconduit-core`'s gossip layer is asynchronous, unreliable,
and partitionable. Mapping:

### Round 1 (commitments)

- Each signer publishes a signing-nonce commitment as a gossip message keyed
  by `(account, tx_hash, signer_id, session_epoch)`.
- The coordinator role is **not** fixed: any signer who observes `t`
  commitments for a session can assemble the `SigningPackage`. This removes
  the "coordinator must be reachable" single point of failure.
- Commitments are single-use; a `session_epoch` bump invalidates all prior
  commitments to prevent nonce reuse if a session is retried.

### Round 2 (signature shares)

- Signers who receive a `SigningPackage` matching their outstanding
  commitment emit a `SignatureShare`.
- Any node with `t` valid shares aggregates the final signature.

### Identified gaps (the actual deliverable)

1. **Nonce reuse under retry.** If a session stalls and is retried, a signer
   must never reuse a Round-1 nonce. Mitigation: nonces are derived from
   `(secret, session_epoch, tx_hash)` and the signer persists "highest
   epoch signed" monotonically; a share request for a stale epoch is
   refused. **Residual risk:** storage rollback (e.g. restore from backup)
   could rewind the monotonic counter — documented as an operational
   constraint (never restore a signer's state from a stale backup).
2. **Liveness with `> n - t` signers offline.** Unfixable by protocol —
   documented: the account should be provisioned with `t` low enough that
   the expected reachable set in a partition still meets threshold, and
   falls back to #029-style accumulation is *not* possible (different key
   model), so this is a provisioning-time decision.
3. **Equivocation.** A malicious signer sending different commitments to
   different partitions. Detectable after partitions merge (two signed
   commitments, same `(signer_id, session_epoch)`); punishable only
   socially. Documented as an open limitation.
4. **Aggregator trust.** Any node can aggregate, but a wrong aggregation is
   detected immediately because the output fails ed25519 verification against
   the group key — so aggregation is trustless. No gap here; noted for
   completeness.

## Comparative analysis vs. #029

| Dimension | FROST (#55) | Weighted accumulation (#029) |
| --- | --- | --- |
| Coordination rounds under mesh | 2, coordinator-free | N independent signings to a coordinator |
| On-chain footprint | 1 signature | N signatures + weights |
| Signer-set privacy | Hidden | Public |
| Impl / audit risk | Moderate (rely on audited `frost-ed25519` + novel transport layer) | Low (native Stellar multisig, no new crypto) |
| Signer permanently offline mid-protocol | Session fails; retry with new epoch and a different `t`-subset | Partial signatures retained; just need any valid `t`-of-weight eventually |
| Key rotation / membership change | Requires re-run of DKG | Add/remove a signer key on the account |

**Recommendation.** Adopt FROST for accounts that prioritize on-chain
privacy and predictable coordination cost and whose membership is stable;
keep #029's accumulation as the default for accounts with churny membership
or where DKG ceremonies are impractical. Both have a place — do not remove
#029.

## Acceptance-criteria mapping

| Criterion | Addressed by |
| --- | --- |
| DKG + threshold signing → standard single-signer ed25519 Stellar accepts | `frost-ed25519` RFC 9591 output; verified in `test_threshold_signature_verifies_as_standard_ed25519` |
| Async-transport adaptation analyzed for liveness/security gaps | "Identified gaps" 1–4 |
| Reasoned comparative recommendation vs. #029 | "Comparative analysis" table + recommendation |
| `fmt` / `clippy` / `test` pass | Implementation PR |

## Test plan

- `test_threshold_signature_verifies_as_standard_ed25519` — aggregate a
  `t`-of-`n` signature, verify with a stock ed25519 verifier against the
  group public key.
- `test_signing_below_threshold_participants_fails` — `t-1` shares never
  aggregate to a valid signature.
- `test_signer_dropout_mid_protocol_is_handled_or_precisely_documented_as_unhandled`
  — drop a signer between rounds; assert session fails cleanly and a
  new-epoch retry with a different subset succeeds.
- `test_key_generation_is_dealer_free` — assert no single party's state ever
  contains the full group secret at any point in the DKG.

## Open questions

- Persisting FROST round state in `storage`: schema and the monotonic
  epoch-counter durability guarantee.
- Whether `session_epoch` should be a Lamport clock shared with the rest of
  the sync engine or a signing-local counter.
- Interaction with `src/envelope/pq.rs` (post-quantum envelope path) — is a
  threshold PQ signature in scope later, or explicitly out?
