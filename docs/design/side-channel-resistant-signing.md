# Design: Side-Channel-Resistant Signing and Sequence Lookups on Shared Devices

Design discussion for [#51](https://github.com/StellarConduit/stellarconduit-sync-engine/issues/51).
Opened per the issue's "open a design discussion first" note and
`CONTRIBUTING.md`. Components: `src/envelope/builder.rs`,
`src/queue/sequence.rs`.

## Threat model

**Deployment reality.** The README lists shared community relay terminals as
a target: multiple accounts' key material and activity flow through one
physical device and one process.

**Adversary.** A co-located process without memory-read access, or another
account holder who can time their own interactions with the same terminal.

**Goal of the adversary.** Not to break ed25519, but to infer, from timing
alone: which accounts are active, how many distinct accounts are cached, and
per-account activity patterns.

**Out of scope.** Full local code execution with `ptrace`/memory read (no
in-process defense is meaningful there), power/EM analysis (not applicable to
the terminal software), and network-observable timing (covered by transport
issues).

## Audit surface

### 1. `SequenceReservationManager` lookup path

`reserve_next`, `last_reserved` over `HashMap<String, i64>`. Timing signals
to characterize:

- **Key present vs. absent** — a miss and a hit take different code paths
  (occupied-bucket probe vs. empty-bucket short-circuit). This leaks
  "has this terminal seen account X before".
- **Hash distribution / collisions** — `SipHash` with a per-map random seed
  already de-correlates bucket index from the account string across process
  restarts; within one process the seed is fixed, so relative probe lengths
  are stable but not attributable to a chosen account without a
  known-plaintext oracle.
- **`HashMap` resize** — an insert that triggers a grow is orders of
  magnitude slower and is correlated with *number of distinct accounts*, not
  identity.

### 2. `OfflineEnvelopeBuilder` signing path

`ed25519-dalek` v2 signing is documented constant-time w.r.t. the secret
scalar. What this crate can still get wrong:

- an early `return Err(..)` before signing on a secret-dependent condition;
- a `tracing`/`log` statement whose formatting cost or emission depends on
  key material or on success/failure of a secret-dependent step;
- `zeroize` / drop ordering that runs only on some branches.

## Proposed approach

1. **Sequence lookups — reduce the present/absent signal.** Replace the
   bare `get` in the hot path with a discipline that always performs the
   same work: look up, and on a miss insert a sentinel / negative-cache
   entry so the following operations take the hit path. Document that this
   narrows but does not eliminate the signal (`HashMap` internals remain
   outside our control) and pair it with the operational recommendation
   below.
2. **Signing path — prove end-to-end constant-time-ness by inspection.**
   Walk every branch between `OfflineEnvelopeBuilder::build` and the
   `Signer::sign` call; assert there is exactly one path, no secret-dependent
   `?`/early return, and no log line between key access and signature
   emission. Add a regression test that fails if a secret-dependent branch
   is reintroduced.
3. **Residual risk acceptance + operational mitigation.** Where the
   platform (`std::collections::HashMap`, allocator) prevents a full fix,
   record a reasoned risk acceptance and add to `README.md` security
   guidance: **run one OS process per account on shared terminals**, so
   cross-account timing inference has no shared address space to observe.

## Timing-analysis methodology

- Measure with a monotonic high-resolution clock, many trials (≥ 100k per
  condition), discard warm-up, and compare **distributions**, not means:
  two-sample Kolmogorov–Smirnov plus a Mann–Whitney U, significance
  threshold documented up front (α = 1e-3), report effect size not just
  p-value.
- Pin the thread to one core, disable turbo where possible, run conditions
  interleaved (not blocked) to spread systematic drift.
- The test asserts "no *detectable* difference at this sample size and
  threshold" and records the minimum detectable effect — it never claims
  "constant time", only a measured upper bound on leakage.

## Acceptance-criteria mapping

| Criterion | Addressed by |
| --- | --- |
| Documented threat model + audit for both paths | "Threat model", "Audit surface" above |
| Side-channel fixed or justified risk acceptance + operational mitigation | "Proposed approach" 1 & 3 |
| Statistically sound, reproducible timing methodology | "Timing-analysis methodology" |
| `cargo fmt` / `clippy -D warnings` / `test` pass | Implementation PR |

## Test plan

- `test_sequence_lookup_timing_does_not_correlate_with_account_presence`
  (KS + Mann–Whitney, α = 1e-3, interleaved conditions).
- `test_signing_timing_does_not_correlate_with_key_material` (statistical,
  varying key material with fixed message).
- `test_signing_path_has_no_secret_dependent_early_return` (regression:
  a fault-injected builder that would branch on key state still produces a
  signature via the single path).

## Open questions

- Is the negative-cache entry in `SequenceReservationManager` acceptable
  given its memory growth on adversary-chosen account churn, or does it need
  an LRU bound (and does that bound reintroduce a timing signal)?
- Should the per-account process isolation recommendation be advisory or
  enforced by the CLI refusing to hold more than one key at once on a
  terminal profile?
