# StellarConduit Sync Engine

> The offline transaction queue, sequence-number reservation, durable settlement tracking, and double-spend conflict detection layer for StellarConduit.

This repository sits directly on top of [`stellarconduit-core`](https://github.com/StellarConduit/stellarconduit-core). Where core's job ends at "propagate this signed envelope across the mesh," the sync engine's job starts one step earlier — deciding what to sign and in what order while fully offline — and continues one step later, tracking each envelope through to on-chain settlement (or a detected conflict).

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Modules](#modules)
- [Metrics and differential privacy](#metrics-and-differential-privacy)
- [Repository Structure](#repository-structure)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

StellarConduit Sync Engine is a Rust library implementing the "Offline Transaction Engine" and "Conflict Resolution Engine" layers of the StellarConduit protocol. It is designed to be embedded in the mobile wallet and in relay-node software — anywhere a device needs to queue, sign, and track its own Stellar payments without a network connection.

The sync engine handles:

- **Priority-Ordered Queuing** — a local outgoing-payment queue where emergency payments are dispatched ahead of routine ones, independent of `stellarconduit-core`'s own mesh-forwarding priority
- **Sequence Number Reservation** — assigning distinct, strictly-increasing Stellar sequence numbers to multiple payments queued offline from the same account, so they never collide
- **Offline Signing** — building and signing `TransactionEnvelope`s (as defined in `stellarconduit-core`) with no network connection required
- **Durable Storage** — persisting queued envelopes, sequence reservations, and settlement status to an on-device SQLite database so nothing is lost across a restart
- **Settlement Tracking** — a state machine following each envelope from `Queued` through `Propagating` to `Settled`/`Failed`, including recovery from a `Disputed` state
- **Double-Spend Detection** — structurally detecting when two different envelopes have been signed against the same (account, sequence) slot, which happens when a split mesh cluster lets both sides believe their payment succeeded

**Not yet implemented** — and the hardest, most interesting problem in this repository — is *deterministic off-chain conflict resolution*: deciding which of two conflicting envelopes is valid using timestamps and cryptographic relay-chain proofs, with consensus among the relay nodes that observed each side. Conflicts that can't be resolved this way are the ones that need final arbitration by the `dispute-resolver` Soroban contract in [`stellarconduit-contracts`](https://github.com/StellarConduit/stellarconduit-contracts). See [`src/conflict/resolver.rs`](src/conflict/resolver.rs) for the current seam.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                 stellarconduit-sync-engine                    │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐    │
│  │    queue    │  │  envelope   │  │      storage         │    │
│  │             │  │             │  │                       │    │
│  │ - priority  │  │ - offline   │  │ - queued envelopes    │    │
│  │   tiers     │  │   signing   │  │ - sequence reservations│   │
│  │ - sequence  │  │   (wraps    │  │ - settlement status   │    │
│  │   reserve   │  │    core)    │  │ - conflicts            │    │
│  └─────────────┘  └─────────────┘  └─────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────┐  ┌─────────────────────────┐      │
│  │       settlement         │  │        conflict          │      │
│  │                           │  │                           │      │
│  │ - status state machine    │  │ - structural detection    │      │
│  │   (Queued→Settled)        │  │ - deterministic resolution│      │
│  │                           │  │   (seam — not implemented)│      │
│  └─────────────────────────┘  └─────────────────────────┘      │
│                                                                 │
└───────────────────────────────────────────────────────────────┘
           │                                        │
           ▼                                        ▼
   stellarconduit-core                    stellarconduit-contracts
   (mesh propagation of                   (on-chain arbitration via
    the signed envelope)                   dispute-resolver, for
                                            conflicts this repo
                                            can't resolve off-chain)
```

---

## Modules

### `queue`
Local, pre-gossip ordering of a device's own outgoing payments, plus reservation of Stellar sequence numbers so multiple envelopes queued from the same account never collide.

**Key responsibilities:**
- `TxPriority` tiers (`Emergency` / `Normal` / `Low`) and a priority-ordered outbound queue
- Per-account sequence number reservation, seeded from the last-known on-chain sequence
- Rollback of a reservation if envelope construction fails after reserving

---

### `envelope`
Builds and signs `TransactionEnvelope`s (as defined in `stellarconduit_core::message::types`) entirely offline, coupling the signing step to sequence reservation so a caller cannot accidentally sign two envelopes for the same account without reserving distinct sequence numbers first.

---

### `storage`
Durable, on-device SQLite persistence (via `rusqlite` + `tokio-rusqlite`, mirroring the pattern in `stellarconduit-core::persistence`) so a device restart never loses a queued payment, a sequence reservation, or a detected conflict.

**Key responsibilities:**
- `queued_envelopes`, `sequence_reservations`, `settlement_status`, and `conflicts` tables
- CRUD operations for each, all `async` via `tokio-rusqlite`

---

### `settlement`
A state machine tracking each envelope from the moment it's signed offline to final on-chain confirmation.

**States:** `Queued` → `Propagating` → `Settled` / `Failed` / `Disputed`, with `Failed` able to retry back to `Propagating` and `Disputed` able to resolve to either `Settled` or `Failed` once arbitrated.

---

### `conflict`
Detects and (eventually) resolves double-spend conflicts arising from split mesh clusters.

**Key responsibilities:**
- `detector`: structural detection — two different envelopes claiming the same (account, sequence) slot can never both settle on-chain
- `resolver`: **the hard centerpiece** — deterministic off-chain resolution from a Sybil-resistant quorum of verified `RelayChainProof`s. `quorum_standing` exposes *why* a conflict is unresolved; conflicts it still can't settle escalate on-chain.
- `vrf_tiebreak`: last-resort step for a genuine quorum-met tie — a `schnorrkel` VRF, evaluated by a deterministically-selected relay (never a conflicting party), producing a tie-break that is unpredictable in advance yet independently verifiable by anyone.
- `proof_compression`: folds an arbitrarily long relay chain's per-hop `RelayChainProof`s into a constant-size `CompressedChainProof` (a hash-based recursive/IVC accumulator with a bounded tail of relay attestations). On-chain verification cost is flat in hop count instead of linear, so a legitimately long chain stays escalatable within a Soroban budget. New hops fold in incrementally as the envelope propagates. Trade-off (documented in the module): for chains longer than `TAIL_WINDOW`, the pre-tail prefix rests on the tail relays' recursive attestations rather than independent re-checking — a *working but not-yet-production* scheme, per issue #63. See `cargo run --release --example compression_bench`.

---

### `metrics`
In-process exact counters (`SyncEngineMetrics`) plus the only supported off-device export path, `DpExporter`. Exact per-device counts must not be scraped as-is: on a shared community relay, or anywhere metrics are aggregated centrally, a spike in `disputes_escalated` can reveal that a particular user or terminal is currently in a dispute. See [Metrics and differential privacy](#metrics-and-differential-privacy).

---

## Metrics and differential privacy

`SyncEngineMetrics` keeps exact `AtomicUsize` lifetime totals for the embedding binary's own use. Off-device export goes through `DpExporter`, which releases **windowed event counts** under the Laplace mechanism (`Lap(b = 1/ε)` per coordinate, L1 sensitivity Δ = 1 for one extra event in the window). Lifetime totals are never exported: noisy lifetime counters collapse under repeated Prometheus scrapes (averaging drives the noise to zero), and `rate()` over a noisy counter is dominated by the noise, not the signal.

**Repeated scrapes.** One noisy snapshot is produced per tumbling window and cached. Subsequent scrapes inside that window return the same values and do not spend more privacy budget — a 15-second Prometheus scrape against the default 60-second window costs `ε` once per minute, not once per scrape. By default the number of windows is uncapped: a single event lives in one window, so event-level `(ε, 0)`-DP does not erode as the process runs. Deployments whose threat model is "hide this device's whole activity trace" (user-level composition, `Tε` after T windows) should set `DpExportConfig::with_max_releases`; once the cap is hit the exporter returns an error rather than falling back to the exact counters.

**Picking `ε`.** Mean absolute error of each released coordinate is `1/ε` (before a non-negativity clamp that slightly biases sparse counters upward):

| Config | `ε` | Window | MAE | 95th \|noise\| | Use when |
|--------|-----|--------|-----|----------------|----------|
| `DpExportConfig::strict()` | 0.1 | 5 min | 10 | ~30 | Shared community terminals, high-risk deployments |
| `DpExportConfig::moderate()` (default) | 1.0 | 60 s | 1 | ~3 | Typical relay / wallet. Single events cannot be confirmed; rate changes of ~10+ stay visible |
| `DpExportConfig::relaxed()` | 2.0 | 15 s | 0.5 | ~1.5 | Scrapes are already aggregated across many devices before anyone looks at them |

```rust
use stellarconduit_sync_engine::metrics::{DpExportConfig, DpExporter, SyncEngineMetrics};

let metrics = SyncEngineMetrics::default();
metrics.record_queued();

let exporter = DpExporter::new(DpExportConfig::moderate()).expect("valid config");
let scrape = exporter.export_prometheus(&metrics).expect("within budget");
// Serve `scrape` from /metrics. Do not also expose the raw atomics.
```

The full design rationale (Laplace vs Gaussian, windowed vs lifetime, budget policy and its residual risk) lives in the module docs of `src/metrics.rs`.

---

## Repository Structure

```
stellarconduit-sync-engine/
├── src/
│   ├── lib.rs
│   ├── errors.rs
│   ├── metrics.rs
│   ├── queue/
│   │   ├── mod.rs
│   │   ├── priority.rs
│   │   └── sequence.rs
│   ├── envelope/
│   │   ├── mod.rs
│   │   └── builder.rs
│   ├── storage/
│   │   ├── mod.rs
│   │   └── db.rs
│   ├── settlement/
│   │   ├── mod.rs
│   │   └── tracker.rs
│   └── conflict/
│       ├── mod.rs
│       ├── detector.rs
│       └── resolver.rs
├── tests/
│   └── integration/
│       └── queue_storage_roundtrip_test.rs
├── Cargo.toml
├── .gitignore
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

---

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) `>=1.74.0`
- SQLite is bundled via the `rusqlite` `bundled` feature — no system SQLite install required

Verify your Rust installation:
```bash
rustc --version
cargo --version
```

---

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/StellarConduit/stellarconduit-sync-engine.git
cd stellarconduit-sync-engine
```

### 2. Build the Library
```bash
cargo build
```

### 3. Run Tests
```bash
cargo test
```

### 4. Run the Mock Relay Example
```bash
# Basic demo — queue 3 payments and watch them settle
cargo run --example mock_relay

# Customise payment count and relay latency
cargo run --example mock_relay -- --payments 5 --relay-delay-ms 200

# Inject a double-spend conflict scenario
cargo run --example mock_relay -- --inject-conflict

# Combine flags
cargo run --example mock_relay -- --payments 2 --relay-delay-ms 1000 --inject-conflict
```

---

## Development

### Running a Specific Module's Tests
```bash
cargo test queue
cargo test conflict
cargo test settlement
cargo test storage
```

### Diagnostic CLI

`sync-engine-cli` is a read-only inspector for a `SyncEngineDb` SQLite file — useful for debugging a real device's local state (what's queued, an envelope's settlement history, unresolved conflicts) without writing a throwaway script or attaching a debugger.

```bash
cargo build --bin sync-engine-cli
```

Every subcommand takes `--db-path <PATH>` pointing at the device's `SyncEngineDb` file, and an optional `--json` flag (placed before the subcommand) for machine-readable output instead of a table:

```bash
# What's currently queued, optionally filtered by account and/or priority
cargo run --bin sync-engine-cli -- --db-path wallet.sqlite3 queue list
cargo run --bin sync-engine-cli -- --db-path wallet.sqlite3 queue list --account GABC... --priority emergency

# Settlement status and full history for one message id (hex-encoded, as printed by `queue list`)
cargo run --bin sync-engine-cli -- --db-path wallet.sqlite3 settlement status <message_id_hex>

# Detected double-spend conflicts
cargo run --bin sync-engine-cli -- --db-path wallet.sqlite3 conflicts list
cargo run --bin sync-engine-cli -- --db-path wallet.sqlite3 conflicts list --unresolved-only

# Row counts per table and queue age extremes
cargo run --bin sync-engine-cli -- --db-path wallet.sqlite3 db summary

# Machine-readable JSON, e.g. for scripting
cargo run --bin sync-engine-cli -- --db-path wallet.sqlite3 --json queue list
```

The CLI never writes to the database. Its argument parsing and data assembly live in `src/cli.rs` (exercised directly by `tests/integration/cli_test.rs`); `src/bin/sync-engine-cli.rs` is a thin wrapper over that library code.

### Linting and Formatting

Always run these before submitting a pull request:
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

---

## Testing

**Unit tests** live alongside the source code in each module and test individual functions and data structures in isolation.

**Integration tests** in `tests/integration/` test how modules interact — e.g. `queue_storage_roundtrip_test.rs` reserves a sequence number, signs an envelope, persists it, and carries it through to a `Settled` status, then separately reproduces a split-mesh double-spend and confirms it's detected and recorded.

```bash
# All tests
cargo test

# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test '*'
```

**Property-based tests** use [`proptest`](https://docs.rs/proptest) (a dev-dependency) to check invariants across a much larger input space than example-based tests reach, for the two most safety-critical pieces of this crate:

- `conflict::detector::detect_conflicts` — for randomly generated batches of `QueuedSlot`s, every reported `Conflict` genuinely shares an (account, sequence) pair with differing message IDs, and no colliding pair is missed. This is cross-checked against a naive O(n²) reference implementation written only for the test (`proptest_detect_conflicts_matches_naive_reference` in `src/conflict/detector.rs`), run over several thousand generated cases.
- `settlement::tracker::SettlementStatus::can_transition_to` — checked exhaustively (not randomly; the state space is small enough that full coverage is stronger) against a hand-written reachability graph, across all 25 `(from, to)` pairs over the 5 `SettlementStatus` variants (`test_settlement_transition_matrix_is_exhaustive` in `src/settlement/tracker.rs`).

These run as part of the normal test suite — no separate command is needed.

### Adversarial Byzantine simulation (`#070`)

`src/sim/` is a seeded simulation harness (stable API for `#049`-style work) plus three pluggable Byzantine agents — forged relay proofs, stale observation replay, and deliberate same-tick races. Same seed ⇒ identical execution trace.

```bash
# Required determinism + regression tests
cargo test --test adversarial_agents_test

# Bounded CI sweep (512 seeds / 60s in GitHub Actions; override locally)
ADVERSARIAL_SWEEP_SEEDS=2000 ADVERSARIAL_SWEEP_BUDGET_SECS=120 \
  cargo test --test adversarial_sweep -- --nocapture
```

The race agent is what surfaced that `detect_conflicts` / `detect_nway_conflicts` used to return `HashMap`-iteration order (insertion-order dependent). Both now sort their output so seeded traces stay reproducible — see `test_race_agent_detect_conflicts_output_is_insertion_order_independent`.

### Fuzz Testing

A [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) target lives in [`fuzz/`](fuzz/) and exercises `rmp_serde::from_slice::<TransactionEnvelope>`, the deserialization path `SyncEngineDb` uses to read queued envelopes back out of SQLite (see `src/storage/db.rs`). Envelope bytes are meant to be ones this crate wrote itself, but corrupted or adversarial input should be rejected with an error, never cause a panic — this matters more once database export/import (for device migration) makes it possible to load a `SyncEngineDb` file from an untrusted source.

The fuzz crate is a separate, detached workspace (`fuzz/Cargo.toml` has its own `[workspace]`), so it does not affect `cargo build`/`cargo test`/`cargo clippy` at the repo root and is not required to run in normal CI.

**Running it locally** (requires the nightly toolchain):
```bash
cargo install cargo-fuzz
rustup install nightly

# Fuzz indefinitely (stop with Ctrl-C); crashing inputs are saved under fuzz/artifacts/
cargo +nightly fuzz run deserialize_envelope
```

**CI-friendly bounded smoke run** — fuzzing indefinitely isn't practical for regular CI, but a short bounded run still catches regressions (e.g. a newly-introduced panic on malformed input) cheaply:
```bash
# Runs for 60 wall-clock seconds, then exits; non-zero exit code means a crash was found
cargo +nightly fuzz run deserialize_envelope -- -max_total_time=60
```

We target a minimum of **85% test coverage** for this repository given its role in guaranteeing funds are never lost or double-spent.

---

## Contributing

This repository especially welcomes contributors with experience in:

- Distributed systems and consensus
- Applied cryptography (signature schemes, proof systems)
- Rust systems programming
- Stellar transaction semantics (sequence numbers, XDR)

The most valuable open problem here is `conflict::resolver` — deterministic, off-chain double-spend resolution. Browse the [Issues](https://github.com/StellarConduit/stellarconduit-sync-engine/issues) tab for current work.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

---

## License

This repository is licensed under the [Apache 2.0 License](LICENSE).

---

<div align="center">

Part of the [StellarConduit](https://github.com/StellarConduit) open-source organization.

**Payments that work everywhere. Even where the internet doesn't.**

</div>
