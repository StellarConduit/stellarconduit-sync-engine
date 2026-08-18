# StellarConduit Sync Engine

> The offline transaction queue, sequence-number reservation, durable settlement tracking, and double-spend conflict detection layer for StellarConduit.

This repository sits directly on top of [`stellarconduit-core`](https://github.com/StellarConduit/stellarconduit-core). Where core's job ends at "propagate this signed envelope across the mesh," the sync engine's job starts one step earlier — deciding what to sign and in what order while fully offline — and continues one step later, tracking each envelope through to on-chain settlement (or a detected conflict).

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Modules](#modules)
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
- `resolver`: **the hard, unsolved centerpiece** — deterministic off-chain resolution using timestamps, `RelayChainProof`s, and relay-node consensus. Currently every conflict falls through to `SyncEngineError::UnresolvedConflict`.

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

### Linting and Formatting

Always run these before submitting a pull request:
```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

### Structured Lifecycle Tracing

The envelope lifecycle is instrumented with `tracing` spans keyed by each
envelope's `message_id`. Enable the output while running the mock relay or a
test with `RUST_LOG`:

```bash
RUST_LOG=stellarconduit_sync_engine=info cargo run --example mock_relay
RUST_LOG=stellarconduit_sync_engine::settlement=trace cargo test settlement -- --nocapture
```

For JSON output suitable for external tooling, initialize a
`tracing_subscriber` JSON formatter in the embedding application:

```rust,no_run
tracing_subscriber::fmt()
        .json()
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
```

Filter one `message_id` in the resulting records. The `envelope_state` spans
cover time spent in `queued`, `propagating`, or another settlement state, and
the transition event includes `state_duration_ms`; queue, storage, signing,
and conflict records use the same identifier.

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
