# Crash-consistency verification findings (#95)

## Setup

`#014` made `enqueue_transaction`'s three-table write (sequence reservation +
queued envelope + initial settlement status) atomic by wrapping it in one
explicit SQLite transaction, and relies on SQLite's own transactional
guarantees for crash safety. Until now that reliance was never verified
empirically: it depended on the underlying filesystem's write/fsync
behavior and the SQLite `journal_mode`/`synchronous` configuration actually
in effect, neither of which this crate checked or controlled.

This work adds:

- **A write-tracing SQLite VFS** (`src/storage/fault_vfs.rs`, `#[cfg(test)]`
  only): wraps SQLite's real default VFS and records every low-level
  `xWrite`/`xTruncate`/`xSync`/`xDelete` call this crate's actual
  `SyncEngineDb` methods issue against the main db file, its rollback
  journal, and its WAL file — while letting every call through unmodified,
  so the traced run always completes normally. This is the same
  "swap-only-`pMethods`" shim technique SQLite's own `vfstrace.c` extension
  uses.
- **A replay engine** (`materialize`/`reordered_prefix` in the same file):
  reconstructs what the on-disk files would look like if a crash landed
  after any prefix of the recorded write sequence, in three fault modes —
  plain **prefix** truncation (SQLite's own `test6.c` crash-test VFS models
  power loss this way), a **torn** final write (25/50/75% applied, modeling
  a torn sector/page write), and a **reordered** adjacent pair within one
  unsynced epoch (modeling a filesystem that reorders writes it had no
  durability barrier between).
- **The sweep** (`src/storage/db/crash_consistency_tests.rs`): for each of
  `enqueue_transaction` and `set_settlement_status`, traces one real call,
  then reopens a materialized "crashed" copy through this crate's own
  *unmodified* `SyncEngineDb::init` recovery path at every crash point in
  all three fault modes, and asserts the result is either exactly the
  pre-operation state, exactly the post-operation state, or an explicit,
  reported open failure — never a silent partial mixture. Both operations
  are swept under **both** `journal_mode=WAL` (this crate's production
  default — see below) and `journal_mode=DELETE` (rollback journal), so the
  sweep isn't only validating one SQLite durability mechanism.

Run it directly with:

```bash
cargo test --lib storage::db::crash_consistency_tests -- --nocapture
```

## Sweep results

| Operation | Journal mode | Events traced | Crash points checked | Outcome |
|---|---|---|---|---|
| `enqueue_transaction` | wal | 15 | 71 | all consistent |
| `enqueue_transaction` | delete | 34 | 160 | all consistent |
| `set_settlement_status` (after fix below) | wal | 11 | 51 | all consistent |
| `set_settlement_status` (after fix below) | delete | 26 | 120 | all consistent |

402 crash points swept in total across both operations and both journal
modes; every one recovered to a state satisfying the operation's atomicity
invariant (or `SyncEngineDb::init` itself failed loudly, which is also an
acceptable outcome — see `test_startup_check_fails_loudly_on_misconfigured_journal_mode`
and the "never silently proceeds" requirement below). `#014`'s
`enqueue_transaction` needed no changes: its explicit `tx.commit()` really
does hold up against truncation, torn writes, and reordering, under both
journal modes.

## Bug found and fixed

**`set_settlement_status` was not transactional.**

Before this fix, `set_settlement_status` executed its `settlement_status`
upsert and its `settlement_history` insert as two separate, independently
autocommitted SQLite statements — no explicit transaction wrapped them
(unlike `enqueue_transaction` and `set_settlement_status_batch`, which both
already did this correctly). Under rollback-journal mode this is easy to
see directly: the first statement's commit fully finishes (journal written,
main db page written, journal deleted) before the second statement even
begins, so the on-disk write trace has a clean boundary between them. A
crash landing exactly there left `settlement_status` already showing the
*new* status while `settlement_history` was missing the entry explaining
how it got there — a real, silent inconsistency between the "current
state" table every read path (`get_settlement_status`,
`SyncEngine::mark_settlement`) trusts and the audit trail
(`SyncEngineDb::history_for`) callers rely on for display and dispute
review. Nothing detected or reported this; it would have shown up only as
a gap in a settlement's history after the fact.

- **Fix**: `src/storage/db.rs`, `SyncEngineDb::set_settlement_status` now
  wraps both statements in one `conn.transaction()` / `tx.commit()`, the
  same pattern `enqueue_transaction` and `set_settlement_status_batch`
  already used.
- **Sweep test**:
  `crash_consistency_tests::test_crash_mid_settlement_transition_leaves_consistent_or_detectably_inconsistent_state`
  (fails against the pre-fix code — every crash point between the two
  statements in rollback-journal mode reproduces the torn state above).
- **Regression test**:
  `crash_consistency_tests::test_regression_settlement_status_and_history_commit_atomically`
  pins the exact mechanism: it asserts the traced call produces exactly one
  journal create/delete cycle (i.e. one commit) and explicitly checks
  consistency on both sides of that boundary, so a future change that
  "simplifies" this back into two bare `execute` calls fails here directly,
  not only as one assertion deep inside the general sweep.

No other real crash-consistency bugs were found in the two operations
issue #95 names. That is reported with the sweep's own data above (402
checked crash points across three fault modes and two journal modes, per
the issue's guidance to treat a clean sweep as something to double check
rather than declare success on) rather than as a bare claim.

## A harness bug along the way (worth recording)

The first two sweep runs found what looked like real torn states in
*both* operations, at crash points corresponding to: (1) the `PRAGMA
journal_mode=...` switch used to force each journal-mode variant onto the
traced connection, and (2) SQLite's own automatic *closing checkpoint*
(closing the last connection to a WAL database checkpoints and deletes the
`-wal` file). Neither is part of what `enqueue_transaction` or
`set_settlement_status` themselves write — a real power loss during either
call never reaches a clean `close()`. The harness now snapshots the
pre-operation baseline and starts recording *after* the pragma switch, and
captures the traced event slice *before* closing the connection, so the
sweep measures exactly the operation under test. This is recorded here
because it's exactly the kind of "harness isn't realistic enough" failure
mode issue #95 warns a suspiciously clean sweep might actually be, and in
this case the first (contaminated) sweep runs were *not* clean — they were
misattributing unrelated connection-lifecycle writes to the operations
under test.

## Required SQLite configuration

See `src/storage/db.rs`'s module docs ("Required SQLite Configuration for
Crash Safety") for the full rationale. In short: **`journal_mode=WAL` +
`synchronous=FULL`**, both applied by `SyncEngineDb::init` and then
**read back to confirm** (SQLite can silently leave `journal_mode=WAL`
unapplied rather than erroring, e.g. on a filesystem without shared-memory
support). If confirmation fails, `init` returns
`SyncEngineError::UnsafeSqliteConfiguration` instead of opening a database
whose crash-safety guarantees can't actually be relied on.
`crate::engine::open_dispatch_connection`'s second, synchronous connection
onto the same file enforces the identical policy via the same
`apply_crash_safety_pragmas`/`read_crash_safety_pragmas`/`check_crash_safety`
functions `SyncEngineDb::init` uses, so the two connections this crate
opens onto one database file can never silently disagree about what "safe"
means. Covered by `test_startup_check_fails_loudly_on_misconfigured_journal_mode`.

## Known residual gaps (not silent)

- **`save_escalation`** writes the `dispute_escalations` row and then makes
  two separate top-level `.await` calls to `set_settlement_status` (for
  each side of the conflict). A crash between the escalation insert and
  either status update leaves a recorded escalation whose envelopes aren't
  yet marked `Disputed`. This spans multiple independent database
  round-trips (not a single connection call `#014`'s pattern or this
  issue's named operations cover) and wasn't in scope here; the same
  write-tracing harness applies directly if this is picked up later.
- **WAL shared-memory (`-shm`) recovery** is exercised only through
  SQLite's own standard rebuild-from-`-wal` path (the harness deletes any
  `-shm` file before every reopen, which is always safe by design — the
  index is fully derivable from the WAL) rather than by injecting faults
  into `-shm` writes directly. The `-shm` file holds no data this crate
  reads back after a restart, so this wasn't considered a priority gap, but
  a `-shm`-targeted sweep is possible future work with this same harness.
- The **reordering** fault mode only swaps the single adjacent pair of
  events immediately preceding each crash point (within one unsynced
  epoch), not a full permutation sweep of every unsynced write — a
  deliberate scope bound (matching `#070`'s adversarial-sweep precedent of
  a bounded, time-budgeted pass rather than exhaustive enumeration) rather
  than an unexamined gap.
