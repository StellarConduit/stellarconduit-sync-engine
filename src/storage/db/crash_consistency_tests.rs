//! Crash-consistency verification for the SQLite-backed queue (issue #95).
//!
//! This uses the write-tracing VFS in `crate::storage::fault_vfs` to record
//! every low-level file write a real [`SyncEngineDb`] write operation
//! issues, then replays prefixes (plain, torn, and reordered) of that trace
//! onto a copy of the pre-operation file bytes to simulate a power loss at
//! every meaningfully distinct point in the operation — and checks that
//! reopening the result through this crate's *real*, unmodified recovery
//! path ([`SyncEngineDb::init`]) always yields either the fully-pre-write
//! state, the fully-post-write state, or an explicit, reported open failure
//! — never a silently torn mixture of the two.
//!
//! See `docs/CRASH_CONSISTENCY_FINDINGS.md` for the sweep results and the
//! real bug this found and fixed (`set_settlement_status` was not
//! transactional).

use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use tempfile::TempDir;

use super::*;
use crate::storage::fault_vfs::{self, FileKind, WriteEvent};

fn mock_envelope(message_id: u8) -> TransactionEnvelope {
    TransactionEnvelope {
        message_id: [message_id; 32],
        origin_pubkey: [1u8; 32],
        tx_xdr: "mock_xdr".to_string(),
        ttl_hops: 10,
        timestamp: 1_700_000_000,
        signature: [0u8; 64],
    }
}

// ── File snapshot / restore helpers ────────────────────────────────────

fn snapshot_files(base_path: &str) -> HashMap<FileKind, Vec<u8>> {
    let mut map = HashMap::new();
    if let Ok(bytes) = std::fs::read(base_path) {
        map.insert(FileKind::MainDb, bytes);
    }
    if let Ok(bytes) = std::fs::read(format!("{base_path}-journal")) {
        map.insert(FileKind::MainJournal, bytes);
    }
    if let Ok(bytes) = std::fs::read(format!("{base_path}-wal")) {
        map.insert(FileKind::Wal, bytes);
    }
    map
}

fn write_files(base_path: &str, files: &HashMap<FileKind, Vec<u8>>) {
    let journal = format!("{base_path}-journal");
    let wal = format!("{base_path}-wal");
    let shm = format!("{base_path}-shm");
    let _ = std::fs::remove_file(&journal);
    let _ = std::fs::remove_file(&wal);
    let _ = std::fs::remove_file(&shm);
    let _ = std::fs::remove_file(base_path);

    for (kind, bytes) in files {
        let path = match kind {
            FileKind::MainDb => base_path.to_string(),
            FileKind::MainJournal => journal.clone(),
            FileKind::Wal => wal.clone(),
        };
        std::fs::write(&path, bytes).unwrap();
    }
}

// ── Tracing a real operation ────────────────────────────────────────────

struct Trace {
    base_path: String,
    baseline: HashMap<FileKind, Vec<u8>>,
    events: Vec<WriteEvent>,
}

/// Create `base_path`'s schema (via a plain, untraced connection forced onto
/// `journal_mode`), snapshot the resulting bytes as the pre-operation
/// baseline, then reopen through the fault-tracing VFS (still forced onto
/// the same `journal_mode`) and run `enqueue_transaction` — the exact
/// method [`SyncEngine::queue_payment`](crate::engine::SyncEngine::queue_payment)
/// calls, and the operation issue #95 names as "envelope enqueue".
async fn trace_enqueue_transaction(dir: &Path, journal_mode: &str) -> Trace {
    let base_path = dir
        .join(format!("enqueue-{journal_mode}.sqlite3"))
        .to_str()
        .unwrap()
        .to_string();

    {
        let db = SyncEngineDb::init(&base_path).await.unwrap();
        db.close_for_test().await.unwrap();
    }

    let controller = fault_vfs::register_controller(&base_path);
    let uri = fault_vfs::trace_uri(&base_path);
    let start;
    let baseline;
    let events;
    {
        let db = SyncEngineDb::init(&uri).await.unwrap();
        db.force_pragma_for_test(&format!("PRAGMA journal_mode={journal_mode};"))
            .await
            .unwrap();
        // Only trace (and only baseline-snapshot before) the operation
        // under test itself -- the pragma switch above (needed to force
        // this connection onto `journal_mode`, since `SyncEngineDb::init`
        // always applies the production default first) issues its own
        // writes that have nothing to do with `enqueue_transaction` and
        // must not be mistaken for part of it, nor left out of the
        // baseline it will be replayed on top of.
        start = controller.event_count();
        baseline = snapshot_files(&base_path);
        db.enqueue_transaction(&mock_envelope(1), "GABC", 101, TxPriority::Normal, 1000)
            .await
            .unwrap();
        // Capture the trace *before* closing: closing the last connection
        // to a WAL database triggers SQLite's own automatic closing
        // checkpoint (writing WAL frames back into the main db file, then
        // truncating and deleting the WAL) -- a real, but entirely
        // separate, operation with its own crash-safety properties, not
        // part of what `enqueue_transaction` itself writes. A real power
        // loss during `enqueue_transaction` never reaches a clean close at
        // all, so including it here would test the wrong thing.
        events = controller.take_events()[start..].to_vec();
        db.close_for_test().await.unwrap();
    }
    fault_vfs::unregister_controller(&base_path);

    Trace {
        base_path,
        baseline,
        events,
    }
}

/// Same shape as [`trace_enqueue_transaction`], but seeds an initial
/// `Queued` status (one settlement_history row) during baseline setup and
/// traces a `Queued -> Propagating` call to `set_settlement_status` — the
/// "settlement state transitions" operation issue #95 names, and exactly
/// what [`SyncEngine::mark_settlement`](crate::engine::SyncEngine::mark_settlement)
/// calls.
async fn trace_settlement_transition(dir: &Path, journal_mode: &str) -> Trace {
    let base_path = dir
        .join(format!("settlement-{journal_mode}.sqlite3"))
        .to_str()
        .unwrap()
        .to_string();
    let id = [7u8; 32];

    {
        let db = SyncEngineDb::init(&base_path).await.unwrap();
        db.set_settlement_status(id, SettlementStatus::Queued, 1000)
            .await
            .unwrap();
        db.close_for_test().await.unwrap();
    }

    let controller = fault_vfs::register_controller(&base_path);
    let uri = fault_vfs::trace_uri(&base_path);
    let start;
    let baseline;
    let events;
    {
        let db = SyncEngineDb::init(&uri).await.unwrap();
        db.force_pragma_for_test(&format!("PRAGMA journal_mode={journal_mode};"))
            .await
            .unwrap();
        // See `trace_enqueue_transaction`'s comments: exclude both the
        // pragma switch and the automatic closing checkpoint from the
        // trace, so only `set_settlement_status`'s own writes are swept.
        start = controller.event_count();
        baseline = snapshot_files(&base_path);
        db.set_settlement_status(id, SettlementStatus::Propagating, 1001)
            .await
            .unwrap();
        events = controller.take_events()[start..].to_vec();
        db.close_for_test().await.unwrap();
    }
    fault_vfs::unregister_controller(&base_path);

    Trace {
        base_path,
        baseline,
        events,
    }
}

// ── Post-crash consistency assertions ──────────────────────────────────

type AssertFn = for<'a> fn(&'a SyncEngineDb, &'a str) -> Pin<Box<dyn Future<Output = ()> + 'a>>;

async fn assert_enqueue_transaction_consistent(db: &SyncEngineDb, description: &str) {
    let envelope = db.get_queued_envelope([1u8; 32]).await.unwrap();
    let status = db.get_settlement_status([1u8; 32]).await.unwrap();
    let reservation = db.load_sequence_reservation("GABC").await.unwrap();

    let all_absent = envelope.is_none() && status.is_none() && reservation.is_none();
    let all_present =
        envelope.is_some() && status == Some(SettlementStatus::Queued) && reservation == Some(101);

    assert!(
        all_absent || all_present,
        "{description}: enqueue_transaction left a TORN state -- \
         envelope_present={} status={:?} reservation={:?} (must be either \
         fully absent -- pre-crash -- or fully present -- post-crash)",
        envelope.is_some(),
        status,
        reservation,
    );
}

fn assert_enqueue_boxed<'a>(
    db: &'a SyncEngineDb,
    description: &'a str,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(assert_enqueue_transaction_consistent(db, description))
}

async fn assert_settlement_transition_consistent(db: &SyncEngineDb, description: &str) {
    let id = [7u8; 32];
    let status = db.get_settlement_status(id).await.unwrap();
    let history = db.history_for(id).await.unwrap();

    let pre_state = status == Some(SettlementStatus::Queued) && history.len() == 1;
    let post_state = status == Some(SettlementStatus::Propagating)
        && history.len() == 2
        && history[1].from_status == "queued"
        && history[1].to_status == "propagating";

    assert!(
        pre_state || post_state,
        "{description}: set_settlement_status left a TORN state -- \
         status={:?} history_len={} (the status row and its settlement_history \
         entry must commit atomically, or neither must)",
        status,
        history.len(),
    );
}

fn assert_settlement_boxed<'a>(
    db: &'a SyncEngineDb,
    description: &'a str,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(assert_settlement_transition_consistent(db, description))
}

// ── Sweep driver ────────────────────────────────────────────────────────

#[derive(Default, Debug)]
struct SweepStats {
    total: usize,
    recovered: usize,
    rejected_at_open: usize,
}

async fn check_materialized(
    base_path: &str,
    files: HashMap<FileKind, Vec<u8>>,
    assert_fn: AssertFn,
    label: String,
    stats: &mut SweepStats,
) {
    write_files(base_path, &files);
    stats.total += 1;
    match SyncEngineDb::init(base_path).await {
        // An explicit open failure is a *reported* inconsistency, not a
        // silent one -- an acceptable recovery outcome per issue #95's
        // acceptance criteria.
        Err(_) => stats.rejected_at_open += 1,
        Ok(db) => {
            assert_fn(&db, &label).await;
            stats.recovered += 1;
        }
    }
}

/// Sweep every crash point in `events`, in three fault modes:
/// - **prefix**: the first `crash_after` events landed on disk, the rest
///   were lost (SQLite's own crash-test VFS, `test6.c`, models power loss
///   this way).
/// - **torn**: like prefix, but the last surviving event (if a write) is
///   only partially applied (25/50/75%), modeling a torn sector/page write.
/// - **reordered**: the last two events before the crash point are swapped
///   if no sync barrier separates them, modeling a filesystem that
///   reorders unsynced writes.
async fn run_crash_sweep(trace: &Trace, assert_fn: AssertFn) -> SweepStats {
    let mut stats = SweepStats::default();
    let events = &trace.events;

    if std::env::var("CRASH_DEBUG").is_ok() {
        eprintln!("[crash-debug] {} events:", events.len());
        for (i, ev) in events.iter().enumerate() {
            match ev {
                WriteEvent::Write { file, offset, data } => eprintln!(
                    "  [{i}] Write {{ file: {file:?}, offset: {offset}, len: {} }}",
                    data.len()
                ),
                other => eprintln!("  [{i}] {other:?}"),
            }
        }
    }

    for crash_after in 0..=events.len() {
        let files = fault_vfs::materialize(&trace.baseline, events, crash_after, None);
        check_materialized(
            &trace.base_path,
            files,
            assert_fn,
            format!("prefix crash_after={crash_after}/{}", events.len()),
            &mut stats,
        )
        .await;

        if crash_after >= 1 {
            if let WriteEvent::Write { data, .. } = &events[crash_after - 1] {
                let len = data.len();
                if len >= 2 {
                    for pct in [25usize, 50, 75] {
                        let t = (len * pct / 100).clamp(1, len - 1);
                        let files =
                            fault_vfs::materialize(&trace.baseline, events, crash_after, Some(t));
                        check_materialized(
                            &trace.base_path,
                            files,
                            assert_fn,
                            format!("torn crash_after={crash_after} bytes={t}/{len}"),
                            &mut stats,
                        )
                        .await;
                    }
                }
            }
        }

        let reordered = fault_vfs::reordered_prefix(events, crash_after);
        let files = fault_vfs::materialize(&trace.baseline, &reordered, crash_after, None);
        check_materialized(
            &trace.base_path,
            files,
            assert_fn,
            format!("reordered crash_after={crash_after}"),
            &mut stats,
        )
        .await;
    }

    stats
}

// ── Required tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_crash_mid_envelope_enqueue_leaves_consistent_or_detectably_inconsistent_state() {
    for journal_mode in ["wal", "delete"] {
        let dir = TempDir::new().unwrap();
        let trace = trace_enqueue_transaction(dir.path(), journal_mode).await;
        assert!(
            !trace.events.is_empty(),
            "harness recorded zero write events for journal_mode={journal_mode} -- \
             the sweep below would trivially pass without checking anything"
        );

        let stats = run_crash_sweep(&trace, assert_enqueue_boxed).await;
        eprintln!(
            "[crash-sweep] enqueue_transaction ({journal_mode}): {} events traced, \
             {} crash points checked ({} recovered + consistent, {} rejected at open)",
            trace.events.len(),
            stats.total,
            stats.recovered,
            stats.rejected_at_open
        );
    }
}

#[tokio::test]
async fn test_crash_mid_settlement_transition_leaves_consistent_or_detectably_inconsistent_state() {
    for journal_mode in ["wal", "delete"] {
        let dir = TempDir::new().unwrap();
        let trace = trace_settlement_transition(dir.path(), journal_mode).await;
        assert!(
            !trace.events.is_empty(),
            "harness recorded zero write events for journal_mode={journal_mode} -- \
             the sweep below would trivially pass without checking anything"
        );

        let stats = run_crash_sweep(&trace, assert_settlement_boxed).await;
        eprintln!(
            "[crash-sweep] set_settlement_status ({journal_mode}): {} events traced, \
             {} crash points checked ({} recovered + consistent, {} rejected at open)",
            trace.events.len(),
            stats.total,
            stats.recovered,
            stats.rejected_at_open
        );
    }
}

#[tokio::test]
async fn test_startup_check_fails_loudly_on_misconfigured_journal_mode() {
    // Simulate a runtime where `PRAGMA journal_mode=WAL` silently failed to
    // take effect (SQLite does this -- e.g. on a filesystem without
    // shared-memory support -- rather than erroring) by putting a
    // connection deliberately on the wrong mode and running it through the
    // exact policy check `SyncEngineDb::init` enforces on every non-memory
    // open.
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("misconfigured.sqlite3");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=NORMAL;")
        .unwrap();

    let (journal_mode, synchronous) = read_crash_safety_pragmas(&conn).unwrap();
    let result = check_crash_safety(&journal_mode, synchronous);

    match result {
        Err(SyncEngineError::UnsafeSqliteConfiguration {
            journal_mode,
            required_journal_mode,
            synchronous,
            required_synchronous,
        }) => {
            assert_eq!(journal_mode, "delete");
            assert_eq!(required_journal_mode, "wal");
            assert_eq!(synchronous, 1); // NORMAL
            assert_eq!(required_synchronous, 2); // FULL
        }
        other => panic!("expected UnsafeSqliteConfiguration, got {other:?}"),
    }

    // This test asserts the exact policy function `SyncEngineDb::init` calls
    // (`read_crash_safety_pragmas` + `check_crash_safety`) rather than going
    // through `init` itself: `init` always *re-applies* WAL on open, which
    // would just silently correct this deliberately-misconfigured file
    // rather than exercise the failure path. Every other test in this
    // module already covers the passing case end-to-end, since they all
    // open successfully through `SyncEngineDb::init`.
    drop(conn);
}

/// Regression test for the real bug this issue's sweep found: prior to this
/// fix, `set_settlement_status` executed its `settlement_status` upsert and
/// its `settlement_history` insert as two separate, independently-committed
/// SQLite statements (no explicit transaction). Under rollback-journal
/// mode this is trivial to demonstrate directly: statement 1's commit fully
/// finishes (journal written, main db written, journal deleted) before
/// statement 2 even begins, so the write trace has a clean boundary between
/// them -- crashing exactly there left `settlement_status` already showing
/// the new status with `settlement_history` still one entry short, a real,
/// silent (no error surfaced anywhere) inconsistency between the "current
/// state" table and the audit trail callers rely on
/// (`SyncEngineDb::history_for`). See `docs/CRASH_CONSISTENCY_FINDINGS.md`.
///
/// This test pins that specific crash point (rather than relying only on
/// the general sweep above) so a future regression -- e.g. someone
/// "simplifying" `set_settlement_status` back into two bare `execute` calls
/// -- fails here with a direct, readable explanation instead of only as an
/// opaque assertion deep inside a 100+-iteration sweep.
#[tokio::test]
async fn test_regression_settlement_status_and_history_commit_atomically() {
    let dir = TempDir::new().unwrap();
    let trace = trace_settlement_transition(dir.path(), "delete").await;

    // Locate the boundary between the two logical writes: the event right
    // after the journal file for the *first* completed autocommit
    // statement is deleted (rollback-journal's commit finalization step),
    // and before any further write begins. If `set_settlement_status` is
    // atomic (one transaction), no such "commit, then more writes, then a
    // second commit" shape exists in the trace at all.
    let mut journal_deletes: Vec<usize> = Vec::new();
    for (i, ev) in trace.events.iter().enumerate() {
        if matches!(
            ev,
            WriteEvent::Delete {
                file: FileKind::MainJournal
            }
        ) {
            journal_deletes.push(i + 1);
        }
    }

    assert_eq!(
        journal_deletes.len(),
        1,
        "set_settlement_status must commit in exactly one rollback-journal \
         transaction (one journal create/delete cycle for the whole call); \
         trace had {} -- this is the exact shape of the original bug \
         (two separate autocommit statements) if it is ever reintroduced",
        journal_deletes.len(),
    );

    // With exactly one commit cycle, the crash point that exposed the
    // original bug (mid-way through the *second* statement in the old,
    // non-transactional code) can no longer occur: every prefix of this
    // trace either predates the single commit (pre-state) or postdates it
    // (post-state). Confirm that explicitly at the boundary itself and on
    // both sides of it.
    let boundary = journal_deletes[0];
    for crash_after in [
        boundary.saturating_sub(1),
        boundary,
        (boundary + 1).min(trace.events.len()),
    ] {
        let files = fault_vfs::materialize(&trace.baseline, &trace.events, crash_after, None);
        write_files(&trace.base_path, &files);
        match SyncEngineDb::init(&trace.base_path).await {
            Err(_) => {}
            Ok(db) => {
                assert_settlement_transition_consistent(
                    &db,
                    &format!("regression boundary crash_after={crash_after}"),
                )
                .await;
            }
        }
    }
}
