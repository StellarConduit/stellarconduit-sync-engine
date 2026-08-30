//! A write-tracing SQLite VFS used only by the crash-consistency test harness
//! (`crate::storage::crash_consistency_tests`, issue #95).
//!
//! # Why a custom VFS
//!
//! [`SyncEngineDb`](super::db::SyncEngineDb) relies on SQLite's transactional
//! guarantees for crash safety, but that guarantee is only as strong as the
//! underlying filesystem's write/fsync behavior actually is. To verify it
//! empirically (in the spirit of ALICE/CrashMonkey-style crash-consistency
//! testing) we need fine-grained control over exactly which low-level file
//! writes a database operation issued, and the ability to reconstruct what
//! the on-disk file(s) would look like if power had been lost after any
//! prefix of that write sequence — including a torn (partially-applied)
//! final write.
//!
//! This module implements that as a **write-tracing VFS shim**: it wraps
//! SQLite's real default VFS (the standard `unix` VFS under Linux/WSL, where
//! this crate's tests actually run — see the repo's `env_windows_rust_build_
//! blocked` note; native Windows builds are out of scope here) and forwards
//! every I/O call to it unmodified, while additionally recording every
//! `xWrite`/`xTruncate`/`xSync`/`xDelete` call against the files that belong
//! to a database opened through it. The traced database always behaves
//! exactly like an ordinary one — nothing is ever dropped, delayed, or
//! corrupted *live*. The actual power-loss simulation happens afterward,
//! entirely in safe Rust (see [`materialize`]), by replaying a prefix of the
//! recorded events onto a copy of the pre-operation file bytes.
//!
//! This is the same "shim VFS that swaps only `pMethods`" technique SQLite's
//! own extensions use (e.g. `ext/misc/vfstrace.c`): the file object SQLite
//! hands to callers is the *real* OS file object with our vtable substituted
//! in front of it, so uninstrumented operations (locking, WAL shared-memory
//! mapping, temp files) fall through to the genuine implementation with zero
//! behavioral difference.
//!
//! # Scope
//!
//! Only `SQLITE_OPEN_MAIN_DB`, `SQLITE_OPEN_MAIN_JOURNAL`, and
//! `SQLITE_OPEN_WAL` files are traced; everything else (temp files,
//! sub-journals, the `-shm` file) is passed straight through untouched
//! because a crash losing those never threatens the durability contract
//! `SyncEngineDb` documents (they hold no data this crate reads back after a
//! restart — `SyncEngineDb::init` never opens or trusts a stale temp file,
//! and the `-shm` index is rebuilt from the `-wal` file automatically).
//!
//! # `#[cfg(test)]`
//!
//! This entire module is test-only. It adds no unsafe FFI surface, no VFS
//! registration, and no runtime cost to a shipped build of this
//! size-sensitive mobile crate.

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use rusqlite::ffi;

const VFS_NAME_STR: &str = "stellarconduit_fault_tracing_vfs";
const VFS_NAME_C: &CStr = c"stellarconduit_fault_tracing_vfs";

/// Which of a database's on-disk files a recorded [`WriteEvent`] belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FileKind {
    MainDb,
    MainJournal,
    Wal,
}

/// One low-level file-I/O call observed while tracing a database operation,
/// in the exact order SQLite issued it. [`materialize`] replays a prefix of
/// a recorded sequence of these to reconstruct a simulated post-crash file
/// state.
#[derive(Debug, Clone)]
pub(crate) enum WriteEvent {
    Write {
        file: FileKind,
        offset: i64,
        data: Vec<u8>,
    },
    Truncate {
        file: FileKind,
        size: i64,
    },
    /// A durability barrier (`fsync`/`fdatasync`) on some file. Which file
    /// doesn't matter to any consumer today ([`materialize`] is a no-op for
    /// it; [`reordered_prefix`] only needs to know *that* a barrier
    /// occurred to keep a swap within one unsynced epoch) but the event is
    /// still recorded so the trace reflects every I/O call SQLite actually
    /// issued.
    Sync,
    Delete {
        file: FileKind,
    },
}

/// Per-traced-database shared state: an append-only log of every intercepted
/// I/O call. Cheap to clone out via [`FaultController::take_events`] once
/// the traced operation has completed normally.
#[derive(Default)]
pub(crate) struct FaultController {
    events: Mutex<Vec<WriteEvent>>,
}

impl FaultController {
    fn record(&self, event: WriteEvent) {
        self.events.lock().unwrap().push(event);
    }

    pub(crate) fn take_events(&self) -> Vec<WriteEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Number of events recorded so far. Callers that need to trace only
    /// one specific operation (and not e.g. a `PRAGMA journal_mode=...`
    /// switch issued on the same connection right after opening it) should
    /// snapshot this before that operation and slice `take_events()` from
    /// it, rather than assume the very first recorded event belongs to the
    /// operation under test.
    pub(crate) fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

static REGISTRY: OnceLock<Mutex<HashMap<String, Arc<FaultController>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<String, Arc<FaultController>>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a fresh [`FaultController`] for `base_path` (the plain
/// filesystem path of the main database file, with no `file:` scheme or
/// query string) and return it. Call [`unregister_controller`] once done to
/// keep the process-wide registry from growing across a whole test run.
pub(crate) fn register_controller(base_path: &str) -> Arc<FaultController> {
    ensure_vfs_registered();
    let controller = Arc::new(FaultController::default());
    registry()
        .lock()
        .unwrap()
        .insert(base_path.to_string(), controller.clone());
    controller
}

pub(crate) fn unregister_controller(base_path: &str) {
    if let Some(reg) = REGISTRY.get() {
        reg.lock().unwrap().remove(base_path);
    }
}

/// Build the SQLite URI `SyncEngineDb::init` (or any `rusqlite`/
/// `tokio_rusqlite` open call using the crate's default `SQLITE_OPEN_URI`
/// flag) should be given to route through this tracing VFS for `base_path`.
pub(crate) fn trace_uri(base_path: &str) -> String {
    ensure_vfs_registered();
    format!("file:{base_path}?vfs={VFS_NAME_STR}")
}

// ── VFS registration ────────────────────────────────────────────────────

static REAL_VFS: AtomicPtr<ffi::sqlite3_vfs> = AtomicPtr::new(ptr::null_mut());
static VFS_REGISTERED: OnceLock<()> = OnceLock::new();

fn ensure_vfs_registered() {
    VFS_REGISTERED.get_or_init(|| unsafe {
        let real = ffi::sqlite3_vfs_find(ptr::null());
        assert!(!real.is_null(), "no default SQLite VFS is registered");
        REAL_VFS.store(real, Ordering::SeqCst);

        // Struct-copy every field from the real VFS (locking, randomness,
        // sleep, current-time, dlopen shims, ...) and then override only
        // zName/xOpen/xDelete. Every uninstrumented field keeps behaving
        // exactly like the real VFS because it *is* the real VFS's function
        // pointer, just reached through our copy of the struct.
        let mut vfs: ffi::sqlite3_vfs = ptr::read(real);
        vfs.szOsFile += std::mem::size_of::<FiFileExtra>() as c_int;
        vfs.zName = VFS_NAME_C.as_ptr();
        vfs.pNext = ptr::null_mut();
        vfs.xOpen = Some(fi_open);
        vfs.xDelete = Some(fi_delete);

        let leaked: &'static mut ffi::sqlite3_vfs = Box::leak(Box::new(vfs));
        let rc = ffi::sqlite3_vfs_register(leaked as *mut ffi::sqlite3_vfs, 0);
        assert_eq!(rc, ffi::SQLITE_OK, "failed to register fault-tracing VFS");
    });
}

// ── Per-file extra state, appended after the real VFS's own file struct ───

struct FiFileExtra {
    real_methods: *const ffi::sqlite3_io_methods,
    /// Owned; freed in `fi_close`.
    my_methods: *mut ffi::sqlite3_io_methods,
    controller: Option<Arc<FaultController>>,
    kind: Option<FileKind>,
}

unsafe fn real_vfs() -> *mut ffi::sqlite3_vfs {
    REAL_VFS.load(Ordering::SeqCst)
}

unsafe fn extra_ptr(file: *mut ffi::sqlite3_file) -> *mut FiFileExtra {
    let off = (*real_vfs()).szOsFile as usize;
    (file as *mut u8).add(off) as *mut FiFileExtra
}

/// Recover the plain base path (no `file:` scheme, no query string, no
/// `-journal`/`-wal` suffix) an opened file belongs to, so it can be looked
/// up in [`registry`]. Returns `None` for file kinds this shim doesn't trace
/// (temp files, sub-journals, `-shm`, ...).
fn classify_open(z_name: Option<&str>, flags: c_int) -> (Option<FileKind>, Option<String>) {
    if flags & ffi::SQLITE_OPEN_MAIN_DB != 0 {
        let base = z_name.map(|s| {
            let no_scheme = s.strip_prefix("file:").unwrap_or(s);
            no_scheme
                .split(['?', '#'])
                .next()
                .unwrap_or(no_scheme)
                .to_string()
        });
        (Some(FileKind::MainDb), base)
    } else if flags & ffi::SQLITE_OPEN_MAIN_JOURNAL != 0 {
        let base = z_name
            .and_then(|s| s.strip_suffix("-journal"))
            .map(str::to_string);
        (Some(FileKind::MainJournal), base)
    } else if flags & ffi::SQLITE_OPEN_WAL != 0 {
        let base = z_name
            .and_then(|s| s.strip_suffix("-wal"))
            .map(str::to_string);
        (Some(FileKind::Wal), base)
    } else {
        (None, None)
    }
}

/// Same idea as [`classify_open`] but for `xDelete`, which is a VFS-level
/// call (filename only, no open file and no flags) — SQLite deletes the
/// rollback journal this way once a transaction commits.
fn classify_delete(z_name: &str) -> (FileKind, Option<String>) {
    if let Some(base) = z_name.strip_suffix("-journal") {
        (FileKind::MainJournal, Some(base.to_string()))
    } else if let Some(base) = z_name.strip_suffix("-wal") {
        (FileKind::Wal, Some(base.to_string()))
    } else {
        (FileKind::MainDb, Some(z_name.to_string()))
    }
}

fn lookup(base: &Option<String>) -> Option<Arc<FaultController>> {
    let base = base.as_ref()?;
    registry().lock().unwrap().get(base).cloned()
}

// ── VFS-level xOpen / xDelete ──────────────────────────────────────────

unsafe extern "C" fn fi_open(
    _vfs: *mut ffi::sqlite3_vfs,
    z_name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    let real = real_vfs();
    let real_xopen = match (*real).xOpen {
        Some(f) => f,
        None => return ffi::SQLITE_ERROR,
    };

    let rc = real_xopen(real, z_name, file, flags, out_flags);
    if rc != ffi::SQLITE_OK {
        return rc;
    }

    let real_methods = (*file).pMethods;
    let name_str: Option<String> = if z_name.is_null() {
        None
    } else {
        CStr::from_ptr(z_name).to_str().ok().map(str::to_string)
    };
    let (kind, base) = classify_open(name_str.as_deref(), flags);
    let controller = if kind.is_some() { lookup(&base) } else { None };

    let mut my_methods: ffi::sqlite3_io_methods = ptr::read(real_methods);
    my_methods.xWrite = Some(fi_write);
    my_methods.xTruncate = Some(fi_truncate);
    my_methods.xSync = Some(fi_sync);
    my_methods.xClose = Some(fi_close);
    let my_methods_ptr = Box::into_raw(Box::new(my_methods));

    let extra = extra_ptr(file);
    ptr::write(
        extra,
        FiFileExtra {
            real_methods,
            my_methods: my_methods_ptr,
            controller,
            kind,
        },
    );
    (*file).pMethods = my_methods_ptr;

    ffi::SQLITE_OK
}

unsafe extern "C" fn fi_delete(
    vfs: *mut ffi::sqlite3_vfs,
    z_name: *const c_char,
    sync_dir: c_int,
) -> c_int {
    let _ = vfs;
    if !z_name.is_null() {
        if let Ok(name) = CStr::from_ptr(z_name).to_str() {
            let (kind, base) = classify_delete(name);
            if let Some(ctrl) = lookup(&base) {
                ctrl.record(WriteEvent::Delete { file: kind });
            }
        }
    }
    let real = real_vfs();
    match (*real).xDelete {
        Some(f) => f(real, z_name, sync_dir),
        None => ffi::SQLITE_IOERR_DELETE,
    }
}

// ── Per-file xWrite / xTruncate / xSync / xClose ───────────────────────

unsafe extern "C" fn fi_write(
    file: *mut ffi::sqlite3_file,
    buf: *const c_void,
    amt: c_int,
    offset: ffi::sqlite3_int64,
) -> c_int {
    let extra = extra_ptr(file);
    if let (Some(ctrl), Some(kind)) = (&(*extra).controller, (*extra).kind) {
        let slice = std::slice::from_raw_parts(buf as *const u8, amt.max(0) as usize);
        ctrl.record(WriteEvent::Write {
            file: kind,
            offset,
            data: slice.to_vec(),
        });
    }
    match (*(*extra).real_methods).xWrite {
        Some(f) => f(file, buf, amt, offset),
        None => ffi::SQLITE_IOERR_WRITE,
    }
}

unsafe extern "C" fn fi_truncate(file: *mut ffi::sqlite3_file, size: ffi::sqlite3_int64) -> c_int {
    let extra = extra_ptr(file);
    if let (Some(ctrl), Some(kind)) = (&(*extra).controller, (*extra).kind) {
        ctrl.record(WriteEvent::Truncate { file: kind, size });
    }
    match (*(*extra).real_methods).xTruncate {
        Some(f) => f(file, size),
        None => ffi::SQLITE_IOERR_TRUNCATE,
    }
}

unsafe extern "C" fn fi_sync(file: *mut ffi::sqlite3_file, flags: c_int) -> c_int {
    let extra = extra_ptr(file);
    if let (Some(ctrl), Some(_kind)) = (&(*extra).controller, (*extra).kind) {
        ctrl.record(WriteEvent::Sync);
    }
    match (*(*extra).real_methods).xSync {
        Some(f) => f(file, flags),
        None => ffi::SQLITE_OK,
    }
}

unsafe extern "C" fn fi_close(file: *mut ffi::sqlite3_file) -> c_int {
    let extra = extra_ptr(file);
    let real_methods = (*extra).real_methods;
    let my_methods_ptr = (*extra).my_methods;

    let rc = match (*real_methods).xClose {
        Some(f) => f(file),
        None => ffi::SQLITE_OK,
    };

    ptr::drop_in_place(extra);
    if !my_methods_ptr.is_null() {
        drop(Box::from_raw(my_methods_ptr));
    }

    rc
}

// ── Replay: reconstruct a simulated post-crash file state ─────────────

/// Reconstruct what each traced file's bytes would be if a crash landed
/// after exactly `crash_after` of `events` had reached disk (a prefix of
/// the real, in-order write sequence — SQLite's own crash-test VFS
/// (`test6.c`'s "crashtest") uses this same "N writes survive, the rest are
/// lost" model, which corresponds to a filesystem that preserves write
/// order but loses everything after an arbitrary cut).
///
/// When `torn_bytes` is `Some(t)`, the *last* surviving event (if it is a
/// [`WriteEvent::Write`]) is applied with only its first `t` bytes, modeling
/// a torn sector/page write instead of a clean cut between two writes.
///
/// `baseline` seeds each file's starting bytes (the state on disk
/// immediately before the traced operation began — typically only
/// [`FileKind::MainDb`] is present, since the journal/WAL file does not
/// exist until the operation starts writing to it).
pub(crate) fn materialize(
    baseline: &HashMap<FileKind, Vec<u8>>,
    events: &[WriteEvent],
    crash_after: usize,
    torn_bytes: Option<usize>,
) -> HashMap<FileKind, Vec<u8>> {
    let mut files = baseline.clone();
    let apply_count = crash_after.min(events.len());

    for (i, ev) in events.iter().take(apply_count).enumerate() {
        let is_last = i + 1 == apply_count;
        match ev {
            WriteEvent::Write { file, offset, data } => {
                let data: &[u8] = if is_last {
                    match torn_bytes {
                        Some(t) => &data[..t.min(data.len())],
                        None => data,
                    }
                } else {
                    data
                };
                let buf = files.entry(*file).or_default();
                let start = (*offset).max(0) as usize;
                let end = start + data.len();
                if buf.len() < end {
                    buf.resize(end, 0);
                }
                buf[start..end].copy_from_slice(data);
            }
            WriteEvent::Truncate { file, size } => {
                let buf = files.entry(*file).or_default();
                buf.resize((*size).max(0) as usize, 0);
            }
            WriteEvent::Sync => {}
            WriteEvent::Delete { file } => {
                files.remove(file);
            }
        }
    }

    files
}

/// Apply an adjacent-pair swap to the two [`WriteEvent`]s issued
/// immediately before `crash_after`, if both fall in the same "epoch"
/// (i.e. no [`WriteEvent::Sync`] separates them) — simulating a filesystem
/// that reorders two writes it had no durability barrier between. Returns
/// `events` unchanged (cloned) if there is no such eligible pair.
pub(crate) fn reordered_prefix(events: &[WriteEvent], crash_after: usize) -> Vec<WriteEvent> {
    let mut out = events.to_vec();
    let n = crash_after.min(out.len());
    if n < 2 {
        return out;
    }
    let (a, b) = (n - 2, n - 1);
    let same_epoch = !matches!(out[a], WriteEvent::Sync) && !matches!(out[b], WriteEvent::Sync);
    if same_epoch {
        out.swap(a, b);
    }
    out
}
