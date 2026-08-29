//! C-compatible Foreign Function Interface for mobile wallets (Android/
//! Kotlin, iOS/Swift) embedding this crate.
//!
//! ## Binding approach
//!
//! Hand-rolled `#[no_mangle] extern "C"` functions, matching
//! `stellarconduit-core`'s existing `src/ffi.rs` (`sc_generate_identity`,
//! `sc_create_envelope`, `sc_free_string`, `sc_free_bytes`) rather than
//! introducing `uniffi` — consistency with the established org-wide pattern
//! matters more here than `uniffi`'s reduced boilerplate, since the mobile
//! team already has to write Kotlin/Swift glue against core's C ABI and
//! having two different binding styles across the two crates linked into the
//! same mobile binary would just make their integration work harder for no
//! real benefit.
//!
//! Functions here are prefixed `sse_` (StellarConduit Sync Engine) rather
//! than reusing core's `sc_` prefix, so the exported C symbols cannot
//! collide when both `libstellarconduit_core` and
//! `libstellarconduit_sync_engine` are linked into one mobile binary (a
//! single Android `.so` or a single iOS static archive).
//!
//! One deliberate departure from core's `ffi.rs`: core's current functions
//! do **not** wrap their bodies in `std::panic::catch_unwind`, even though a
//! panic unwinding across an `extern "C"` boundary is undefined behavior.
//! This module follows issue #24's explicit acceptance criteria (no panics
//! across the boundary under *any* input, tested explicitly) rather than
//! that gap in core — every entry point below is wrapped in `catch_unwind`.
//! Hardening core's `ffi.rs` the same way is a reasonable follow-up but is a
//! change to a different repository and out of scope here.
//!
//! ## Bridging async to a synchronous FFI call
//!
//! This crate's [`crate::engine::SyncEngine`] and [`crate::storage`] layer
//! are `async` throughout (backed by `tokio-rusqlite`), but FFI functions
//! must be plain synchronous `extern "C" fn`s callable from Kotlin/Swift,
//! which have no notion of a Rust `Future`. Each FFI call drives the
//! necessary `async` work to completion with `Runtime::block_on` against a
//! single, lazily-initialized, **current-thread** Tokio runtime shared by
//! every call in the process (see [`runtime`] below).
//!
//! Current-thread rather than multi-threaded is a deliberate choice, not
//! just the smaller default: `Runtime::block_on` does not require the future
//! it drives to be `Send`, only `Runtime::spawn` does. A current-thread
//! runtime lets `block_on` run the engine's async methods directly on the
//! calling (mobile-side) thread without needing `SyncEngine` or its
//! `tokio_rusqlite::Connection` to satisfy `Send + 'static` spawn bounds, and
//! without spinning up a worker thread pool this FFI layer has no use for —
//! `tokio-rusqlite` already owns a dedicated background OS thread per
//! connection for the actual blocking SQLite calls, so the async side here
//! is just awaiting that connection's response channel. This is also exactly
//! the runtime flavor this crate's own `#[tokio::test]` functions already
//! use by default, so the async behavior exercised here matches what's
//! already tested elsewhere in the crate.
//!
//! **Every `sse_*` call below blocks the calling thread until the underlying
//! database operation completes.** Mobile bindings must invoke these from a
//! background thread/coroutine (e.g. Kotlin `Dispatchers.IO`, Swift
//! `DispatchQueue.global()`), never the UI thread — see the example
//! snippets below.
//!
//! ## Memory ownership across the boundary
//!
//! - **Handles** (`*mut SseEngineHandle`, returned by [`sse_engine_open`]):
//!   heap-allocated by Rust via `Box::into_raw`, owned by the caller from
//!   that point on. The caller must pass it to [`sse_engine_close`] exactly
//!   once when done; using it afterward, or closing it twice, is a
//!   use-after-free / double-free, exactly as with any other C handle.
//! - **Strings** returned by [`sse_queue_payment`], [`sse_settlement_status`],
//!   and [`sse_list_unresolved_conflicts`]: heap-allocated by Rust via
//!   `CString::into_raw`, owned by the caller. Free each one exactly once
//!   with [`sse_free_string`]. Never free them with the platform's own
//!   `free()` — they were allocated by Rust's allocator, and freeing across
//!   allocators is undefined behavior.
//! - **Strings passed in** (`*const c_char` parameters): borrowed only for
//!   the duration of the call. This module never retains, mutates, or frees
//!   a caller-supplied pointer; the caller retains ownership and may free it
//!   immediately after the call returns.
//! - **`SseEngineHandle`** is `Send`/`Sync` (an internal `std::sync::Mutex`
//!   serializes access to the wrapped `SyncEngine`), so it is safe to call
//!   `sse_*` functions against the same handle from multiple native threads
//!   concurrently — calls simply queue on the lock. If a panic is ever
//!   caught while the lock is held, the `Mutex` becomes poisoned by design:
//!   every subsequent call against that handle safely fails (returns
//!   null/`false`) rather than risk operating on a `SyncEngine` whose
//!   in-memory state might have desynced from durable storage mid-panic.
//!   Close the handle with [`sse_engine_close`] and reopen a fresh one via
//!   [`sse_engine_open`] to recover.
//!
//! ## Never panics across the boundary
//!
//! Every function's body runs inside `std::panic::catch_unwind`; a caught
//! panic is converted into the same "failure" return value (null pointer /
//! `false`) as an ordinary `Err`, and is logged via the `log` crate rather
//! than propagated. Null pointers, invalid UTF-8, malformed hex, and
//! malformed/truncated XDR are all treated as ordinary input-validation
//! failures — see `test_ffi_does_not_panic_on_malformed_input` below.
//!
//! ## Kotlin example (JNA/JNI-style external declarations)
//!
//! ```kotlin
//! class SyncEngineFfi {
//!     external fun sse_engine_open(dbPath: String): Long
//!     external fun sse_engine_close(handle: Long)
//!     external fun sse_seed_account(handle: Long, sourceAccount: String, currentChainSequence: Long): Boolean
//!     external fun sse_queue_payment(
//!         handle: Long,
//!         sourceAccount: String,
//!         signingSeedHex: String,
//!         txXdr: String,
//!         priority: Byte,
//!         ttlHops: Byte,
//!     ): String? // hex message_id, or null on failure
//!     external fun sse_settlement_status(handle: Long, messageIdHex: String): String?
//!     external fun sse_list_unresolved_conflicts(handle: Long): String? // JSON array
//!
//!     companion object { init { System.loadLibrary("stellarconduit_sync_engine") } }
//! }
//!
//! // Off the UI thread, e.g. inside a coroutine on Dispatchers.IO:
//! val handle = ffi.sse_engine_open(dbPath)
//! ffi.sse_seed_account(handle, sourceAccount, lastKnownChainSequence)
//! val messageIdHex = ffi.sse_queue_payment(handle, sourceAccount, seedHex, txXdrBase64, 1, 10)
//! if (messageIdHex != null) {
//!     val status = ffi.sse_settlement_status(handle, messageIdHex)
//! }
//! ffi.sse_engine_close(handle)
//! ```
//!
//! ## Swift example (via a generated bridging header)
//!
//! ```swift
//! let handle = sse_engine_open(dbPath)
//! defer { sse_engine_close(handle) }
//!
//! _ = sourceAccount.withCString { acct in
//!     sse_seed_account(handle, acct, lastKnownChainSequence)
//! }
//!
//! if let messageIdPtr = sse_queue_payment(handle, acctPtr, seedHexPtr, txXdrPtr, 1, 10) {
//!     let messageIdHex = String(cString: messageIdPtr)
//!     sse_free_string(messageIdPtr)
//!
//!     if let statusPtr = sse_settlement_status(handle, messageIdHex) {
//!         let status = String(cString: statusPtr)
//!         sse_free_string(statusPtr)
//!     }
//! }
//! // Call every `sse_*` function above off the main thread, e.g. inside
//! // `DispatchQueue.global().async { ... }`.
//! ```

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::{Mutex, OnceLock};

use ed25519_dalek::SigningKey;

use crate::conflict::Conflict;
use crate::engine::SyncEngine;
use crate::queue::TxPriority;

/// Opaque handle to a live [`SyncEngine`], returned by [`sse_engine_open`]
/// and consumed by every other `sse_*` call. Mobile bindings should treat
/// this purely as an opaque pointer/handle value — never dereference or
/// interpret its contents from Kotlin/Swift.
pub struct SseEngineHandle {
    inner: Mutex<SyncEngine>,
}

/// The single, lazily-initialized, current-thread Tokio runtime used to
/// drive this crate's async engine from every synchronous FFI call. See the
/// module docs above for why current-thread (not multi-threaded) is the
/// correct choice here.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build the FFI bridge's Tokio runtime")
    })
}

/// Borrow a `*const c_char` as a `&str`, or `None` if it is null or not
/// valid UTF-8. Never panics.
fn cstr_to_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Decode a 64-character hex string into a 32-byte ed25519 signing seed and
/// build the corresponding [`SigningKey`]. `None` on any malformed input.
fn decode_signing_key(seed_hex: &str) -> Option<SigningKey> {
    let bytes = hex::decode(seed_hex).ok()?;
    let seed: [u8; 32] = bytes.try_into().ok()?;
    Some(SigningKey::from_bytes(&seed))
}

/// Decode a hex string into a 32-byte `message_id`. `None` on any malformed
/// input (bad hex, or not exactly 32 bytes once decoded).
fn decode_message_id(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    bytes.try_into().ok()
}

/// Minimal, dependency-free JSON array serialization for `Conflict`s. A full
/// `serde_json` dependency was deliberately not added just for this one
/// call site — `Conflict`'s four fields (a `String`, an `i64`, and two
/// `[u8; 32]`s rendered as hex) are simple enough to encode by hand without
/// pulling in a new crate for a size-sensitive mobile dependency graph (see
/// the `Cargo.toml` note on the `stellar-xdr` dependency for the same
/// footprint concern).
fn conflicts_to_json(conflicts: &[Conflict]) -> String {
    let entries: Vec<String> = conflicts
        .iter()
        .map(|c| {
            format!(
                r#"{{"source_account":{},"sequence":{},"envelope_a":"{}","envelope_b":"{}"}}"#,
                json_escape_string(&c.source_account),
                c.sequence,
                hex::encode(c.envelope_a),
                hex::encode(c.envelope_b),
            )
        })
        .collect();
    format!("[{}]", entries.join(","))
}

/// Escape and quote `s` as a JSON string literal.
fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Open (or create) the sync engine's SQLite database at `db_path_ptr` (a
/// null-terminated UTF-8 C string; pass `":memory:"` for an ephemeral,
/// test-only database) and return an opaque handle to the running engine.
///
/// Returns null on any failure: a null or non-UTF-8 `db_path_ptr`, or an
/// I/O/database error while opening or rehydrating state. Never panics.
///
/// # Ownership
/// The returned handle is heap-allocated and owned by the caller from this
/// point on. It must later be passed to exactly one [`sse_engine_close`]
/// call.
#[no_mangle]
pub extern "C" fn sse_engine_open(db_path_ptr: *const c_char) -> *mut SseEngineHandle {
    catch_unwind(AssertUnwindSafe(|| {
        let db_path = match cstr_to_str(db_path_ptr) {
            Some(s) => s,
            None => return ptr::null_mut(),
        };
        match runtime().block_on(SyncEngine::open(db_path)) {
            Ok(engine) => Box::into_raw(Box::new(SseEngineHandle {
                inner: Mutex::new(engine),
            })),
            Err(err) => {
                log::error!("sse_engine_open failed: {err}");
                ptr::null_mut()
            }
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// Close and free a handle previously returned by [`sse_engine_open`].
///
/// Safe to call with a null pointer (no-op). Never panics.
///
/// # Ownership
/// Takes back ownership of `handle` and drops it (closing the underlying
/// SQLite connections). `handle` must not be used by any other `sse_*` call
/// after this returns, and must not be passed to `sse_engine_close` again.
#[no_mangle]
pub extern "C" fn sse_engine_close(handle: *mut SseEngineHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle));
    }));
}

/// Seed (or re-seed) `source_account_ptr`'s known on-chain sequence
/// baseline, as observed the last time the device had connectivity. A
/// wallet should call this once per account before its first
/// [`sse_queue_payment`] call for that account — see
/// [`SyncEngine::seed_account`]'s docs for why: an unseeded account
/// otherwise defaults to a `0` baseline, which only matches a transaction
/// XDR's real embedded sequence number for that account's very first-ever
/// payment.
///
/// Returns `true` on success, `false` on any failure (null handle, null or
/// non-UTF-8 `source_account_ptr`, or a storage error). Never panics.
#[no_mangle]
pub extern "C" fn sse_seed_account(
    handle: *mut SseEngineHandle,
    source_account_ptr: *const c_char,
    current_chain_sequence: i64,
) -> bool {
    catch_unwind(AssertUnwindSafe(|| {
        let handle = match unsafe { handle.as_ref() } {
            Some(h) => h,
            None => return false,
        };
        let source_account = match cstr_to_str(source_account_ptr) {
            Some(s) => s,
            None => return false,
        };
        let mut engine = match handle.inner.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        runtime()
            .block_on(engine.seed_account(source_account, current_chain_sequence))
            .is_ok()
    }))
    .unwrap_or(false)
}

/// Queue a payment: reserve the next sequence number for `source_account_ptr`,
/// sign a mesh envelope wrapping `tx_xdr_ptr` offline, and durably persist
/// it — see [`SyncEngine::queue_payment`].
///
/// - `source_account_ptr`: the Stellar `G...` account the caller believes it
///   is signing for. Cross-checked against the account actually encoded in
///   `tx_xdr_ptr`; a mismatch is rejected (returns null), never trusted.
/// - `signing_seed_hex_ptr`: a 64-character hex string encoding the 32-byte
///   ed25519 seed used to sign the *mesh envelope* (not a Stellar-network
///   signature) — mirrors `stellarconduit-core`'s `sc_create_envelope` seed
///   convention.
/// - `tx_xdr_ptr`: the already-built, base64-encoded Stellar transaction
///   envelope XDR. Treated as opaque and parsed only to recover the source
///   account/sequence it encodes (see `crate::envelope::xdr`).
/// - `priority`: `0` = Low, `1` = Normal, `2` = Emergency (see
///   [`TxPriority`]); any other value is rejected.
/// - `ttl_hops`: mesh time-to-live, in hops.
///
/// Returns a newly-allocated, null-terminated 64-character hex string of the
/// signed envelope's `message_id` on success. Returns null on **any**
/// failure: a null handle, null/non-UTF-8 string arguments, malformed hex,
/// an out-of-range `priority`, unparseable/malformed XDR, a source-account
/// or sequence mismatch, a caught panic, or a storage error — this function
/// never panics across the FFI boundary regardless of input.
///
/// # Ownership
/// The returned string is heap-allocated by Rust; free it with
/// [`sse_free_string`] exactly once. `handle` is borrowed, not consumed.
#[no_mangle]
pub extern "C" fn sse_queue_payment(
    handle: *mut SseEngineHandle,
    source_account_ptr: *const c_char,
    signing_seed_hex_ptr: *const c_char,
    tx_xdr_ptr: *const c_char,
    priority: u8,
    ttl_hops: u8,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        let handle = match unsafe { handle.as_ref() } {
            Some(h) => h,
            None => return ptr::null_mut(),
        };
        let source_account = match cstr_to_str(source_account_ptr) {
            Some(s) => s,
            None => return ptr::null_mut(),
        };
        let seed_hex = match cstr_to_str(signing_seed_hex_ptr) {
            Some(s) => s,
            None => return ptr::null_mut(),
        };
        let tx_xdr = match cstr_to_str(tx_xdr_ptr) {
            Some(s) => s,
            None => return ptr::null_mut(),
        };
        let signing_key = match decode_signing_key(seed_hex) {
            Some(k) => k,
            None => return ptr::null_mut(),
        };
        let signer = crate::envelope::secure_signing::InMemorySigner::new(signing_key);
        let priority = match TxPriority::try_from(priority as i64) {
            Ok(p) => p,
            Err(_) => return ptr::null_mut(),
        };

        let mut engine = match handle.inner.lock() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };

        let result = runtime().block_on(engine.queue_payment(
            source_account,
            &signer,
            tx_xdr.to_string(),
            priority,
            ttl_hops,
        ));

        match result {
            Ok(envelope) => match CString::new(hex::encode(envelope.message_id)) {
                Ok(s) => s.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            Err(err) => {
                log::warn!("sse_queue_payment failed: {err}");
                ptr::null_mut()
            }
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// Look up the current settlement status of a queued envelope by its
/// `message_id_hex_ptr` (a 64-character hex string) — see
/// [`SyncEngine::settlement_status`].
///
/// Returns a newly-allocated, null-terminated string — one of `"queued"`,
/// `"propagating"`, `"settled"`, `"failed"`, `"disputed"` — on success.
/// Returns null if `message_id_hex_ptr` is not currently tracked, is
/// null/non-UTF-8/malformed hex, `handle` is null, or a panic was caught.
/// Never panics.
///
/// # Ownership
/// The returned string is heap-allocated by Rust; free it with
/// [`sse_free_string`] exactly once. `handle` is borrowed, not consumed.
#[no_mangle]
pub extern "C" fn sse_settlement_status(
    handle: *mut SseEngineHandle,
    message_id_hex_ptr: *const c_char,
) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        let handle = match unsafe { handle.as_ref() } {
            Some(h) => h,
            None => return ptr::null_mut(),
        };
        let message_id = match cstr_to_str(message_id_hex_ptr).and_then(decode_message_id) {
            Some(id) => id,
            None => return ptr::null_mut(),
        };
        let engine = match handle.inner.lock() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        match engine.settlement_status(message_id) {
            Some(status) => match CString::new(status.as_str()) {
                Ok(s) => s.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            None => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// List every unresolved (not yet arbitrated) double-spend conflict
/// currently recorded in durable storage — see
/// [`SyncEngine::list_unresolved_conflicts`].
///
/// Returns a newly-allocated, null-terminated JSON array on success — `"[]"`
/// if there are none — of objects shaped like:
/// ```json
/// {"source_account":"GABC...","sequence":101,"envelope_a":"<64 hex chars>","envelope_b":"<64 hex chars>"}
/// ```
/// Returns null only on a null `handle`, a caught panic, or a storage error
/// — an empty conflict set is `"[]"`, never null, so callers can distinguish
/// "no conflicts" from "the call failed". Never panics.
///
/// # Ownership
/// The returned string is heap-allocated by Rust; free it with
/// [`sse_free_string`] exactly once. `handle` is borrowed, not consumed.
#[no_mangle]
pub extern "C" fn sse_list_unresolved_conflicts(handle: *mut SseEngineHandle) -> *mut c_char {
    catch_unwind(AssertUnwindSafe(|| {
        let handle = match unsafe { handle.as_ref() } {
            Some(h) => h,
            None => return ptr::null_mut(),
        };
        let engine = match handle.inner.lock() {
            Ok(g) => g,
            Err(_) => return ptr::null_mut(),
        };
        match runtime().block_on(engine.list_unresolved_conflicts()) {
            Ok(conflicts) => match CString::new(conflicts_to_json(&conflicts)) {
                Ok(s) => s.into_raw(),
                Err(_) => ptr::null_mut(),
            },
            Err(err) => {
                log::warn!("sse_list_unresolved_conflicts failed: {err}");
                ptr::null_mut()
            }
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// Free a string previously returned by [`sse_queue_payment`],
/// [`sse_settlement_status`], or [`sse_list_unresolved_conflicts`].
///
/// Safe to call with a null pointer (no-op). Never panics. Must be called
/// exactly once per returned string — calling it twice on the same pointer,
/// or on a pointer this module did not return, is undefined behavior (a
/// double-free or a foreign-allocator free), same as C's `free()` contract.
#[no_mangle]
pub extern "C" fn sse_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(CString::from_raw(ptr));
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::ffi::CString;

    /// Source account (`G...`) and sequence embedded in
    /// `tests/fixtures/transaction_v1_envelope.b64` — shared with
    /// `tests/integration/queue_storage_roundtrip_test.rs`.
    const SOURCE_G: &str = "GAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCF6M";
    const SEQ: i64 = 103_720_918_407_610_369;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
            .trim()
            .to_string()
    }

    fn cstring(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    /// Take ownership of an `sse_*`-returned string: read it to an owned
    /// `String`, free it via `sse_free_string`, and hand back the owned copy.
    fn take_string(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null(), "expected a non-null string pointer");
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        sse_free_string(ptr);
        s
    }

    fn open_test_engine() -> *mut SseEngineHandle {
        let path = cstring(":memory:");
        let handle = sse_engine_open(path.as_ptr());
        assert!(!handle.is_null(), "engine should open against :memory:");
        handle
    }

    fn random_seed_hex() -> CString {
        cstring(&hex::encode(SigningKey::generate(&mut OsRng).to_bytes()))
    }

    #[test]
    fn test_ffi_queue_payment_happy_path() {
        let handle = open_test_engine();
        let account = cstring(SOURCE_G);

        // The fixture's embedded sequence is far from 0, so the account must
        // be seeded to one below it first (mirrors what a real wallet does
        // via `SyncEngine::seed_account` before its first payment).
        assert!(
            sse_seed_account(handle, account.as_ptr(), SEQ - 1),
            "seeding a valid account must succeed"
        );

        let seed_hex = random_seed_hex();
        let tx_xdr = cstring(&fixture("transaction_v1_envelope.b64"));

        let message_id_ptr = sse_queue_payment(
            handle,
            account.as_ptr(),
            seed_hex.as_ptr(),
            tx_xdr.as_ptr(),
            1, // Normal
            10,
        );
        let message_id_hex = take_string(message_id_ptr);
        assert_eq!(
            message_id_hex.len(),
            64,
            "message_id is returned as a 64-char hex string"
        );
        assert!(hex::decode(&message_id_hex).is_ok());

        sse_engine_close(handle);
    }

    #[test]
    fn test_ffi_does_not_panic_on_malformed_input() {
        // Opening with a null/invalid path must fail gracefully.
        assert!(sse_engine_open(ptr::null()).is_null());
        let invalid_utf8_bytes = [0x66u8, 0x6f, 0xff, 0x00];
        let invalid_utf8_ptr = invalid_utf8_bytes.as_ptr() as *const c_char;
        assert!(sse_engine_open(invalid_utf8_ptr).is_null());

        let handle = open_test_engine();

        // Every entry point against a null handle.
        assert!(
            sse_queue_payment(ptr::null_mut(), ptr::null(), ptr::null(), ptr::null(), 0, 0)
                .is_null()
        );
        assert!(sse_settlement_status(ptr::null_mut(), ptr::null()).is_null());
        assert!(sse_list_unresolved_conflicts(ptr::null_mut()).is_null());
        assert!(!sse_seed_account(ptr::null_mut(), ptr::null(), 0));
        // Closing/freeing null must be a safe no-op, not a crash.
        sse_engine_close(ptr::null_mut());
        sse_free_string(ptr::null_mut());

        // Null string arguments against a real handle.
        assert!(sse_queue_payment(handle, ptr::null(), ptr::null(), ptr::null(), 0, 0).is_null());
        assert!(sse_settlement_status(handle, ptr::null()).is_null());
        assert!(!sse_seed_account(handle, ptr::null(), 0));

        // Invalid UTF-8 byte sequences in every string argument.
        assert!(sse_queue_payment(
            handle,
            invalid_utf8_ptr,
            invalid_utf8_ptr,
            invalid_utf8_ptr,
            0,
            0
        )
        .is_null());
        assert!(sse_settlement_status(handle, invalid_utf8_ptr).is_null());

        // Malformed hex seed / malformed XDR / unknown account.
        let account = cstring("GNOTAREALACCOUNTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
        let not_hex = cstring("this is not hex!!");
        let not_xdr = cstring("this is not valid base64 xdr!!!");
        assert!(sse_queue_payment(
            handle,
            account.as_ptr(),
            not_hex.as_ptr(),
            not_xdr.as_ptr(),
            0,
            0
        )
        .is_null());

        // Right-format-wrong-length seed (valid hex, wrong byte count).
        let short_seed = cstring("aabbcc");
        let real_xdr = cstring(&fixture("transaction_v1_envelope.b64"));
        assert!(sse_queue_payment(
            handle,
            account.as_ptr(),
            short_seed.as_ptr(),
            real_xdr.as_ptr(),
            0,
            0
        )
        .is_null());

        // Out-of-range priority discriminant with otherwise-valid input.
        let seed_hex = random_seed_hex();
        assert!(sse_queue_payment(
            handle,
            account.as_ptr(),
            seed_hex.as_ptr(),
            real_xdr.as_ptr(),
            250,
            0
        )
        .is_null());

        // Source-account/XDR mismatch (account doesn't match what the XDR
        // actually encodes) must be rejected, not panic.
        assert!(sse_queue_payment(
            handle,
            account.as_ptr(),
            seed_hex.as_ptr(),
            real_xdr.as_ptr(),
            1,
            10
        )
        .is_null());

        // Malformed / wrong-length message_id hex.
        let bad_hex = cstring("not hex at all");
        let wrong_len = cstring("aabb");
        assert!(sse_settlement_status(handle, bad_hex.as_ptr()).is_null());
        assert!(sse_settlement_status(handle, wrong_len.as_ptr()).is_null());

        sse_engine_close(handle);
    }

    #[test]
    fn test_ffi_settlement_status_lookup() {
        let handle = open_test_engine();
        let account = cstring(SOURCE_G);
        assert!(sse_seed_account(handle, account.as_ptr(), SEQ - 1));

        let seed_hex = random_seed_hex();
        let tx_xdr = cstring(&fixture("transaction_v1_envelope.b64"));

        let message_id_ptr = sse_queue_payment(
            handle,
            account.as_ptr(),
            seed_hex.as_ptr(),
            tx_xdr.as_ptr(),
            2,
            10,
        );
        let message_id_hex = take_string(message_id_ptr);
        let message_id_c = cstring(&message_id_hex);

        let status = take_string(sse_settlement_status(handle, message_id_c.as_ptr()));
        assert_eq!(
            status, "queued",
            "a freshly-queued envelope starts in the Queued state"
        );

        // A message_id that was never queued resolves to null, not an error
        // string or a panic.
        let unknown = cstring(&hex::encode([9u8; 32]));
        assert!(sse_settlement_status(handle, unknown.as_ptr()).is_null());

        sse_engine_close(handle);
    }

    #[test]
    fn test_ffi_conflict_listing() {
        let handle = open_test_engine();

        // A freshly-opened engine has no conflicts: the empty case is a
        // non-null empty array, not null.
        let empty_json = take_string(sse_list_unresolved_conflicts(handle));
        assert_eq!(empty_json, "[]");

        // Record a conflict at the storage layer this FFI call surfaces
        // (`SyncEngine::record_conflict`, a thin pass-through to
        // `SyncEngineDb::record_conflict` — see the module-level note on
        // conflict detection/wiring being a separate follow-up), then
        // confirm `sse_list_unresolved_conflicts` reports it correctly.
        let conflict = Conflict {
            source_account: "GCONFLICT".to_string(),
            sequence: 42,
            envelope_a: [0x11; 32],
            envelope_b: [0x22; 32],
        };
        {
            let engine = unsafe { &*handle }.inner.lock().unwrap();
            runtime()
                .block_on(engine.record_conflict(&conflict, 1_700_000_000))
                .unwrap();
        }

        let json = take_string(sse_list_unresolved_conflicts(handle));
        assert!(json.contains("\"source_account\":\"GCONFLICT\""));
        assert!(json.contains("\"sequence\":42"));
        assert!(json.contains(&hex::encode(conflict.envelope_a)));
        assert!(json.contains(&hex::encode(conflict.envelope_b)));

        sse_engine_close(handle);
    }
}
