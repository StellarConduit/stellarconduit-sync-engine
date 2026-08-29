//! At-rest envelope compression with a built-in compression-oracle
//! (CRIME / BREACH-class) side-channel mitigation.
//!
//! # Why this module exists
//!
//! Issue #56 ("Compress Queued Envelope Payloads Before Storage") wants
//! [`TransactionEnvelope`] blobs compressed before issue #12's AES-256-GCM
//! encryption writes them to SQLite. That is the textbook *compress-then-
//! encrypt* pipeline — and it is the exact shape behind the CRIME and BREACH
//! attacks. Whenever a single compression context mixes
//!
//! * **attacker-influenceable plaintext** — a transaction **memo**, which a
//!   co-located malicious app can cause this device to queue by initiating a
//!   payment *to* this device with a memo of the attacker's choosing, and
//! * **secret plaintext** — the destination account and amount the attacker
//!   wants to learn,
//!
//! the compressed length becomes an oracle: a guessed secret byte that matches
//! compresses better (LZ77 emits a back-reference instead of literals), so an
//! attacker who can trigger many writes with chosen memos and observe the
//! resulting at-rest blob sizes (via file size, backup size, or write timing)
//! can mount a byte-at-a-time recovery of the secret field.
//!
//! See `docs/design/compression-oracle-mitigation.md` for the full
//! context-separation analysis, the attacker model, and the residual-leakage
//! quantification. [`crate::storage::compression_oracle`] is the measurement
//! harness that attacks both schemes below and reports what it recovers.
//!
//! # The one shared context in a `TransactionEnvelope`
//!
//! The memo, destination and amount are *all* encoded inside the single opaque
//! `tx_xdr` base64 string. That string is the one and only point where
//! attacker-influenceable and secret plaintext meet. Everything else on the
//! envelope (`message_id`, `origin_pubkey`, `ttl_hops`, `timestamp`,
//! `signature`) is either a hash, a public key, a hop counter, a timestamp, or
//! a 64-byte random-looking signature — none of it is attacker-chosen and none
//! of it compresses against the memo.
//!
//! # Mitigation
//!
//! [`CompressionScheme::Mitigated`] (the shipped scheme):
//!
//! 1. **Separate compression contexts.** The transaction XDR is parsed, the
//!    `Memo` is lifted out into its own independent DEFLATE stream, and the
//!    rest of the envelope (with the memo blanked to `Memo::None`) is
//!    compressed in a second, separate DEFLATE stream. No shared window, no
//!    shared dictionary — a cross-context LZ77 match is structurally
//!    impossible, which removes the primary CRIME mechanism.
//! 2. **Length quantization.** The finished frame is zero-padded up to the next
//!    multiple of [`PAD_GRANULARITY`] bytes, so a single at-rest observation
//!    reveals only which quantization bucket the blob fell in, not its exact
//!    size. This is a *reduction*, not elimination — see the residual-leakage
//!    note below and the harness numbers in the design doc.
//! 3. **No adaptive dictionary.** A dictionary trained on, or seeded with,
//!    attacker-influenced content would re-introduce the oracle, so the scheme
//!    deliberately uses none.
//!
//! [`CompressionScheme::Unmitigated`] is issue #56 "as originally scoped" — one
//! DEFLATE stream over the whole envelope, no padding. It is retained **only**
//! as the measurement baseline and must never be selected for real storage.
//!
//! ## Residual leakage
//!
//! Separate contexts fully kill *cross-field* leakage (memo ↔ secret). What
//! remains is *intra-secret* leakage: the secret stream's own compressed size
//! still depends on the secret's contents, and [`PAD_GRANULARITY`]-byte
//! quantization only blunts it. An attacker who can force very many writes can
//! still observe when the secret stream's true compressed size crosses a
//! bucket boundary. That residual is bounded (at most ~1 bit per boundary near
//! the operating point, 0 when the secret stays mid-bucket) and is measured by
//! the harness; it is not claimed to be zero.

use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::decompress_to_vec_with_limit;
use serde::{Deserialize, Serialize};
use stellar_xdr::curr::{
    FeeBumpTransactionInnerTx, Limits, Memo, ReadXdr, TransactionEnvelope as XdrTxEnvelope,
    WriteXdr,
};

use stellarconduit_core::message::types::TransactionEnvelope;

use crate::errors::SyncEngineError;

/// DEFLATE effort on miniz_oxide's `0..=10` scale. Level 10 gives the greediest
/// LZ77 match-finding, which is the *worst case* for the oracle — using it for
/// the baseline keeps the measurement honest, and using it for the mitigated
/// scheme maximises the ratio we recover after context separation.
const DEFLATE_LEVEL: u8 = 10;

/// Upper bound on the plaintext any single at-rest stream may inflate to.
/// A corrupt or hostile blob cannot make [`decompress_at_rest`] allocate past
/// this (decompression-bomb guard).
const MAX_STREAM_PLAINTEXT: usize = 1 << 20; // 1 MiB

/// Frame magic. Doubles as issue #56's compressed-vs-legacy row discriminator:
/// a bare `rmp_serde`-serialized `TransactionEnvelope` starts with a MessagePack
/// fixmap/fixarray marker (`0x80..=0x9f`) or `0xdc..=0xdf`, never `b'S'`.
const FRAME_MAGIC: [u8; 4] = *b"SCz1";

/// Bytes the mitigated frame is zero-padded up to a multiple of. 16 keeps the
/// storage cost low (≈8 bytes/blob on average, so #56's ratio is preserved)
/// while quantizing away the ~1-byte granularity a byte-at-a-time oracle needs.
/// A deployment wanting a stronger guarantee can raise this; the frame records
/// nothing about padding (decompression uses the exact recorded stream
/// lengths), so the value is free to change between writes.
pub const PAD_GRANULARITY: usize = 16;

const FRAME_HEADER_LEN: usize = 16;

/// Which compression pipeline produced, or should produce, an at-rest blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionScheme {
    /// One shared DEFLATE context over the entire envelope, no padding. This is
    /// issue #56 as originally scoped and is **compression-oracle-vulnerable**.
    /// Retained only as the [`crate::storage::compression_oracle`] baseline.
    Unmitigated,
    /// Memo and secret plaintext compressed in separate DEFLATE contexts, frame
    /// length-quantized to [`PAD_GRANULARITY`]. The shipped scheme.
    Mitigated,
}

impl CompressionScheme {
    fn tag(self) -> u8 {
        match self {
            CompressionScheme::Unmitigated => 0,
            CompressionScheme::Mitigated => 1,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SyncEngineError> {
        match tag {
            0 => Ok(CompressionScheme::Unmitigated),
            1 => Ok(CompressionScheme::Mitigated),
            other => Err(SyncEngineError::CompressionError(format!(
                "unknown compression scheme tag {other}"
            ))),
        }
    }
}

/// Pre- and post-padding sizes of each compression context, for the harness and
/// the ratio tests. `attacker_*` is zero whenever the memo was not split out
/// (the opaque fallback, or the unmitigated scheme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSizes {
    pub attacker_plaintext: usize,
    pub attacker_compressed: usize,
    pub secret_plaintext: usize,
    pub secret_compressed: usize,
    /// Total at-rest blob size a filesystem/backup observer sees, padding
    /// included.
    pub framed_total: usize,
}

// ---------------------------------------------------------------------------
// Decomposition
// ---------------------------------------------------------------------------

/// The outer envelope fields that are never attacker-chosen and never
/// compressed against the memo. Serialized with `rmp_serde` into the secret
/// stream. `signature` is a `Vec<u8>` (always length 64) purely to sidestep
/// serde's large-array friction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct OuterFields {
    message_id: [u8; 32],
    origin_pubkey: [u8; 32],
    ttl_hops: u8,
    timestamp: u64,
    signature: Vec<u8>,
}

impl OuterFields {
    fn from_envelope(env: &TransactionEnvelope) -> Self {
        Self {
            message_id: env.message_id,
            origin_pubkey: env.origin_pubkey,
            ttl_hops: env.ttl_hops,
            timestamp: env.timestamp,
            signature: env.signature.to_vec(),
        }
    }

    fn into_envelope(self, tx_xdr: String) -> Result<TransactionEnvelope, SyncEngineError> {
        let signature: [u8; 64] = self.signature.try_into().map_err(|v: Vec<u8>| {
            SyncEngineError::CompressionError(format!(
                "outer-field signature is {} bytes, expected 64",
                v.len()
            ))
        })?;
        Ok(TransactionEnvelope {
            message_id: self.message_id,
            origin_pubkey: self.origin_pubkey,
            tx_xdr,
            ttl_hops: self.ttl_hops,
            timestamp: self.timestamp,
            signature,
        })
    }
}

/// 1 = the memo was lifted into its own context; the secret stream carries the
/// memo-blanked XDR plus [`OuterFields`]. 0 = opaque: the secret stream is just
/// `rmp_serde(TransactionEnvelope)` and the attacker stream is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecompKind {
    Opaque,
    MemoSplit,
}

impl DecompKind {
    fn tag(self) -> u8 {
        match self {
            DecompKind::Opaque => 0,
            DecompKind::MemoSplit => 1,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, SyncEngineError> {
        match tag {
            0 => Ok(DecompKind::Opaque),
            1 => Ok(DecompKind::MemoSplit),
            other => Err(SyncEngineError::CompressionError(format!(
                "unknown decomposition kind {other}"
            ))),
        }
    }
}

/// Read the `Memo` out of a parsed XDR envelope and replace it with
/// `Memo::None` in place, returning the original memo. Covers all three
/// envelope shapes, mirroring `crate::envelope::xdr`.
fn take_memo(xdr: &mut XdrTxEnvelope) -> Memo {
    match xdr {
        XdrTxEnvelope::Tx(env) => std::mem::replace(&mut env.tx.memo, Memo::None),
        XdrTxEnvelope::TxV0(env) => std::mem::replace(&mut env.tx.memo, Memo::None),
        XdrTxEnvelope::TxFeeBump(env) => {
            let FeeBumpTransactionInnerTx::Tx(inner) = &mut env.tx.inner_tx;
            std::mem::replace(&mut inner.tx.memo, Memo::None)
        }
    }
}

/// Put a `Memo` back into a parsed XDR envelope (inverse of [`take_memo`]).
fn set_memo(xdr: &mut XdrTxEnvelope, memo: Memo) {
    match xdr {
        XdrTxEnvelope::Tx(env) => env.tx.memo = memo,
        XdrTxEnvelope::TxV0(env) => env.tx.memo = memo,
        XdrTxEnvelope::TxFeeBump(env) => {
            let FeeBumpTransactionInnerTx::Tx(inner) = &mut env.tx.inner_tx;
            inner.tx.memo = memo;
        }
    }
}

/// The raw material each scheme compresses, after deciding whether the memo can
/// be safely separated.
struct Decomposition {
    kind: DecompKind,
    /// Attacker-influenceable plaintext (XDR-encoded `Memo`), empty for
    /// [`DecompKind::Opaque`].
    attacker: Vec<u8>,
    /// Secret plaintext: for `MemoSplit`, `len-prefixed blanked XDR || rmp(OuterFields)`;
    /// for `Opaque`, `rmp(TransactionEnvelope)`.
    secret: Vec<u8>,
    /// Same, but with the memo left *in* the XDR — the single-context input the
    /// unmitigated baseline compresses. Only populated for `MemoSplit`.
    unsplit_secret: Vec<u8>,
}

fn decompose(env: &TransactionEnvelope) -> Result<Decomposition, SyncEngineError> {
    let opaque = || -> Result<Decomposition, SyncEngineError> {
        let bytes = rmp_serde::to_vec(env)?;
        Ok(Decomposition {
            kind: DecompKind::Opaque,
            attacker: Vec::new(),
            secret: bytes.clone(),
            unsplit_secret: bytes,
        })
    };

    // Only a well-formed, canonically-encoded transaction XDR can be split and
    // losslessly reassembled. Anything else falls back to the opaque path,
    // which is conservative: no cross-context leak, just a worse ratio.
    let mut parsed = match XdrTxEnvelope::from_xdr_base64(&env.tx_xdr, Limits::none()) {
        Ok(p) => p,
        Err(_) => return opaque(),
    };

    let canonical_xdr = match parsed.to_xdr(Limits::none()) {
        Ok(x) => x,
        Err(_) => return opaque(),
    };
    // Re-encoding must reproduce the caller's exact base64, or reassembly would
    // silently change `tx_xdr`.
    if parsed
        .to_xdr_base64(Limits::none())
        .map(|b64| b64 != env.tx_xdr)
        .unwrap_or(true)
    {
        return opaque();
    }

    let memo = take_memo(&mut parsed);
    let blanked_xdr = match parsed.to_xdr(Limits::none()) {
        Ok(x) => x,
        Err(_) => return opaque(),
    };
    let attacker = match memo.to_xdr(Limits::none()) {
        Ok(x) => x,
        Err(_) => return opaque(),
    };

    let outer = rmp_serde::to_vec(&OuterFields::from_envelope(env))?;
    let secret = frame_len_prefixed(&blanked_xdr, &outer);
    let unsplit_secret = frame_len_prefixed(&canonical_xdr, &outer);

    let decomp = Decomposition {
        kind: DecompKind::MemoSplit,
        attacker,
        secret,
        unsplit_secret,
    };

    // Prove the split round-trips to the exact input before committing to it.
    match reassemble_memo_split(&decomp.attacker, &decomp.secret) {
        Ok(rebuilt) if &rebuilt == env => Ok(decomp),
        _ => opaque(),
    }
}

fn frame_len_prefixed(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + a.len() + b.len());
    out.extend_from_slice(&(a.len() as u32).to_le_bytes());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

fn split_len_prefixed(buf: &[u8]) -> Result<(&[u8], &[u8]), SyncEngineError> {
    if buf.len() < 4 {
        return Err(SyncEngineError::CompressionError(
            "secret stream too short for length prefix".into(),
        ));
    }
    let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
    let rest = &buf[4..];
    if len > rest.len() {
        return Err(SyncEngineError::CompressionError(
            "secret stream length prefix exceeds buffer".into(),
        ));
    }
    Ok((&rest[..len], &rest[len..]))
}

fn reassemble_memo_split(
    attacker: &[u8],
    secret: &[u8],
) -> Result<TransactionEnvelope, SyncEngineError> {
    let (blanked_xdr, outer_bytes) = split_len_prefixed(secret)?;
    let outer: OuterFields = rmp_serde::from_slice(outer_bytes)?;
    let memo = Memo::from_xdr(attacker, Limits::none())
        .map_err(|e| SyncEngineError::CompressionError(format!("memo XDR invalid: {e}")))?;
    let mut parsed = XdrTxEnvelope::from_xdr(blanked_xdr, Limits::none())
        .map_err(|e| SyncEngineError::CompressionError(format!("blanked XDR invalid: {e}")))?;
    set_memo(&mut parsed, memo);
    let tx_xdr = parsed
        .to_xdr_base64(Limits::none())
        .map_err(|e| SyncEngineError::CompressionError(format!("reassembled XDR invalid: {e}")))?;
    outer.into_envelope(tx_xdr)
}

fn reassemble_unsplit(secret: &[u8]) -> Result<TransactionEnvelope, SyncEngineError> {
    let (xdr, outer_bytes) = split_len_prefixed(secret)?;
    let outer: OuterFields = rmp_serde::from_slice(outer_bytes)?;
    let parsed = XdrTxEnvelope::from_xdr(xdr, Limits::none())
        .map_err(|e| SyncEngineError::CompressionError(format!("XDR invalid: {e}")))?;
    let tx_xdr = parsed
        .to_xdr_base64(Limits::none())
        .map_err(|e| SyncEngineError::CompressionError(format!("XDR invalid: {e}")))?;
    outer.into_envelope(tx_xdr)
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

fn pad_up(n: usize) -> usize {
    n.div_ceil(PAD_GRANULARITY) * PAD_GRANULARITY
}

fn build_frame(
    scheme: CompressionScheme,
    kind: DecompKind,
    attacker_stream: &[u8],
    secret_stream: &[u8],
) -> Vec<u8> {
    let body_len = FRAME_HEADER_LEN + attacker_stream.len() + secret_stream.len();
    let padded_len = match scheme {
        CompressionScheme::Unmitigated => body_len,
        // Each context is quantized independently so that an attacker who knows
        // their own injected memo (hence `pad_up(attacker_stream.len())`) can
        // still only resolve the secret stream's size to a PAD_GRANULARITY
        // bucket. Padding sits at the tail of the frame; the exact stream
        // lengths in the header drive decompression, so the zeros are inert.
        CompressionScheme::Mitigated => {
            FRAME_HEADER_LEN + pad_up(attacker_stream.len()) + pad_up(secret_stream.len())
        }
    };

    let mut frame = Vec::with_capacity(padded_len);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.push(scheme.tag());
    frame.push(kind.tag());
    frame.push(0); // reserved
    frame.push(0); // reserved
    frame.extend_from_slice(&(attacker_stream.len() as u32).to_le_bytes());
    frame.extend_from_slice(&(secret_stream.len() as u32).to_le_bytes());
    frame.extend_from_slice(attacker_stream);
    frame.extend_from_slice(secret_stream);
    frame.resize(padded_len, 0);
    frame
}

struct ParsedFrame<'a> {
    scheme: CompressionScheme,
    kind: DecompKind,
    attacker_stream: &'a [u8],
    secret_stream: &'a [u8],
}

fn parse_frame(bytes: &[u8]) -> Result<ParsedFrame<'_>, SyncEngineError> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(SyncEngineError::CompressionError(
            "at-rest blob shorter than frame header".into(),
        ));
    }
    if bytes[..4] != FRAME_MAGIC {
        return Err(SyncEngineError::CompressionError(
            "at-rest blob has wrong magic (not a compression frame)".into(),
        ));
    }
    let scheme = CompressionScheme::from_tag(bytes[4])?;
    let kind = DecompKind::from_tag(bytes[5])?;
    let attacker_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let secret_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;

    let streams = &bytes[FRAME_HEADER_LEN..];
    let total = attacker_len
        .checked_add(secret_len)
        .ok_or_else(|| SyncEngineError::CompressionError("frame stream lengths overflow".into()))?;
    if total > streams.len() {
        return Err(SyncEngineError::CompressionError(
            "frame stream lengths exceed blob".into(),
        ));
    }
    Ok(ParsedFrame {
        scheme,
        kind,
        attacker_stream: &streams[..attacker_len],
        secret_stream: &streams[attacker_len..attacker_len + secret_len],
    })
}

fn inflate(stream: &[u8]) -> Result<Vec<u8>, SyncEngineError> {
    decompress_to_vec_with_limit(stream, MAX_STREAM_PLAINTEXT)
        .map_err(|e| SyncEngineError::CompressionError(format!("DEFLATE stream invalid: {e}")))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compress `env` for storage at rest under `scheme`.
///
/// The returned frame is what issue #56 would hand to
/// [`crate::encryption::EncryptedData::encrypt`]. [`decompress_at_rest`] is its
/// exact inverse for any envelope, regardless of scheme or whether the memo
/// could be split out.
///
/// [`CompressionScheme::Unmitigated`] is for the measurement harness only and
/// must not be used for real storage.
pub fn compress_at_rest(
    env: &TransactionEnvelope,
    scheme: CompressionScheme,
) -> Result<Vec<u8>, SyncEngineError> {
    let decomp = decompose(env)?;

    let frame = match scheme {
        CompressionScheme::Unmitigated => {
            // One shared context. For a split-able envelope that is the memo
            // sitting right next to the destination in a single DEFLATE window.
            let (kind, plaintext) = match decomp.kind {
                DecompKind::MemoSplit => (DecompKind::MemoSplit, decomp.unsplit_secret),
                DecompKind::Opaque => (DecompKind::Opaque, decomp.secret),
            };
            let stream = compress_to_vec(&plaintext, DEFLATE_LEVEL);
            build_frame(scheme, kind, &[], &stream)
        }
        CompressionScheme::Mitigated => {
            let secret_stream = compress_to_vec(&decomp.secret, DEFLATE_LEVEL);
            let attacker_stream = if decomp.attacker.is_empty() {
                Vec::new()
            } else {
                compress_to_vec(&decomp.attacker, DEFLATE_LEVEL)
            };
            build_frame(scheme, decomp.kind, &attacker_stream, &secret_stream)
        }
    };

    Ok(frame)
}

/// Recover the exact [`TransactionEnvelope`] from a frame produced by
/// [`compress_at_rest`]. Never panics on corrupt input — every malformed frame
/// returns [`SyncEngineError::CompressionError`].
pub fn decompress_at_rest(bytes: &[u8]) -> Result<TransactionEnvelope, SyncEngineError> {
    let frame = parse_frame(bytes)?;
    let secret = inflate(frame.secret_stream)?;

    match frame.kind {
        DecompKind::Opaque => Ok(rmp_serde::from_slice(&secret)?),
        DecompKind::MemoSplit => match frame.scheme {
            CompressionScheme::Unmitigated => reassemble_unsplit(&secret),
            CompressionScheme::Mitigated => {
                let attacker = inflate(frame.attacker_stream)?;
                reassemble_memo_split(&attacker, &secret)
            }
        },
    }
}

/// Per-context sizes for `env` under `scheme`, for the oracle harness and the
/// ratio tests. Does not allocate a stored frame beyond what it measures.
pub fn compressed_segment_sizes(
    env: &TransactionEnvelope,
    scheme: CompressionScheme,
) -> Result<SegmentSizes, SyncEngineError> {
    let decomp = decompose(env)?;
    let frame = compress_at_rest(env, scheme)?;

    Ok(match scheme {
        CompressionScheme::Unmitigated => {
            let plaintext = match decomp.kind {
                DecompKind::MemoSplit => &decomp.unsplit_secret,
                DecompKind::Opaque => &decomp.secret,
            };
            SegmentSizes {
                attacker_plaintext: 0,
                attacker_compressed: 0,
                secret_plaintext: plaintext.len(),
                secret_compressed: compress_to_vec(plaintext, DEFLATE_LEVEL).len(),
                framed_total: frame.len(),
            }
        }
        CompressionScheme::Mitigated => {
            let attacker_compressed = if decomp.attacker.is_empty() {
                0
            } else {
                compress_to_vec(&decomp.attacker, DEFLATE_LEVEL).len()
            };
            SegmentSizes {
                attacker_plaintext: decomp.attacker.len(),
                attacker_compressed,
                secret_plaintext: decomp.secret.len(),
                secret_compressed: compress_to_vec(&decomp.secret, DEFLATE_LEVEL).len(),
                framed_total: frame.len(),
            }
        }
    })
}

/// The compressed size of just the secret context — the quantity a
/// byte-at-a-time oracle actually chases. Padding is applied to the *frame*, so
/// this is reported pre-padding for the harness to model both "attacker sees
/// exact stream size" and "attacker sees padded blob size".
pub fn secret_context_compressed_size(
    env: &TransactionEnvelope,
    scheme: CompressionScheme,
) -> Result<usize, SyncEngineError> {
    Ok(compressed_segment_sizes(env, scheme)?.secret_compressed)
}

/// The blob-size quantity a compression-oracle attacker can actually resolve
/// about the **secret** context of `env` under `scheme`.
///
/// * [`CompressionScheme::Unmitigated`]: the whole at-rest frame length — memo
///   and secret share one DEFLATE stream, so every byte of the secret's
///   compressibility (including its correlation with the injected memo) shows
///   up here.
/// * [`CompressionScheme::Mitigated`]: the secret stream's compressed size
///   quantized to [`PAD_GRANULARITY`]. An attacker knows their own injected
///   memo and therefore its (padded) stream size, so they can subtract it;
///   what remains is the secret stream, resolvable only to a bucket.
///
/// This is the exact signal [`crate::storage::compression_oracle`] feeds into
/// its byte-at-a-time search, so the harness models a *strong* attacker
/// (per-write observation, no measurement noise) — a conservative choice.
pub fn oracle_observable(
    env: &TransactionEnvelope,
    scheme: CompressionScheme,
) -> Result<usize, SyncEngineError> {
    match scheme {
        CompressionScheme::Unmitigated => Ok(compress_at_rest(env, scheme)?.len()),
        CompressionScheme::Mitigated => {
            let secret = compressed_segment_sizes(env, scheme)?.secret_compressed;
            Ok(FRAME_HEADER_LEN + pad_up(secret))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{Hash, StringM};

    const SEQ: i64 = 103_720_918_407_610_369;

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/{}", env!("CARGO_MANIFEST_DIR"), name);
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed to read fixture {name}: {e}"))
            .trim()
            .to_string()
    }

    /// Rebuild a fixture's `tx_xdr` with `memo` swapped in, returning canonical
    /// base64 — the shape an incoming attacker-influenced payment would take.
    fn xdr_with_memo(fixture_name: &str, memo: Memo) -> String {
        let mut parsed =
            XdrTxEnvelope::from_xdr_base64(fixture(fixture_name), Limits::none()).unwrap();
        set_memo(&mut parsed, memo);
        parsed.to_xdr_base64(Limits::none()).unwrap()
    }

    fn envelope_with_xdr(tx_xdr: String) -> TransactionEnvelope {
        TransactionEnvelope {
            message_id: [7u8; 32],
            origin_pubkey: [9u8; 32],
            tx_xdr,
            ttl_hops: 8,
            timestamp: 1_700_000_000,
            signature: [0x5a; 64],
        }
    }

    fn text_memo(bytes: &[u8]) -> Memo {
        Memo::Text(StringM::<28>::try_from(bytes.to_vec()).unwrap())
    }

    #[test]
    fn test_compress_decompress_roundtrip_unmitigated_and_mitigated() {
        let cases = [
            "transaction_v1_envelope.b64",
            "transaction_v1_envelope_muxed.b64",
            "fee_bump_envelope.b64",
        ];
        for name in cases {
            let env = envelope_with_xdr(fixture(name));
            for scheme in [CompressionScheme::Unmitigated, CompressionScheme::Mitigated] {
                let frame = compress_at_rest(&env, scheme).unwrap();
                let back = decompress_at_rest(&frame).unwrap();
                assert_eq!(env, back, "roundtrip failed for {name} under {scheme:?}");
            }
        }
    }

    #[test]
    fn test_roundtrip_with_attacker_chosen_memo() {
        let env = envelope_with_xdr(xdr_with_memo(
            "transaction_v1_envelope.b64",
            text_memo(b"attacker chosen memo!!"),
        ));
        for scheme in [CompressionScheme::Unmitigated, CompressionScheme::Mitigated] {
            let frame = compress_at_rest(&env, scheme).unwrap();
            assert_eq!(env, decompress_at_rest(&frame).unwrap());
        }
    }

    #[test]
    fn test_non_parseable_tx_xdr_falls_back_to_opaque_but_still_roundtrips() {
        let env = envelope_with_xdr("this is not base64 XDR !!!".to_string());
        let frame = compress_at_rest(&env, CompressionScheme::Mitigated).unwrap();
        let parsed = parse_frame(&frame).unwrap();
        assert_eq!(parsed.kind, DecompKind::Opaque);
        assert!(parsed.attacker_stream.is_empty());
        assert_eq!(env, decompress_at_rest(&frame).unwrap());
    }

    #[test]
    fn test_attacker_influenceable_and_secret_fields_use_separate_compression_contexts() {
        // Same secret transaction, two very different memos. One memo is
        // crafted to contain a long run equal to the destination account bytes
        // (0x22 * 32 in the fixture) — the ideal CRIME feed.
        let benign = envelope_with_xdr(xdr_with_memo(
            "transaction_v1_envelope.b64",
            text_memo(b"lunch"),
        ));
        let malicious = envelope_with_xdr(xdr_with_memo(
            "transaction_v1_envelope.b64",
            text_memo(&[0x22u8; 28]),
        ));

        let a = parse_frame(&compress_at_rest(&benign, CompressionScheme::Mitigated).unwrap())
            .map(|f| f.secret_stream.to_vec())
            .unwrap();
        let b = parse_frame(&compress_at_rest(&malicious, CompressionScheme::Mitigated).unwrap())
            .map(|f| f.secret_stream.to_vec())
            .unwrap();

        // The secret context is byte-for-byte independent of the memo.
        assert_eq!(
            a, b,
            "mitigated secret stream changed with memo content — contexts are not separated"
        );

        // And under the unmitigated scheme the shared stream *does* move.
        let ua = compress_at_rest(&benign, CompressionScheme::Unmitigated).unwrap();
        let ub = compress_at_rest(&malicious, CompressionScheme::Unmitigated).unwrap();
        assert_ne!(
            ua.len(),
            ub.len(),
            "baseline was expected to leak memo/secret correlation via length"
        );
    }

    #[test]
    fn test_compression_still_provides_meaningful_size_reduction_after_mitigation() {
        // Realistic envelope: a 64-byte incompressible signature inside the XDR,
        // a repeated-byte destination (compresses), base64 bloat on tx_xdr.
        let env = envelope_with_xdr(fixture("transaction_v1_envelope.b64"));
        let raw = rmp_serde::to_vec(&env).unwrap().len();

        let sizes = compressed_segment_sizes(&env, CompressionScheme::Mitigated).unwrap();
        let unmit = compressed_segment_sizes(&env, CompressionScheme::Unmitigated).unwrap();
        eprintln!(
            "raw rmp blob      : {raw} B\n\
             unmitigated frame : {} B  ({:.1}% of raw)\n\
             mitigated frame   : {} B  ({:.1}% of raw)",
            unmit.framed_total,
            100.0 * unmit.framed_total as f64 / raw as f64,
            sizes.framed_total,
            100.0 * sizes.framed_total as f64 / raw as f64,
        );
        assert!(
            sizes.framed_total < raw,
            "mitigated frame ({}) is not smaller than the raw rmp blob ({raw})",
            sizes.framed_total
        );
        // Guard against a mitigation so aggressive it defeats #56's purpose:
        // require at least a 15% reduction on this specimen.
        assert!(
            (sizes.framed_total as f64) < 0.85 * (raw as f64),
            "mitigated frame {} is not <85% of raw {raw}",
            sizes.framed_total
        );

        // Mitigation costs some ratio vs the (vulnerable) baseline, but not much.
        assert!(sizes.framed_total >= unmit.framed_total);
    }

    #[test]
    fn test_decompress_rejects_corrupt_frames_without_panic() {
        let env = envelope_with_xdr(fixture("transaction_v1_envelope.b64"));
        let good = compress_at_rest(&env, CompressionScheme::Mitigated).unwrap();

        // Truncations that land in the header or the compressed streams (a
        // truncation that only clips trailing padding is harmless by design).
        for cut in [0usize, 4, 8, 15, 16, FRAME_HEADER_LEN + 2] {
            assert!(
                decompress_at_rest(&good[..cut.min(good.len())]).is_err(),
                "truncation to {cut} bytes should be rejected"
            );
        }
        // Bad magic.
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0xFF;
        assert!(decompress_at_rest(&bad_magic).is_err());
        // Absurd stream length.
        let mut bad_len = good.clone();
        bad_len[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decompress_at_rest(&bad_len).is_err());
        // Corrupt DEFLATE body.
        let mut bad_body = good.clone();
        let n = bad_body.len();
        bad_body[n - 5] ^= 0xFF;
        let _ = decompress_at_rest(&bad_body); // must not panic; may or may not error
    }

    #[test]
    fn test_memo_hash_variant_roundtrips() {
        let env = envelope_with_xdr(xdr_with_memo(
            "transaction_v1_envelope.b64",
            Memo::Hash(Hash([0x22u8; 32])),
        ));
        let frame = compress_at_rest(&env, CompressionScheme::Mitigated).unwrap();
        assert_eq!(env, decompress_at_rest(&frame).unwrap());
        let _ = SEQ;
    }
}
