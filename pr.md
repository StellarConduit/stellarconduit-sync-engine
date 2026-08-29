# Compression-Oracle Side-Channel Mitigation for At-Rest Envelope Compression

Closes #93.

## Problem

Issue #56 wants queued `TransactionEnvelope` blobs compressed before issue #12's
AES-256-GCM encryption writes them to SQLite — the textbook *compress-then-encrypt*
pipeline, and the exact shape behind CRIME/BREACH. The transaction **memo**
(attacker-influenceable: a co-located app can make this device queue a payment
whose memo it chose) and the **destination / amount** (secret) are all encoded
in the single `tx_xdr` base64 string. Compress that in one DEFLATE context and
the compressed length becomes a byte-at-a-time oracle for the secret fields,
observable through database-file or backup size.

> **Note on #56.** #56 is still open and unimplemented — there is no envelope
> compression in the crate yet. This PR *defines* the at-rest compression scheme
> (`compress_at_rest` / `decompress_at_rest`) with the oracle mitigation built in
> from the start. It is **not** wired into `SyncEngineDb`'s write path — that
> integration, and the legacy-row migration, are left for #56; the frame format
> already carries the magic-byte discriminator it will need.

## Context-separation analysis

`tx_xdr` is the **one and only** shared compression context. Every other envelope
field (`message_id`, `origin_pubkey`, `ttl_hops`, `timestamp`, `signature`) is a
hash, a public key, a small int, or a random-looking signature — not
attacker-chosen, no shared redundancy with a memo. Within `tx_xdr`: the memo
value versus {destination account, amount, source account}, which sit 16–70
bytes apart, well inside one DEFLATE window.

Full analysis, attacker model (co-located app / backup-size observer — **not** a
network attacker; no adaptive-feedback loop), rejected alternatives, and residual
accounting: **`docs/design/compression-oracle-mitigation.md`**.

## Mitigation (`CompressionScheme::Mitigated`)

1. **Separate compression contexts.** Parse the XDR (reusing `src/envelope/xdr.rs`'s
   pattern), lift the `Memo` into its **own** independent DEFLATE stream, compress
   the memo-blanked remainder in a **second** stream. No shared window/dictionary
   ⇒ a cross-context LZ77 match is structurally impossible. `compress_at_rest`
   self-checks bit-exact reassembly and falls back to opaque whole-blob
   compression for non-canonical / unparseable `tx_xdr`.
2. **Length quantization.** Frame zero-padded to
   `16 + pad16(attacker_len) + pad16(secret_len)`; decompression uses the exact
   recorded lengths so padding is inert. Resolves the secret stream's size only to
   a 16-byte bucket, removing the ~1-byte granularity the oracle needs.
3. **No adaptive dictionary** — deliberately none; a dictionary seeded with memo
   content is the same bug in a new shape.

## Measurement harness (`src/storage/compression_oracle.rs`)

Deterministic byte-at-a-time recovery attack (BREACH-style known-prefix +
multi-round majority vote against Huffman quantization), modelling a strong
attacker with exact per-write size observation. Attacks **both** schemes:

| Target secret | Unmitigated | Mitigated |
|---------------|-------------|-----------|
| Payment amount, low 4 bytes (top 4 known) | **24 bits (3/4 bytes)** | **0 bits (0/4)** |
| Destination account, 4 bytes (8-byte prefix known) | **16 bits (2/4 bytes)** | **0 bits (0/4)** |
| Low-entropy fixture amount `0x0EE6B280` (end-to-end w/ AES-GCM) | **8 bits (1/4 bytes)** | **0 bits (0/4)** |

Cross-context leakage is **eliminated** (mitigated secret stream is byte-identical
regardless of memo). Residual, disclosed honestly in the design doc:
*intra-secret* leakage is **reduced, not zero** — an attacker forcing very many
writes of the same secret can still detect a 16-byte-bucket boundary crossing
(≤ 1 bit per crossing, 0 mid-bucket).

## Compression ratio (canonical fixture payment)

| | Bytes | % of raw |
|---|-------|----------|
| `rmp_serde(TransactionEnvelope)` (today) | 443 | 100 % |
| Unmitigated frame | 127 | 28.7 % |
| **Mitigated frame** | **144** | **32.5 %** |

~3× reduction retained; mitigation costs 17 bytes vs the vulnerable baseline.

## Changes

- `src/storage/envelope_compression.rs` *(new)* — `CompressionScheme`,
  `compress_at_rest` / `decompress_at_rest`, memo/secret decomposition, framing,
  `oracle_observable`, `compressed_segment_sizes`.
- `src/storage/compression_oracle.rs` *(new)* — `run_byte_at_a_time_oracle`,
  `OracleConfig` / `OracleReport`, `SecretField`.
- `src/storage/mod.rs` — module decls + re-exports.
- `src/errors.rs` — `SyncEngineError::CompressionError` (classified `Permanent`) +
  `classify()` arm + variant checklist + doc table row.
- `Cargo.toml` — `miniz_oxide = "0.8"` (pure-Rust DEFLATE; justification comment
  in-file), `[[test]]` for the new integration test.
- `docs/design/compression-oracle-mitigation.md` *(new)*.
- `tests/integration/compression_oracle_test.rs` *(new)* — end-to-end through the
  real `EncryptedData` AES-GCM pipeline; proves GCM's +28-byte overhead preserves
  (doesn't mask) the quantization buckets.

## Tests

Required (all present, passing):

- `test_unmitigated_baseline_leaks_secret_byte_via_compressed_length`
- `test_mitigated_implementation_reduces_oracle_signal`
- `test_attacker_influenceable_and_secret_fields_use_separate_compression_contexts`
- `test_compression_still_provides_meaningful_size_reduction_after_mitigation`

Plus: both-scheme round-trip (incl. fee-bump, muxed, MEMO_HASH, non-parseable
fallback), corrupt-frame rejection without panic, destination-field recovery,
and the 4 end-to-end integration tests.

```
cargo fmt --all --check           # clean
cargo clippy --all-targets -- -D warnings   # clean
cargo test                        # 263 lib + all integration/sim, 0 failures
```
