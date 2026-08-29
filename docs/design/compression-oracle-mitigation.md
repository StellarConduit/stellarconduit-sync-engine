# Design: Compression-Oracle Side-Channel Mitigation for At-Rest Envelope Compression

Design discussion for
[#93](https://github.com/StellarConduit/stellarconduit-sync-engine/issues/93).
Opened per the issue's "open a design discussion first" note and
`CONTRIBUTING.md`. Components: `src/storage/envelope_compression.rs`,
`src/storage/compression_oracle.rs`; builds on
[#56](https://github.com/StellarConduit/stellarconduit-sync-engine/issues/56)
(envelope compression at rest), [#12](https://github.com/StellarConduit/stellarconduit-sync-engine/issues/12)
(encryption at rest).

> **Status of #56.** At the time of writing #56 is still open and unimplemented
> — there is no envelope compression anywhere in the crate. This PR therefore
> *defines* the at-rest compression scheme (`compress_at_rest` /
> `decompress_at_rest`) with the oracle mitigation built in from the start,
> rather than retrofitting a mitigation onto merged code. #56's integration work
> (wiring it into `SyncEngineDb`'s write path, the legacy-row magic-byte
> migration) is deliberately left for #56; the frame format already carries the
> discriminator it needs.

## 1. Context-separation analysis

### Where attacker-influenceable and secret plaintext meet

A queued envelope is a `stellarconduit_core::message::types::TransactionEnvelope`:

| Field | Attacker-influenceable? | Secret? | Compresses against a memo? |
|-------|------------------------|---------|----------------------------|
| `message_id` (`[u8;32]`) | no (hash of payload) | no | no |
| `origin_pubkey` (`[u8;32]`) | no | no | no |
| `tx_xdr` (`String`, base64 XDR) | **the memo, yes** | **destination, amount, source: yes** | **yes — see below** |
| `ttl_hops` (`u8`) | no | no | no |
| `timestamp` (`u64`) | no | no | no |
| `signature` (`[u8;64]`) | no | no | no (≈incompressible) |

Every field except `tx_xdr` is a hash, a public key, a small integer, or a
random-looking signature. None is attacker-chosen and none shares
exploitable redundancy with a memo.

**`tx_xdr` is the one and only shared compression context.** The transaction
memo, the destination account, and the amount are *all* serialized inside that
single base64 string. In the standard payment layout the memo value sits about
16–48 bytes before the destination public key and about 50–70 bytes before the
8-byte amount — comfortably inside one 32 KiB DEFLATE window. Issue #56 as
scoped ("compress the stored envelope blob") puts all of it in one DEFLATE
stream, so:

* a memo byte string that matches the destination/amount bytes lets LZ77 emit a
  back-reference instead of literals, shrinking the output by ≈1 byte per
  matched byte;
* an attacker who can queue many envelopes with chosen memos (by initiating
  payments *to* this device — see the attacker model) and observe the resulting
  at-rest blob sizes runs the CRIME/BREACH byte-at-a-time recovery.

This is the complete list of shared contexts: **one**, `tx_xdr`, and within it
the memo versus {destination, amount, source account}.

### Confirmed by measurement

`src/storage/compression_oracle.rs` mounts the actual byte-at-a-time attack.
Against the **unmitigated** single-context scheme, on a realistic payment
(pseudo-random 32-byte destination, distinctive amount):

| Target secret | Bytes recovered | Bits | Chosen-plaintext writes |
|---------------|-----------------|------|-------------------------|
| Payment amount, low 4 bytes (top 4 known) | 3 / 4 | 24 | 16 384 |
| Destination account, 4 bytes (8-byte prefix known) | 2 / 4 | 16 | 12 288 |
| Payment amount `0x0EE6B280` (low-entropy fixture, e2e test) | 1 / 4 | 8 | 16 384 |

The signal is genuinely ~1 byte per position and DEFLATE's dynamic-Huffman
repacking quantizes the output, so the harness votes across several probe
rounds with different benign memo fillers — the same statistical shape real
BREACH exploitation needs. Recovery is not always total, but it is
unambiguously present: **the unmitigated pipeline leaks tens of bits of a
secret payment field.**

## 2. Attacker model for *this* crate

Taken from `README.md` (offline-first mesh wallet on shared / low-storage
devices) and issue #93.

**Adversary.** A co-located application on the same device, or a party who can
read the size of the wallet's database file or its backups. **Not** a network
attacker — envelopes in flight are a transport concern, not this crate's.

**Capabilities.**

* *Chosen plaintext:* can cause this device to enqueue envelopes whose **memo**
  it controls, by initiating payments to this device that the wallet queues for
  relay. Rate is effectively unlimited and offline.
* *Observation:* the size of the at-rest artifact per write — the SQLite file's
  growth, a backup's size delta, or (weakly) the timing of the write. The
  harness models the strong end of this: exact, per-write, noise-free size.

**Explicitly weaker than the TLS setting** that CRIME/BREACH target: there is
*no adaptive compression feedback loop over a live channel*, and there is no
mixing of many users' secrets in one stream. The attacker gets size
observations, one per write, and must do the byte-at-a-time search offline.

**Goal.** Recover a secret field of a *third party's* queued transaction —
most damagingly the destination account (deanonymizes a payment) or the amount.

**Out of scope.** In-process memory read (no at-rest defense helps), breaking
AES-GCM, and the metadata `src/encryption.rs` already documents as visible
(row counts, table names, write timing at coarse grain).

## 3. Mitigation: separate contexts + length quantization, no adaptive dictionary

`CompressionScheme::Mitigated` in `src/storage/envelope_compression.rs`.

### 3.1 Separate compression contexts (primary)

The transaction XDR is parsed with `stellar-xdr` (reusing the parse/re-serialize
pattern from `src/envelope/xdr.rs`). The `Memo` is lifted out into its **own**
independent DEFLATE stream; the rest of the envelope, with the memo blanked to
`Memo::None`, is compressed in a **second, separate** DEFLATE stream. The two
streams share no window and no dictionary, so a cross-context LZ77 match — the
entire CRIME mechanism — is structurally impossible.

`compress_at_rest` self-checks that the split reassembles bit-exactly to the
input before committing to it; a non-canonical or unparseable `tx_xdr` falls
back to compressing the whole `rmp_serde` blob as one *secret* stream (empty
attacker stream). That fallback is conservative: worse ratio, but still no
cross-context leak, because the memo is not separately attacker-controlled
relative to anything in that path — the whole thing is treated as secret.

Frame layout (`b"SCz1"` magic, distinct from any `rmp` first byte, so #56 gets
its legacy-row discriminator for free):

```
[0..4]   magic
[4]      scheme tag (0 = Unmitigated, 1 = Mitigated)
[5]      decomposition kind (0 = opaque, 1 = memo-split)
[6..8]   reserved
[8..12]  attacker-stream length  (u32 LE, exact)
[12..16] secret-stream length    (u32 LE, exact)
[16..]   attacker stream, secret stream, then zero padding
```

### 3.2 Length quantization (secondary)

The finished frame is zero-padded so its total length is
`16 + pad16(attacker_len) + pad16(secret_len)`, where `pad16` rounds up to a
multiple of `PAD_GRANULARITY = 16` bytes. Decompression uses the exact recorded
lengths, so the padding is inert. An attacker who knows their own injected memo
knows `pad16(attacker_len)` exactly and subtracts it; what remains resolves the
secret stream's compressed size only to a 16-byte bucket. That removes the
~1-byte granularity the byte-at-a-time search depends on.

16 bytes was chosen to keep #56's ratio: it costs ≈8 bytes/blob on average.
A deployment wanting a stronger guarantee can raise it with no format change
(the frame records nothing about padding).

### 3.3′ Measured size, canonical fixture payment

| | Bytes | % of raw |
|---|-------|----------|
| `rmp_serde(TransactionEnvelope)` — what #12 stores today | 443 | 100 % |
| Unmitigated frame (single context) | 127 | 28.7 % |
| **Mitigated frame (separate contexts + 16-byte quantization)** | **144** | **32.5 %** |

The mitigation still delivers a ~3× reduction; it costs 17 bytes versus the
vulnerable baseline (a second DEFLATE stream header plus up to two 16-byte
padding rounds). Real envelopes carry a random signature and destination that
compress less than this fixture's placeholder `0xbb…`/`0x22…` bytes, but
base64-decoding `tx_xdr` alone is a guaranteed ~25 % win, so a meaningful
reduction always remains (`test_compression_still_provides_meaningful_size_reduction_after_mitigation`
asserts < 85 % of raw).

### 3.3 No adaptive dictionary (rejected alternative)

Issue #93 lists "a fixed, non-adaptive compression dictionary" as an option. We
use **no dictionary at all**. A dictionary *seeded with* or *trained on* memo
content is exactly the adaptive-context bug in a different shape. A dictionary
of only invariant XDR framing bytes would help ratio slightly but adds format
and migration surface for a marginal gain; if #56 wants it later it can be
added to the secret stream only, never the attacker stream.

### 3.4 Alternatives considered

* *Disable compression for `tx_xdr` entirely* — defeats #56's whole purpose
  (that is the field with the redundancy).
* *Pad to exponential buckets (64, 128, 256…)* — much stronger length hiding,
  but on a ~350-byte envelope it inflates the blob 2–4× and fails #56's
  "meaningful size reduction" criterion. Rejected in favour of fine-grained
  quantization plus the (dominant) context separation.
* *Compress after encryption* — encryption output is incompressible; this just
  disables #56.

## 4. Residual leakage — honest accounting

**Cross-context leakage (memo ↔ secret): eliminated.** Separate DEFLATE streams
make it structurally impossible, and the harness confirms it: the mitigated
secret stream is byte-for-byte identical regardless of memo content
(`test_attacker_influenceable_and_secret_fields_use_separate_compression_contexts`),
and the byte-at-a-time attack recovers **0 bytes / 0 bits** in every
configuration tested:

| Target secret | Unmitigated | Mitigated |
|---------------|-------------|-----------|
| Payment amount, low 4 bytes | 24 bits (3/4) | **0 bits (0/4)** |
| Destination account, 4 bytes | 16 bits (2/4) | **0 bits (0/4)** |
| Low-entropy fixture amount (e2e) | 8 bits (1/4) | **0 bits (0/4)** |

**Intra-secret leakage: reduced, not eliminated.** The secret stream's
compressed size still depends on the secret's own contents (e.g. a destination
account that happens to share a run with the source account compresses a little
better). `PAD_GRANULARITY`-byte quantization blunts this to a 16-byte bucket per
observation. An attacker who can force very many writes of the *same* secret can
still detect when its true compressed size sits within a byte of a bucket
boundary and a change pushes it across — bounded at **≤ 1 bit per boundary
crossing near the operating point, and 0 bits when the secret's compressed size
stays mid-bucket.** This is not claimed to be zero. Raising `PAD_GRANULARITY`
trades ratio for a smaller residual.

**Not addressed here (unchanged from `src/encryption.rs`'s model):** row counts,
the *existence* and rough timing of a write, and total database size trends.

## 5. Verification

```
cargo test --lib storage::envelope_compression
cargo test --lib storage::compression_oracle -- --nocapture   # prints the tables above
cargo test --test compression_oracle_test -- --nocapture      # end-to-end with #12 AES-GCM
cargo fmt --all --check && cargo clippy --all-targets -- -D warnings
```

Required tests (all in the two new modules):

* `test_unmitigated_baseline_leaks_secret_byte_via_compressed_length`
* `test_mitigated_implementation_reduces_oracle_signal`
* `test_attacker_influenceable_and_secret_fields_use_separate_compression_contexts`
* `test_compression_still_provides_meaningful_size_reduction_after_mitigation`
