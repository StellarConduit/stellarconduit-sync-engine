//! Byte-at-a-time compression-oracle measurement harness.
//!
//! This is the instrument issue #93 asks for: it mounts the CRIME / BREACH
//! byte-at-a-time recovery attack against
//! [`crate::storage::envelope_compression`]'s two schemes and reports, in bits,
//! how much of a secret transaction field the compressed-size side channel
//! gives up.
//!
//! # Attack model
//!
//! The attacker can cause this device to queue transaction envelopes whose
//! **memo** they choose (per the issue: by initiating payments *to* this device
//! with a chosen memo), and can observe the size of the resulting at-rest blob
//! (file size, backup size, or write timing). They want a **secret** field of
//! the queued transaction — the payment [`SecretField::Amount`] or
//! [`SecretField::Destination`].
//!
//! For each unknown secret byte the harness, holding the already-known prefix
//! fixed, tries every candidate value in the memo and records the observed blob
//! signal ([`crate::storage::envelope_compression::oracle_observable`]). A
//! correct guess lets DEFLATE replace literals with a back-reference to the
//! identical bytes sitting at the secret's offset in the same window, so it
//! compresses (very slightly) better. Because that per-byte signal is only
//! about one byte and DEFLATE's dynamic-Huffman repacking quantizes the output,
//! each position is probed in several independent *rounds* (different benign
//! memo fillers); the recovered byte is the **majority vote** of the per-round
//! argmin candidates. The harness is deterministic — a fixed compressor, no RNG
//! — and models a *strong* attacker with per-write, noise-free observation,
//! which makes the mitigated-scheme result a conservative upper bound on
//! real-world leakage.
//!
//! # What "recovered" means
//!
//! A position counts as recovered only if the argmin candidate equals the true
//! secret byte. `bits_recovered` is `positions_recovered × log2(alphabet)` — a
//! full recovery over the default 256-value alphabet is 8 bits per byte.

use stellar_xdr::curr::{
    Limits, Memo, MuxedAccount, Operation, OperationBody, ReadXdr, StringM,
    TransactionEnvelope as XdrTxEnvelope, WriteXdr,
};

use stellarconduit_core::message::types::TransactionEnvelope;

use crate::storage::envelope_compression::{oracle_observable, CompressionScheme};

/// Which secret field of the queued payment the harness tries to recover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretField {
    /// The 8-byte big-endian stroop amount. The high bytes are low-entropy for
    /// any sane payment (often zero), which gives the attacker a cheap
    /// bootstrap prefix.
    Amount,
    /// The 32-byte destination account public key. No internal structure, so
    /// the attacker must be *given* a known prefix to bootstrap — the harder,
    /// less realistic case, included for completeness.
    Destination,
}

/// Knobs for [`run_byte_at_a_time_oracle`].
#[derive(Debug, Clone)]
pub struct OracleConfig {
    pub scheme: CompressionScheme,
    /// Bytes of the secret assumed already known. The search extends this
    /// prefix one byte at a time.
    pub known_prefix_len: usize,
    /// How many further byte positions to attempt.
    pub target_positions: usize,
    /// Candidate byte values tried at each position.
    pub candidate_alphabet: Vec<u8>,
    /// Bytes of already-known secret context placed in the memo *before* the
    /// guess (longer context ⇒ longer, more discriminating match). Capped at 26
    /// so at least one byte of the 28-byte MEMO_TEXT budget is left for the
    /// guess.
    pub context_window: usize,
    /// Number of distinct trailing-filler lengths tried per filler byte. More
    /// rounds ⇒ more votes ⇒ more robust recovery against Huffman quantization,
    /// at linear cost in chosen-plaintext writes.
    pub trials_per_candidate: usize,
}

impl OracleConfig {
    /// A realistic amount-recovery attack: the attacker knows the top 4 amount
    /// bytes (low-entropy for any sane payment) and recovers the low 4.
    pub fn amount_recovery(scheme: CompressionScheme) -> Self {
        Self {
            scheme,
            known_prefix_len: 4,
            target_positions: 4,
            candidate_alphabet: (0u8..=255).collect(),
            context_window: 20,
            trials_per_candidate: 4,
        }
    }
}

/// Outcome for one targeted secret byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositionOutcome {
    pub index: usize,
    pub true_byte: u8,
    pub guessed_byte: u8,
    pub recovered: bool,
    /// Distinct candidate values that tied for the minimum signal (1 = a clean
    /// unique minimum).
    pub argmin_ties: usize,
}

/// What the harness recovered.
#[derive(Debug, Clone)]
pub struct OracleReport {
    pub scheme: CompressionScheme,
    pub field: SecretField,
    pub bytes_targeted: usize,
    pub bytes_recovered: usize,
    pub bits_recovered: f64,
    pub chosen_plaintext_writes: usize,
    pub per_position: Vec<PositionOutcome>,
}

impl OracleReport {
    /// A compact one-line summary for logs / PR tables.
    pub fn summary(&self) -> String {
        format!(
            "{:?}/{:?}: recovered {}/{} bytes ({:.1} bits) in {} chosen-plaintext writes",
            self.scheme,
            self.field,
            self.bytes_recovered,
            self.bytes_targeted,
            self.bits_recovered,
            self.chosen_plaintext_writes,
        )
    }
}

fn payment_op(xdr: &XdrTxEnvelope) -> Option<&Operation> {
    let ops = match xdr {
        XdrTxEnvelope::Tx(e) => &e.tx.operations,
        XdrTxEnvelope::TxV0(e) => &e.tx.operations,
        XdrTxEnvelope::TxFeeBump(_) => return None,
    };
    ops.iter()
        .find(|op| matches!(op.body, OperationBody::Payment(_)))
}

/// The ground-truth secret bytes as they appear in `base_env`'s XDR.
fn extract_secret(base_env: &TransactionEnvelope, field: SecretField) -> Vec<u8> {
    let xdr = XdrTxEnvelope::from_xdr_base64(&base_env.tx_xdr, Limits::none())
        .expect("harness base envelope must carry a parseable payment XDR");
    let op = payment_op(&xdr).expect("harness base envelope must contain a payment operation");
    let OperationBody::Payment(p) = &op.body else {
        panic!("harness expects a plain Payment operation");
    };
    match field {
        SecretField::Amount => p.amount.to_be_bytes().to_vec(),
        SecretField::Destination => match &p.destination {
            MuxedAccount::Ed25519(k) => k.0.to_vec(),
            MuxedAccount::MuxedEd25519(m) => m.ed25519.0.to_vec(),
        },
    }
}

/// Build a probe envelope whose memo carries `memo_bytes`.
fn probe_envelope(base_env: &TransactionEnvelope, memo_bytes: &[u8]) -> TransactionEnvelope {
    let mut xdr = XdrTxEnvelope::from_xdr_base64(&base_env.tx_xdr, Limits::none()).unwrap();
    let memo = Memo::Text(StringM::<28>::try_from(memo_bytes.to_vec()).unwrap());
    match &mut xdr {
        XdrTxEnvelope::Tx(e) => e.tx.memo = memo,
        XdrTxEnvelope::TxV0(e) => e.tx.memo = memo,
        XdrTxEnvelope::TxFeeBump(_) => unreachable!("payment envelope, not fee-bump"),
    }
    TransactionEnvelope {
        tx_xdr: xdr.to_xdr_base64(Limits::none()).unwrap(),
        ..base_env.clone()
    }
}

/// Run the byte-at-a-time oracle described in the module docs.
///
/// `base_env.tx_xdr` must be a parseable, canonically-encoded transaction with
/// a `Payment` operation.
pub fn run_byte_at_a_time_oracle(
    base_env: &TransactionEnvelope,
    field: SecretField,
    cfg: &OracleConfig,
) -> OracleReport {
    let secret = extract_secret(base_env, field);
    let alphabet_bits = (cfg.candidate_alphabet.len() as f64).log2();

    // Leave at least 1 byte of the 28-byte MEMO_TEXT budget for the guess;
    // fillers consume whatever remains.
    let max_ctx = cfg.context_window.min(26);

    let mut per_position = Vec::new();
    let mut writes = 0usize;

    for step in 0..cfg.target_positions {
        let idx = cfg.known_prefix_len + step;
        if idx >= secret.len() {
            break;
        }
        let true_byte = secret[idx];

        // Known context: the real secret bytes ending just before `idx`
        // (the attacker knows the prefix + everything recovered so far).
        let ctx_start = idx.saturating_sub(max_ctx);
        let context = &secret[ctx_start..idx];

        // Fillers that perturb the DEFLATE Huffman table without touching the
        // `context || guess` run that carries the signal. Each `(byte, len)`
        // pair is one independent oracle "round"; the recovered byte is the
        // majority vote of the per-round argmin candidates, which is far more
        // robust to Huffman-repacking quantization than a single measurement.
        const FILLERS: &[u8; 4] = b"#.~@";
        let budget = 28usize.saturating_sub(context.len() + 1);
        let rounds: Vec<(u8, usize)> = FILLERS
            .iter()
            .flat_map(|&fb| {
                (0..=budget)
                    .step_by(2)
                    .take(cfg.trials_per_candidate.max(1))
                    .map(move |len| (fb, len))
            })
            .collect();

        let mut votes = vec![0usize; 256];
        for &(fb, flen) in &rounds {
            let mut round_best: Option<(usize, u8)> = None;
            let mut round_ties: Vec<u8> = Vec::new();
            for &cand in &cfg.candidate_alphabet {
                let mut memo = Vec::with_capacity(context.len() + 1 + flen);
                memo.extend_from_slice(context);
                memo.push(cand);
                memo.extend(std::iter::repeat_n(fb, flen));
                let observed =
                    oracle_observable(&probe_envelope(base_env, &memo), cfg.scheme).unwrap();
                writes += 1;
                match round_best {
                    Some((b, _)) if observed > b => {}
                    Some((b, _)) if observed == b => round_ties.push(cand),
                    _ => {
                        round_best = Some((observed, cand));
                        round_ties = vec![cand];
                    }
                }
            }
            // A round only votes when it has a unique minimum.
            if round_ties.len() == 1 {
                votes[round_ties[0] as usize] += 1;
            }
        }

        let (guessed_byte, top_votes) = votes
            .iter()
            .enumerate()
            .max_by_key(|(_, v)| **v)
            .map(|(b, v)| (b as u8, *v))
            .unwrap();
        let ties = votes
            .iter()
            .filter(|v| **v == top_votes && top_votes > 0)
            .count();
        per_position.push(PositionOutcome {
            index: idx,
            true_byte,
            guessed_byte: if top_votes == 0 { 0 } else { guessed_byte },
            recovered: top_votes > 0 && guessed_byte == true_byte && ties == 1,
            argmin_ties: ties,
        });
    }

    let bytes_recovered = per_position.iter().filter(|p| p.recovered).count();
    OracleReport {
        scheme: cfg.scheme,
        field,
        bytes_targeted: per_position.len(),
        bytes_recovered,
        bits_recovered: bytes_recovered as f64 * alphabet_bits,
        chosen_plaintext_writes: writes,
        per_position,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use stellar_xdr::curr::Uint256;

    /// A payment envelope with a **pseudo-random** destination and a
    /// distinctive amount, so the oracle has to exploit real byte structure
    /// rather than the all-`0x22` placeholder destination in the raw fixture.
    fn base_envelope() -> TransactionEnvelope {
        let path = format!(
            "{}/tests/fixtures/transaction_v1_envelope.b64",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(path).unwrap().trim().to_string();
        let mut xdr = XdrTxEnvelope::from_xdr_base64(&raw, Limits::none()).unwrap();

        let dest: [u8; 32] = Sha256::digest(b"oracle-harness destination v1").into();
        if let XdrTxEnvelope::Tx(e) = &mut xdr {
            if let Some(op) = e.tx.operations.to_vec().first().cloned() {
                if let OperationBody::Payment(mut p) = op.body {
                    p.destination = MuxedAccount::Ed25519(Uint256(dest));
                    p.amount = 0x0123_4567_89ab_cdef_i64;
                    let ops = vec![Operation {
                        source_account: None,
                        body: OperationBody::Payment(p),
                    }];
                    e.tx.operations = ops.try_into().unwrap();
                }
            }
        }

        TransactionEnvelope {
            message_id: [3u8; 32],
            origin_pubkey: [4u8; 32],
            tx_xdr: xdr.to_xdr_base64(Limits::none()).unwrap(),
            ttl_hops: 9,
            timestamp: 1_699_999_999,
            signature: [0x11; 64],
        }
    }

    #[test]
    fn test_unmitigated_baseline_leaks_secret_byte_via_compressed_length() {
        let base = base_envelope();
        let cfg = OracleConfig::amount_recovery(CompressionScheme::Unmitigated);
        let report = run_byte_at_a_time_oracle(&base, SecretField::Amount, &cfg);

        eprintln!("BASELINE  {}", report.summary());
        for p in &report.per_position {
            eprintln!(
                "  byte[{}] true={:#04x} guess={:#04x} recovered={} ties={}",
                p.index, p.true_byte, p.guessed_byte, p.recovered, p.argmin_ties
            );
        }

        assert!(
            report.bytes_recovered >= 1,
            "the unmitigated compress-then-encrypt pipeline was expected to leak \
             at least one secret byte through compressed length; recovered {}",
            report.bytes_recovered
        );
    }

    #[test]
    fn test_mitigated_implementation_reduces_oracle_signal() {
        let base = base_envelope();

        let unmit = run_byte_at_a_time_oracle(
            &base,
            SecretField::Amount,
            &OracleConfig::amount_recovery(CompressionScheme::Unmitigated),
        );
        let mit = run_byte_at_a_time_oracle(
            &base,
            SecretField::Amount,
            &OracleConfig::amount_recovery(CompressionScheme::Mitigated),
        );

        eprintln!("BASELINE  {}", unmit.summary());
        eprintln!("MITIGATED {}", mit.summary());

        assert!(
            mit.bytes_recovered < unmit.bytes_recovered,
            "mitigation did not reduce recovery: baseline {} vs mitigated {}",
            unmit.bytes_recovered,
            mit.bytes_recovered
        );
        assert!(
            mit.bits_recovered <= 1.0,
            "mitigated scheme still leaks {:.1} bits (> 1.0) of the secret amount",
            mit.bits_recovered
        );
    }

    #[test]
    fn test_destination_recovery_also_mitigated() {
        let base = base_envelope();
        // Give the attacker a generous 8-byte known prefix of the destination.
        let mk = |scheme| OracleConfig {
            scheme,
            known_prefix_len: 8,
            target_positions: 4,
            candidate_alphabet: (0u8..=255).collect(),
            context_window: 12,
            trials_per_candidate: 3,
        };
        let unmit = run_byte_at_a_time_oracle(
            &base,
            SecretField::Destination,
            &mk(CompressionScheme::Unmitigated),
        );
        let mit = run_byte_at_a_time_oracle(
            &base,
            SecretField::Destination,
            &mk(CompressionScheme::Mitigated),
        );
        eprintln!("DEST BASELINE  {}", unmit.summary());
        eprintln!("DEST MITIGATED {}", mit.summary());
        assert!(mit.bytes_recovered <= unmit.bytes_recovered);
    }
}
