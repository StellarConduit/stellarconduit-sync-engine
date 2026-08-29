use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use stellarconduit_core::message::envelope::validate_envelope;
use stellarconduit_sync_engine::conflict::{conflicts_between, QueuedSlot};
use stellarconduit_sync_engine::envelope::pq::SigningPolicy;
use stellarconduit_sync_engine::envelope::OfflineEnvelopeBuilder;
use stellarconduit_sync_engine::queue::{OutboundTxQueue, SequenceReservationManager, TxPriority};
use stellarconduit_sync_engine::settlement::{SettlementStatus, SettlementTracker};
use stellarconduit_sync_engine::storage::SyncEngineDb;

#[derive(Parser, Debug)]
#[command(
    name = "mock_relay",
    about = "Mock relay demo for StellarConduit Sync Engine"
)]
struct Args {
    #[arg(long, default_value = "3")]
    payments: usize,
    #[arg(long, default_value = "500")]
    relay_delay_ms: u64,
    #[arg(long)]
    inject_conflict: bool,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   StellarConduit Sync Engine — Mock Relay Demo         ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();

    // ── Scenario A: Normal payment flow ──────────────────────────────
    println!(
        "▸ Scenario A: Queue {} payments and settle via mock relay",
        args.payments
    );
    println!(
        "  (relay delay = {}ms, tiers rotate Emergency → Normal → Low)",
        args.relay_delay_ms
    );
    println!();

    let db = SyncEngineDb::init(":memory:").await.expect("DB init");
    let mut sequences = SequenceReservationManager::new();
    let mut tracker = SettlementTracker::new();
    let clock = std::sync::Arc::new(stellarconduit_sync_engine::clock::HybridClock::new());
    let mut queue = OutboundTxQueue::new(clock);
    let signing_key = SigningKey::generate(&mut OsRng);
    let signer = stellarconduit_sync_engine::envelope::InMemorySigner::new(signing_key.clone());
    let source_account = "GDEMO";

    sequences.seed(source_account, 1_000_000);
    let start = now_secs();

    for i in 0..args.payments {
        let priority = match i % 3 {
            0 => TxPriority::Emergency,
            1 => TxPriority::Normal,
            _ => TxPriority::Low,
        };

        let (hybrid, seq) = OfflineEnvelopeBuilder::build_and_sign(
            &mut sequences,
            source_account,
            &signer,
            &SigningPolicy::ClassicalOnly,
            format!("mock_tx_xdr_{}", i),
            10,
        )
        .expect("build_and_sign");
        let envelope = hybrid.classical_envelope;

        assert!(validate_envelope(&envelope).is_ok());

        queue
            .push(envelope.clone(), priority)
            .expect("push to queue");
        db.enqueue_envelope(&envelope, source_account, seq, priority, start + i as u64)
            .await
            .expect("persist queued envelope");
        db.set_settlement_status(
            envelope.message_id,
            SettlementStatus::Queued,
            start + i as u64,
        )
        .await
        .expect("set Queued status");
        tracker.track(envelope.message_id);

        println!(
            "  📝 Queued   [{}] seq={:<8} {:?}",
            hex::encode(envelope.message_id),
            seq,
            priority
        );
    }

    println!();
    println!("  ── Relay begins picking up payments ──");

    let delay = Duration::from_millis(args.relay_delay_ms);
    let mut settled = 0usize;

    while let Some(envelope) = queue.pop() {
        let mid = envelope.message_id;
        let id_hex = hex::encode(mid);

        // Propagating
        tokio::time::sleep(delay).await;
        let ts = now_secs();
        tracker
            .transition(mid, SettlementStatus::Propagating)
            .expect("transition to Propagating");
        db.set_settlement_status(mid, SettlementStatus::Propagating, ts)
            .await
            .expect("set Propagating");
        println!("  📡 Relaying [{}]  → Propagating", id_hex);

        // Settled
        tokio::time::sleep(delay).await;
        let ts = now_secs();
        tracker
            .transition(mid, SettlementStatus::Settled)
            .expect("transition to Settled");
        db.set_settlement_status(mid, SettlementStatus::Settled, ts)
            .await
            .expect("set Settled");
        println!("  ✅ Settled  [{}]  → Settled", id_hex);

        settled += 1;
    }

    println!();
    println!("  🎯 {} / {} payments settled", settled, args.payments);

    // ── Scenario B: Conflict injection ──────────────────────────────
    if args.inject_conflict {
        println!();
        println!("╔══════════════════════════════════════════════════════════╗");
        println!("║   Scenario B: Conflict Detection                       ║");
        println!("╚══════════════════════════════════════════════════════════╝");
        println!();

        let mut seq_a = SequenceReservationManager::new();
        let mut seq_b = SequenceReservationManager::new();
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let signer_a = stellarconduit_sync_engine::envelope::InMemorySigner::new(key_a.clone());
        let signer_b = stellarconduit_sync_engine::envelope::InMemorySigner::new(key_b.clone());
        let shared = "GSHARED";

        seq_a.seed(shared, 500);
        seq_b.seed(shared, 500);

        let (hybrid_a, s_a) = OfflineEnvelopeBuilder::build_and_sign(
            &mut seq_a,
            shared,
            &signer_a,
            &SigningPolicy::ClassicalOnly,
            "conflict_xdr_a",
            10,
        )
        .expect("build A");
        let env_a = hybrid_a.classical_envelope;

        let (hybrid_b, s_b) = OfflineEnvelopeBuilder::build_and_sign(
            &mut seq_b,
            shared,
            &signer_b,
            &SigningPolicy::ClassicalOnly,
            "conflict_xdr_b",
            10,
        )
        .expect("build B");
        let env_b = hybrid_b.classical_envelope;

        assert_eq!(s_a, s_b);

        let slot_a = QueuedSlot {
            source_account: shared.to_string(),
            sequence: s_a,
            message_id: env_a.message_id,
        };
        let slot_b = QueuedSlot {
            source_account: shared.to_string(),
            sequence: s_b,
            message_id: env_b.message_id,
        };

        println!(
            "  Two devices share account {} and both build a payment",
            shared
        );
        println!("  against sequence {} while offline:", s_a);
        println!("    Device A → [{}]", hex::encode(env_a.message_id));
        println!("    Device B → [{}]", hex::encode(env_b.message_id));
        println!();

        match conflicts_between(&slot_a, &slot_b) {
            Some(c) => {
                println!("  ⚠️  CONFLICT DETECTED");
                println!("     Account:    {}", c.source_account);
                println!("     Sequence:   {}", c.sequence);
                println!("     Envelope A: {}", hex::encode(c.envelope_a));
                println!("     Envelope B: {}", hex::encode(c.envelope_b));
                println!();
                println!("  🔍 Two different envelopes claim the same (account, sequence)");
                println!("     slot — only one can ever settle on-chain.");
                println!("  ❓ Off-chain resolution not yet implemented (see resolver.rs).");
            }
            None => println!("  ✅ No conflict (unexpected)"),
        }
    }

    println!();
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║   Demo complete.                                        ║");
    println!("╚══════════════════════════════════════════════════════════╝");
}
