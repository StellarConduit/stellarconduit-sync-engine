//! Throughput benchmarks for [`OutboundTxQueue`] push and pop operations.
//!
//! ## Queue-depth rationale
//!
//! Three representative depths are used:
//!
//! * **1 ("empty")** — the hot path: a device that just came online and is
//!   dispatching a single queued payment. Measures pure per-operation overhead
//!   with a nearly-empty heap.
//! * **256 ("hundreds")** — a moderately busy merchant terminal that has been
//!   offline for several hours and accumulated a realistic backlog. The heap is
//!   large enough that `BinaryHeap`'s O(log n) characteristic starts showing.
//! * **4 096 ("thousands")** — pressure above the three-tier capacity limits;
//!   this benchmark now captures the steady-state *eviction* cost as well as
//!   heap operations rather than assuming all 4 096 entries are retained.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use stellarconduit_core::message::types::TransactionEnvelope;
use stellarconduit_sync_engine::queue::priority::{
    EMERGENCY_CAPACITY, LOW_CAPACITY, NORMAL_CAPACITY,
};
use stellarconduit_sync_engine::queue::{OutboundTxQueue, TxPriority};

fn mock_envelope(id: u32) -> TransactionEnvelope {
    let mut message_id = [0u8; 32];
    message_id[0..4].copy_from_slice(&id.to_le_bytes());
    TransactionEnvelope {
        message_id,
        origin_pubkey: [1u8; 32],
        tx_xdr: "bench_xdr".to_string(),
        ttl_hops: 10,
        timestamp: 1_700_000_000,
        signature: [0u8; 64],
    }
}

/// Benchmark: push N envelopes at mixed priorities into a fresh queue.
fn bench_push(c: &mut Criterion) {
    let mut group = c.benchmark_group("OutboundTxQueue/push");
    let priorities = [TxPriority::Low, TxPriority::Normal, TxPriority::Emergency];

    for depth in [1usize, 256, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &n| {
            b.iter(|| {
                let clock =
                    std::sync::Arc::new(stellarconduit_sync_engine::clock::HybridClock::new());
                let mut q = OutboundTxQueue::new(clock);
                for i in 0..n as u32 {
                    let priority = priorities[(i as usize) % priorities.len()];
                    q.push(mock_envelope(i), priority).unwrap();
                }
                // Each priority is selected round-robin and independently
                // capped. A 4096-input run necessarily exercises evictions.
                let expected_len = n.div_ceil(3).min(LOW_CAPACITY)
                    + ((n + 1) / 3).min(NORMAL_CAPACITY)
                    + (n / 3).min(EMERGENCY_CAPACITY);
                assert_eq!(q.len(), expected_len);
            });
        });
    }
    group.finish();
}

/// Benchmark: pop all N envelopes from a pre-filled queue.
fn bench_pop(c: &mut Criterion) {
    let mut group = c.benchmark_group("OutboundTxQueue/pop");
    let priorities = [TxPriority::Low, TxPriority::Normal, TxPriority::Emergency];

    for depth in [1usize, 256, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, &n| {
            b.iter_batched(
                || {
                    let clock =
                        std::sync::Arc::new(stellarconduit_sync_engine::clock::HybridClock::new());
                    let mut q = OutboundTxQueue::new(clock);
                    for i in 0..n as u32 {
                        let priority = priorities[(i as usize) % priorities.len()];
                        q.push(mock_envelope(i), priority).unwrap();
                    }
                    q
                },
                |mut q| {
                    while q.pop().is_some() {}
                },
                criterion::BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_push, bench_pop);
criterion_main!(benches);
