//! Sybil-Resistant, L1-Anchored Relay Prioritization (Tit-for-Tat)
//!
//! # Problem Context
//! In an offline-first mesh, devices connect to relays to forward queued transactions.
//! A naive relay that processes all incoming traffic equally is vulnerable to Sybil flooding,
//! where an attacker generates thousands of cheap identities to overwhelm the relay with low-value
//! or invalid traffic, crowding out legitimate payments.
//!
//! Because the mesh lacks a fixed identity registry and a local fee market, we cannot rely on
//! traditional identity reputation or local fee auctions.
//!
//! # Mechanism: L1-Anchored Local Reputation
//! This module implements a local reputation tracker for relays. It anchors the reputation of a
//! connecting device (`PeerId`) to the **Stellar L1 Base Fees** paid by the transactions it forwards.
//!
//! 1. **Reward (Proof of Useful Work)**: When a device (mule) forwards a transaction to the relay,
//!    and the transaction **settles successfully** on the Stellar network, the mule earns positive
//!    reputation.
//! 2. **Penalty (Spam Defense)**: If the transaction is **rejected** (e.g., bad signature, bad sequence,
//!    insufficient funds), the mule is heavily penalized.
//!
//! # Sybil Resistance & Game Theory
//! - **Honest Strategy**: An honest device collects valid transactions from peers and forwards them.
//!   Because these transactions are valid, they settle successfully, increasing the device's reputation
//!   at no additional cost. The device thus earns priority for its own transactions.
//! - **Sybil Attack (Garbage Spam)**: An attacker spins up Sybil identities and floods the relay with
//!   invalid transactions. The network rejects them, the attacker is penalized heavily, and their reputation
//!   drops below zero. They gain no priority. If they cycle to new identities (score = 0), they are relegated
//!   to the cold-start bucket, unable to monopolize the relay.
//! - **Sybil Attack (Valid Transactions)**: An attacker spins up Sybils and submits *valid* transactions
//!   to artificially inflate their reputation. Because the transactions are valid, they must pay the
//!   **Stellar L1 Base Fee**. The attacker is forced to burn real XLM to gain priority. This bounds the
//!   attack economically, turning a "free" attack into a paid one. The relay still receives valid traffic.
//!
//! # Cold Start Policy
//! New devices start with a score of `0`. The relay allocates its outbound bandwidth into two buckets:
//! - **Priority**: For high-reputation devices (score > 0).
//! - **Fair-Share**: For new devices (score <= 0), using round-robin.
//!
//! This ensures new users are never locked out, but they cannot monopolize the relay's resources
//! without earning reputation first.

use std::collections::HashMap;

/// Tracks reputation scores of peers (identified by an opaque 32-byte pubkey or ID)
#[derive(Debug, Default)]
pub struct ReputationTracker {
    // Map peer_id -> reputation score
    scores: HashMap<[u8; 32], i64>,
    // Map message_id -> peer_id that submitted it
    in_flight: HashMap<[u8; 32], [u8; 32]>,
}

impl ReputationTracker {
    /// Creates a new, empty reputation tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a specific peer submitted a transaction.
    /// The `message_id` will be used later when the settlement result is known.
    pub fn record_submission(&mut self, peer_id: [u8; 32], message_id: [u8; 32]) {
        self.in_flight.insert(message_id, peer_id);
    }

    /// Record the settlement result of a transaction.
    /// If successful, the submitting peer earns a reward.
    /// If failed, the submitting peer is heavily penalized (Spam defense).
    pub fn apply_settlement_result(&mut self, message_id: [u8; 32], success: bool) {
        if let Some(peer_id) = self.in_flight.remove(&message_id) {
            let score = self.scores.entry(peer_id).or_insert(0);
            if success {
                // Reward: corresponds to the cost paid by the transaction (base fee)
                // We use a fixed unit of +10 for a success for simplicity.
                *score = score.saturating_add(10);
            } else {
                // Penalty: heavily penalize invalid/rejected transactions to stop Sybil spam.
                // Penalty > Reward to ensure that guessing/spamming is negatively EV.
                *score = score.saturating_sub(100);
            }
        }
    }

    /// Get the current reputation score of a peer.
    pub fn score(&self, peer_id: &[u8; 32]) -> i64 {
        *self.scores.get(peer_id).unwrap_or(&0)
    }

    /// Determine if a peer qualifies for the "Priority" bucket.
    pub fn is_priority(&self, peer_id: &[u8; 32]) -> bool {
        self.score(peer_id) > 0
    }
}
