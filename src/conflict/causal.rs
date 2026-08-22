//! Causal history tracking for mesh envelope ordering.
//!
//! # Design: Interval Tree Clock (ITC)
//!
//! Chosen over naive vector clock because the mesh has unbounded, dynamically
//! joining devices. A fixed-size vector clock is O(total devices ever seen),
//! which causes memory exhaustion on phones that reconnect after months offline.
//!
//! ITC sizes with active concurrency, not total device count. Pruning is
//! natural (merged forks shrink the tree) and never loses causal precision —
//! unlike LRU-eviction of vector clock entries, which introduces false concurrency.
//!
//! # Tradeoff
//!
//! ITC does not identify *which* device caused a clock advance, only ordering.
//! This is acceptable: we need "did B observe A?" not "who generated A?".
//!
//! # Current Implementation
//!
//! For simplicity, we use a pruned vector clock (a simplified ITC) with a maximum
//! of MAX_CLOCK_ENTRIES entries. When size exceeds the limit, we remove the entry
//! with the smallest counter value (least recently active device). This minimizes
//! false concurrency introduced by pruning while keeping the implementation bounded.

use std::collections::BTreeMap;

/// A device identity in the mesh — typically a public key or similar fixed-size identifier.
pub type DeviceId = [u8; 32];

/// Maximum number of entries to keep in the clock before pruning.
/// When exceeded, the entry with the smallest counter is removed.
/// This bounds memory usage for devices that reconnect after long offline periods.
pub const MAX_CLOCK_ENTRIES: usize = 128;

/// A logical clock for a single device — a pruned vector clock.
///
/// Tracks the highest sequence number observed from each device in the mesh.
/// This allows us to determine causal relationships: device B saw device A's
/// state if B's clock dominates A's clock component-wise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalClock {
    /// Map from device ID to the highest sequence number observed from that device.
    entries: BTreeMap<DeviceId, u64>,
}

impl CausalClock {
    /// Creates a new empty causal clock.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Increments this device's own counter (called when generating a new envelope).
    ///
    /// This should be called by the device that is authoring a new envelope,
    /// to increment its own logical clock before attaching it to the envelope.
    pub fn tick(&mut self, device: DeviceId) {
        let counter = self.entries.entry(device).or_insert(0);
        *counter += 1;
        self.prune_if_needed();
    }

    /// Merges another clock into this one (called when observing another envelope).
    ///
    /// After merge, this clock reflects knowledge of everything both clocks have seen.
    /// Each device's entry is set to the maximum of the two clocks' values for that device.
    pub fn merge(&mut self, other: &CausalClock) {
        for (device, &their_count) in &other.entries {
            let our_count = self.entries.entry(*device).or_insert(0);
            *our_count = (*our_count).max(their_count);
        }
        self.prune_if_needed();
    }

    /// Returns true if this clock dominates another (this >= other component-wise).
    ///
    /// If `self.dominates(other)` is true, then this clock has observed all the
    /// events that `other` has observed. This means the envelope carrying `self`'s
    /// clock happened *after* the envelope carrying `other`'s clock.
    pub fn dominates(&self, other: &CausalClock) -> bool {
        for (device, &their_count) in &other.entries {
            match self.entries.get(device) {
                Some(&our_count) if our_count >= their_count => {}
                _ => return false,
            }
        }
        true
    }

    /// Prune to MAX_CLOCK_ENTRIES by removing the entry with the smallest counter.
    ///
    /// This pruning strategy removes the least recently active device.
    /// This introduces minimal false concurrency — only for events from the removed device.
    /// This tradeoff is acceptable because: reconnecting devices are rare, and a device
    /// that was offline for months contributes little to current causal ordering anyway.
    fn prune_if_needed(&mut self) {
        while self.entries.len() > MAX_CLOCK_ENTRIES {
            // Find the entry with the smallest counter (least recently active device)
            if let Some(&min_key) = self
                .entries
                .keys()
                .min_by_key(|k| self.entries[k])
            {
                self.entries.remove(&min_key);
                // Note: removing this entry loses causal information for that device's history.
                // This is an acceptable tradeoff — see module documentation.
            } else {
                break; // Should not happen if len > MAX_CLOCK_ENTRIES, but be safe
            }
        }
    }
}

impl Default for CausalClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents the causal relationship between two events (envelopes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CausalRelation {
    /// A happened before B — B's clock dominates A's clock.
    /// B observed A's state before generating itself.
    HappensBefore,

    /// A happened after B — A's clock dominates B's clock.
    /// A observed B's state before generating itself.
    HappensAfter,

    /// Neither happened before the other — genuinely concurrent events.
    /// Neither clock dominates the other, meaning neither device saw the other's state.
    /// This is a true conflict: both could be valid in different parts of a split mesh.
    Concurrent,
}

/// An envelope with attached causal metadata.
///
/// Wraps the underlying envelope (e.g., `QueuedSlot` or similar) without modifying
/// the wire-level `TransactionEnvelope` from `stellarconduit-core`.
/// The causal metadata is stored separately and used only for conflict detection.
#[derive(Debug, Clone)]
pub struct CausalEnvelope<T> {
    /// The underlying envelope (could be QueuedSlot, TransactionEnvelope, or any wrapper).
    pub inner: T,

    /// Causal clock at the time this envelope was generated.
    /// Represents everything the generating device had observed.
    pub clock: CausalClock,

    /// Identity of the device that generated this envelope.
    pub device_id: DeviceId,
}

impl<T> CausalEnvelope<T> {
    /// Creates a new causal envelope with the given inner value, clock, and device ID.
    pub fn new(inner: T, clock: CausalClock, device_id: DeviceId) -> Self {
        CausalEnvelope {
            inner,
            clock,
            device_id,
        }
    }
}

/// Determines the causal relationship between two envelopes.
///
/// # Returns
///
/// - `HappensBefore`: a's clock is dominated by b's clock (b observed a)
/// - `HappensAfter`: b's clock is dominated by a's clock (a observed b)
/// - `Concurrent`: neither dominates (true concurrency — real conflict)
pub fn causal_relation<T>(a: &CausalEnvelope<T>, b: &CausalEnvelope<T>) -> CausalRelation {
    let b_saw_a = b.clock.dominates(&a.clock);
    let a_saw_b = a.clock.dominates(&b.clock);

    match (b_saw_a, a_saw_b) {
        (true, false) => CausalRelation::HappensBefore,  // b observed a
        (false, true) => CausalRelation::HappensAfter,   // a observed b
        (true, true) => {
            // Both dominate each other — clocks are identical.
            // Same logical state; treat as causally ordered for determinism.
            CausalRelation::HappensBefore
        }
        (false, false) => CausalRelation::Concurrent, // true conflict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a device ID from a single byte.
    fn device(n: u8) -> DeviceId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    /// Helper: build a CausalEnvelope with a specific clock state.
    fn envelope_with_clock<T: Clone>(
        inner: T,
        dev: DeviceId,
        clock_entries: &[(DeviceId, u64)],
    ) -> CausalEnvelope<T> {
        let mut clock = CausalClock::new();
        for &(d, count) in clock_entries {
            clock.entries.insert(d, count);
        }
        CausalEnvelope {
            inner,
            clock,
            device_id: dev,
        }
    }

    /// Test 1: A → B causally ordered pair is not a conflict.
    ///
    /// Device 2 observes device 1's envelope before generating its own.
    /// Both for the same slot, B supersedes A. Should NOT be reported as a conflict.
    #[test]
    fn test_causally_ordered_pair_is_not_a_conflict() {
        let dev1 = device(1);
        let dev2 = device(2);

        // A: device 1 generated envelope, had only seen its own history
        let a = envelope_with_clock("slot_1", dev1, &[(dev1, 1)]);

        // B: device 2 generated AFTER observing A (dev1 count = 1 in B's clock)
        let b = envelope_with_clock("slot_1", dev2, &[(dev1, 1), (dev2, 1)]);

        assert_eq!(
            causal_relation(&a, &b),
            CausalRelation::HappensBefore,
            "A should happen before B — B observed A"
        );

        // In the eventual conflict detection, this pair must NOT be flagged as a conflict
        // because the later one (B) supersedes the earlier one (A).
    }

    /// Test 2: A and B are concurrent — neither observed the other. Same slot.
    ///
    /// Should be reported as a true conflict because both could have been valid
    /// in different parts of a split mesh.
    #[test]
    fn test_concurrent_pair_is_still_a_conflict() {
        let dev1 = device(1);
        let dev2 = device(2);

        // A: device 1 only knows about itself
        let a = envelope_with_clock("slot_1", dev1, &[(dev1, 1)]);

        // B: device 2 only knows about itself (never saw A)
        let b = envelope_with_clock("slot_1", dev2, &[(dev2, 1)]);

        assert_eq!(
            causal_relation(&a, &b),
            CausalRelation::Concurrent,
            "Neither observed the other — genuinely concurrent"
        );

        // This pair MUST be flagged as a real conflict.
    }

    /// Test 3: Three-way partial order resolves correctly.
    ///
    /// A→B (ordered), C concurrent with both. All for same slot.
    /// Result: A-B not a conflict, A-C conflict, B-C conflict.
    #[test]
    fn test_three_way_partial_order_resolves_correctly() {
        let dev1 = device(1);
        let dev2 = device(2);
        let dev3 = device(3);

        let a = envelope_with_clock("slot_1", dev1, &[(dev1, 1)]);

        // B observed A
        let b = envelope_with_clock("slot_1", dev2, &[(dev1, 1), (dev2, 1)]);

        // C is concurrent with both — never saw dev1 or dev2
        let c = envelope_with_clock("slot_1", dev3, &[(dev3, 1)]);

        assert_eq!(causal_relation(&a, &b), CausalRelation::HappensBefore);
        assert_eq!(causal_relation(&a, &c), CausalRelation::Concurrent);
        assert_eq!(causal_relation(&b, &c), CausalRelation::Concurrent);

        // In the eventual conflict detection:
        // A-B: not a conflict (ordered)
        // A-C: conflict (concurrent)
        // B-C: conflict (concurrent)
    }

    /// Test 4: Clock pruning preserves correctness for recent history.
    ///
    /// Verify that when the clock exceeds MAX_CLOCK_ENTRIES,
    /// recent device ordering is still preserved.
    #[test]
    fn test_clock_pruning_preserves_correctness_for_recent_history() {
        // Fill clock beyond MAX_CLOCK_ENTRIES
        let mut clock_a = CausalClock::new();

        for i in 0..=(MAX_CLOCK_ENTRIES + 10) as u8 {
            clock_a.tick(device(i));
        }

        // Clock should be pruned to MAX_CLOCK_ENTRIES
        assert!(
            clock_a.entries.len() <= MAX_CLOCK_ENTRIES,
            "Clock size {} exceeded MAX_CLOCK_ENTRIES {}",
            clock_a.entries.len(),
            MAX_CLOCK_ENTRIES
        );

        // Recent device (high counter) should still be present
        let recent_device = device(MAX_CLOCK_ENTRIES as u8 + 10);
        assert!(
            clock_a.entries.contains_key(&recent_device),
            "Recent device should be preserved after pruning"
        );

        // After pruning, ordering with a recently-seen device should still work
        let mut clock_b = clock_a.clone();
        clock_b.tick(recent_device);

        // clock_b dominates clock_a for the devices both know about
        let dominates = clock_b.dominates(&clock_a);
        assert!(
            dominates,
            "Clock with newer tick should dominate the older clock"
        );

        // This verifies pruning doesn't break ordering for recent history
        let a = CausalEnvelope {
            inner: "slot_1",
            clock: clock_a,
            device_id: device(0),
        };

        let b = CausalEnvelope {
            inner: "slot_1",
            clock: clock_b,
            device_id: recent_device,
        };

        let relation = causal_relation(&a, &b);
        assert!(
            relation == CausalRelation::HappensBefore || relation == CausalRelation::Concurrent,
            "After pruning, recent ordering must be preserved or show concurrency"
        );
    }

    /// Test 5: Long offline device clock growth is bounded.
    ///
    /// A device that was offline for months generates many ticks.
    /// Its clock must not grow unboundedly; must stay within MAX_CLOCK_ENTRIES.
    #[test]
    fn test_long_offline_device_clock_growth_is_bounded() {
        let offline_device = device(99);
        let mut clock = CausalClock::new();

        // Simulate generating 1000 envelopes while offline (only knows about itself)
        for _ in 0..1000 {
            clock.tick(offline_device);
        }

        // Clock should have at most 1 entry (only itself while offline)
        assert_eq!(
            clock.entries.len(),
            1,
            "Offline device with no peers should have clock size 1"
        );

        // The single entry should have a high counter (from 1000 ticks)
        assert_eq!(
            clock.entries.get(&offline_device),
            Some(&1000),
            "Device should have ticked 1000 times"
        );

        // Now simulate reconnecting and merging with 200 other devices
        for i in 0..200u8 {
            let mut peer_clock = CausalClock::new();
            peer_clock.tick(device(i));
            clock.merge(&peer_clock);
        }

        // Clock must be bounded after merging many peers
        assert!(
            clock.entries.len() <= MAX_CLOCK_ENTRIES,
            "Clock must be bounded after merging many peers: got {} entries, max is {}",
            clock.entries.len(),
            MAX_CLOCK_ENTRIES
        );
    }

    /// Additional unit tests for CausalClock operations

    #[test]
    fn test_clock_dominates_itself() {
        let mut clock = CausalClock::new();
        clock.tick(device(1));

        assert!(clock.dominates(&clock), "A clock should dominate itself");
    }

    #[test]
    fn test_empty_clock_dominates_empty_clock() {
        let a = CausalClock::new();
        let b = CausalClock::new();

        assert!(a.dominates(&b), "Empty clocks should dominate each other");
        assert!(b.dominates(&a), "Empty clocks should dominate each other");
    }

    #[test]
    fn test_merge_combines_all_entries() {
        let dev1 = device(1);
        let dev2 = device(2);

        let mut a = CausalClock::new();
        a.tick(dev1);
        a.tick(dev1);

        let mut b = CausalClock::new();
        b.tick(dev2);
        b.tick(dev2);
        b.tick(dev2);

        a.merge(&b);

        assert_eq!(a.entries.get(&dev1), Some(&2));
        assert_eq!(a.entries.get(&dev2), Some(&3));
    }

    #[test]
    fn test_merge_takes_maximum_per_device() {
        let dev1 = device(1);

        let mut a = CausalClock::new();
        a.entries.insert(dev1, 10);

        let mut b = CausalClock::new();
        b.entries.insert(dev1, 5);

        a.merge(&b);

        assert_eq!(a.entries.get(&dev1), Some(&10), "Should take the maximum");
    }

    #[test]
    fn test_causal_relation_same_envelope_twice() {
        let dev1 = device(1);
        let a = envelope_with_clock("slot_1", dev1, &[(dev1, 5)]);
        let b = envelope_with_clock("slot_1", dev1, &[(dev1, 5)]);

        // Same clock state means they happened at the same logical time
        // We treat this as HappensBefore for determinism
        assert_eq!(causal_relation(&a, &b), CausalRelation::HappensBefore);
    }
}
