//! Protocol-level counters for the sync engine, mirroring the pattern used in
//! `stellarconduit-core::metrics`. Intended to be exposed by whichever binary
//! embeds this crate (mobile wallet, relay node).
//!
//! # Privacy-preserving export
//!
//! The in-process counters on [`SyncEngineMetrics`] stay exact — the engine
//! and the embedding binary need a precise view of their own queue. What must
//! not leave the device unchanged is a scrape of those counters: on a shared
//! community relay, or anywhere metrics are aggregated centrally, an exact
//! per-device `disputes_escalated` (or a sudden jump in it) can reveal that a
//! particular user or terminal is currently involved in a dispute. In the
//! disaster-relief / vulnerable-population settings this project is built
//! for, that disclosure is a real-world harm, not a theoretical one.
//!
//! [`DpExporter`] is the only supported off-device export path. It releases
//! **windowed event counts** (not lifetime totals) under the Laplace
//! mechanism, with a configurable privacy budget `ε`.
//!
//! ## Why windowed counts, not noisy lifetime totals
//!
//! A monotonically-increasing lifetime counter is the wrong unit to apply
//! differential privacy to, for three independent reasons:
//!
//! 1. **Repeated-query collapse.** A Prometheus scrape every 15s of the
//!    *same* underlying total, each time with fresh independent noise, is
//!    `T` queries against one dataset. Averaging T samples drives the noise
//!    to 0 as `1/√T` (and the Laplace mean is consistent), so the exact
//!    total is recovered in minutes. Noisy-lifetime export would therefore
//!    only be private for a one-shot dump, which is not how metrics are
//!    consumed.
//! 2. **Sensitivity grows with the user.** Neighboring datasets that differ
//!    by one device's entire history can differ by an unbounded amount on a
//!    lifetime total. Calibrating Laplace for that sensitivity makes the
//!    number useless; calibrating for Δ = 1 (one extra event) does *not*
//!    hide a spike of 50 disputes, which is exactly the signal the threat
//!    model cares about at the lifetime scale.
//! 3. **Operators want rates.** Network health monitoring asks "is this
//!    node failing *now*?", not "how many envelopes has it queued since
//!    first boot?". Prometheus `rate()` over a noisy counter is dominated
//!    by the noise jumps, not the true increment.
//!
//! Windowed counts fix all three. Each tumbling window is a *new* dataset:
//! a single event appears in exactly one window, so event-level `(ε, 0)`-DP
//! holds for that event regardless of how many later windows are released.
//! The sensitivity of one windowed counter, for the neighboring relation
//! "one additional event of this type in this window", is **Δ₁ = 1**.
//! Operators still see large rate changes (the health-monitoring job);
//! they cannot confidently confirm a single extra dispute.
//!
//! ## Mechanism: Laplace, not Gaussian
//!
//! The export is a 5-coordinate vector
//! `(queued, settled, failed, conflicts_detected, disputes_escalated)` of
//! windowed counts. One additional event changes **exactly one** coordinate
//! by 1, so the vector's L1 sensitivity is Δ₁ = 1. The Laplace mechanism
//! adds independent `Lap(b = Δ₁/ε)` noise to each coordinate and is
//! `(ε, 0)`-DP for that vector query (Dwork & Roth, *The Algorithmic
//! Foundations of Differential Privacy*, §3.3).
//!
//! Gaussian would give `(ε, δ)`-DP from L2 sensitivity (also 1 here). We
//! do not use it:
//!
//! - Five dimensions is not high enough for the L2/L1 gap to buy accuracy.
//! - Operators would have to pick `δ` as well as `ε`. `δ`-composition over
//!   years of scrapes is easy to get wrong and hard to explain.
//! - Pure `ε`-DP composes by addition with no extra parameter: T windows
//!   cost `Tε` under *user-level* composition (a user active in every
//!   window), and still just `ε` under *event-level* composition (the
//!   threat in the issue — "is this device in a dispute *right now*").
//!
//! Negative noisy counts are clamped to 0 before release. Clamping is a
//! function of the already-noised value, so post-processing immunity
//! preserves the DP guarantee. It introduces a small positive bias when
//! the true window count is near zero; that bias is visible in the
//! accuracy table below and is why the default `ε = 1` is a better
//! starting point than very small `ε` for sparse counters like
//! `disputes_escalated`.
//!
//! ## Repeated queries and the privacy budget
//!
//! Differential privacy is not free to re-apply. The policy this crate
//! **enforces**, not merely documents:
//!
//! - **One noisy snapshot per window.** The first scrape that needs a
//!   new window spends `ε` once, caches the result, and every subsequent
//!   scrape inside that window returns the *same* bytes. A 15-second
//!   Prometheus scrape against a 60-second window therefore costs `ε` per
//!   minute, not `ε` per scrape. Re-noising on every scrape is rejected
//!   because it would let an observer average out the noise.
//! - **Event-level DP does not erode across windows.** An event is in one
//!   window. Observing later windows does not spend more budget *against
//!   that event*. This is the threat model in the issue (current
//!   involvement in a dispute), and it is why the default configuration
//!   does not cap the number of window releases: network health monitoring
//!   is a continuous process, and stopping the endpoint after N scrapes
//!   would make the metrics useless.
//! - **User-level composition is opt-in.** If a deployment's threat model
//!   is "hide this device's *whole* activity over the lifetime of the
//!   process" rather than "hide a single event", T released windows
//!   compose to `Tε`. [`DpExportConfig::with_max_releases`] enforces a
//!   hard cap: after that many distinct window releases, further rolls
//!   return [`DpExportError::BudgetExhausted`] rather than falling back
//!   to the exact counters (a silent fallback would be a privacy hole).
//!   The last cached snapshot remains available until its window expires.
//!
//! The risk of the default (uncapped) policy, stated plainly: an adversary
//! who observes every window for a long-lived process learns the device's
//! approximate *activity level over time* to within Laplace noise per
//! window. They still cannot confirm any individual event at better than
//! `e^ε` odds. Deployments that consider the activity-level trace itself
//! sensitive should set `max_releases` (and/or a larger window / smaller
//! `ε`).
//!
//! ## Accuracy / privacy tradeoff
//!
//! For `Lap(b = 1/ε)` the mean absolute error is `b`, and the two-sided
//! percentiles of `|noise|` are `t = −b ln(1 − p)`:
//!
//! | `ε` | MAE (`b`) | 50th \|noise\| | 95th \|noise\| | 99th \|noise\| | What an operator can still see |
//! |-----|-----------|----------------|----------------|----------------|--------------------------------|
//! | 0.1 | 10 | 6.9 | 30.0 | 46.1 | Outages and spikes of tens of events; a single dispute is well hidden. Sparse counters (`disputes_escalated`) will often read as a small positive even when truly 0 (clamp bias). |
//! | 0.5 | 2 | 1.4 | 6.0 | 9.2 | Changes of ~10+ events stand out; 1–3 extra events do not. |
//! | 1.0 | 1 | 0.69 | 3.0 | 4.6 | **Default.** Rate changes of ~10+ are clear; a single extra dispute cannot be confirmed. |
//! | 2.0 | 0.5 | 0.35 | 1.5 | 2.3 | Light privacy. Appropriate when scrapes are already aggregated across many devices before anyone looks at them. |
//!
//! These figures are exact properties of the Laplace distribution (they
//! do not depend on the true count, other than the near-zero clamp bias)
//! and are the numbers an operator should use when picking `ε`.
//! [`DpExportConfig::moderate`], [`DpExportConfig::strict`], and
//! [`DpExportConfig::relaxed`] pin the three common operating points.
//!
//! ## What this module will not do
//!
//! - It will not export exact lifetime totals, even alongside the noisy
//!   gauges. A second, exact channel would void the DP guarantee.
//! - It will not re-noise a cached window because a caller asked nicely.
//! - It will not, on budget exhaustion, return the raw atomics.

use std::fmt::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Plain-data snapshot of all counters at a point in time.
///
/// This is an approximate, independently-read snapshot — not a transactionally
/// consistent one. Each counter is read separately, so cross-field atomicity
/// is not guaranteed. This is acceptable for monitoring/reporting purposes
/// where perfect consistency is not required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Total number of envelopes ever queued (lifetime counter).
    pub queued_total: usize,
    /// Total number of envelopes successfully settled on-chain (lifetime counter).
    pub settled_total: usize,
    /// Total number of envelopes that failed to settle (lifetime counter).
    pub failed_total: usize,
    /// Total number of double-spend conflicts detected (lifetime counter).
    pub conflicts_detected: usize,
    /// Total number of conflicts that could not be resolved off-chain and
    /// required escalation to the on-chain dispute resolver (lifetime counter).
    pub disputes_escalated: usize,
    /// Total number of envelopes evicted from the queue due to staleness
    /// or TTL expiration (lifetime counter), including capacity evictions.
    pub queue_evictions: usize,
}

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use thiserror::Error;

/// L1 sensitivity of the 5-counter windowed vector: one extra event
/// changes exactly one coordinate by 1.
pub const L1_SENSITIVITY: f64 = 1.0;

/// Number of counters released together as one vector query.
const METRIC_COUNT: usize = 5;

/// In-process exact counters. These are **not** an export API.
///
/// Off-device scrapes must go through [`DpExporter`]. Direct reads of
/// these atomics are for the embedding binary's own diagnostics (crash
/// reports, on-device UI) where the observer is the device owner, not a
/// central aggregator.
#[derive(Debug, Default)]
pub struct SyncEngineMetrics {
    pub queued_total: AtomicUsize,
    pub settled_total: AtomicUsize,
    pub failed_total: AtomicUsize,
    pub conflicts_detected: AtomicUsize,
    pub disputes_escalated: AtomicUsize,
    /// Count of envelopes evicted from queue due to capacity or staleness/TTL expiration.
    pub queue_evictions: AtomicUsize,
}

impl SyncEngineMetrics {
    /// Create a new metrics instance with all counters initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Capture a snapshot of all counter values at this moment.
    ///
    /// Returns a plain-data struct capturing every counter's current value.
    /// This is an approximate, independently-read snapshot — not a
    /// transactionally consistent one. Each counter is read atomically, but
    /// the reads are not coordinated across fields. This is acceptable for
    /// monitoring/reporting purposes where perfect consistency is not required.
    ///
    /// Use this for:
    /// - Exposing current state to monitoring dashboards
    /// - Periodic reporting of absolute values
    /// - Debugging and introspection
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queued_total: self.queued_total.load(Ordering::Relaxed),
            settled_total: self.settled_total.load(Ordering::Relaxed),
            failed_total: self.failed_total.load(Ordering::Relaxed),
            conflicts_detected: self.conflicts_detected.load(Ordering::Relaxed),
            disputes_escalated: self.disputes_escalated.load(Ordering::Relaxed),
            queue_evictions: self.queue_evictions.load(Ordering::Relaxed),
        }
    }

    /// Capture a snapshot and reset all counters to zero.
    ///
    /// This is useful for callers who want periodic deltas rather than
    /// lifetime totals. After calling this method, the snapshot contains
    /// the values that were present immediately before the reset, and all
    /// counters are reset to zero.
    ///
    /// Use this for:
    /// - Periodic reporting windows (e.g., "how many payments this hour")
    /// - Calculating deltas between reporting periods
    /// - Time-windowed monitoring
    ///
    /// Note: Like `snapshot()`, this is not transactionally consistent —
    /// each counter is read and reset independently.
    pub fn snapshot_and_reset(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queued_total: self.queued_total.swap(0, Ordering::Relaxed),
            settled_total: self.settled_total.swap(0, Ordering::Relaxed),
            failed_total: self.failed_total.swap(0, Ordering::Relaxed),
            conflicts_detected: self.conflicts_detected.swap(0, Ordering::Relaxed),
            disputes_escalated: self.disputes_escalated.swap(0, Ordering::Relaxed),
            queue_evictions: self.queue_evictions.swap(0, Ordering::Relaxed),
        }
    }

    /// Export metrics in Prometheus text exposition format.
    ///
    /// Returns a string in the Prometheus text format (version 0.0.4) suitable
    /// for scraping by a Prometheus server. All counters are exported with
    /// appropriate `# TYPE` and `# HELP` annotations following Prometheus
    /// naming conventions.
    ///
    /// The metric names follow the pattern `stellarconduit_sync_<name>_total`
    /// for consistency with Prometheus naming best practices (counters should
    /// have a `_total` suffix).
    ///
    /// See: https://prometheus.io/docs/instrumenting/exposition_formats/
    pub fn to_prometheus_text(&self) -> String {
        let snapshot = self.snapshot();
        let mut output = String::new();

        // queued_total
        output.push_str(
            "# HELP stellarconduit_sync_queued_total Total number of envelopes ever queued.\n",
        );
        output.push_str("# TYPE stellarconduit_sync_queued_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_queued_total {}\n",
            snapshot.queued_total
        ));

        // settled_total
        output.push_str("# HELP stellarconduit_sync_settled_total Total number of envelopes successfully settled on-chain.\n");
        output.push_str("# TYPE stellarconduit_sync_settled_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_settled_total {}\n",
            snapshot.settled_total
        ));

        // failed_total
        output.push_str("# HELP stellarconduit_sync_failed_total Total number of envelopes that failed to settle.\n");
        output.push_str("# TYPE stellarconduit_sync_failed_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_failed_total {}\n",
            snapshot.failed_total
        ));

        // conflicts_detected
        output.push_str("# HELP stellarconduit_sync_conflicts_detected_total Total number of double-spend conflicts detected.\n");
        output.push_str("# TYPE stellarconduit_sync_conflicts_detected_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_conflicts_detected_total {}\n",
            snapshot.conflicts_detected
        ));

        // disputes_escalated
        output.push_str("# HELP stellarconduit_sync_disputes_escalated_total Total number of conflicts escalated to on-chain dispute resolver.\n");
        output.push_str("# TYPE stellarconduit_sync_disputes_escalated_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_disputes_escalated_total {}\n",
            snapshot.disputes_escalated
        ));

        // queue_evictions
        output.push_str("# HELP stellarconduit_sync_queue_evictions_total Total number of envelopes evicted from queue due to capacity, staleness or TTL.\n");
        output.push_str("# TYPE stellarconduit_sync_queue_evictions_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_queue_evictions_total {}\n",
            snapshot.queue_evictions
        ));

        output
    }

    /// Record one newly-queued envelope.
    pub fn record_queued(&self) {
        self.queued_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one envelope reaching `Settled`.
    pub fn record_settled(&self) {
        self.settled_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one envelope reaching `Failed`.
    pub fn record_failed(&self) {
        self.failed_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one newly-detected double-spend conflict.
    pub fn record_conflict(&self) {
        self.conflicts_detected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one dispute that was escalated off this device.
    pub fn record_dispute_escalated(&self) {
        self.disputes_escalated.fetch_add(1, Ordering::Relaxed);
    }

    fn lifetime_vec(&self) -> [usize; METRIC_COUNT] {
        [
            self.queued_total.load(Ordering::Relaxed),
            self.settled_total.load(Ordering::Relaxed),
            self.failed_total.load(Ordering::Relaxed),
            self.conflicts_detected.load(Ordering::Relaxed),
            self.disputes_escalated.load(Ordering::Relaxed),
        ]
    }
}

/// Laplace scale `b = Δ₁ / ε` for the windowed vector query.
///
/// Mean absolute error of a released coordinate is exactly this value
/// (before the non-negativity clamp).
#[must_use]
pub fn laplace_scale(epsilon: f64) -> f64 {
    L1_SENSITIVITY / epsilon
}

/// Inverse-CDF sample of `Lap(0, scale)`.
///
/// `U ~ Uniform(-0.5, 0.5) \ {0}`; `X = −b sgn(U) ln(1 − 2|U|)`.
/// Draws that land on the open-interval endpoints (where `ln` would
/// diverge) are rejected and resampled — a measure-zero event in
/// theory, a `gen::<f64>()` hitting `0.0` in practice.
fn sample_laplace<R: Rng + ?Sized>(scale: f64, rng: &mut R) -> f64 {
    debug_assert!(scale > 0.0 && scale.is_finite());
    loop {
        let u: f64 = rng.gen::<f64>() - 0.5;
        let one_minus_two_abs = 1.0 - 2.0 * u.abs();
        if u != 0.0 && one_minus_two_abs > 0.0 {
            return -scale * u.signum() * one_minus_two_abs.ln();
        }
    }
}

/// Tunables for [`DpExporter`].
///
/// Construct via [`DpExportConfig::new`] or one of the named operating
/// points ([`moderate`](DpExportConfig::moderate),
/// [`strict`](DpExportConfig::strict),
/// [`relaxed`](DpExportConfig::relaxed)) so `ε` and the window are
/// validated up front rather than on the first scrape.
#[derive(Debug, Clone, PartialEq)]
pub struct DpExportConfig {
    /// Per-window privacy budget for the 5-counter vector query.
    /// Smaller is more private and noisier. See the module-level accuracy
    /// table.
    pub epsilon: f64,
    /// Tumbling-window length. Repeated scrapes inside one window reuse
    /// the cached noisy snapshot and do **not** spend more budget.
    pub window: Duration,
    /// Hard cap on the number of distinct window releases. `None`
    /// (default) means unlimited: event-level DP stays `ε` forever, and
    /// user-level composition grows as `Tε`. See the module docs.
    pub max_releases: Option<u32>,
}

impl DpExportConfig {
    /// `ε = 1.0`, 60-second window, no lifetime cap.
    ///
    /// The default operating point in the accuracy table: a single extra
    /// event cannot be confirmed, rate changes of ~10+ remain visible,
    /// and a 15-second Prometheus scrape costs `ε` once per minute.
    #[must_use]
    pub fn moderate() -> Self {
        Self {
            epsilon: 1.0,
            window: Duration::from_secs(60),
            max_releases: None,
        }
    }

    /// `ε = 0.1`, 5-minute window, no lifetime cap.
    ///
    /// For shared community terminals and other high-risk deployments.
    /// MAE is 10 events; sparse counters will show clamp bias.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            epsilon: 0.1,
            window: Duration::from_secs(300),
            max_releases: None,
        }
    }

    /// `ε = 2.0`, 15-second window, no lifetime cap.
    ///
    /// For deployments that already aggregate many devices before a
    /// human looks at the numbers, and that want scrape-granularity
    /// rates. Light privacy on any *single* device's export.
    #[must_use]
    pub fn relaxed() -> Self {
        Self {
            epsilon: 2.0,
            window: Duration::from_secs(15),
            max_releases: None,
        }
    }

    /// Validated constructor. `epsilon` must be finite and strictly
    /// positive; `window` must be at least 1 millisecond.
    pub fn new(epsilon: f64, window: Duration) -> Result<Self, DpExportError> {
        let cfg = Self {
            epsilon,
            window,
            max_releases: None,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Cap distinct window releases at `max_releases` (must be ≥ 1).
    ///
    /// After the cap, [`DpExporter::export`] returns
    /// [`DpExportError::BudgetExhausted`] instead of producing a new
    /// noisy snapshot. The last snapshot is still served until its
    /// window expires. This is the user-level composition bound: total
    /// spend is at most `max_releases * epsilon`.
    pub fn with_max_releases(mut self, max_releases: u32) -> Result<Self, DpExportError> {
        if max_releases == 0 {
            return Err(DpExportError::InvalidConfig(
                "max_releases must be at least 1",
            ));
        }
        self.max_releases = Some(max_releases);
        Ok(self)
    }

    fn validate(&self) -> Result<(), DpExportError> {
        if !(self.epsilon > 0.0 && self.epsilon.is_finite()) {
            return Err(DpExportError::InvalidConfig(
                "epsilon must be finite and strictly positive",
            ));
        }
        if self.window < Duration::from_millis(1) {
            return Err(DpExportError::InvalidConfig("window must be at least 1ms"));
        }
        if self.max_releases == Some(0) {
            return Err(DpExportError::InvalidConfig(
                "max_releases must be at least 1",
            ));
        }
        Ok(())
    }

    fn window_ms(&self) -> u64 {
        self.window.as_millis() as u64
    }
}

/// Failure to produce a DP export. Never contains the true counter
/// values — callers must not "recover" from this by reading the atomics
/// and shipping them instead.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DpExportError {
    #[error("invalid DP export config: {0}")]
    InvalidConfig(&'static str),

    /// The configured lifetime budget has been spent. The previous
    /// snapshot is no longer in-window, and producing a new one would
    /// exceed `max_releases`.
    #[error(
        "privacy budget exhausted: {releases_done} window releases already produced \
         (cap {max_releases}); refusing to re-noise or to return exact counters"
    )]
    BudgetExhausted {
        releases_done: u32,
        max_releases: u32,
    },
}

/// One `(ε, 0)`-DP release of the windowed counter vector.
///
/// Values are Laplace-noised windowed counts, clamped below at 0. They
/// are **not** lifetime totals and **not** the true window counts.
#[derive(Debug, Clone, PartialEq)]
pub struct DpSnapshot {
    pub queued: f64,
    pub settled: f64,
    pub failed: f64,
    pub conflicts_detected: f64,
    pub disputes_escalated: f64,
    /// `ε` this release was calibrated at.
    pub epsilon: f64,
    /// Distinct window releases produced by this exporter, including
    /// this snapshot. Stays put when a scrape reuses the cache.
    pub releases_done: u32,
    /// Window length this snapshot is cached for.
    pub window: Duration,
}

impl DpSnapshot {
    /// Prometheus 0.0.4 text exposition of the noisy windowed gauges.
    ///
    /// Lifetime totals are intentionally absent. The `releases_done`
    /// counter is not a privacy-sensitive measurement of user behaviour
    /// (it is the exporter's own budget clock) and is included so
    /// operators can alert on unexpected roll rates or on a cap being
    /// approached.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(1024);
        let eps = format_prom_label(self.epsilon);
        writeln!(
            out,
            "# HELP stellarconduit_sync_queued_window Queued envelopes in the current DP window (Laplace-noised)\n\
             # TYPE stellarconduit_sync_queued_window gauge\n\
             stellarconduit_sync_queued_window{{epsilon=\"{eps}\"}} {}\n\
             # HELP stellarconduit_sync_settled_window Settled envelopes in the current DP window (Laplace-noised)\n\
             # TYPE stellarconduit_sync_settled_window gauge\n\
             stellarconduit_sync_settled_window{{epsilon=\"{eps}\"}} {}\n\
             # HELP stellarconduit_sync_failed_window Failed envelopes in the current DP window (Laplace-noised)\n\
             # TYPE stellarconduit_sync_failed_window gauge\n\
             stellarconduit_sync_failed_window{{epsilon=\"{eps}\"}} {}\n\
             # HELP stellarconduit_sync_conflicts_window Conflicts detected in the current DP window (Laplace-noised)\n\
             # TYPE stellarconduit_sync_conflicts_window gauge\n\
             stellarconduit_sync_conflicts_window{{epsilon=\"{eps}\"}} {}\n\
             # HELP stellarconduit_sync_disputes_window Disputes escalated in the current DP window (Laplace-noised)\n\
             # TYPE stellarconduit_sync_disputes_window gauge\n\
             stellarconduit_sync_disputes_window{{epsilon=\"{eps}\"}} {}\n\
             # HELP stellarconduit_sync_dp_releases_total Distinct DP window releases (budget spend)\n\
             # TYPE stellarconduit_sync_dp_releases_total counter\n\
             stellarconduit_sync_dp_releases_total {}",
            format_prom_value(self.queued),
            format_prom_value(self.settled),
            format_prom_value(self.failed),
            format_prom_value(self.conflicts_detected),
            format_prom_value(self.disputes_escalated),
            self.releases_done,
        )
        .expect("write to String is infallible");
        out
    }
}

fn format_prom_label(epsilon: f64) -> String {
    // Stable, boring formatting so scrapes of an unchanged snapshot
    // really are byte-identical.
    format!("{epsilon:.6}")
}

fn format_prom_value(v: f64) -> String {
    format!("{v:.6}")
}

/// Applies the Laplace mechanism to windowed [`SyncEngineMetrics`]
/// counters and enforces the repeated-query budget policy.
///
/// Cheap to share across threads: all mutable state sits behind one
/// mutex, so concurrent Prometheus scrapes serialize and see a single
/// cached snapshot rather than racing two independent noise draws.
pub struct DpExporter {
    config: DpExportConfig,
    clock: ClockFn,
    inner: Mutex<Inner>,
}

type ClockFn = Box<dyn Fn() -> u64 + Send + Sync>;

struct Inner {
    rng: StdRng,
    last_lifetime: [usize; METRIC_COUNT],
    cached: Option<DpSnapshot>,
    window_start_ms: u64,
    releases_done: u32,
}

impl std::fmt::Debug for DpExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().expect("DpExporter mutex poisoned");
        f.debug_struct("DpExporter")
            .field("config", &self.config)
            .field("releases_done", &inner.releases_done)
            .field("has_cached_snapshot", &inner.cached.is_some())
            .finish()
    }
}

impl DpExporter {
    /// Production constructor: OS entropy for the Laplace sampler, wall
    /// clock for window boundaries.
    pub fn new(config: DpExportConfig) -> Result<Self, DpExportError> {
        config.validate()?;
        Ok(Self::from_parts(
            config,
            StdRng::from_entropy(),
            Box::new(system_clock_ms),
        ))
    }

    fn from_parts(config: DpExportConfig, rng: StdRng, clock: ClockFn) -> Self {
        Self {
            config,
            clock,
            inner: Mutex::new(Inner {
                rng,
                last_lifetime: [0; METRIC_COUNT],
                cached: None,
                window_start_ms: 0,
                releases_done: 0,
            }),
        }
    }

    #[must_use]
    pub fn config(&self) -> &DpExportConfig {
        &self.config
    }

    /// Distinct window releases produced so far (budget spend).
    #[must_use]
    pub fn releases_done(&self) -> u32 {
        self.inner
            .lock()
            .expect("DpExporter mutex poisoned")
            .releases_done
    }

    /// Release the current window as a noisy snapshot, or return the
    /// cached snapshot if this scrape still falls inside the window
    /// that snapshot was paid for.
    pub fn export(&self, metrics: &SyncEngineMetrics) -> Result<DpSnapshot, DpExportError> {
        let now = (self.clock)();
        let mut inner = self.inner.lock().expect("DpExporter mutex poisoned");

        if let Some(ref snap) = inner.cached {
            let elapsed = now.saturating_sub(inner.window_start_ms);
            if elapsed < self.config.window_ms() {
                return Ok(snap.clone());
            }
            if let Some(max) = self.config.max_releases {
                if inner.releases_done >= max {
                    return Err(DpExportError::BudgetExhausted {
                        releases_done: inner.releases_done,
                        max_releases: max,
                    });
                }
            }
        }

        let current = metrics.lifetime_vec();
        let last = inner.last_lifetime;
        let scale = laplace_scale(self.config.epsilon);
        let mut noisy = [0.0; METRIC_COUNT];
        for (slot, (&now_count, &prev_count)) in
            noisy.iter_mut().zip(current.iter().zip(last.iter()))
        {
            let delta = now_count.saturating_sub(prev_count) as f64;
            *slot = (delta + sample_laplace(scale, &mut inner.rng)).max(0.0);
        }

        inner.last_lifetime = current;
        inner.releases_done = inner.releases_done.saturating_add(1);
        inner.window_start_ms = now;

        let snap = DpSnapshot {
            queued: noisy[0],
            settled: noisy[1],
            failed: noisy[2],
            conflicts_detected: noisy[3],
            disputes_escalated: noisy[4],
            epsilon: self.config.epsilon,
            releases_done: inner.releases_done,
            window: self.config.window,
        };
        inner.cached = Some(snap.clone());
        Ok(snap)
    }

    /// [`export`] plus Prometheus text exposition, in one call.
    pub fn export_prometheus(&self, metrics: &SyncEngineMetrics) -> Result<String, DpExportError> {
        Ok(self.export(metrics)?.to_prometheus())
    }
}

fn system_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    #[test]
    fn test_snapshot_reflects_current_values() {
        let metrics = SyncEngineMetrics::new();

        // Increment some counters
        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        metrics.settled_total.fetch_add(5, Ordering::Relaxed);
        metrics.failed_total.fetch_add(2, Ordering::Relaxed);
        metrics.conflicts_detected.fetch_add(3, Ordering::Relaxed);
        metrics.disputes_escalated.fetch_add(1, Ordering::Relaxed);
        metrics.queue_evictions.fetch_add(4, Ordering::Relaxed);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.queued_total, 10);
        assert_eq!(snapshot.settled_total, 5);
        assert_eq!(snapshot.failed_total, 2);
        assert_eq!(snapshot.conflicts_detected, 3);
        assert_eq!(snapshot.disputes_escalated, 1);
        assert_eq!(snapshot.queue_evictions, 4);
    }

    #[test]
    fn test_prometheus_output_is_well_formed() {
        let metrics = SyncEngineMetrics::new();

        metrics.queued_total.fetch_add(42, Ordering::Relaxed);
        metrics.settled_total.fetch_add(17, Ordering::Relaxed);

        let output = metrics.to_prometheus_text();

        // Verify it contains required Prometheus format elements
        assert!(output.contains("# TYPE stellarconduit_sync_queued_total counter"));
        assert!(output.contains("# HELP stellarconduit_sync_queued_total"));
        assert!(output.contains("stellarconduit_sync_queued_total 42"));
        assert!(output.contains("stellarconduit_sync_settled_total 17"));

        // Verify each metric has TYPE and HELP lines
        assert!(output.contains("# TYPE stellarconduit_sync_settled_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_failed_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_conflicts_detected_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_disputes_escalated_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_queue_evictions_total counter"));

        // Verify metric names follow Prometheus naming conventions
        // (letters, numbers, underscores, and colons allowed)
        assert!(!output.contains("stellarconduit-sync")); // no hyphens
        assert!(output.contains("_total")); // counter suffix

        // Verify each line ends with newline
        for line in output.lines() {
            assert!(!line.is_empty() || line.starts_with('#') || line.contains(' '));
        }
    }

    #[test]
    fn test_snapshot_and_reset_zeroes_counters() {
        let metrics = SyncEngineMetrics::new();

        // Set some values
        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        metrics.settled_total.fetch_add(5, Ordering::Relaxed);
        metrics.failed_total.fetch_add(2, Ordering::Relaxed);
        metrics.conflicts_detected.fetch_add(3, Ordering::Relaxed);
        metrics.disputes_escalated.fetch_add(1, Ordering::Relaxed);
        metrics.queue_evictions.fetch_add(4, Ordering::Relaxed);

        // Capture snapshot and reset
        let snapshot = metrics.snapshot_and_reset();

        // Verify snapshot has the values before reset
        assert_eq!(snapshot.queued_total, 10);
        assert_eq!(snapshot.settled_total, 5);
        assert_eq!(snapshot.failed_total, 2);
        assert_eq!(snapshot.conflicts_detected, 3);
        assert_eq!(snapshot.disputes_escalated, 1);
        assert_eq!(snapshot.queue_evictions, 4);

        // Verify all counters are now zero
        let after_snapshot = metrics.snapshot();
        assert_eq!(after_snapshot.queued_total, 0);
        assert_eq!(after_snapshot.settled_total, 0);
        assert_eq!(after_snapshot.failed_total, 0);
        assert_eq!(after_snapshot.conflicts_detected, 0);
        assert_eq!(after_snapshot.disputes_escalated, 0);
        assert_eq!(after_snapshot.queue_evictions, 0);
    }

    #[test]
    fn test_default_metrics_are_zero() {
        let metrics = SyncEngineMetrics::default();
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.queued_total, 0);
        assert_eq!(snapshot.settled_total, 0);
        assert_eq!(snapshot.failed_total, 0);
        assert_eq!(snapshot.conflicts_detected, 0);
        assert_eq!(snapshot.disputes_escalated, 0);
        assert_eq!(snapshot.queue_evictions, 0);
    }

    #[test]
    fn test_prometheus_output_with_zero_values() {
        let metrics = SyncEngineMetrics::new();
        let output = metrics.to_prometheus_text();

        // Should still output all metrics with zero values
        assert!(output.contains("stellarconduit_sync_queued_total 0"));
        assert!(output.contains("stellarconduit_sync_settled_total 0"));
        assert!(output.contains("stellarconduit_sync_failed_total 0"));
        assert!(output.contains("stellarconduit_sync_conflicts_detected_total 0"));
        assert!(output.contains("stellarconduit_sync_disputes_escalated_total 0"));
        assert!(output.contains("stellarconduit_sync_queue_evictions_total 0"));
    }

    #[test]
    fn test_snapshot_is_independent_of_future_changes() {
        let metrics = SyncEngineMetrics::new();

        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        let snapshot1 = metrics.snapshot();

        metrics.queued_total.fetch_add(5, Ordering::Relaxed);
        let snapshot2 = metrics.snapshot();

        // First snapshot should not be affected by later changes
        assert_eq!(snapshot1.queued_total, 10);
        assert_eq!(snapshot2.queued_total, 15);
    }

    #[test]
    fn test_multiple_resets_accumulate_correctly() {
        let metrics = SyncEngineMetrics::new();

        // First period
        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        let period1 = metrics.snapshot_and_reset();
        assert_eq!(period1.queued_total, 10);

        // Second period
        metrics.queued_total.fetch_add(5, Ordering::Relaxed);
        let period2 = metrics.snapshot_and_reset();
        assert_eq!(period2.queued_total, 5);

        // Verify both periods are tracked independently
        assert_eq!(period1.queued_total, 10);
        assert_eq!(period2.queued_total, 5);
    }

    #[test]
    fn test_prometheus_metric_names_follow_conventions() {
        let metrics = SyncEngineMetrics::new();
        let output = metrics.to_prometheus_text();

        // Extract all metric names
        let metric_names: Vec<&str> = output
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();

        // Verify all metric names match Prometheus naming conventions
        // Must match regex: [a-zA-Z_:][a-zA-Z0-9_:]*
        for name in metric_names {
            assert!(
                name.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == ':'),
                "Metric name '{}' contains invalid characters",
                name
            );
            assert!(
                name.chars()
                    .next()
                    .map(|c| c.is_alphabetic() || c == '_' || c == ':')
                    .unwrap_or(false),
                "Metric name '{}' must start with letter, underscore, or colon",
                name
            );
        }
    }

    fn test_exporter(config: DpExportConfig, seed: u64, clock: Arc<AtomicU64>) -> DpExporter {
        DpExporter::from_parts(
            config,
            StdRng::seed_from_u64(seed),
            Box::new(move || clock.load(Ordering::SeqCst)),
        )
    }

    fn moderate_windowed(seed: u64, clock: Arc<AtomicU64>) -> DpExporter {
        test_exporter(DpExportConfig::moderate(), seed, clock)
    }

    /// Replay the exporter's RNG stream for `releases` vector draws so a
    /// test can compute the exact noisy values the Laplace mechanism
    /// must have produced (calibration, not an independence check).
    fn expected_noisy_deltas(
        true_deltas: &[[f64; METRIC_COUNT]],
        epsilon: f64,
        seed: u64,
    ) -> Vec<[f64; METRIC_COUNT]> {
        let mut rng = StdRng::seed_from_u64(seed);
        let scale = laplace_scale(epsilon);
        true_deltas
            .iter()
            .map(|delta| {
                let mut noisy = [0.0; METRIC_COUNT];
                for (slot, &true_count) in noisy.iter_mut().zip(delta.iter()) {
                    *slot = (true_count + sample_laplace(scale, &mut rng)).max(0.0);
                }
                noisy
            })
            .collect()
    }

    #[test]
    fn test_exported_metric_has_calibrated_noise_applied() {
        // Seeded RNG + known true delta ⇒ the released value must equal
        // true + Lap(Δ/ε) with the *same* first draw, clamped at 0.
        // If the scale were wrong (e.g. Lap(ε) instead of Lap(1/ε), or
        // Gaussian, or no noise), this equality fails.
        let clock = Arc::new(AtomicU64::new(0));
        let epsilon = 1.0;
        let config = DpExportConfig::new(epsilon, Duration::from_secs(60)).unwrap();
        let exporter = test_exporter(config, 42, clock);
        let metrics = SyncEngineMetrics::default();
        metrics.queued_total.store(17, Ordering::Relaxed);
        metrics.settled_total.store(4, Ordering::Relaxed);
        metrics.failed_total.store(1, Ordering::Relaxed);
        metrics.conflicts_detected.store(2, Ordering::Relaxed);
        metrics.disputes_escalated.store(3, Ordering::Relaxed);

        let snap = exporter.export(&metrics).unwrap();
        let expected = &expected_noisy_deltas(&[[17.0, 4.0, 1.0, 2.0, 3.0]], epsilon, 42)[0];

        assert_eq!(snap.queued.to_bits(), expected[0].to_bits());
        assert_eq!(snap.settled.to_bits(), expected[1].to_bits());
        assert_eq!(snap.failed.to_bits(), expected[2].to_bits());
        assert_eq!(snap.conflicts_detected.to_bits(), expected[3].to_bits());
        assert_eq!(snap.disputes_escalated.to_bits(), expected[4].to_bits());
        assert_eq!(snap.epsilon.to_bits(), epsilon.to_bits());
        assert_eq!(snap.releases_done, 1);

        // And the noise is actually there: at least one coordinate moved.
        // (A broken exporter that returned the true integers would fail
        // the exact-match above unless the first five Laplace draws were
        // all 0, which `sample_laplace` refuses.)
        let true_vals: [f64; METRIC_COUNT] = [17.0, 4.0, 1.0, 2.0, 3.0];
        let released = [
            snap.queued,
            snap.settled,
            snap.failed,
            snap.conflicts_detected,
            snap.disputes_escalated,
        ];
        assert!(
            released
                .iter()
                .zip(true_vals.iter())
                .any(|(r, t)| r.to_bits() != t.to_bits()),
            "calibrated noise must change at least one released coordinate, got {released:?}"
        );
        assert_eq!(
            laplace_scale(epsilon).to_bits(),
            (L1_SENSITIVITY / epsilon).to_bits()
        );
    }

    #[test]
    fn test_epsilon_configuration_affects_noise_magnitude_as_expected() {
        // Same seed ⇒ same Uniform draws ⇒ |Lap(1/ε)| is exactly
        // proportional to 1/ε. Using a large true count so the
        // non-negativity clamp cannot distort the ratio.
        let true_queued = 1000usize;
        let seed = 7u64;

        let sample = |eps: f64| -> f64 {
            let clock = Arc::new(AtomicU64::new(0));
            let config = DpExportConfig::new(eps, Duration::from_secs(60)).unwrap();
            let exporter = test_exporter(config, seed, clock);
            let metrics = SyncEngineMetrics::default();
            metrics.queued_total.store(true_queued, Ordering::Relaxed);
            let snap = exporter.export(&metrics).unwrap();
            (snap.queued - true_queued as f64).abs()
        };

        let n_half = sample(0.5);
        let n_two = sample(2.0);

        assert!(
            n_half > 0.0 && n_two > 0.0,
            "seed {seed} produced zero noise, pick another seed"
        );
        // |noise(ε)| = |Z| / ε  with the same Z, so n(0.5)/n(2.0) = 4.
        let ratio = n_half / n_two;
        assert!(
            (ratio - 4.0).abs() < 1e-9,
            "noise magnitude must scale as 1/ε; |n(0.5)|/|n(2.0)| = {ratio} (want 4)"
        );

        // Named operating points must land on the documented ε values
        // so the accuracy table in the module docs is not decorative.
        assert_eq!(DpExportConfig::strict().epsilon.to_bits(), 0.1f64.to_bits());
        assert_eq!(
            DpExportConfig::moderate().epsilon.to_bits(),
            1.0f64.to_bits()
        );
        assert_eq!(
            DpExportConfig::relaxed().epsilon.to_bits(),
            2.0f64.to_bits()
        );
        assert_eq!(laplace_scale(0.1).to_bits(), 10.0f64.to_bits());
        assert_eq!(laplace_scale(1.0).to_bits(), 1.0f64.to_bits());
        assert_eq!(laplace_scale(2.0).to_bits(), 0.5f64.to_bits());
    }

    #[test]
    fn test_repeated_queries_respect_declared_budget_policy() {
        let clock = Arc::new(AtomicU64::new(1_000));
        let window = Duration::from_secs(10);
        let config = DpExportConfig::new(1.0, window)
            .unwrap()
            .with_max_releases(2)
            .unwrap();
        let exporter = test_exporter(config, 99, Arc::clone(&clock));
        let metrics = SyncEngineMetrics::default();
        metrics.record_queued();
        metrics.record_queued();

        // 1. First scrape spends the first release.
        let first = exporter.export(&metrics).unwrap();
        assert_eq!(first.releases_done, 1);
        assert_eq!(exporter.releases_done(), 1);

        // 2. More events accrue, but we are still in the same window:
        //    the cached snapshot is returned unchanged (no extra spend,
        //    and the new events are *not* leaked via a delta).
        metrics.record_queued();
        clock.store(1_000 + 5_000, Ordering::SeqCst); // +5s, window is 10s
        let reused = exporter.export(&metrics).unwrap();
        assert_eq!(reused, first);
        assert_eq!(exporter.releases_done(), 1);
        // Prometheus bytes are identical too — observers cannot tell
        // that a third queued event happened by diffing scrapes.
        assert_eq!(first.to_prometheus(), reused.to_prometheus());

        // 3. Window rolls: a new release is produced, budget ticks to 2.
        clock.store(1_000 + 10_000, Ordering::SeqCst);
        let second = exporter.export(&metrics).unwrap();
        assert_eq!(second.releases_done, 2);
        assert_ne!(second.queued.to_bits(), first.queued.to_bits());
        assert_eq!(exporter.releases_done(), 2);

        // 4. Still inside window 2: cache hit, cap not yet applied.
        clock.store(1_000 + 15_000, Ordering::SeqCst);
        let second_reused = exporter.export(&metrics).unwrap();
        assert_eq!(second_reused, second);

        // 5. Window 3 would be release 3, which exceeds max_releases=2.
        //    We refuse rather than returning exact counters.
        clock.store(1_000 + 20_000, Ordering::SeqCst);
        let err = exporter.export(&metrics).unwrap_err();
        assert_eq!(
            err,
            DpExportError::BudgetExhausted {
                releases_done: 2,
                max_releases: 2,
            }
        );
        // The atomics are still exact in-process — exhaustion must not
        // have mutated them, and must not have offered them as a
        // fallback in the error.
        assert_eq!(metrics.queued_total.load(Ordering::Relaxed), 3);
        match err {
            DpExportError::BudgetExhausted { .. } => {}
            other => panic!("budget policy must fail closed, got {other:?}"),
        }
    }

    #[test]
    fn test_true_underlying_value_is_not_exactly_recoverable_from_a_single_export() {
        let clock = Arc::new(AtomicU64::new(0));
        let exporter = moderate_windowed(123, clock);
        let metrics = SyncEngineMetrics::default();
        // A mid-range true count so clamp-to-zero cannot collapse the
        // release onto the true value.
        let true_queued = 11usize;
        metrics.queued_total.store(true_queued, Ordering::Relaxed);
        metrics.settled_total.store(8, Ordering::Relaxed);
        metrics.disputes_escalated.store(1, Ordering::Relaxed);

        let snap = exporter.export(&metrics).unwrap();

        assert_ne!(
            snap.queued.to_bits(),
            (true_queued as f64).to_bits(),
            "a single export must not equal the true queued count"
        );
        assert_ne!(snap.settled.to_bits(), 8.0f64.to_bits());
        assert_ne!(
            snap.disputes_escalated.to_bits(),
            1.0f64.to_bits(),
            "the motivating leak (exact disputes_escalated) must not survive a single export"
        );

        // Continuous Laplace plus no rounding ⇒ the released f64 is not
        // an integer, so even an observer who assumes "the true value is
        // an integer" cannot read it off the export.
        assert_ne!(snap.queued.to_bits(), snap.queued.round().to_bits());
        assert_ne!(
            snap.disputes_escalated.to_bits(),
            snap.disputes_escalated.round().to_bits()
        );
    }

    #[test]
    fn test_export_is_windowed_delta_not_lifetime_total() {
        let clock = Arc::new(AtomicU64::new(0));
        let config = DpExportConfig::new(1.0, Duration::from_secs(10)).unwrap();
        let exporter = test_exporter(config, 3, Arc::clone(&clock));
        let metrics = SyncEngineMetrics::default();

        metrics.queued_total.store(10, Ordering::Relaxed);
        let first = exporter.export(&metrics).unwrap();
        let expected_first = expected_noisy_deltas(&[[10.0, 0.0, 0.0, 0.0, 0.0]], 1.0, 3);
        assert_eq!(first.queued.to_bits(), expected_first[0][0].to_bits());

        // Lifetime total is now 13; the *window* only saw +3. If we had
        // noised the lifetime counter, the second release would be
        // calibrated around 13, not 3.
        metrics.queued_total.store(13, Ordering::Relaxed);
        clock.store(10_000, Ordering::SeqCst);
        let second = exporter.export(&metrics).unwrap();
        let expected_second = expected_noisy_deltas(
            &[[10.0, 0.0, 0.0, 0.0, 0.0], [3.0, 0.0, 0.0, 0.0, 0.0]],
            1.0,
            3,
        );
        assert_eq!(second.queued.to_bits(), expected_second[1][0].to_bits());
        assert_ne!(
            second.queued.to_bits(),
            expected_noisy_deltas(&[[13.0, 0.0, 0.0, 0.0, 0.0]], 1.0, 3)[0][0].to_bits(),
            "second release must not be a noisy lifetime total"
        );
    }

    #[test]
    fn test_invalid_epsilon_is_rejected() {
        for eps in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            let err = DpExportConfig::new(eps, Duration::from_secs(1)).unwrap_err();
            assert!(
                matches!(err, DpExportError::InvalidConfig(_)),
                "epsilon {eps} must be rejected"
            );
        }
        assert!(DpExportConfig::new(1.0, Duration::from_secs(0)).is_err());
        assert!(DpExportConfig::moderate().with_max_releases(0).is_err());
        assert!(DpExporter::new(DpExportConfig {
            epsilon: 0.0,
            window: Duration::from_secs(1),
            max_releases: None,
        })
        .is_err());
    }

    #[test]
    fn test_prometheus_text_omits_lifetime_totals() {
        let clock = Arc::new(AtomicU64::new(0));
        let exporter = moderate_windowed(1, clock);
        let metrics = SyncEngineMetrics::default();
        metrics.queued_total.store(42, Ordering::Relaxed);
        let text = exporter.export_prometheus(&metrics).unwrap();

        assert!(text.contains("# TYPE stellarconduit_sync_queued_window gauge"));
        assert!(text.contains("stellarconduit_sync_dp_releases_total 1"));
        assert!(
            !text.contains("queued_total"),
            "exact lifetime series names must not appear in the exposition"
        );
        // The true integer 42 must not appear as a scraped value. It
        // *could* theoretically appear inside a noised float (42.xxx)
        // or the epsilon label; check the value position more tightly
        // by asserting the documented gauge is not the integer form.
        assert!(!text.contains("stellarconduit_sync_queued_window{epsilon=\"1.000000\"} 42\n"));
        assert!(
            !text.contains("stellarconduit_sync_queued_window{epsilon=\"1.000000\"} 42.000000\n")
        );
    }

    #[test]
    fn test_record_helpers_touch_the_atomics() {
        let m = SyncEngineMetrics::default();
        m.record_queued();
        m.record_settled();
        m.record_failed();
        m.record_conflict();
        m.record_dispute_escalated();
        assert_eq!(m.queued_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.settled_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.failed_total.load(Ordering::Relaxed), 1);
        assert_eq!(m.conflicts_detected.load(Ordering::Relaxed), 1);
        assert_eq!(m.disputes_escalated.load(Ordering::Relaxed), 1);
    }
}
