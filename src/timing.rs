//! Statistical helpers for timing-side-channel analysis.
//!
//! Timing side-channel tests are easy to write in a way that looks rigorous
//! but only reflects scheduler noise on the day they ran. The rule this
//! module supports (see `docs/design/side-channel-resistant-signing.md`): do
//! not compare two single measurements, or even two means — collect many
//! samples per condition and compare the whole *distributions* with a
//! non-parametric test that assumes nothing about their shape.
//!
//! [`mann_whitney_u`] is that test. It is deterministic given its inputs, so
//! the methodology itself is unit-tested here against hand-computed values;
//! the wall-clock measurement that feeds it in practice is a separate,
//! opt-in (`#[ignore]`) test, because timing is inherently machine- and
//! load-dependent.

/// Result of a two-sided Mann–Whitney U test via the normal approximation.
#[derive(Debug, Clone, Copy)]
pub struct MannWhitneyResult {
    /// The U statistic for the first sample.
    pub u_first: f64,
    /// Mean of U under the null hypothesis that the distributions are equal.
    pub mean_u: f64,
    /// Standard deviation of U under the null hypothesis (no tie correction).
    pub std_u: f64,
    /// Standardised distance of the observed U from its null mean. A large
    /// magnitude means the two sample distributions differ.
    pub z_score: f64,
}

impl MannWhitneyResult {
    /// Whether the two distributions differ at a two-sided significance level
    /// expressed as a `z` threshold (e.g. `3.2905` for alpha = 1e-3,
    /// `1.96` for alpha = 0.05).
    ///
    /// For a timing side-channel test the *wanted* answer is `false`: no
    /// detectable difference between the two conditions being compared.
    pub fn differs_at(&self, z_threshold: f64) -> bool {
        self.z_score.abs() > z_threshold
    }
}

/// Run a two-sample Mann–Whitney U test (Wilcoxon rank-sum) on two sets of
/// measurements and return the U statistic for `first` together with its
/// normal-approximation `z`-score.
///
/// Ranking uses average ranks for ties. The variance is the standard
/// uncorrected `n1 * n2 * (n1 + n2 + 1) / 12`; for the near-continuous
/// nanosecond timings this is used on, the tie correction is negligible.
/// Both samples are non-empty, so `std_u` is always at least `0.5` and the
/// `z`-score is well defined.
///
/// # Panics
/// Panics if either sample is empty, or if any measurement is NaN.
pub fn mann_whitney_u(first: &[f64], second: &[f64]) -> MannWhitneyResult {
    assert!(
        !first.is_empty() && !second.is_empty(),
        "both samples must be non-empty"
    );

    let n1 = first.len() as f64;
    let n2 = second.len() as f64;

    let mut pooled: Vec<(f64, bool)> = Vec::with_capacity(first.len() + second.len());
    pooled.extend(first.iter().map(|&v| (v, true)));
    pooled.extend(second.iter().map(|&v| (v, false)));
    assert!(
        pooled.iter().all(|&(v, _)| !v.is_nan()),
        "measurements must not be NaN"
    );
    pooled.sort_by(|a, b| a.0.total_cmp(&b.0));

    // Sum the (average) ranks that belong to `first`.
    let mut rank_sum_first = 0.0_f64;
    let mut i = 0;
    while i < pooled.len() {
        let mut j = i;
        while j + 1 < pooled.len() && pooled[j + 1].0.to_bits() == pooled[i].0.to_bits() {
            j += 1;
        }
        // 0-based positions i..=j share the 1-based ranks (i+1)..=(j+1).
        let average_rank = ((i + 1 + j + 1) as f64) / 2.0;
        for &(_, is_first) in &pooled[i..=j] {
            if is_first {
                rank_sum_first += average_rank;
            }
        }
        i = j + 1;
    }

    let u_first = rank_sum_first - n1 * (n1 + 1.0) / 2.0;
    let mean_u = n1 * n2 / 2.0;
    let std_u = (n1 * n2 * (n1 + n2 + 1.0) / 12.0).sqrt();
    let z_score = (u_first - mean_u) / std_u;

    MannWhitneyResult {
        u_first,
        mean_u,
        std_u,
        z_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u_statistic_matches_hand_computation() {
        // first = [1, 3], second = [2, 4]: pooled ranks 1, 2, 3, 4;
        // rank sum for `first` = 1 + 3 = 4; U = 4 - (2 * 3 / 2) = 1.
        let result = mann_whitney_u(&[1.0, 3.0], &[2.0, 4.0]);
        assert!((result.u_first - 1.0).abs() < 1e-12);
        assert!((result.mean_u - 2.0).abs() < 1e-12);
        // std = sqrt(2 * 2 * 5 / 12) = sqrt(5 / 3)
        let expected_std = (5.0_f64 / 3.0).sqrt();
        assert!((result.std_u - expected_std).abs() < 1e-12);
        assert!((result.z_score - (-1.0 / expected_std)).abs() < 1e-12);
    }

    #[test]
    fn test_identical_samples_have_zero_z_score() {
        let sample = [1.0, 2.0, 3.0, 4.0, 5.0];
        let result = mann_whitney_u(&sample, &sample);
        assert!(result.z_score.abs() < 1e-12);
        assert!(!result.differs_at(1.96));
    }

    #[test]
    fn test_all_values_tied_is_symmetric() {
        let result = mann_whitney_u(&[5.0, 5.0, 5.0], &[5.0, 5.0, 5.0]);
        assert!((result.u_first - result.mean_u).abs() < 1e-12);
        assert!(result.z_score.abs() < 1e-12);
    }

    #[test]
    fn test_clearly_separated_distributions_are_flagged() {
        let low: Vec<f64> = (0..20).map(f64::from).collect();
        let high: Vec<f64> = (0..20).map(|x| f64::from(x) + 100.0).collect();
        let result = mann_whitney_u(&low, &high);
        assert!(result.differs_at(3.2905));
        assert!(
            result.z_score < 0.0,
            "the lower sample should push U below its null mean"
        );
    }

    #[test]
    #[should_panic(expected = "non-empty")]
    fn test_empty_sample_panics() {
        let _ = mann_whitney_u(&[], &[1.0]);
    }
}
