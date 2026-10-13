//! How many rows to fetch for a probabilistic query: [`Stats`] in,
//! [`Limit`] out (ADR-0009, decision 5).
//!
//! A Bloom match returns every real match and some rows that matched by
//! chance. A non-matching row whose stored filter has fill `f` (the
//! fraction of its bits set) passes a query that sets `b` bits with
//! probability about `f^b`. Over a table the pass rate `p` is the *mean* of
//! each row's `f^b`, and the false positives a query scanning `N` rows
//! draws are `Poisson(λ = p·N)`. To expect `want` real matches at a given
//! confidence, fetch
//!
//! ```text
//! want + Poisson_quantile(λ, confidence)
//! ```
//!
//! rows. The bound is probabilistic: at 99% confidence one query in a
//! hundred draws more false positives than the quantile.

/// What a probabilistic query's [`target_limit`] knows of the table: how
/// many rows the predicate scans, how full their stored filters are, and
/// the confidence the fetch should meet.
///
/// The numbers come from the server, read by the application at startup or
/// on a timer and kept as plain numbers. None of them is secret: the server
/// holds the filters and the catalog holds the row count. A stale `Stats`
/// moves the confidence, never the correctness, because
/// [`verify`](super::Probabilistic::verify) still decides every row.
///
/// [`target_limit`]: super::Probabilistic::target_limit
#[derive(Clone, Debug, PartialEq)]
pub struct Stats {
    rows: u64,
    fill: Fill,
    confidence: f64,
}

/// Where a [`Stats`] takes the stored filters' fill from.
#[derive(Clone, Debug, PartialEq)]
enum Fill {
    /// The index's declared `expected_tokens` prior.
    Declared,
    /// A histogram of set-bit counts: `(bits, rows)` pairs.
    Measured(Vec<(u32, u64)>),
}

/// The confidence a [`Stats`] targets unless told otherwise.
pub const DEFAULT_CONFIDENCE: f64 = 0.99;

impl Stats {
    /// Statistics from the index's declared prior
    /// ([`MatchConfig::expected_tokens`](crate::sem::MatchConfig::expected_tokens))
    /// and an estimate of the rows the query scans, such as
    /// `pg_class.reltuples`.
    ///
    /// The prior knows nothing about the spread of value lengths, so it
    /// underestimates a column of mixed lengths; measure the column
    /// ([`measured`](Self::measured)) once it holds data. An index that
    /// declares no prior gives [`Limit::Unbounded`].
    pub fn declared(rows: u64) -> Self {
        Self {
            rows,
            fill: Fill::Declared,
            confidence: DEFAULT_CONFIDENCE,
        }
    }

    /// Statistics from a measured histogram of the stored filters' set-bit
    /// counts, as `(bits, rows)` pairs, and an estimate of the rows the
    /// query scans.
    ///
    /// One aggregate over the column gives the histogram, with at most `m`
    /// buckets; a page sample bounds its cost on a large table:
    ///
    /// ```sql
    /// SELECT cardinality(eql_v4.match_term(name)) AS bits, count(*)
    /// FROM users TABLESAMPLE SYSTEM (1)
    /// GROUP BY 1
    /// ```
    ///
    /// A page sample can select no page of a small table, so drop the
    /// `TABLESAMPLE` there. An empty histogram falls back to the declared
    /// prior.
    pub fn measured(rows: u64, histogram: impl IntoIterator<Item = (u32, u64)>) -> Self {
        Self {
            rows,
            fill: Fill::Measured(histogram.into_iter().collect()),
            confidence: DEFAULT_CONFIDENCE,
        }
    }

    /// Target `confidence` instead of 99%: the probability that the fetch
    /// holds `want` real matches when the table has that many. Outside the
    /// open interval `(0, 1)` there is no finite fetch to promise, and
    /// [`target_limit`](super::Probabilistic::target_limit) answers
    /// [`Limit::Unbounded`].
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence;
        self
    }

    /// The rows the query scans.
    pub fn rows(&self) -> u64 {
        self.rows
    }

    /// The confidence the fetch targets.
    pub fn confidence(&self) -> f64 {
        self.confidence
    }

    /// The probability that one non-matching row passes a query that sets
    /// `bits` of an `m`-bit filter, or `None` when nothing is known of the
    /// stored filters' fill. `declared` is the fill of one stored filter
    /// under the index's prior, if it declares one.
    pub(crate) fn pass_rate(&self, bits: u32, m: u32, declared: Option<f64>) -> Option<f64> {
        let measured = match &self.fill {
            Fill::Measured(histogram) => mean_power(histogram, bits, m),
            Fill::Declared => None,
        };
        measured.or_else(|| declared.map(|fill| fill.powi(bits as i32)))
    }

    /// The fetch for `want` real matches at pass rate `p`.
    pub(crate) fn limit(&self, want: u64, pass_rate: Option<f64>) -> Limit {
        let Some(p) = pass_rate else {
            return Limit::Unbounded;
        };
        let promisable = self.confidence > 0.0 && self.confidence < 1.0;
        if !promisable || !p.is_finite() {
            return Limit::Unbounded;
        }
        let lambda = p.clamp(0.0, 1.0) * self.rows as f64;
        Limit::Rows(want.saturating_add(poisson_quantile(lambda, self.confidence)))
    }
}

/// The mean of `(bits_i / m)^b` over a histogram of set-bit counts, or
/// `None` for an empty one. A count above `m` (a histogram from another
/// configuration) is a full filter.
fn mean_power(histogram: &[(u32, u64)], b: u32, m: u32) -> Option<f64> {
    let rows: u64 = histogram.iter().map(|&(_, rows)| rows).sum();
    if rows == 0 || m == 0 {
        return None;
    }
    let total: f64 = histogram
        .iter()
        .map(|&(bits, rows)| {
            let fill = (f64::from(bits) / f64::from(m)).min(1.0);
            rows as f64 * fill.powi(b as i32)
        })
        .sum();
    Some(total / rows as f64)
}

/// The fill of one stored filter of `tokens` tokens, each setting `k` of
/// `m` bits: `1 − e^(−k·tokens/m)`.
pub(crate) fn expected_fill(tokens: u32, k: usize, m: u32) -> f64 {
    1.0 - (-(k as f64) * f64::from(tokens) / f64::from(m)).exp()
}

/// How many rows a probabilistic query should fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// Fetch this many rows: `want` and the false positives expected at the
    /// stated confidence.
    Rows(u64),
    /// No finite fetch can be promised: the statistics say nothing about
    /// the stored filters, or the confidence is not below 1. Page through
    /// the candidates with a cursor until `want` rows verify.
    Unbounded,
}

impl Limit {
    /// The rows to fetch, if a finite fetch can be promised.
    pub fn rows(self) -> Option<u64> {
        match self {
            Self::Rows(rows) => Some(rows),
            Self::Unbounded => None,
        }
    }

    /// The rows to fetch, or `page` when no finite fetch can be promised,
    /// for a caller that pages either way.
    pub fn fetch_or(self, page: u64) -> u64 {
        self.rows().unwrap_or(page)
    }
}

/// The smallest `q` with `P(X ≤ q) ≥ confidence` for `X ~ Poisson(λ)`.
///
/// Exact up to floating point: the probabilities are summed in log space
/// from where the mass begins, `λ − 10√λ` for a large `λ` (the mass below
/// it is under `1e-23`), so the work is about `12√λ` terms. Past `1e7`
/// expected false positives the query is hopeless anyway and the answer is
/// the conservative `λ + 8√λ`, which covers any confidence below
/// `1 − 1e-15`.
pub(crate) fn poisson_quantile(lambda: f64, confidence: f64) -> u64 {
    if lambda <= 0.0 || lambda.is_nan() {
        return 0;
    }
    if lambda > 1e7 {
        return (lambda + 8.0 * lambda.sqrt()).ceil() as u64;
    }
    // Saturates to 0 for a small `λ`, where the mass starts at 0.
    let start = (lambda - 10.0 * lambda.sqrt()).floor().max(0.0) as u64;
    let ln_lambda = lambda.ln();
    let mut log_term = -lambda + start as f64 * ln_lambda - ln_factorial(start);
    let mut cdf = 0.0;
    let mut k = start;
    loop {
        cdf += log_term.exp();
        // Past the mode, a term this small adds nothing a float can hold:
        // the remaining mass is below any confidence that is not 1.
        if cdf >= confidence || (k as f64 > lambda && log_term < -50.0) {
            return k;
        }
        k += 1;
        log_term += ln_lambda - (k as f64).ln();
    }
}

/// `ln(n!)`: summed exactly below 20, Stirling's series above, where it is
/// accurate to about `1e-12`.
fn ln_factorial(n: u64) -> f64 {
    if n < 20 {
        return (2..=n).map(|i| (i as f64).ln()).sum();
    }
    let x = n as f64 + 1.0;
    (x - 0.5) * x.ln() - x + 0.5 * (2.0 * std::f64::consts::PI).ln() + 1.0 / (12.0 * x)
        - 1.0 / (360.0 * x.powi(3))
        + 1.0 / (1260.0 * x.powi(5))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference quantiles, computed exactly with `math.lgamma` in log space.
    #[test]
    fn the_poisson_quantile_matches_reference_values() {
        for (lambda, confidence, expected) in [
            (0.034, 0.99, 1),
            (0.439, 0.99, 3),
            (1.0, 0.5, 1),
            (1.0, 0.99, 4),
            (10.0, 0.99, 18),
            (57.8, 0.99, 76),
            (100.0, 0.99, 124),
            (245.0, 0.99, 282),
            (1000.0, 0.999, 1099),
            (3800.0, 0.99, 3944),
            (7600.0, 0.99, 7804),
            (1e6, 0.99, 1_002_327),
        ] {
            assert_eq!(
                poisson_quantile(lambda, confidence),
                expected,
                "λ = {lambda}, confidence = {confidence}"
            );
        }
        assert_eq!(poisson_quantile(0.0, 0.99), 0);
        assert_eq!(poisson_quantile(-1.0, 0.99), 0);
    }

    #[test]
    fn past_ten_million_the_quantile_is_conservative() {
        let lambda = 4e7;
        let q = poisson_quantile(lambda, 0.999_999);
        assert!(q as f64 >= lambda + 4.9 * lambda.sqrt(), "{q}");
        assert!(q as f64 <= lambda + 8.0 * lambda.sqrt() + 1.0, "{q}");
    }

    #[test]
    fn a_confidence_at_one_still_ends() {
        // A float CDF may never reach 1; the tail cut-off ends the sum.
        let q = poisson_quantile(5.0, 1.0);
        assert!(q > 20, "{q}");
    }

    #[test]
    fn ln_factorial_is_continuous_where_the_series_takes_over() {
        let exact: f64 = (2..=20u64).map(|i| (i as f64).ln()).sum();
        assert!((ln_factorial(20) - exact).abs() < 1e-10);
        assert_eq!(ln_factorial(0), 0.0);
        assert_eq!(ln_factorial(1), 0.0);
        assert!((ln_factorial(5) - 120f64.ln()).abs() < 1e-12);
    }

    /// ADR-0009 decision 5's worked table: EQL v4 defaults (`k = 6`,
    /// `m = 2048`), a million rows, 99%.
    #[test]
    fn the_declared_prior_reproduces_the_worked_table() {
        let stats = Stats::declared(1_000_000);
        for (tokens, bits, want_extra) in [(20, 6, 1), (200, 6, 7805), (200, 18, 3)] {
            let fill = expected_fill(tokens, 6, 2048);
            let p = stats.pass_rate(bits, 2048, Some(fill));
            assert_eq!(
                stats.limit(10, p),
                Limit::Rows(10 + want_extra),
                "{tokens} stored tokens, {bits} query bits"
            );
        }
    }

    /// The mixed-length column of decision 5: half the rows hold 20 tokens,
    /// half 200. The mean of `f^b` is what the bound needs; the mean fill
    /// raised to `b` would promise a fetch about fifteen times too small.
    #[test]
    fn a_measured_histogram_uses_the_mean_of_the_power_not_the_power_of_the_mean() {
        let short = (expected_fill(20, 6, 2048) * 2048.0).round() as u32;
        let long = (expected_fill(200, 6, 2048) * 2048.0).round() as u32;
        let stats = Stats::measured(1_000_000, [(short, 500_000), (long, 500_000)]);
        let p = stats.pass_rate(6, 2048, None).unwrap();
        let lambda = p * 1e6;
        assert!((3700.0..3900.0).contains(&lambda), "λ = {lambda}");

        let mean_fill = (f64::from(short) + f64::from(long)) / 2.0 / 2048.0;
        assert!(mean_fill.powi(6) * 1e6 < 300.0);
        let Limit::Rows(rows) = stats.limit(10, Some(p)) else {
            panic!("a measured column has a finite fetch");
        };
        assert!(rows > 3800, "{rows}");
    }

    #[test]
    fn nothing_known_is_unbounded() {
        let stats = Stats::declared(1_000_000);
        assert_eq!(
            stats.limit(10, stats.pass_rate(6, 2048, None)),
            Limit::Unbounded
        );

        let empty = Stats::measured(1_000_000, []);
        assert_eq!(empty.pass_rate(6, 2048, None), None);
        assert_eq!(
            empty.pass_rate(6, 2048, Some(0.5)),
            Some(0.5f64.powi(6)),
            "an empty histogram falls back to the prior"
        );
    }

    #[test]
    fn a_confidence_outside_the_open_interval_is_unbounded() {
        for confidence in [0.0, 1.0, -0.5, 1.5, f64::NAN] {
            let stats = Stats::declared(1000).with_confidence(confidence);
            assert_eq!(
                stats.limit(10, Some(0.01)),
                Limit::Unbounded,
                "{confidence}"
            );
        }
        let stats = Stats::declared(1000).with_confidence(0.5);
        assert_eq!(stats.confidence(), 0.5);
        assert_eq!(stats.rows(), 1000);
        assert_eq!(stats.limit(10, Some(0.01)), Limit::Rows(10 + 10));
    }

    #[test]
    fn a_count_above_the_filter_size_is_a_full_filter() {
        let stats = Stats::measured(100, [(5000, 1)]);
        assert_eq!(stats.pass_rate(6, 2048, None), Some(1.0));
        // Every row passes: λ = 100, whose 99% quantile is 124.
        assert_eq!(stats.limit(1, Some(1.0)), Limit::Rows(1 + 124));
    }

    #[test]
    fn a_limit_reads_back_as_rows_or_a_page() {
        assert_eq!(Limit::Rows(12).rows(), Some(12));
        assert_eq!(Limit::Rows(12).fetch_or(50), 12);
        assert_eq!(Limit::Unbounded.rows(), None);
        assert_eq!(Limit::Unbounded.fetch_or(50), 50);
    }

    #[test]
    fn want_does_not_overflow() {
        assert_eq!(
            Stats::declared(10).limit(u64::MAX, Some(0.5)),
            Limit::Rows(u64::MAX)
        );
    }
}
