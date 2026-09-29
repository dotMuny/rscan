//! Pacing: token buckets, RTT estimation and adaptive congestion control.
//!
//! This is the part of the scanner that decides *how fast* to go, and it is the
//! reason `rscan` can be both fast and accurate. Three pieces:
//!
//! - [`TokenBucket`] — a classic token bucket. Smooths bursts into a steady
//!   packets-per-second rate.
//! - [`RttEstimator`] — Jacobson/Karels RTO estimation, the same algorithm TCP
//!   uses. A fixed timeout is either too slow on a LAN or produces false
//!   `filtered` results over a satellite link; an estimated one is neither.
//! - [`AimdController`] — additive-increase / multiplicative-decrease control
//!   over both concurrency and rate, driven by the observed timeout ratio.
//!
//! Every type here is **pure logic**: it takes observations and a clock reading
//! and returns decisions. Nothing touches the network, nothing sleeps, and
//! everything is unit-testable with synthetic observation series. The async
//! plumbing that couples these to real sockets lives in
//! [`crate::governor`].

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Result of asking a [`TokenBucket`] for permission to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenOutcome {
    /// Tokens were available and have been consumed; send now.
    Ready,
    /// Not enough tokens; wait this long and ask again.
    Wait(Duration),
}

/// A token bucket rate limiter.
///
/// The bucket refills continuously at `rate` tokens per second up to `burst`
/// tokens. One token is one probe.
///
/// The type is deliberately clock-injected: every method that needs "now" takes
/// it as an argument, so the whole thing can be tested deterministically.
///
/// ```
/// use std::time::{Duration, Instant};
/// use rscan_core::rate::{TokenBucket, TokenOutcome};
///
/// let t0 = Instant::now();
/// // 10 probes/second, burst of 2.
/// let mut bucket = TokenBucket::new(10.0, 2.0, t0);
/// assert_eq!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Ready);
/// assert_eq!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Ready);
/// // The burst is spent; the third probe has to wait ~100ms.
/// assert!(matches!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Wait(_)));
/// assert_eq!(bucket.try_acquire_at(t0 + Duration::from_millis(100), 1.0), TokenOutcome::Ready);
/// ```
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a bucket that starts full.
    ///
    /// `rate` is in tokens per second and `burst` is the bucket capacity; both
    /// are clamped to sane minimums so a misconfiguration cannot deadlock the
    /// scan.
    pub fn new(rate: f64, burst: f64, now: Instant) -> Self {
        let rate = rate.max(f64::MIN_POSITIVE);
        let burst = burst.max(1.0);
        Self { rate, burst, tokens: burst, last_refill: now }
    }

    /// Current rate in tokens per second.
    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// Change the rate, refilling first so the change takes effect cleanly.
    ///
    /// The burst is kept proportional to the rate (one tenth of a second's
    /// worth, at least one token), which keeps the limiter smooth as the
    /// adaptive controller moves the rate around.
    pub fn set_rate(&mut self, rate: f64, now: Instant) {
        self.refill(now);
        self.rate = rate.max(f64::MIN_POSITIVE);
        self.burst = (self.rate / 10.0).max(1.0);
        self.tokens = self.tokens.min(self.burst);
    }

    /// Try to consume `n` tokens.
    ///
    /// On [`TokenOutcome::Wait`] no tokens are consumed, so callers can sleep
    /// and retry without losing their place.
    pub fn try_acquire_at(&mut self, now: Instant, n: f64) -> TokenOutcome {
        self.refill(now);
        let n = n.max(0.0);
        if self.tokens >= n {
            self.tokens -= n;
            return TokenOutcome::Ready;
        }
        let deficit = n - self.tokens;
        let seconds = deficit / self.rate;
        // Round up to at least a microsecond so a caller in a loop always makes
        // progress instead of spinning on a zero-length sleep.
        TokenOutcome::Wait(Duration::from_secs_f64(seconds).max(Duration::from_micros(1)))
    }

    /// Return `n` tokens to the bucket, up to its capacity.
    ///
    /// Used when a probe acquires a global token but is then blocked by a
    /// per-target limit: the global budget should not be charged for work that
    /// did not happen.
    pub fn refund(&mut self, n: f64) {
        self.tokens = (self.tokens + n.max(0.0)).min(self.burst);
    }

    /// Tokens currently in the bucket, for diagnostics.
    pub fn available(&self) -> f64 {
        self.tokens
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.rate).min(self.burst);
    }
}

/// Tuning for [`RttEstimator`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RttConfig {
    /// Timeout used before any RTT sample has been taken.
    pub initial: Duration,
    /// Floor for the computed timeout.
    pub min: Duration,
    /// Ceiling for the computed timeout.
    pub max: Duration,
}

impl Default for RttConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_millis(1000),
            min: Duration::from_millis(50),
            max: Duration::from_secs(3),
        }
    }
}

/// Jacobson/Karels round-trip time estimator, as used for TCP's RTO.
///
/// `srtt` is a smoothed average of observed RTTs and `rttvar` a smoothed mean
/// deviation; the timeout is `srtt + 4·rttvar`, clamped to
/// [`RttConfig::min`]`..=`[`RttConfig::max`].
///
/// Using the deviation rather than a multiple of the mean is what makes this
/// robust: a link with a stable 200 ms RTT gets a tight timeout, and a jittery
/// one gets a generous one, without any per-network tuning.
///
/// ```
/// use std::time::Duration;
/// use rscan_core::rate::{RttConfig, RttEstimator};
///
/// let mut est = RttEstimator::new(RttConfig::default());
/// assert_eq!(est.timeout(), Duration::from_millis(1000)); // no samples yet
///
/// for _ in 0..20 {
///     est.observe(Duration::from_millis(20));
/// }
/// // A stable 20ms link converges to a timeout far below the 1s default.
/// assert!(est.timeout() < Duration::from_millis(200));
/// assert!(est.timeout() >= Duration::from_millis(50)); // but never below the floor
/// ```
#[derive(Debug, Clone)]
pub struct RttEstimator {
    config: RttConfig,
    srtt: Option<Duration>,
    rttvar: Duration,
    samples: u64,
}

impl RttEstimator {
    /// Gains from RFC 6298: alpha = 1/8 for the mean, beta = 1/4 for the
    /// deviation.
    const ALPHA: f64 = 0.125;
    const BETA: f64 = 0.25;
    /// RFC 6298 uses K = 4.
    const K: f64 = 4.0;

    /// Create an estimator with no samples yet.
    pub fn new(config: RttConfig) -> Self {
        Self { config, srtt: None, rttvar: Duration::ZERO, samples: 0 }
    }

    /// Feed in one measured round-trip time.
    pub fn observe(&mut self, rtt: Duration) {
        self.samples += 1;
        match self.srtt {
            None => {
                // RFC 6298 §2.2: first sample seeds srtt and rttvar = rtt/2.
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let srtt_s = srtt.as_secs_f64();
                let rtt_s = rtt.as_secs_f64();
                let var_s = self.rttvar.as_secs_f64();
                let new_var = (1.0 - Self::BETA) * var_s + Self::BETA * (srtt_s - rtt_s).abs();
                let new_srtt = (1.0 - Self::ALPHA) * srtt_s + Self::ALPHA * rtt_s;
                self.rttvar = Duration::from_secs_f64(new_var.max(0.0));
                self.srtt = Some(Duration::from_secs_f64(new_srtt.max(0.0)));
            }
        }
    }

    /// The timeout to use for the next probe.
    pub fn timeout(&self) -> Duration {
        match self.srtt {
            None => self.config.initial.clamp(self.config.min, self.config.max),
            Some(srtt) => {
                let rto = srtt.as_secs_f64() + Self::K * self.rttvar.as_secs_f64();
                Duration::from_secs_f64(rto).clamp(self.config.min, self.config.max)
            }
        }
    }

    /// The timeout for retransmission number `attempt` (0-based).
    ///
    /// Karn's algorithm: each retransmission doubles the timeout, so a host
    /// that is merely slow is not written off as `filtered` on the strength of
    /// one late reply.
    pub fn timeout_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.timeout();
        let factor = 1u32.checked_shl(attempt.min(4)).unwrap_or(16);
        (base * factor).min(self.config.max * 4)
    }

    /// Smoothed RTT, once at least one sample has been seen.
    pub fn smoothed(&self) -> Option<Duration> {
        self.srtt
    }

    /// Number of samples observed.
    pub fn samples(&self) -> u64 {
        self.samples
    }
}

/// What happened to one probe, from the congestion controller's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The target answered — open or closed, it does not matter here.
    Responded,
    /// Nothing came back before the deadline.
    TimedOut,
    /// A local error (no route, out of descriptors). Deliberately *not*
    /// evidence of network congestion, so it is excluded from the ratio.
    LocalError,
}

/// The direction the controller moved in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlAction {
    /// Timeout ratio above the high-water mark: cut back multiplicatively.
    Decrease,
    /// Timeout ratio below the low-water mark: creep up additively.
    Increase,
    /// In between, or still cooling down after a decrease.
    Hold,
}

/// A decision emitted at the end of a control window.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ControlDecision {
    /// New concurrency limit.
    pub concurrency: usize,
    /// New rate limit in probes per second.
    pub rate_pps: f64,
    /// What the controller did.
    pub action: ControlAction,
    /// Timeout ratio measured over the window that triggered this decision.
    pub timeout_rate: f64,
    /// Number of network-attributable observations in that window.
    pub observations: usize,
}

impl ControlDecision {
    /// `true` when the decision changed either limit.
    pub fn is_change(&self) -> bool {
        !matches!(self.action, ControlAction::Hold)
    }
}

/// Tuning for [`AimdController`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct AimdConfig {
    /// Lower bound on concurrency. Never goes below this, however bad it gets.
    pub min_concurrency: usize,
    /// Upper bound on concurrency.
    pub max_concurrency: usize,
    /// Concurrency to start from.
    pub initial_concurrency: usize,
    /// Lower bound on rate, probes per second.
    pub min_rate_pps: f64,
    /// Upper bound on rate, probes per second.
    pub max_rate_pps: f64,
    /// Rate to start from.
    pub initial_rate_pps: f64,
    /// Number of network-attributable observations per control window.
    pub window: usize,
    /// Timeout ratio above which the controller backs off.
    pub high_timeout_rate: f64,
    /// Timeout ratio below which the controller speeds up.
    pub low_timeout_rate: f64,
    /// Additive increase step for concurrency, in permits per window.
    pub increase_concurrency: usize,
    /// Additive increase step for rate, as a fraction of the current rate.
    pub increase_rate_frac: f64,
    /// Multiplicative decrease factor, applied to both limits.
    pub decrease_factor: f64,
    /// Windows to hold steady after a decrease before increasing again.
    pub cooldown_windows: u32,
}

impl Default for AimdConfig {
    /// Conservative defaults: 64-way concurrency and 500 probes/second.
    ///
    /// These are chosen so that an unattended scan does not fill a conntrack
    /// table or trip a rate limiter. Aggressive values are opt-in, which is a
    /// deliberate safety property, not an oversight.
    fn default() -> Self {
        Self {
            min_concurrency: 4,
            max_concurrency: 1024,
            initial_concurrency: 64,
            min_rate_pps: 10.0,
            max_rate_pps: 20_000.0,
            initial_rate_pps: 500.0,
            window: 64,
            high_timeout_rate: 0.15,
            low_timeout_rate: 0.05,
            increase_concurrency: 8,
            increase_rate_frac: 0.25,
            decrease_factor: 0.6,
            cooldown_windows: 2,
        }
    }
}

impl AimdConfig {
    /// Clamp the configuration into a self-consistent state.
    ///
    /// Called by the scanner so that a caller mixing CLI flags cannot create a
    /// controller with, say, `min_concurrency > max_concurrency`.
    pub fn normalised(mut self) -> Self {
        self.min_concurrency = self.min_concurrency.max(1);
        self.max_concurrency = self.max_concurrency.max(self.min_concurrency);
        self.initial_concurrency =
            self.initial_concurrency.clamp(self.min_concurrency, self.max_concurrency);
        self.min_rate_pps = self.min_rate_pps.max(0.1);
        self.max_rate_pps = self.max_rate_pps.max(self.min_rate_pps);
        self.initial_rate_pps = self.initial_rate_pps.clamp(self.min_rate_pps, self.max_rate_pps);
        self.window = self.window.max(1);
        self.high_timeout_rate = self.high_timeout_rate.clamp(0.0, 1.0);
        self.low_timeout_rate = self.low_timeout_rate.clamp(0.0, self.high_timeout_rate);
        self.increase_concurrency = self.increase_concurrency.max(1);
        self.increase_rate_frac = self.increase_rate_frac.clamp(0.001, 10.0);
        self.decrease_factor = self.decrease_factor.clamp(0.05, 0.99);
        self
    }
}

/// Additive-increase / multiplicative-decrease controller over concurrency and
/// rate.
///
/// # The algorithm
///
/// Observations are collected into fixed-size windows of
/// [`AimdConfig::window`] network-attributable outcomes (local errors are
/// counted but excluded from the ratio, because a missing route says nothing
/// about the path being congested). At the end of each window the controller
/// computes `timeout_rate = timeouts / (timeouts + responses)` and:
///
/// - `timeout_rate > high_timeout_rate` → **multiplicative decrease**: both
///   concurrency and rate are multiplied by [`AimdConfig::decrease_factor`],
///   and a cooldown of [`AimdConfig::cooldown_windows`] windows starts.
/// - `timeout_rate < low_timeout_rate` and not cooling down → **additive
///   increase**: concurrency grows by a fixed number of permits and rate by a
///   fixed fraction.
/// - Otherwise → **hold**.
///
/// The asymmetry is the point, and it is the same reason TCP uses AIMD: backing
/// off hard and recovering slowly converges on a rate the path can actually
/// carry. Probing upwards aggressively would oscillate, and oscillation in a
/// port scanner shows up as false `filtered` results.
///
/// ```
/// use rscan_core::rate::{AimdConfig, AimdController, ProbeOutcome};
///
/// let config = AimdConfig { window: 10, ..AimdConfig::default() }.normalised();
/// let mut controller = AimdController::new(config);
/// let started_at = controller.concurrency();
///
/// // A window of pure timeouts: the controller must back off.
/// for _ in 0..10 {
///     controller.observe(ProbeOutcome::TimedOut);
/// }
/// assert!(controller.concurrency() < started_at);
/// ```
#[derive(Debug, Clone)]
pub struct AimdController {
    config: AimdConfig,
    concurrency: f64,
    rate_pps: f64,
    window_responses: usize,
    window_timeouts: usize,
    window_errors: usize,
    cooldown: u32,
    last_timeout_rate: f64,
    windows_evaluated: u64,
}

impl AimdController {
    /// Create a controller sitting at the configured initial limits.
    pub fn new(config: AimdConfig) -> Self {
        let config = config.normalised();
        Self {
            concurrency: config.initial_concurrency as f64,
            rate_pps: config.initial_rate_pps,
            config,
            window_responses: 0,
            window_timeouts: 0,
            window_errors: 0,
            cooldown: 0,
            last_timeout_rate: 0.0,
            windows_evaluated: 0,
        }
    }

    /// Record one probe outcome.
    ///
    /// Returns `Some(decision)` exactly when this observation completed a
    /// control window.
    pub fn observe(&mut self, outcome: ProbeOutcome) -> Option<ControlDecision> {
        match outcome {
            ProbeOutcome::Responded => self.window_responses += 1,
            ProbeOutcome::TimedOut => self.window_timeouts += 1,
            ProbeOutcome::LocalError => self.window_errors += 1,
        }

        let network_observations = self.window_responses + self.window_timeouts;
        if network_observations < self.config.window {
            return None;
        }
        Some(self.evaluate())
    }

    /// Force evaluation of a partial window.
    ///
    /// The scanner calls this when the work queue drains, so a scan smaller
    /// than one window still produces a final decision.
    pub fn flush(&mut self) -> Option<ControlDecision> {
        if self.window_responses + self.window_timeouts == 0 {
            return None;
        }
        Some(self.evaluate())
    }

    fn evaluate(&mut self) -> ControlDecision {
        let observations = self.window_responses + self.window_timeouts;
        let timeout_rate =
            if observations == 0 { 0.0 } else { self.window_timeouts as f64 / observations as f64 };

        let action = if timeout_rate > self.config.high_timeout_rate {
            self.concurrency = (self.concurrency * self.config.decrease_factor)
                .max(self.config.min_concurrency as f64);
            self.rate_pps =
                (self.rate_pps * self.config.decrease_factor).max(self.config.min_rate_pps);
            self.cooldown = self.config.cooldown_windows;
            ControlAction::Decrease
        } else if timeout_rate < self.config.low_timeout_rate && self.cooldown == 0 {
            self.concurrency = (self.concurrency + self.config.increase_concurrency as f64)
                .min(self.config.max_concurrency as f64);
            self.rate_pps = (self.rate_pps * (1.0 + self.config.increase_rate_frac))
                .min(self.config.max_rate_pps);
            ControlAction::Increase
        } else {
            self.cooldown = self.cooldown.saturating_sub(1);
            ControlAction::Hold
        };

        self.window_responses = 0;
        self.window_timeouts = 0;
        self.window_errors = 0;
        self.last_timeout_rate = timeout_rate;
        self.windows_evaluated += 1;

        ControlDecision {
            concurrency: self.concurrency(),
            rate_pps: self.rate_pps,
            action,
            timeout_rate,
            observations,
        }
    }

    /// Current concurrency limit.
    pub fn concurrency(&self) -> usize {
        (self.concurrency.round() as usize)
            .clamp(self.config.min_concurrency, self.config.max_concurrency)
    }

    /// Current rate limit in probes per second.
    pub fn rate_pps(&self) -> f64 {
        self.rate_pps
    }

    /// Timeout ratio measured in the most recently completed window.
    pub fn timeout_rate(&self) -> f64 {
        self.last_timeout_rate
    }

    /// Number of control windows evaluated so far.
    pub fn windows_evaluated(&self) -> u64 {
        self.windows_evaluated
    }

    /// The configuration in use, after normalisation.
    pub fn config(&self) -> &AimdConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AimdConfig {
        AimdConfig {
            min_concurrency: 4,
            max_concurrency: 256,
            initial_concurrency: 64,
            min_rate_pps: 10.0,
            max_rate_pps: 5000.0,
            initial_rate_pps: 500.0,
            window: 10,
            high_timeout_rate: 0.2,
            low_timeout_rate: 0.05,
            increase_concurrency: 8,
            increase_rate_frac: 0.25,
            decrease_factor: 0.5,
            cooldown_windows: 1,
        }
        .normalised()
    }

    fn feed(
        controller: &mut AimdController,
        outcome: ProbeOutcome,
        n: usize,
    ) -> Option<ControlDecision> {
        let mut last = None;
        for _ in 0..n {
            if let Some(d) = controller.observe(outcome) {
                last = Some(d);
            }
        }
        last
    }

    // ---- token bucket -------------------------------------------------

    #[test]
    fn bucket_starts_full_and_drains() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100.0, 5.0, t0);
        for _ in 0..5 {
            assert_eq!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Ready);
        }
        assert!(matches!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Wait(_)));
    }

    #[test]
    fn bucket_refills_at_the_configured_rate() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100.0, 1.0, t0);
        assert_eq!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Ready);
        // 100 pps means one token every 10ms.
        assert!(matches!(
            bucket.try_acquire_at(t0 + Duration::from_millis(5), 1.0),
            TokenOutcome::Wait(_)
        ));
        assert_eq!(bucket.try_acquire_at(t0 + Duration::from_millis(10), 1.0), TokenOutcome::Ready);
    }

    #[test]
    fn bucket_never_exceeds_its_burst() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(1000.0, 3.0, t0);
        // A long idle period must not let a thousand tokens accumulate.
        let _ = bucket.try_acquire_at(t0 + Duration::from_secs(60), 3.0);
        assert!(matches!(
            bucket.try_acquire_at(t0 + Duration::from_secs(60), 1.0),
            TokenOutcome::Wait(_)
        ));
    }

    #[test]
    fn bucket_wait_is_proportional_to_the_deficit() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(10.0, 1.0, t0);
        assert_eq!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Ready);
        let TokenOutcome::Wait(w1) = bucket.try_acquire_at(t0, 1.0) else {
            panic!("expected a wait");
        };
        // One token at 10pps is 100ms.
        assert!((w1.as_secs_f64() - 0.1).abs() < 0.01, "{w1:?}");
    }

    #[test]
    fn failed_acquire_consumes_nothing() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(10.0, 2.0, t0);
        assert!(matches!(bucket.try_acquire_at(t0, 5.0), TokenOutcome::Wait(_)));
        assert!((bucket.available() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn refunded_tokens_come_back_but_never_overflow() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(10.0, 2.0, t0);
        assert_eq!(bucket.try_acquire_at(t0, 2.0), TokenOutcome::Ready);
        bucket.refund(1.0);
        assert_eq!(bucket.try_acquire_at(t0, 1.0), TokenOutcome::Ready);
        bucket.refund(100.0);
        assert!((bucket.available() - 2.0).abs() < 1e-9, "refund must respect the burst");
    }

    #[test]
    fn changing_the_rate_resizes_the_burst() {
        let t0 = Instant::now();
        let mut bucket = TokenBucket::new(100.0, 10.0, t0);
        bucket.set_rate(50.0, t0);
        assert_eq!(bucket.rate(), 50.0);
        // burst = rate/10 = 5
        assert!(bucket.available() <= 5.0 + 1e-9);
    }

    #[test]
    fn bucket_tolerates_a_non_monotonic_clock() {
        let t0 = Instant::now() + Duration::from_secs(10);
        let mut bucket = TokenBucket::new(10.0, 1.0, t0);
        // An earlier "now" must not panic or invent tokens.
        assert_eq!(bucket.try_acquire_at(t0 - Duration::from_secs(5), 1.0), TokenOutcome::Ready);
        assert!(matches!(
            bucket.try_acquire_at(t0 - Duration::from_secs(5), 1.0),
            TokenOutcome::Wait(_)
        ));
    }

    // ---- RTT estimator ------------------------------------------------

    #[test]
    fn estimator_uses_the_initial_timeout_before_any_sample() {
        let est = RttEstimator::new(RttConfig::default());
        assert_eq!(est.timeout(), Duration::from_millis(1000));
        assert_eq!(est.samples(), 0);
        assert!(est.smoothed().is_none());
    }

    #[test]
    fn estimator_converges_on_a_stable_link() {
        let mut est = RttEstimator::new(RttConfig {
            initial: Duration::from_millis(1000),
            min: Duration::from_millis(1),
            max: Duration::from_secs(3),
        });
        for _ in 0..50 {
            est.observe(Duration::from_millis(20));
        }
        let srtt = est.smoothed().expect("has samples");
        assert!((srtt.as_secs_f64() - 0.020).abs() < 0.002, "{srtt:?}");
        // With no jitter, rttvar decays towards zero and the timeout towards srtt.
        assert!(est.timeout() < Duration::from_millis(40), "{:?}", est.timeout());
    }

    #[test]
    fn estimator_widens_the_timeout_on_a_jittery_link() {
        let mut stable = RttEstimator::new(RttConfig::default());
        let mut jittery = RttEstimator::new(RttConfig::default());
        for i in 0..50 {
            stable.observe(Duration::from_millis(100));
            jittery.observe(Duration::from_millis(if i % 2 == 0 { 20 } else { 180 }));
        }
        // Same mean, very different deviation: the jittery link must get more slack.
        assert!(
            jittery.timeout() > stable.timeout(),
            "jittery {:?} should exceed stable {:?}",
            jittery.timeout(),
            stable.timeout()
        );
    }

    #[test]
    fn estimator_respects_its_floor_and_ceiling() {
        let config = RttConfig {
            initial: Duration::from_millis(500),
            min: Duration::from_millis(100),
            max: Duration::from_millis(400),
        };
        let mut fast = RttEstimator::new(config);
        for _ in 0..50 {
            fast.observe(Duration::from_micros(50));
        }
        assert_eq!(fast.timeout(), Duration::from_millis(100));

        let mut slow = RttEstimator::new(config);
        for _ in 0..50 {
            slow.observe(Duration::from_secs(5));
        }
        assert_eq!(slow.timeout(), Duration::from_millis(400));
    }

    #[test]
    fn retransmissions_back_off_exponentially() {
        let mut est = RttEstimator::new(RttConfig {
            initial: Duration::from_millis(100),
            min: Duration::from_millis(10),
            max: Duration::from_secs(10),
        });
        est.observe(Duration::from_millis(50));
        let first = est.timeout_for_attempt(0);
        let second = est.timeout_for_attempt(1);
        let third = est.timeout_for_attempt(2);
        assert_eq!(second, first * 2);
        assert_eq!(third, first * 4);
    }

    // ---- AIMD controller ----------------------------------------------

    #[test]
    fn controller_holds_when_the_timeout_rate_is_moderate() {
        let mut c = AimdController::new(test_config());
        let before = (c.concurrency(), c.rate_pps());
        // 10% timeouts: above low (5%), below high (20%).
        feed(&mut c, ProbeOutcome::TimedOut, 1);
        let decision = feed(&mut c, ProbeOutcome::Responded, 9).expect("window closed");
        assert_eq!(decision.action, ControlAction::Hold);
        assert_eq!((c.concurrency(), c.rate_pps()), before);
    }

    #[test]
    fn controller_backs_off_under_heavy_timeouts() {
        let mut c = AimdController::new(test_config());
        let decision = feed(&mut c, ProbeOutcome::TimedOut, 10).expect("window closed");
        assert_eq!(decision.action, ControlAction::Decrease);
        assert_eq!(decision.timeout_rate, 1.0);
        assert_eq!(c.concurrency(), 32); // 64 * 0.5
        assert_eq!(c.rate_pps(), 250.0); // 500 * 0.5
    }

    #[test]
    fn controller_speeds_up_on_a_clean_window() {
        let mut c = AimdController::new(test_config());
        let decision = feed(&mut c, ProbeOutcome::Responded, 10).expect("window closed");
        assert_eq!(decision.action, ControlAction::Increase);
        assert_eq!(c.concurrency(), 72); // 64 + 8
        assert_eq!(c.rate_pps(), 625.0); // 500 * 1.25
    }

    /// The headline acceptance criterion: back off under load, then recover.
    #[test]
    fn controller_recovers_after_congestion_clears() {
        let mut c = AimdController::new(test_config());
        let initial = c.concurrency();

        // Three bad windows: concurrency should collapse.
        for _ in 0..3 {
            feed(&mut c, ProbeOutcome::TimedOut, 10);
        }
        let bottom = c.concurrency();
        assert!(bottom < initial, "expected a decrease from {initial} but got {bottom}");
        assert_eq!(bottom, 8); // 64 -> 32 -> 16 -> 8

        // Cooldown: the first clean window after a decrease must not increase.
        let decision = feed(&mut c, ProbeOutcome::Responded, 10).expect("window closed");
        assert_eq!(decision.action, ControlAction::Hold);
        assert_eq!(c.concurrency(), bottom);

        // Now it climbs back, one additive step per window.
        for _ in 0..10 {
            feed(&mut c, ProbeOutcome::Responded, 10);
        }
        assert!(c.concurrency() > bottom, "expected recovery from {bottom}");
        assert!(c.concurrency() >= initial, "should have climbed back past {initial}");
        assert!(c.rate_pps() > 62.5);
    }

    #[test]
    fn controller_clamps_to_its_bounds() {
        let mut c = AimdController::new(test_config());
        for _ in 0..50 {
            feed(&mut c, ProbeOutcome::TimedOut, 10);
        }
        assert_eq!(c.concurrency(), 4); // min_concurrency
        assert_eq!(c.rate_pps(), 10.0); // min_rate_pps

        let mut c = AimdController::new(test_config());
        for _ in 0..200 {
            feed(&mut c, ProbeOutcome::Responded, 10);
        }
        assert_eq!(c.concurrency(), 256); // max_concurrency
        assert_eq!(c.rate_pps(), 5000.0); // max_rate_pps
    }

    #[test]
    fn local_errors_do_not_count_as_congestion() {
        let mut c = AimdController::new(test_config());
        // A hundred local errors must not close a window or move the limits.
        assert!(feed(&mut c, ProbeOutcome::LocalError, 100).is_none());
        assert_eq!(c.concurrency(), 64);
        assert_eq!(c.windows_evaluated(), 0);
    }

    #[test]
    fn windows_are_sized_by_network_observations_only() {
        let mut c = AimdController::new(test_config());
        feed(&mut c, ProbeOutcome::LocalError, 5);
        assert!(feed(&mut c, ProbeOutcome::Responded, 9).is_none());
        let decision = c.observe(ProbeOutcome::Responded).expect("tenth network observation");
        assert_eq!(decision.observations, 10);
    }

    #[test]
    fn flush_evaluates_a_partial_window() {
        let mut c = AimdController::new(test_config());
        feed(&mut c, ProbeOutcome::TimedOut, 3);
        let decision = c.flush().expect("partial window");
        assert_eq!(decision.observations, 3);
        assert_eq!(decision.action, ControlAction::Decrease);
        assert!(c.flush().is_none(), "a second flush has nothing to evaluate");
    }

    #[test]
    fn a_realistic_congestion_episode_settles() {
        // Timeouts spike in the middle of the scan, then clear.
        let mut c = AimdController::new(test_config());
        let mut trace = Vec::new();
        for window in 0..30 {
            let timeouts = if (8..14).contains(&window) { 8 } else { 0 };
            feed(&mut c, ProbeOutcome::TimedOut, timeouts);
            feed(&mut c, ProbeOutcome::Responded, 10 - timeouts);
            trace.push(c.concurrency());
        }
        let during = trace[13];
        let after = trace[29];
        assert!(during < trace[7], "should have backed off during the episode");
        assert!(after > during, "should have recovered after it");
    }

    #[test]
    fn normalisation_fixes_inconsistent_configs() {
        let config = AimdConfig {
            min_concurrency: 100,
            max_concurrency: 10,
            initial_concurrency: 0,
            min_rate_pps: 900.0,
            max_rate_pps: 10.0,
            initial_rate_pps: -5.0,
            window: 0,
            high_timeout_rate: 5.0,
            low_timeout_rate: 9.0,
            increase_concurrency: 0,
            increase_rate_frac: 0.0,
            decrease_factor: 5.0,
            cooldown_windows: 0,
        }
        .normalised();
        assert!(config.min_concurrency <= config.max_concurrency);
        assert!(config.initial_concurrency >= config.min_concurrency);
        assert!(config.min_rate_pps <= config.max_rate_pps);
        assert!(config.low_timeout_rate <= config.high_timeout_rate);
        assert!(config.window >= 1);
        assert!(config.decrease_factor < 1.0);
        // The controller must still be constructible and usable.
        let mut c = AimdController::new(config);
        assert!(c.observe(ProbeOutcome::Responded).is_some());
    }
}
