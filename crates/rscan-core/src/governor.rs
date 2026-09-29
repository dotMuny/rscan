//! The async coupling between the pure controllers in [`crate::rate`] and real
//! sockets.
//!
//! A [`Governor`] owns three things:
//!
//! - a Tokio [`Semaphore`] whose permit count is **resized while the scan
//!   runs**, so the adaptive controller can actually throttle in-flight work;
//! - a global [`TokenBucket`] limiting probes per second across the whole scan;
//! - one token bucket per target address, so a single slow host cannot be
//!   hammered just because the global budget has room.
//!
//! Every probe goes through [`Governor::acquire`] before it touches the network
//! and reports its outcome through [`Governor::observe`] afterwards. That is
//! the entire contract; the scan engines do not know the algorithm exists.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::rate::{
    AimdConfig, AimdController, ControlDecision, ProbeOutcome, RttConfig, RttEstimator,
    TokenBucket, TokenOutcome,
};

/// Tuning for a [`Governor`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GovernorConfig {
    /// Concurrency and global-rate control.
    pub aimd: AimdConfig,
    /// Per-target rate cap in probes per second. `None` disables it.
    pub per_target_pps: Option<f64>,
    /// RTT estimation parameters, used for adaptive timeouts.
    pub rtt: RttConfig,
    /// Hard ceiling on concurrency imposed by the descriptor budget.
    pub fd_ceiling: usize,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            aimd: AimdConfig::default(),
            per_target_pps: Some(100.0),
            rtt: RttConfig::default(),
            fd_ceiling: usize::MAX,
        }
    }
}

/// A permit to send exactly one probe.
///
/// Holding it counts against the concurrency limit; dropping it releases the
/// slot. It is deliberately not `Clone`.
#[derive(Debug)]
pub struct ProbePermit {
    _permit: OwnedSemaphorePermit,
}

struct Inner {
    controller: AimdController,
    global_bucket: TokenBucket,
    per_target: HashMap<IpAddr, TokenBucket>,
    rtt: HashMap<IpAddr, RttEstimator>,
    /// Permits currently issued to the semaphore.
    issued: usize,
    /// Permits we would like the semaphore to have.
    target: usize,
}

/// Runtime pacing authority for a scan.
///
/// Cheap to clone through an [`Arc`]; all state is shared.
pub struct Governor {
    semaphore: Arc<Semaphore>,
    inner: Mutex<Inner>,
    config: GovernorConfig,
    packets_sent: AtomicU64,
    timeouts: AtomicU64,
    responses: AtomicU64,
}

impl std::fmt::Debug for Governor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Governor")
            .field("concurrency", &self.concurrency())
            .field("rate_pps", &self.rate_pps())
            .field("packets_sent", &self.packets_sent())
            .finish()
    }
}

impl Governor {
    /// Build a governor and prime the semaphore with the initial concurrency.
    pub fn new(config: GovernorConfig) -> Arc<Self> {
        let mut aimd = config.aimd.normalised();
        // The descriptor budget is a hard ceiling: the controller may never
        // climb past what the process can actually open.
        aimd.max_concurrency = aimd.max_concurrency.min(config.fd_ceiling.max(1));
        aimd.initial_concurrency = aimd.initial_concurrency.min(aimd.max_concurrency);
        aimd.min_concurrency = aimd.min_concurrency.min(aimd.max_concurrency);
        let aimd = aimd.normalised();

        let controller = AimdController::new(aimd);
        let initial = controller.concurrency();
        let now = Instant::now();
        let bucket =
            TokenBucket::new(controller.rate_pps(), (controller.rate_pps() / 10.0).max(1.0), now);

        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(initial)),
            inner: Mutex::new(Inner {
                controller,
                global_bucket: bucket,
                per_target: HashMap::new(),
                rtt: HashMap::new(),
                issued: initial,
                target: initial,
            }),
            config: GovernorConfig { aimd, ..config },
            packets_sent: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
            responses: AtomicU64::new(0),
        })
    }

    /// Wait until it is this probe's turn to run against `addr`.
    ///
    /// Order matters: rate first, then concurrency. Taking the concurrency
    /// permit first would let a slow rate limit pin permits that other targets
    /// could be using.
    pub async fn acquire(self: &Arc<Self>, addr: IpAddr) -> ProbePermit {
        self.pace(addr).await;

        // `Semaphore::acquire_owned` only fails if the semaphore was closed,
        // and nothing in this crate ever closes it.
        let permit = loop {
            match Arc::clone(&self.semaphore).acquire_owned().await {
                Ok(permit) => break permit,
                Err(_) => {
                    // Defensive: re-open rather than panic in a library.
                    self.semaphore.add_permits(1);
                }
            }
        };
        ProbePermit { _permit: permit }
    }

    /// Wait for a rate-limiter token for one transmission to `addr`.
    ///
    /// Called once per probe by [`Governor::acquire`] and again by the caller
    /// for every retransmission, so that retries are paced and counted like any
    /// other packet. Getting this wrong is how a scanner ends up sending three
    /// times its configured rate whenever a network starts dropping packets.
    pub async fn pace(&self, addr: IpAddr) {
        loop {
            let wait = {
                let now = Instant::now();
                let mut inner = self.inner.lock();
                match inner.global_bucket.try_acquire_at(now, 1.0) {
                    TokenOutcome::Wait(d) => Some(d),
                    TokenOutcome::Ready => match self.config.per_target_pps {
                        None => None,
                        Some(pps) => {
                            let outcome = inner
                                .per_target
                                .entry(addr)
                                .or_insert_with(|| {
                                    TokenBucket::new(pps, (pps / 10.0).max(1.0), now)
                                })
                                .try_acquire_at(now, 1.0);
                            match outcome {
                                TokenOutcome::Ready => None,
                                TokenOutcome::Wait(d) => {
                                    // The global token has already been spent;
                                    // hand it back so that a per-target stall
                                    // does not eat into the global budget.
                                    inner.global_bucket.refund(1.0);
                                    Some(d)
                                }
                            }
                        }
                    },
                }
            };

            match wait {
                Some(d) => tokio::time::sleep(d.min(Duration::from_millis(250))).await,
                None => break,
            }
        }

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Report the outcome of a probe and let the controller react.
    ///
    /// Returns the control decision when this observation closed a window.
    pub fn observe(
        &self,
        addr: IpAddr,
        outcome: ProbeOutcome,
        rtt: Option<Duration>,
    ) -> Option<ControlDecision> {
        match outcome {
            ProbeOutcome::Responded => self.responses.fetch_add(1, Ordering::Relaxed),
            ProbeOutcome::TimedOut => self.timeouts.fetch_add(1, Ordering::Relaxed),
            ProbeOutcome::LocalError => 0,
        };

        let mut inner = self.inner.lock();
        if let Some(rtt) = rtt {
            let rtt_config = self.config.rtt;
            inner.rtt.entry(addr).or_insert_with(|| RttEstimator::new(rtt_config)).observe(rtt);
        }
        let decision = inner.controller.observe(outcome);
        if let Some(decision) = decision {
            inner.target = decision.concurrency;
        }
        // Reconcile on every observation, not only on a decision: a shrink can
        // be left partially applied when no permits were free at the time.
        self.reconcile(&mut inner);
        if let Some(decision) = decision {
            let now = Instant::now();
            inner.global_bucket.set_rate(decision.rate_pps, now);
        }
        decision
    }

    /// Evaluate whatever partial window is outstanding.
    pub fn flush(&self) -> Option<ControlDecision> {
        let mut inner = self.inner.lock();
        let decision = inner.controller.flush();
        if let Some(decision) = decision {
            inner.target = decision.concurrency;
            let now = Instant::now();
            inner.global_bucket.set_rate(decision.rate_pps, now);
        }
        self.reconcile(&mut inner);
        decision
    }

    /// Move the semaphore towards the target permit count.
    ///
    /// Growing is immediate. Shrinking can only reclaim permits that are not
    /// currently held, so the remainder is picked up on a later call — which is
    /// why this runs on every observation.
    fn reconcile(&self, inner: &mut Inner) {
        use std::cmp::Ordering as CmpOrdering;
        match inner.target.cmp(&inner.issued) {
            CmpOrdering::Greater => {
                let delta = inner.target - inner.issued;
                self.semaphore.add_permits(delta);
                inner.issued = inner.target;
            }
            CmpOrdering::Less => {
                let delta = inner.issued - inner.target;
                let removed = self.semaphore.forget_permits(delta);
                inner.issued -= removed;
            }
            CmpOrdering::Equal => {}
        }
    }

    /// The adaptive timeout to use for attempt `attempt` (0-based) against
    /// `addr`.
    pub fn timeout_for(&self, addr: IpAddr, attempt: u32) -> Duration {
        let inner = self.inner.lock();
        match inner.rtt.get(&addr) {
            Some(est) => est.timeout_for_attempt(attempt),
            None => {
                let base = self.config.rtt.initial.clamp(self.config.rtt.min, self.config.rtt.max);
                let factor = 1u32.checked_shl(attempt.min(4)).unwrap_or(16);
                (base * factor).min(self.config.rtt.max * 4)
            }
        }
    }

    /// Current concurrency limit.
    pub fn concurrency(&self) -> usize {
        self.inner.lock().controller.concurrency()
    }

    /// Current global rate limit in probes per second.
    pub fn rate_pps(&self) -> f64 {
        self.inner.lock().controller.rate_pps()
    }

    /// Timeout ratio from the most recent control window.
    pub fn timeout_rate(&self) -> f64 {
        self.inner.lock().controller.timeout_rate()
    }

    /// Probes transmitted so far, retransmissions included.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Probes that timed out, across the whole scan.
    pub fn timeouts(&self) -> u64 {
        self.timeouts.load(Ordering::Relaxed)
    }

    /// Probes that got an answer, across the whole scan.
    pub fn responses(&self) -> u64 {
        self.responses.load(Ordering::Relaxed)
    }

    /// The configuration in force, after clamping.
    pub fn config(&self) -> &GovernorConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn fast_config() -> GovernorConfig {
        GovernorConfig {
            aimd: AimdConfig {
                initial_concurrency: 8,
                min_concurrency: 2,
                max_concurrency: 32,
                initial_rate_pps: 100_000.0,
                max_rate_pps: 1_000_000.0,
                window: 4,
                decrease_factor: 0.5,
                cooldown_windows: 0,
                ..AimdConfig::default()
            },
            per_target_pps: None,
            rtt: RttConfig::default(),
            fd_ceiling: usize::MAX,
        }
    }

    #[tokio::test]
    async fn concurrency_is_bounded_by_the_semaphore() {
        let governor = Governor::new(fast_config());
        let mut permits = Vec::new();
        for _ in 0..8 {
            permits.push(governor.acquire(addr(1)).await);
        }
        // The ninth must block until one is released.
        let pending =
            tokio::time::timeout(Duration::from_millis(50), governor.acquire(addr(1))).await;
        assert!(pending.is_err(), "semaphore did not cap in-flight probes");
        drop(permits.pop());
        let granted =
            tokio::time::timeout(Duration::from_millis(200), governor.acquire(addr(1))).await;
        assert!(granted.is_ok(), "releasing a permit must unblock a waiter");
    }

    #[tokio::test]
    async fn the_semaphore_shrinks_when_the_controller_backs_off() {
        let governor = Governor::new(fast_config());
        assert_eq!(governor.concurrency(), 8);

        // One bad window at this configuration halves concurrency.
        for _ in 0..4 {
            governor.observe(addr(1), ProbeOutcome::TimedOut, None);
        }
        assert_eq!(governor.concurrency(), 4);

        let mut permits = Vec::new();
        for _ in 0..4 {
            permits.push(governor.acquire(addr(1)).await);
        }
        let pending =
            tokio::time::timeout(Duration::from_millis(50), governor.acquire(addr(1))).await;
        assert!(pending.is_err(), "the semaphore must honour the reduced limit");
    }

    #[tokio::test]
    async fn the_semaphore_grows_when_the_controller_speeds_up() {
        let governor = Governor::new(fast_config());
        for _ in 0..4 {
            governor.observe(addr(1), ProbeOutcome::Responded, Some(Duration::from_millis(1)));
        }
        assert!(governor.concurrency() > 8, "a clean window must raise the limit");

        let limit = governor.concurrency();
        let mut permits = Vec::new();
        for _ in 0..limit {
            permits.push(
                tokio::time::timeout(Duration::from_millis(200), governor.acquire(addr(1)))
                    .await
                    .expect("permits up to the new limit are available"),
            );
        }
        assert_eq!(permits.len(), limit);
    }

    #[tokio::test]
    async fn a_shrink_blocked_by_held_permits_is_applied_later() {
        let governor = Governor::new(fast_config());
        // Hold every permit, so `forget_permits` has nothing to reclaim.
        let mut permits = Vec::new();
        for _ in 0..8 {
            permits.push(governor.acquire(addr(1)).await);
        }
        for _ in 0..4 {
            governor.observe(addr(1), ProbeOutcome::TimedOut, None);
        }
        assert_eq!(governor.concurrency(), 4);

        // Release everything, then let a later observation reconcile.
        permits.clear();
        governor.observe(addr(1), ProbeOutcome::Responded, None);

        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(governor.acquire(addr(1)).await);
        }
        let pending =
            tokio::time::timeout(Duration::from_millis(50), governor.acquire(addr(1))).await;
        assert!(pending.is_err(), "the deferred shrink was never applied");
    }

    #[tokio::test]
    async fn the_global_rate_limit_paces_probes() {
        let config = GovernorConfig {
            aimd: AimdConfig {
                initial_rate_pps: 50.0,
                max_rate_pps: 50.0,
                min_rate_pps: 50.0,
                initial_concurrency: 64,
                window: 1_000_000,
                ..AimdConfig::default()
            },
            per_target_pps: None,
            ..fast_config()
        };
        let governor = Governor::new(config);
        let start = Instant::now();
        let mut permits = Vec::new();
        // burst is rate/10 = 5, so 10 probes needs at least 5 more tokens: 100ms.
        for _ in 0..10 {
            permits.push(governor.acquire(addr(1)).await);
        }
        assert!(start.elapsed() >= Duration::from_millis(80), "elapsed {:?}", start.elapsed());
    }

    #[tokio::test]
    async fn a_per_target_limit_does_not_stall_other_targets() {
        let config = GovernorConfig { per_target_pps: Some(20.0), ..fast_config() };
        let governor = Governor::new(config);
        // Drain the first target's burst (20/10 = 2 tokens).
        let _a = governor.acquire(addr(1)).await;
        let _b = governor.acquire(addr(1)).await;
        // A different target must still be served immediately.
        let other =
            tokio::time::timeout(Duration::from_millis(100), governor.acquire(addr(2))).await;
        assert!(other.is_ok(), "per-target pacing must not become a global stall");
    }

    #[tokio::test]
    async fn the_descriptor_ceiling_caps_the_controller() {
        let config = GovernorConfig {
            aimd: AimdConfig {
                max_concurrency: 4096,
                initial_concurrency: 16,
                ..fast_config().aimd
            },
            fd_ceiling: 20,
            ..fast_config()
        };
        let governor = Governor::new(config);
        for _ in 0..200 {
            governor.observe(addr(1), ProbeOutcome::Responded, None);
        }
        assert!(governor.concurrency() <= 20, "{}", governor.concurrency());
    }

    #[tokio::test]
    async fn timeouts_are_estimated_per_host() {
        let governor = Governor::new(fast_config());
        let slow = addr(1);
        let fast = addr(2);
        for _ in 0..20 {
            governor.observe(slow, ProbeOutcome::Responded, Some(Duration::from_millis(500)));
            governor.observe(fast, ProbeOutcome::Responded, Some(Duration::from_millis(1)));
        }
        assert!(
            governor.timeout_for(slow, 0) > governor.timeout_for(fast, 0),
            "a slow host must get a longer timeout"
        );
        assert_eq!(governor.timeout_for(fast, 1), governor.timeout_for(fast, 0) * 2);
    }

    #[tokio::test]
    async fn retransmissions_are_paced_and_counted() {
        let governor = Governor::new(fast_config());
        let _permit = governor.acquire(addr(1)).await;
        assert_eq!(governor.packets_sent(), 1);
        // Two retries against the same probe, without taking a second slot.
        governor.pace(addr(1)).await;
        governor.pace(addr(1)).await;
        assert_eq!(governor.packets_sent(), 3, "retransmissions are packets too");
    }

    #[tokio::test]
    async fn counters_track_the_scan() {
        let governor = Governor::new(fast_config());
        let _p = governor.acquire(addr(1)).await;
        governor.observe(addr(1), ProbeOutcome::Responded, None);
        governor.observe(addr(1), ProbeOutcome::TimedOut, None);
        assert_eq!(governor.packets_sent(), 1);
        assert_eq!(governor.responses(), 1);
        assert_eq!(governor.timeouts(), 1);
    }
}
