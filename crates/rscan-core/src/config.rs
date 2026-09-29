//! Scan configuration and its builder.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::ports::PortSpec;
use crate::rate::{AimdConfig, RttConfig};
use crate::target::TargetSet;

/// Technique used for TCP ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScanMode {
    /// Full TCP handshake through the OS stack. Needs no privileges and
    /// distinguishes `open`, `closed` and `filtered` reliably.
    #[default]
    Connect,
    /// Half-open SYN scan using raw sockets. Faster and quieter, but needs
    /// `CAP_NET_RAW`.
    Syn,
}

impl ScanMode {
    /// Short name used in output metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ScanMode::Connect => "connect",
            ScanMode::Syn => "syn",
        }
    }
}

/// Which host-discovery techniques to attempt, and in what order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// When `false`, every target is assumed up (`--skip-discovery`).
    pub enabled: bool,
    /// Send ICMP (or ICMPv6) echo requests.
    pub icmp_echo: bool,
    /// Try a TCP connection to [`DiscoveryConfig::tcp_ports`].
    pub tcp_connect: bool,
    /// Send a bare TCP ACK and treat a RST as proof of life. Needs raw sockets.
    pub tcp_ack: bool,
    /// Resolve link-layer addresses with ARP on the local segment. Linux only,
    /// needs raw sockets.
    pub arp: bool,
    /// Ports used by the TCP probes.
    pub tcp_ports: Vec<u16>,
    /// Per-probe timeout.
    pub timeout: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            icmp_echo: true,
            tcp_connect: true,
            tcp_ack: false,
            arp: true,
            tcp_ports: vec![80, 443, 22, 445],
            timeout: Duration::from_millis(800),
        }
    }
}

/// What to do once a port is found open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDetection {
    /// Master switch. When `false`, nothing below runs.
    pub enabled: bool,
    /// Read whatever the service sends unprompted after connecting.
    pub banner: bool,
    /// Send payloads from the probe database and match the responses.
    pub probes: bool,
    /// Attempt a TLS handshake and report version, ALPN and certificate names.
    pub tls: bool,
    /// Send an HTTP request and report status, `Server`, title and redirects.
    pub http: bool,
    /// Probe rarity cutoff, 0..=9. Higher runs more probes and takes longer.
    pub intensity: u8,
    /// Budget for the whole detection sequence on one port.
    pub timeout: Duration,
}

impl Default for ServiceDetection {
    fn default() -> Self {
        Self {
            enabled: false,
            banner: true,
            probes: true,
            tls: true,
            http: true,
            intensity: 5,
            timeout: Duration::from_millis(3000),
        }
    }
}

impl ServiceDetection {
    /// Everything on, at the default intensity.
    pub fn all() -> Self {
        Self { enabled: true, ..Self::default() }
    }
}

/// How hard to cap the probe rate against any one target.
///
/// A per-target cap exists so that a wide scan cannot dump its entire budget on
/// one fragile host. It must not, however, quietly throttle a scan of a *single*
/// host below the global limit the user asked for — which is what a fixed
/// default does, and it makes `--max-rate` look broken.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PerTargetRate {
    /// No cap when a single address is in scope; [`PerTargetRate::AUTO_PPS`]
    /// probes per second each when there are several.
    ///
    /// The default. A one-host scan is bounded by the global limiter alone, so
    /// `--max-rate` means what it says; a wide scan additionally protects each
    /// host.
    #[default]
    Auto,
    /// No per-target cap at all; the global limiter is the only control.
    Off,
    /// A fixed cap in probes per second.
    Fixed(f64),
}

impl PerTargetRate {
    /// The cap [`PerTargetRate::Auto`] applies to multi-host scans.
    pub const AUTO_PPS: f64 = 1000.0;

    /// Resolve to a concrete cap given how many addresses are in scope.
    pub fn resolve(self, hosts_in_scope: u128) -> Option<f64> {
        match self {
            PerTargetRate::Auto if hosts_in_scope <= 1 => None,
            PerTargetRate::Auto => Some(Self::AUTO_PPS),
            PerTargetRate::Off => None,
            PerTargetRate::Fixed(pps) => Some(pps),
        }
    }
}

/// Everything a [`Scanner`](crate::Scanner) needs to run.
///
/// Build one with [`ScanConfig::builder`].
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Targets, before resolution.
    pub targets: TargetSet,
    /// Ports, split by protocol.
    pub ports: PortSpec,
    /// TCP technique.
    pub mode: ScanMode,
    /// When the SYN scan cannot get raw sockets, fall back to connect instead
    /// of failing.
    pub fallback_to_connect: bool,
    /// Host discovery settings.
    pub discovery: DiscoveryConfig,
    /// Service detection settings.
    pub service_detection: ServiceDetection,
    /// How many extra probes to send before declaring a port `filtered`.
    pub retries: u32,
    /// Concurrency and global rate control.
    pub aimd: AimdConfig,
    /// Per-target rate cap.
    pub per_target_pps: PerTargetRate,
    /// RTT estimation and timeout bounds.
    pub rtt: RttConfig,
    /// Path to a resume state file, when resuming or checkpointing.
    pub resume_path: Option<PathBuf>,
    /// How often to checkpoint resume state.
    pub checkpoint_interval: Duration,
    /// Emit [`ScanEvent::Progress`](crate::ScanEvent::Progress) this often.
    pub progress_interval: Duration,
    /// Report `closed` and `filtered` ports, not just the interesting ones.
    pub report_all_states: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: TargetSet::new(),
            ports: PortSpec::new(),
            mode: ScanMode::Connect,
            fallback_to_connect: true,
            discovery: DiscoveryConfig::default(),
            service_detection: ServiceDetection::default(),
            retries: 1,
            aimd: AimdConfig::default(),
            per_target_pps: PerTargetRate::Auto,
            rtt: RttConfig::default(),
            resume_path: None,
            checkpoint_interval: Duration::from_secs(5),
            progress_interval: Duration::from_millis(250),
            report_all_states: false,
        }
    }
}

impl ScanConfig {
    /// Start building a configuration.
    pub fn builder() -> ScanConfigBuilder {
        ScanConfigBuilder { config: ScanConfig::default() }
    }

    /// Check the configuration for internal consistency.
    ///
    /// Called automatically by [`ScanConfigBuilder::build`] and again by
    /// [`Scanner::new`](crate::Scanner::new).
    pub fn validate(&self) -> Result<()> {
        if self.targets.is_empty() {
            return Err(Error::config("no targets specified"));
        }
        if self.ports.is_empty() {
            return Err(Error::config("no ports specified"));
        }
        if self.retries > 10 {
            return Err(Error::config("retries above 10 will not make a filtered port open"));
        }
        if self.service_detection.intensity > 9 {
            return Err(Error::config("service detection intensity must be 0..=9"));
        }
        if let PerTargetRate::Fixed(pps) = self.per_target_pps {
            if !(pps.is_finite() && pps > 0.0) {
                return Err(Error::config("per-target rate must be a positive number"));
            }
        }
        if self.rtt.min > self.rtt.max {
            return Err(Error::config("minimum timeout is greater than maximum timeout"));
        }
        Ok(())
    }

    /// Normalise derived fields. Idempotent.
    pub fn normalised(mut self) -> Self {
        self.aimd = self.aimd.normalised();
        if self.rtt.min > self.rtt.max {
            std::mem::swap(&mut self.rtt.min, &mut self.rtt.max);
        }
        self.rtt.initial = self.rtt.initial.clamp(self.rtt.min, self.rtt.max);
        self
    }
}

/// Fluent builder for [`ScanConfig`].
///
/// ```
/// use rscan_core::{ScanConfig, ScanMode};
/// use rscan_core::ports::PortSpec;
/// use rscan_core::target::{TargetSet, TargetSpec};
///
/// let mut targets = TargetSet::new();
/// targets.add(TargetSpec::parse("192.0.2.0/30")?);
///
/// let config = ScanConfig::builder()
///     .targets(targets)
///     .ports(PortSpec::parse("22,80")?)
///     .mode(ScanMode::Connect)
///     .retries(2)
///     .max_rate_pps(250.0)
///     .build()?;
///
/// assert_eq!(config.retries, 2);
/// # Ok::<(), rscan_core::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct ScanConfigBuilder {
    config: ScanConfig,
}

impl ScanConfigBuilder {
    /// Set the targets.
    pub fn targets(mut self, targets: TargetSet) -> Self {
        self.config.targets = targets;
        self
    }

    /// Set the ports.
    pub fn ports(mut self, ports: PortSpec) -> Self {
        self.config.ports = ports;
        self
    }

    /// Choose the TCP technique.
    pub fn mode(mut self, mode: ScanMode) -> Self {
        self.config.mode = mode;
        self
    }

    /// Allow (or forbid) falling back to a connect scan without `CAP_NET_RAW`.
    pub fn fallback_to_connect(mut self, fallback: bool) -> Self {
        self.config.fallback_to_connect = fallback;
        self
    }

    /// Replace the discovery configuration.
    pub fn discovery(mut self, discovery: DiscoveryConfig) -> Self {
        self.config.discovery = discovery;
        self
    }

    /// Skip host discovery and assume every target is up.
    pub fn skip_discovery(mut self, skip: bool) -> Self {
        self.config.discovery.enabled = !skip;
        self
    }

    /// Replace the service detection configuration.
    pub fn service_detection(mut self, detection: ServiceDetection) -> Self {
        self.config.service_detection = detection;
        self
    }

    /// Number of retransmissions before a silent port is called `filtered`.
    pub fn retries(mut self, retries: u32) -> Self {
        self.config.retries = retries;
        self
    }

    /// Starting concurrency. The adaptive controller moves from here.
    pub fn concurrency(mut self, concurrency: usize) -> Self {
        self.config.aimd.initial_concurrency = concurrency;
        self.config.aimd.max_concurrency = self.config.aimd.max_concurrency.max(concurrency);
        self
    }

    /// Ceiling on the global probe rate.
    pub fn max_rate_pps(mut self, pps: f64) -> Self {
        self.config.aimd.max_rate_pps = pps;
        self.config.aimd.initial_rate_pps = self.config.aimd.initial_rate_pps.min(pps);
        self
    }

    /// Per-target probe rate cap.
    pub fn per_target_pps(mut self, rate: PerTargetRate) -> Self {
        self.config.per_target_pps = rate;
        self
    }

    /// Replace the AIMD controller configuration wholesale.
    pub fn aimd(mut self, aimd: AimdConfig) -> Self {
        self.config.aimd = aimd;
        self
    }

    /// Replace the RTT estimation configuration.
    pub fn rtt(mut self, rtt: RttConfig) -> Self {
        self.config.rtt = rtt;
        self
    }

    /// Use a fixed timeout instead of an estimated one.
    ///
    /// Pins the floor, ceiling and initial value to the same number, which
    /// disables adaptation. Mostly useful for reproducible benchmarks.
    pub fn fixed_timeout(mut self, timeout: Duration) -> Self {
        self.config.rtt = RttConfig { initial: timeout, min: timeout, max: timeout };
        self
    }

    /// Enable resume checkpointing to `path`.
    pub fn resume_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.resume_path = Some(path.into());
        self
    }

    /// How often to write resume state.
    pub fn checkpoint_interval(mut self, interval: Duration) -> Self {
        self.config.checkpoint_interval = interval;
        self
    }

    /// Emit results for `closed` and `filtered` ports too.
    pub fn report_all_states(mut self, report: bool) -> Self {
        self.config.report_all_states = report;
        self
    }

    /// Validate and produce the configuration.
    pub fn build(self) -> Result<ScanConfig> {
        let config = self.config.normalised();
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::TargetSpec;

    fn targets() -> TargetSet {
        let mut set = TargetSet::new();
        set.add(TargetSpec::parse("127.0.0.1").expect("literal"));
        set
    }

    #[test]
    fn building_requires_targets_and_ports() {
        assert!(ScanConfig::builder().build().is_err());
        assert!(ScanConfig::builder().targets(targets()).build().is_err());
        assert!(ScanConfig::builder()
            .targets(targets())
            .ports(PortSpec::parse("80").expect("literal"))
            .build()
            .is_ok());
    }

    #[test]
    fn defaults_are_conservative() {
        let config = ScanConfig::default();
        assert_eq!(config.aimd.initial_rate_pps, 500.0);
        assert_eq!(config.aimd.initial_concurrency, 64);
        assert!(!config.service_detection.enabled, "detection is opt-in");
        assert!(config.discovery.enabled);
    }

    #[test]
    fn normalisation_orders_the_timeout_bounds() {
        let config = ScanConfig {
            rtt: RttConfig {
                initial: Duration::from_secs(10),
                min: Duration::from_secs(5),
                max: Duration::from_secs(1),
            },
            ..ScanConfig::default()
        }
        .normalised();
        assert!(config.rtt.min <= config.rtt.max);
        assert!(config.rtt.initial <= config.rtt.max);
    }

    #[test]
    fn absurd_settings_are_rejected() {
        let base = || {
            ScanConfig::builder().targets(targets()).ports(PortSpec::parse("80").expect("literal"))
        };
        assert!(base().retries(50).build().is_err());
        assert!(base().per_target_pps(PerTargetRate::Fixed(0.0)).build().is_err());
        assert!(base().per_target_pps(PerTargetRate::Fixed(f64::NAN)).build().is_err());
        assert!(base()
            .service_detection(ServiceDetection { intensity: 20, ..ServiceDetection::all() })
            .build()
            .is_err());
    }

    #[test]
    fn the_automatic_per_target_cap_does_not_throttle_a_single_host() {
        // The bug this guards against: a fixed per-target default silently
        // capping a one-host scan below --max-rate, so the flag looks broken.
        assert_eq!(PerTargetRate::Auto.resolve(1), None);
        assert_eq!(PerTargetRate::Auto.resolve(0), None);
        assert_eq!(PerTargetRate::Auto.resolve(2), Some(PerTargetRate::AUTO_PPS));
        assert_eq!(PerTargetRate::Auto.resolve(65_536), Some(PerTargetRate::AUTO_PPS));
        assert_eq!(PerTargetRate::Off.resolve(1000), None);
        assert_eq!(PerTargetRate::Fixed(7.5).resolve(1), Some(7.5));
        assert_eq!(PerTargetRate::Fixed(7.5).resolve(1000), Some(7.5));
    }

    #[test]
    fn fixed_timeout_disables_adaptation() {
        let config = ScanConfig::builder()
            .targets(targets())
            .ports(PortSpec::parse("80").expect("literal"))
            .fixed_timeout(Duration::from_millis(250))
            .build()
            .expect("valid");
        assert_eq!(config.rtt.min, config.rtt.max);
        assert_eq!(config.rtt.initial, Duration::from_millis(250));
    }
}
