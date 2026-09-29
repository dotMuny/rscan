//! Command-line interface definition.
//!
//! Flags map onto [`ScanConfig`] and nothing else; all the policy lives in
//! `rscan-core`. Where a name has an obvious nmap equivalent this uses it, so
//! that muscle memory transfers.
//!
//! Note what is **not** here: no decoys, no source spoofing, no fragmentation,
//! no IDS-evasion timing. Those are deliberate omissions, explained in the
//! README.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser, ValueEnum};
use rscan_core::config::{DiscoveryConfig, ServiceDetection};
use rscan_core::ports::{self, PortSpec};
use rscan_core::rate::{AimdConfig, RttConfig};
use rscan_core::target::TargetSet;
use rscan_core::{PerTargetRate, Protocol, ScanConfig, ScanMode};

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum OutputFormat {
    /// Coloured table with a summary. The default.
    Text,
    /// A single JSON document, written at the end.
    Json,
    /// One JSON object per line, streamed as results are found.
    Jsonl,
    /// XML compatible with nmap's DTD, for tools that already parse it.
    NmapXml,
    /// Comma-separated values.
    Csv,
    /// One line per host, in the style of nmap's `-oG`.
    Grepable,
}

impl OutputFormat {
    /// `true` when this format writes results as they arrive rather than at the
    /// end.
    pub fn is_streaming(self) -> bool {
        matches!(self, OutputFormat::Jsonl | OutputFormat::Text)
    }
}

/// TCP scanning technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum ScanType {
    /// Full TCP handshake. No privileges required. The default.
    Connect,
    /// Half-open SYN scan. Requires `CAP_NET_RAW`.
    Syn,
}

impl From<ScanType> for ScanMode {
    fn from(value: ScanType) -> Self {
        match value {
            ScanType::Connect => ScanMode::Connect,
            ScanType::Syn => ScanMode::Syn,
        }
    }
}

/// Pacing preset.
///
/// These change **rate and concurrency only**. They are not nmap's `-T`
/// templates: nothing here alters packet shape or timing patterns to evade
/// detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum Timing {
    /// Very slow and gentle: for fragile networks and embedded devices.
    Polite,
    /// The default. Conservative enough to run unattended.
    Normal,
    /// Faster. Appropriate on a network you control.
    Aggressive,
    /// As fast as the adaptive controller will allow. Local networks only.
    Insane,
}

impl Timing {
    fn apply(self, aimd: &mut AimdConfig) {
        let (concurrency, max_concurrency, rate, max_rate) = match self {
            Timing::Polite => (16, 64, 50.0, 200.0),
            Timing::Normal => (64, 1024, 500.0, 20_000.0),
            Timing::Aggressive => (256, 4096, 3_000.0, 60_000.0),
            Timing::Insane => (1024, 8192, 20_000.0, 250_000.0),
        };
        aimd.initial_concurrency = concurrency;
        aimd.max_concurrency = max_concurrency;
        aimd.initial_rate_pps = rate;
        aimd.max_rate_pps = max_rate;
    }
}

/// `rscan` — a fast, adaptive asynchronous port scanner with service detection.
///
/// Scan only systems you own or have written authorisation to test.
#[derive(Debug, Parser)]
#[command(
    name = "rscan",
    version,
    about = "Fast asynchronous port scanner with adaptive congestion control",
    long_about = None,
    after_help = "EXAMPLES:\n  \
        rscan 192.168.1.0/24                     scan the top 100 TCP ports of a /24\n  \
        rscan -p- --service-detection example.com  every port, with service detection\n  \
        rscan -iL hosts.txt -o jsonl -O out.jsonl  stream results into a pipeline\n  \
        rscan --udp -p 53,161,123 10.0.0.1         UDP scan with service payloads\n\n\
        Scanning hosts without authorisation is illegal in most jurisdictions."
)]
pub struct Args {
    /// Targets: addresses, CIDR blocks, ranges or hostnames.
    #[arg(value_name = "TARGET")]
    pub targets: Vec<String>,

    /// Read targets from a file, one or more per line. Use `-` for stdin.
    #[arg(short = 'i', long = "target-file", value_name = "FILE")]
    pub target_file: Option<PathBuf>,

    /// Exclude these targets. Repeatable, and accepts comma-separated lists.
    #[arg(long, value_name = "SPEC")]
    pub exclude: Vec<String>,

    /// Read exclusions from a file.
    #[arg(long, value_name = "FILE")]
    pub exclude_file: Option<PathBuf>,

    /// Ports to scan: `80`, `1-1024`, `-` for all, `T:80,U:53` for both.
    #[arg(short = 'p', long, value_name = "SPEC")]
    pub ports: Option<String>,

    /// Scan the N most commonly open ports.
    #[arg(long, value_name = "N", conflicts_with = "ports")]
    pub top_ports: Option<usize>,

    /// Remove these ports from the scan.
    #[arg(long, value_name = "SPEC")]
    pub exclude_ports: Option<String>,

    /// Scan UDP instead of TCP. Combine with `-p` to choose the ports.
    #[arg(short = 'U', long)]
    pub udp: bool,

    /// TCP technique.
    #[arg(long, value_enum, default_value_t = ScanType::Connect)]
    pub scan_type: ScanType,

    /// Fail instead of falling back to a connect scan when SYN needs
    /// privileges the process does not have.
    #[arg(long)]
    pub no_fallback: bool,

    /// Skip host discovery and treat every target as up.
    #[arg(short = 'P', long = "skip-discovery")]
    pub skip_discovery: bool,

    /// Ports used by TCP host-discovery probes.
    #[arg(long, value_name = "LIST", default_value = "80,443,22,445")]
    pub discovery_ports: String,

    /// Do not send ICMP echo requests during discovery.
    #[arg(long)]
    pub no_icmp: bool,

    /// Do not use the ARP neighbour table during discovery.
    #[arg(long)]
    pub no_arp: bool,

    /// Use TCP ACK probes for discovery. Requires `CAP_NET_RAW`.
    #[arg(long)]
    pub tcp_ack: bool,

    /// Identify the services behind open ports.
    #[arg(short = 's', long)]
    pub service_detection: bool,

    /// How hard to try during service detection, 0 (fastest) to 9 (thorough).
    #[arg(long, value_name = "0-9", default_value_t = 5)]
    pub version_intensity: u8,

    /// Skip the TLS handshake during service detection.
    #[arg(long)]
    pub no_tls: bool,

    /// Skip the HTTP request during service detection.
    #[arg(long)]
    pub no_http: bool,

    /// Pacing preset. Changes rate and concurrency only.
    #[arg(short = 'T', long, value_enum, default_value_t = Timing::Normal)]
    pub timing: Timing,

    /// Starting number of probes in flight.
    #[arg(short = 'c', long, value_name = "N")]
    pub concurrency: Option<usize>,

    /// Ceiling on probes per second across the whole scan.
    #[arg(long, value_name = "PPS")]
    pub max_rate: Option<f64>,

    /// Ceiling on probes per second against any single host.
    ///
    /// By default a single-host scan is bounded only by `--max-rate`, and a
    /// scan of several hosts caps each at 1000/s so one host cannot absorb the
    /// whole budget. Pass 0 to remove the cap entirely.
    #[arg(long, value_name = "PPS")]
    pub max_rate_host: Option<f64>,

    /// Turn off adaptive control and hold the starting rate and concurrency.
    #[arg(long)]
    pub no_adapt: bool,

    /// Extra probes to send before calling a silent port filtered.
    #[arg(long, value_name = "N", default_value_t = 1)]
    pub retries: u32,

    /// Fixed probe timeout in milliseconds. Disables RTT estimation.
    #[arg(long, value_name = "MS")]
    pub timeout: Option<u64>,

    /// Lower bound for the estimated timeout, in milliseconds.
    #[arg(long, value_name = "MS", default_value_t = 50)]
    pub min_timeout: u64,

    /// Upper bound for the estimated timeout, in milliseconds.
    #[arg(long, value_name = "MS", default_value_t = 3000)]
    pub max_timeout: u64,

    /// Output format.
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Text)]
    pub output: OutputFormat,

    /// Write output to a file instead of stdout.
    #[arg(short = 'O', long, value_name = "PATH")]
    pub output_file: Option<PathBuf>,

    /// Report closed and filtered ports as well as interesting ones.
    #[arg(long)]
    pub all_states: bool,

    /// Never colour the output.
    #[arg(long)]
    pub no_color: bool,

    /// Do not draw a progress bar.
    #[arg(long)]
    pub no_progress: bool,

    /// Save progress here and continue an interrupted scan from it.
    #[arg(long, value_name = "FILE")]
    pub resume: Option<PathBuf>,

    /// Answer yes to the large-scan confirmation prompt.
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Suppress the first-run legal notice.
    #[arg(long)]
    pub no_banner: bool,

    /// Increase log verbosity. Repeatable.
    #[arg(short = 'v', long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Suppress everything except results.
    #[arg(short = 'q', long, conflicts_with = "verbose")]
    pub quiet: bool,
}

impl Args {
    /// The `tracing` filter these flags imply.
    pub fn log_filter(&self) -> &'static str {
        if self.quiet {
            "error"
        } else {
            match self.verbose {
                0 => "warn",
                1 => "info",
                2 => "debug",
                _ => "trace",
            }
        }
    }

    /// `true` when a progress bar should be drawn.
    ///
    /// Never when stderr is redirected, never when the data output is also
    /// going to stderr, and never in quiet mode.
    pub fn wants_progress(&self) -> bool {
        !self.no_progress && !self.quiet && std::io::IsTerminal::is_terminal(&std::io::stderr())
    }

    /// `true` when colour should be used.
    pub fn wants_color(&self) -> bool {
        if self.no_color || std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        self.output_file.is_some() || std::io::IsTerminal::is_terminal(&std::io::stdout())
    }

    /// Build the scan configuration these arguments describe.
    ///
    /// `stdin_targets` is the already-read content of stdin, when `-i -` asked
    /// for it; reading is the caller's job so that this stays testable.
    pub fn to_config(&self, stdin_targets: Option<&str>) -> Result<ScanConfig> {
        let targets = self.build_targets(stdin_targets)?;
        let ports = self.build_ports()?;

        let default_protocol = if self.udp { Protocol::Udp } else { Protocol::Tcp };
        let mut aimd = AimdConfig::default();
        self.timing.apply(&mut aimd);
        if let Some(concurrency) = self.concurrency {
            if concurrency == 0 {
                bail!("--concurrency must be at least 1");
            }
            aimd.initial_concurrency = concurrency;
            aimd.max_concurrency = aimd.max_concurrency.max(concurrency);
        }
        if let Some(rate) = self.max_rate {
            if !(rate.is_finite() && rate > 0.0) {
                bail!("--max-rate must be a positive number");
            }
            aimd.max_rate_pps = rate;
            aimd.initial_rate_pps = aimd.initial_rate_pps.min(rate);
        }
        if self.no_adapt {
            // Pin the controller: min == max in both dimensions.
            aimd.min_concurrency = aimd.initial_concurrency;
            aimd.max_concurrency = aimd.initial_concurrency;
            aimd.min_rate_pps = aimd.initial_rate_pps;
            aimd.max_rate_pps = aimd.initial_rate_pps;
        }

        if self.version_intensity > 9 {
            bail!("--version-intensity must be between 0 and 9");
        }

        let rtt = match self.timeout {
            Some(ms) => {
                let fixed = Duration::from_millis(ms.max(1));
                RttConfig { initial: fixed, min: fixed, max: fixed }
            }
            None => RttConfig {
                initial: Duration::from_millis(self.max_timeout.min(1000).max(self.min_timeout)),
                min: Duration::from_millis(self.min_timeout.max(1)),
                max: Duration::from_millis(self.max_timeout.max(self.min_timeout.max(1))),
            },
        };

        let discovery = DiscoveryConfig {
            enabled: !self.skip_discovery,
            icmp_echo: !self.no_icmp,
            tcp_connect: true,
            tcp_ack: self.tcp_ack,
            arp: !self.no_arp,
            tcp_ports: parse_port_list(&self.discovery_ports)?,
            ..DiscoveryConfig::default()
        };

        let service_detection = ServiceDetection {
            enabled: self.service_detection,
            banner: true,
            probes: true,
            tls: !self.no_tls,
            http: !self.no_http,
            intensity: self.version_intensity,
            ..ServiceDetection::default()
        };

        let mut builder = ScanConfig::builder()
            .targets(targets)
            .ports(ports)
            .mode(self.scan_type.into())
            .fallback_to_connect(!self.no_fallback)
            .discovery(discovery)
            .service_detection(service_detection)
            .retries(self.retries)
            .aimd(aimd)
            .rtt(rtt)
            .per_target_pps(match self.max_rate_host {
                None => PerTargetRate::Auto,
                Some(pps) if pps <= 0.0 => PerTargetRate::Off,
                Some(pps) => PerTargetRate::Fixed(pps),
            })
            .report_all_states(self.all_states);

        if let Some(path) = &self.resume {
            builder = builder.resume_path(path.clone());
        }
        let _ = default_protocol;

        builder.build().context("invalid scan configuration")
    }

    fn build_targets(&self, stdin_targets: Option<&str>) -> Result<TargetSet> {
        let mut set = TargetSet::new();

        for spec in &self.targets {
            set.add_line(spec).with_context(|| format!("target {spec:?}"))?;
        }

        if let Some(path) = &self.target_file {
            let text = if path.as_os_str() == "-" {
                stdin_targets
                    .map(str::to_string)
                    .context("stdin was requested but no input was supplied")?
            } else {
                std::fs::read_to_string(path)
                    .with_context(|| format!("reading targets from {}", path.display()))?
            };
            set.add_list(&text).context("parsing the target list")?;
        }

        if set.is_empty() {
            bail!("no targets given: pass addresses as arguments or use -i/--target-file");
        }

        for spec in &self.exclude {
            set.exclude_line(spec).with_context(|| format!("exclusion {spec:?}"))?;
        }
        if let Some(path) = &self.exclude_file {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading exclusions from {}", path.display()))?;
            for line in text.lines() {
                set.exclude_line(line).context("parsing the exclusion list")?;
            }
        }

        Ok(set)
    }

    fn build_ports(&self) -> Result<PortSpec> {
        let protocol = if self.udp { Protocol::Udp } else { Protocol::Tcp };

        let mut spec = match (&self.ports, self.top_ports) {
            (Some(text), _) => PortSpec::parse_for(text, protocol)
                .with_context(|| format!("port specification {text:?}"))?,
            (None, Some(n)) => {
                let available = ports::top_ports_available(protocol);
                if n > available {
                    eprintln!(
                        "warning: --top-ports {n} exceeds the {available} {protocol} entries in \
                         the embedded table; scanning all {available}"
                    );
                }
                PortSpec::top(protocol, n).context("building the top-ports list")?
            }
            (None, None) => {
                PortSpec::top(protocol, 100).context("building the default port list")?
            }
        };

        if let Some(text) = &self.exclude_ports {
            let excluded = PortSpec::parse_for(text, protocol)
                .with_context(|| format!("port exclusion {text:?}"))?;
            spec.exclude(&excluded);
            if spec.is_empty() {
                bail!("--exclude-ports removed every port from the scan");
            }
        }

        Ok(spec)
    }
}

fn parse_port_list(text: &str) -> Result<Vec<u16>> {
    let spec = PortSpec::parse(text).with_context(|| format!("port list {text:?}"))?;
    Ok(spec.ports(Protocol::Tcp).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Args {
        let mut full = vec!["rscan"];
        full.extend_from_slice(args);
        Args::try_parse_from(full).expect("arguments parse")
    }

    #[test]
    fn the_command_definition_is_valid() {
        Args::command().debug_assert();
    }

    #[test]
    fn defaults_are_a_top_100_tcp_connect_scan() {
        let args = parse(&["127.0.0.1"]);
        let config = args.to_config(None).expect("valid");
        assert_eq!(config.mode, ScanMode::Connect);
        assert_eq!(config.ports.ports(Protocol::Tcp).len(), 100);
        assert!(config.ports.ports(Protocol::Udp).is_empty());
        assert!(!config.service_detection.enabled);
        assert!(config.discovery.enabled);
    }

    #[test]
    fn port_specifications_are_honoured() {
        let config = parse(&["-p", "22,80,443", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.ports.ports(Protocol::Tcp), &[22, 80, 443]);

        let config = parse(&["-p", "-", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.ports.ports(Protocol::Tcp).len(), 65535);

        let config = parse(&["--top-ports", "10", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.ports.ports(Protocol::Tcp).len(), 10);
    }

    #[test]
    fn udp_mode_moves_unprefixed_ports_to_udp() {
        let config = parse(&["-U", "-p", "53,161", "127.0.0.1"]).to_config(None).expect("valid");
        assert!(config.ports.ports(Protocol::Tcp).is_empty());
        assert_eq!(config.ports.ports(Protocol::Udp), &[53, 161]);
    }

    #[test]
    fn both_protocols_can_be_scanned_at_once() {
        let config = parse(&["-p", "T:80,U:53", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.ports.ports(Protocol::Tcp), &[80]);
        assert_eq!(config.ports.ports(Protocol::Udp), &[53]);
    }

    #[test]
    fn port_exclusions_are_applied() {
        let config = parse(&["-p", "20-25", "--exclude-ports", "22", "127.0.0.1"])
            .to_config(None)
            .expect("valid");
        assert_eq!(config.ports.ports(Protocol::Tcp), &[20, 21, 23, 24, 25]);
    }

    #[test]
    fn excluding_every_port_is_an_error() {
        assert!(parse(&["-p", "80", "--exclude-ports", "80", "127.0.0.1"])
            .to_config(None)
            .is_err());
    }

    #[test]
    fn target_exclusions_are_applied() {
        let args = parse(&["192.0.2.0/30", "--exclude", "192.0.2.1,192.0.2.2"]);
        let config = args.to_config(None).expect("valid");
        let plan = config.targets.resolve_blocking().expect("no hostnames");
        assert_eq!(plan.approx_len(), 2);
    }

    #[test]
    fn targets_can_come_from_stdin() {
        let args = parse(&["-i", "-"]);
        let config = args.to_config(Some("192.0.2.1\n192.0.2.2\n")).expect("valid");
        assert_eq!(config.targets.specs().len(), 2);
    }

    #[test]
    fn a_missing_target_is_an_error() {
        assert!(parse(&["-p", "80"]).to_config(None).is_err());
        assert!(parse(&["-i", "-"]).to_config(None).is_err(), "stdin requested but unavailable");
    }

    #[test]
    fn timing_presets_change_only_pacing() {
        let polite = parse(&["-T", "polite", "127.0.0.1"]).to_config(None).expect("valid");
        let insane = parse(&["-T", "insane", "127.0.0.1"]).to_config(None).expect("valid");
        assert!(polite.aimd.max_rate_pps < insane.aimd.max_rate_pps);
        assert!(polite.aimd.initial_concurrency < insane.aimd.initial_concurrency);
        assert_eq!(polite.mode, insane.mode);
        assert_eq!(polite.retries, insane.retries);
    }

    #[test]
    fn explicit_rate_overrides_the_preset() {
        let config = parse(&["-T", "insane", "--max-rate", "42", "127.0.0.1"])
            .to_config(None)
            .expect("valid");
        assert_eq!(config.aimd.max_rate_pps, 42.0);
        assert!(config.aimd.initial_rate_pps <= 42.0);
    }

    #[test]
    fn no_adapt_pins_the_controller() {
        let config =
            parse(&["--no-adapt", "-c", "10", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.aimd.min_concurrency, config.aimd.max_concurrency);
        assert_eq!(config.aimd.min_rate_pps, config.aimd.max_rate_pps);
    }

    #[test]
    fn a_fixed_timeout_disables_estimation() {
        let config = parse(&["--timeout", "250", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.rtt.min, config.rtt.max);
        assert_eq!(config.rtt.min, Duration::from_millis(250));
    }

    #[test]
    fn the_per_target_cap_is_automatic_unless_asked_for() {
        let config = parse(&["127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.per_target_pps, PerTargetRate::Auto);

        let config =
            parse(&["--max-rate-host", "250", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.per_target_pps, PerTargetRate::Fixed(250.0));

        let config = parse(&["--max-rate-host", "0", "127.0.0.1"]).to_config(None).expect("valid");
        assert_eq!(config.per_target_pps, PerTargetRate::Off);
    }

    #[test]
    fn nonsense_pacing_values_are_rejected() {
        assert!(parse(&["-c", "0", "127.0.0.1"]).to_config(None).is_err());
        assert!(parse(&["--max-rate", "0", "127.0.0.1"]).to_config(None).is_err());
        assert!(parse(&["--version-intensity", "12", "127.0.0.1"]).to_config(None).is_err());
    }

    #[test]
    fn service_detection_flags_compose() {
        let config = parse(&["-s", "--no-tls", "127.0.0.1"]).to_config(None).expect("valid");
        assert!(config.service_detection.enabled);
        assert!(!config.service_detection.tls);
        assert!(config.service_detection.http);
    }

    #[test]
    fn discovery_flags_compose() {
        let config = parse(&["--no-icmp", "--no-arp", "--discovery-ports", "8080", "127.0.0.1"])
            .to_config(None)
            .expect("valid");
        assert!(!config.discovery.icmp_echo);
        assert!(!config.discovery.arp);
        assert_eq!(config.discovery.tcp_ports, vec![8080]);

        let config = parse(&["-P", "127.0.0.1"]).to_config(None).expect("valid");
        assert!(!config.discovery.enabled);
    }

    #[test]
    fn log_filters_follow_verbosity() {
        assert_eq!(parse(&["127.0.0.1"]).log_filter(), "warn");
        assert_eq!(parse(&["-v", "127.0.0.1"]).log_filter(), "info");
        assert_eq!(parse(&["-vv", "127.0.0.1"]).log_filter(), "debug");
        assert_eq!(parse(&["-q", "127.0.0.1"]).log_filter(), "error");
    }

    #[test]
    fn streaming_formats_are_identified() {
        assert!(OutputFormat::Jsonl.is_streaming());
        assert!(!OutputFormat::Json.is_streaming());
        assert!(!OutputFormat::NmapXml.is_streaming());
    }

    #[test]
    fn no_evasion_flags_exist() {
        // A regression guard on the project's stated scope.
        let command = Args::command();
        let names: Vec<String> = command.get_arguments().map(|a| a.get_id().to_string()).collect();
        for forbidden in ["decoy", "spoof", "spoof_source", "fragment", "badsum", "data_length"] {
            assert!(!names.iter().any(|n| n == forbidden), "{forbidden} must not be an option");
        }
    }
}
