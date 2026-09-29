//! Core result types: what a scan produces.
//!
//! These types are the stable, versioned surface that output formatters and
//! downstream consumers depend on. They are `serde`-serialisable and carry a
//! schema version ([`SCHEMA_VERSION`]) so that JSON consumers can detect
//! breaking changes.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Version of the JSON/JSONL schema emitted by this crate.
///
/// Bumped on any backwards-incompatible change to [`ScanEvent`] or
/// [`PortResult`].
pub const SCHEMA_VERSION: u32 = 1;

/// Transport protocol of a probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// Lowercase wire name (`"tcp"` / `"udp"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The state of a single port.
///
/// The distinction between [`Closed`](PortState::Closed) and
/// [`Filtered`](PortState::Filtered) is load-bearing: `closed` means the host
/// actively refused the connection (a RST came back), `filtered` means nothing
/// came back at all. Collapsing the two destroys most of the value of a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortState {
    /// A service accepted the connection (TCP) or answered (UDP).
    Open,
    /// The host actively refused: TCP RST, or ICMP port unreachable for UDP.
    Closed,
    /// No response at all, after every retransmission. Something is dropping
    /// packets: a firewall, a rate limiter, or the network.
    Filtered,
    /// UDP only: silence, which is indistinguishable from an open port whose
    /// service ignores unrecognised payloads.
    OpenFiltered,
    /// ACK-scan style result: a response proves the port is reachable but says
    /// nothing about whether it is open.
    Unfiltered,
}

impl PortState {
    /// Lowercase wire name, matching the serde representation and nmap's
    /// vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::Unfiltered => "unfiltered",
        }
    }

    /// `true` for states worth reporting by default (`open` and
    /// `open|filtered`).
    pub fn is_interesting(self) -> bool {
        matches!(self, PortState::Open | PortState::OpenFiltered)
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why the scanner concluded a given [`PortState`].
///
/// Mirrors nmap's `reason` attribute so that the XML output is faithful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// The TCP handshake completed.
    SynAck,
    /// A TCP RST came back.
    Reset,
    /// The connection was refused by the OS (`ECONNREFUSED`).
    ConnRefused,
    /// No response before the deadline, on every attempt.
    NoResponse,
    /// A UDP datagram came back.
    UdpResponse,
    /// ICMP type 3 code 3 (port unreachable).
    PortUnreachable,
    /// ICMP type 3 with an admin-prohibited style code.
    AdminProhibited,
    /// ICMP host or network unreachable.
    HostUnreachable,
    /// ICMP echo reply (host discovery).
    EchoReply,
    /// An ARP reply (host discovery on the local segment).
    ArpReply,
    /// The host was assumed up because discovery was skipped.
    UserSpecified,
    /// A local error (e.g. `ENETUNREACH`) prevented the probe.
    LocalError,
}

impl Reason {
    /// nmap-compatible reason string.
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::SynAck => "syn-ack",
            Reason::Reset => "reset",
            Reason::ConnRefused => "conn-refused",
            Reason::NoResponse => "no-response",
            Reason::UdpResponse => "udp-response",
            Reason::PortUnreachable => "port-unreach",
            Reason::AdminProhibited => "admin-prohibited",
            Reason::HostUnreachable => "host-unreach",
            Reason::EchoReply => "echo-reply",
            Reason::ArpReply => "arp-response",
            Reason::UserSpecified => "user-set",
            Reason::LocalError => "local-error",
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Everything learned about the service behind an open port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name, e.g. `"http"`, `"ssh"`. `None` when nothing matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Product name extracted from the banner, e.g. `"OpenSSH"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    /// Version string extracted from the banner, e.g. `"9.6p1"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Free-form extra information (OS hints, protocol details).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
    /// How confident the match is, 0..=10 (nmap's convention).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    /// The raw bytes the service sent, lossily decoded and truncated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// Populated when a TLS handshake succeeded on this port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsInfo>,
    /// Populated when the port speaks HTTP (directly or through TLS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpInfo>,
}

impl ServiceInfo {
    /// `true` when nothing at all was learned.
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.product.is_none()
            && self.version.is_none()
            && self.banner.is_none()
            && self.tls.is_none()
            && self.http.is_none()
    }

    /// Compact one-line rendering, e.g. `"OpenSSH 9.6p1 (Ubuntu)"`.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        if let Some(product) = &self.product {
            out.push_str(product);
        } else if let Some(name) = &self.name {
            out.push_str(name);
        }
        if let Some(version) = &self.version {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(version);
        }
        if let Some(info) = &self.info {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push('(');
            out.push_str(info);
            out.push(')');
        }
        out
    }
}

/// What a successful TLS handshake revealed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsInfo {
    /// Negotiated protocol version, e.g. `"TLSv1.3"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Negotiated ALPN protocol, e.g. `"h2"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// Leaf certificate subject common name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_cn: Option<String>,
    /// Leaf certificate issuer common name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_cn: Option<String>,
    /// Subject alternative names from the leaf certificate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sans: Vec<String>,
    /// `notBefore`, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// `notAfter`, RFC 3339.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
}

/// What an HTTP request to the port revealed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpInfo {
    /// HTTP status code from the response line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// `Server` response header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Contents of `<title>`, if the body contained one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// `Location` header, when the response was a redirect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// `true` when the response redirects to an `https://` URL.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub redirects_to_https: bool,
}

/// The result of probing one port on one host.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortResult {
    /// Address probed.
    pub addr: IpAddr,
    /// Hostname the address was resolved from, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Port number.
    pub port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
    /// Conclusion.
    pub state: PortState,
    /// Evidence behind the conclusion.
    pub reason: Reason,
    /// Round-trip time of the probe that produced the conclusion.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "millis_opt")]
    pub rtt: Option<Duration>,
    /// How many probes were sent before concluding (1 = no retransmissions).
    pub attempts: u32,
    /// Service detection results, when requested and the port is open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceInfo>,
}

impl PortResult {
    /// Build a minimal result with no timing or service information.
    pub fn new(
        addr: IpAddr,
        port: u16,
        protocol: Protocol,
        state: PortState,
        reason: Reason,
    ) -> Self {
        Self {
            addr,
            hostname: None,
            port,
            protocol,
            state,
            reason,
            rtt: None,
            attempts: 1,
            service: None,
        }
    }
}

/// Method that proved a host was up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryMethod {
    /// ICMP (or ICMPv6) echo reply.
    IcmpEcho,
    /// A completed or refused TCP connection to a probe port.
    TcpConnect,
    /// A RST in response to a bare ACK (requires raw sockets).
    TcpAck,
    /// An ARP reply on the local segment.
    Arp,
    /// Discovery was skipped; the host is assumed up.
    Assumed,
}

/// A host that was found (or assumed) to be up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostStatus {
    /// Address of the host.
    pub addr: IpAddr,
    /// Hostname it was resolved from, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// `true` when the host answered a discovery probe (or discovery was off).
    pub up: bool,
    /// How it was determined to be up.
    pub method: DiscoveryMethod,
    /// Round-trip time of the discovery probe.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "millis_opt")]
    pub rtt: Option<Duration>,
}

/// End-of-scan statistics.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Number of addresses in scope after expansion and exclusions.
    pub hosts_total: usize,
    /// Number of hosts that answered discovery (or were assumed up).
    pub hosts_up: usize,
    /// Number of port probes completed.
    pub ports_scanned: u64,
    /// Number of ports concluded `open`.
    pub ports_open: u64,
    /// Number of ports concluded `closed`.
    pub ports_closed: u64,
    /// Number of ports concluded `filtered` or `open|filtered`.
    pub ports_filtered: u64,
    /// Total probes transmitted, retransmissions included.
    pub packets_sent: u64,
    /// Wall-clock duration of the scan.
    #[serde(with = "millis")]
    pub elapsed: Duration,
    /// Concurrency the adaptive controller settled on.
    pub final_concurrency: usize,
    /// Rate (probes/second) the adaptive controller settled on.
    pub final_rate_pps: f64,
}

/// Live counters emitted alongside results so a UI can draw progress.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    /// Probes completed so far.
    pub completed: u64,
    /// Probes in scope in total.
    pub total: u64,
    /// Open ports found so far.
    pub open: u64,
    /// Current concurrency limit chosen by the adaptive controller.
    pub concurrency: usize,
    /// Current rate limit in probes per second.
    pub rate_pps: f64,
    /// Timeout rate observed in the most recent control window, 0.0..=1.0.
    pub timeout_rate: f64,
}

/// An event emitted by a running scan.
///
/// A [`Scanner`](crate::Scanner) produces a `Stream` of these, in the order
/// results become available. Nothing is buffered until the end: a consumer that
/// writes JSONL can start writing with the first event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum ScanEvent {
    /// Emitted once, before any probing.
    Started {
        /// Schema version of the events that follow.
        schema_version: u32,
        /// Number of addresses in scope.
        hosts_total: usize,
        /// Number of port probes in scope.
        probes_total: u64,
        /// RFC 3339 start time.
        started_at: String,
    },
    /// Emitted once per host that answered discovery.
    HostUp(HostStatus),
    /// Emitted once per host that did not answer discovery.
    HostDown(HostStatus),
    /// Emitted once per completed port probe.
    Port(Box<PortResult>),
    /// Periodic progress counters. Consumers may ignore these.
    Progress(ProgressSnapshot),
    /// Emitted once, last.
    Finished(Box<ScanSummary>),
}

/// serde helper: `Duration` as fractional milliseconds.
mod millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_f64(d.as_secs_f64() * 1000.0)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        let ms = f64::deserialize(d)?;
        Ok(Duration::from_secs_f64((ms / 1000.0).max(0.0)))
    }
}

/// serde helper: `Option<Duration>` as fractional milliseconds.
mod millis_opt {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S: Serializer>(d: &Option<Duration>, s: S) -> Result<S::Ok, S::Error> {
        match d {
            Some(d) => s.serialize_some(&(d.as_secs_f64() * 1000.0)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
        let ms = Option::<f64>::deserialize(d)?;
        Ok(ms.map(|ms| Duration::from_secs_f64((ms / 1000.0).max(0.0))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_state_strings_are_nmap_compatible() {
        assert_eq!(PortState::Open.as_str(), "open");
        assert_eq!(PortState::OpenFiltered.as_str(), "open|filtered");
    }

    #[test]
    fn closed_and_filtered_are_distinct() {
        assert_ne!(PortState::Closed, PortState::Filtered);
        assert!(!PortState::Closed.is_interesting());
        assert!(PortState::OpenFiltered.is_interesting());
    }

    #[test]
    fn port_result_round_trips_through_json() {
        let mut result = PortResult::new(
            "192.0.2.1".parse().expect("literal address"),
            22,
            Protocol::Tcp,
            PortState::Open,
            Reason::SynAck,
        );
        result.rtt = Some(Duration::from_micros(1500));
        let json = serde_json::to_string(&result).expect("serialise");
        assert!(json.contains("\"rtt\":1.5"), "{json}");
        let back: PortResult = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(back, result);
    }

    #[test]
    fn service_summary_renders_product_version_info() {
        let svc = ServiceInfo {
            name: Some("ssh".into()),
            product: Some("OpenSSH".into()),
            version: Some("9.6p1".into()),
            info: Some("Ubuntu".into()),
            ..Default::default()
        };
        assert_eq!(svc.summary(), "OpenSSH 9.6p1 (Ubuntu)");
    }

    #[test]
    fn event_tagging_is_stable() {
        let ev = ScanEvent::Progress(ProgressSnapshot {
            completed: 1,
            total: 2,
            open: 0,
            concurrency: 8,
            rate_pps: 100.0,
            timeout_rate: 0.0,
        });
        let json = serde_json::to_string(&ev).expect("serialise");
        assert!(json.starts_with("{\"event\":\"progress\""), "{json}");
    }
}
