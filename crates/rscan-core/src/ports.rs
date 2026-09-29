//! Port specification parsing and the embedded top-ports table.
//!
//! ```
//! use rscan_core::ports::PortSpec;
//! use rscan_core::Protocol;
//!
//! let spec = PortSpec::parse("22,80,8000-8002")?;
//! assert_eq!(spec.ports(Protocol::Tcp), &[22, 80, 8000, 8001, 8002]);
//!
//! // `-p-` is the whole range.
//! assert_eq!(PortSpec::parse("-")?.ports(Protocol::Tcp).len(), 65535);
//!
//! // nmap-style protocol prefixes are understood too.
//! let spec = PortSpec::parse("T:80,U:53")?;
//! assert_eq!(spec.ports(Protocol::Tcp), &[80]);
//! assert_eq!(spec.ports(Protocol::Udp), &[53]);
//! # Ok::<(), rscan_core::Error>(())
//! ```

use std::collections::BTreeSet;
use std::str::FromStr;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::Protocol;

/// The embedded top-ports table, as shipped in `data/top-ports.csv`.
const TOP_PORTS_CSV: &str = include_str!("../data/top-ports.csv");

/// One row of the top-ports table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopPortEntry {
    /// Port number.
    pub port: u16,
    /// Transport protocol.
    pub protocol: Protocol,
    /// 1-based rank; 1 is the most commonly open port.
    pub rank: u32,
    /// Conventional service name for the port.
    pub service: String,
}

/// Parse a top-ports table in the `port,protocol,rank,service` format.
///
/// Exposed so that the fuzz target and tests can exercise it directly. Blank
/// lines and `#` comments are skipped; anything else that does not have exactly
/// four fields is an error.
pub fn parse_top_ports_table(text: &str) -> Result<Vec<TopPortEntry>> {
    let mut entries = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let err = |reason: &str| {
            Error::invalid_ports(line, format!("top-ports table line {}: {reason}", lineno + 1))
        };
        let mut fields = line.split(',');
        let (Some(port), Some(proto), Some(rank), Some(service), None) =
            (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(err("expected exactly 4 comma-separated fields"));
        };
        let port: u16 = port.trim().parse().map_err(|_| err("port is not a number in 1-65535"))?;
        if port == 0 {
            return Err(err("port 0 is not scannable"));
        }
        let protocol = match proto.trim() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => return Err(err(&format!("unknown protocol {other:?}"))),
        };
        let rank: u32 = rank.trim().parse().map_err(|_| err("rank is not a number"))?;
        entries.push(TopPortEntry { port, protocol, rank, service: service.trim().to_string() });
    }
    Ok(entries)
}

static TOP_PORTS: Lazy<Vec<TopPortEntry>> = Lazy::new(|| {
    // The table is embedded at compile time and covered by a test, so a parse
    // failure here means the shipped data file is broken. Degrade to an empty
    // table rather than panicking inside a library.
    parse_top_ports_table(TOP_PORTS_CSV).unwrap_or_default()
});

/// The first `n` ports of `protocol`, ordered by rank.
///
/// Returns fewer than `n` entries when the table is smaller, which the CLI
/// reports as a warning rather than an error.
pub fn top_ports(protocol: Protocol, n: usize) -> Vec<u16> {
    TOP_PORTS.iter().filter(|e| e.protocol == protocol).take(n).map(|e| e.port).collect()
}

/// How many ports the embedded table holds for `protocol`.
pub fn top_ports_available(protocol: Protocol) -> usize {
    TOP_PORTS.iter().filter(|e| e.protocol == protocol).count()
}

/// The conventional service name for a port, from the embedded table.
pub fn service_name(protocol: Protocol, port: u16) -> Option<&'static str> {
    TOP_PORTS.iter().find(|e| e.protocol == protocol && e.port == port).map(|e| e.service.as_str())
}

/// A parsed set of ports, split by protocol.
///
/// Ports are stored sorted and de-duplicated, which makes the scan order
/// deterministic and keeps resume bookkeeping simple.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSpec {
    tcp: Vec<u16>,
    udp: Vec<u16>,
}

impl PortSpec {
    /// An empty specification.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a specification from explicit port lists.
    pub fn from_lists(
        tcp: impl IntoIterator<Item = u16>,
        udp: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self { tcp: sorted_unique(tcp), udp: sorted_unique(udp) }
    }

    /// Parse a port specification.
    ///
    /// Accepted forms, comma separated and freely mixed:
    ///
    /// - `80` — a single port
    /// - `1-1024` — an inclusive range
    /// - `-1024` / `1024-` — open-ended ranges, anchored at 1 and 65535
    /// - `-` — every port, 1 to 65535
    /// - `T:` / `U:` prefixes — everything after the prefix applies to that
    ///   protocol until the next prefix
    ///
    /// Without a prefix, ports apply to TCP.
    pub fn parse(spec: &str) -> Result<Self> {
        Self::parse_for(spec, Protocol::Tcp)
    }

    /// Like [`PortSpec::parse`] but with an explicit default protocol for
    /// unprefixed entries, so `--udp -p 53` does the obvious thing.
    pub fn parse_for(spec: &str, default_protocol: Protocol) -> Result<Self> {
        let trimmed = spec.trim();
        if trimmed.is_empty() {
            return Err(Error::invalid_ports(spec, "empty port specification"));
        }

        let mut tcp = BTreeSet::new();
        let mut udp = BTreeSet::new();
        let mut current = default_protocol;

        for raw in trimmed.split(',') {
            let mut item = raw.trim();
            if item.is_empty() {
                return Err(Error::invalid_ports(spec, "empty entry between commas"));
            }

            if let Some(rest) = strip_protocol_prefix(item) {
                let (proto, rest) = rest;
                current = proto;
                if rest.is_empty() {
                    // A bare `T:` just switches protocol for what follows.
                    continue;
                }
                item = rest;
            }

            let sink = match current {
                Protocol::Tcp => &mut tcp,
                Protocol::Udp => &mut udp,
            };
            parse_entry(spec, item, sink)?;
        }

        if tcp.is_empty() && udp.is_empty() {
            return Err(Error::invalid_ports(spec, "specification selects no ports"));
        }

        Ok(Self { tcp: tcp.into_iter().collect(), udp: udp.into_iter().collect() })
    }

    /// Build a specification from the top `n` ports of the embedded table.
    pub fn top(protocol: Protocol, n: usize) -> Result<Self> {
        if n == 0 {
            return Err(Error::invalid_ports(format!("--top-ports {n}"), "must be at least 1"));
        }
        let ports = top_ports(protocol, n);
        if ports.is_empty() {
            return Err(Error::invalid_ports(
                format!("--top-ports {n}"),
                format!("the embedded table has no {protocol} entries"),
            ));
        }
        Ok(match protocol {
            Protocol::Tcp => Self { tcp: sorted_unique(ports), udp: Vec::new() },
            Protocol::Udp => Self { tcp: Vec::new(), udp: sorted_unique(ports) },
        })
    }

    /// Every port from 1 to 65535 on `protocol`.
    pub fn all(protocol: Protocol) -> Self {
        let ports: Vec<u16> = (1..=u16::MAX).collect();
        match protocol {
            Protocol::Tcp => Self { tcp: ports, udp: Vec::new() },
            Protocol::Udp => Self { tcp: Vec::new(), udp: ports },
        }
    }

    /// Remove ports listed in `spec` from this specification.
    ///
    /// Backs `--exclude-ports`.
    pub fn exclude(&mut self, spec: &PortSpec) -> &mut Self {
        self.tcp.retain(|p| !spec.tcp.contains(p));
        self.udp.retain(|p| !spec.udp.contains(p));
        self
    }

    /// Merge another specification into this one.
    pub fn merge(&mut self, other: &PortSpec) -> &mut Self {
        self.tcp = sorted_unique(self.tcp.iter().copied().chain(other.tcp.iter().copied()));
        self.udp = sorted_unique(self.udp.iter().copied().chain(other.udp.iter().copied()));
        self
    }

    /// The sorted ports for `protocol`.
    pub fn ports(&self, protocol: Protocol) -> &[u16] {
        match protocol {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
        }
    }

    /// Total number of ports across both protocols.
    pub fn len(&self) -> usize {
        self.tcp.len() + self.udp.len()
    }

    /// `true` when no port is selected.
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty()
    }

    /// The protocols that have at least one port.
    pub fn protocols(&self) -> Vec<Protocol> {
        let mut out = Vec::new();
        if !self.tcp.is_empty() {
            out.push(Protocol::Tcp);
        }
        if !self.udp.is_empty() {
            out.push(Protocol::Udp);
        }
        out
    }
}

impl FromStr for PortSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        PortSpec::parse(s)
    }
}

fn strip_protocol_prefix(item: &str) -> Option<(Protocol, &str)> {
    let (head, rest) = item.split_once(':')?;
    let proto = match head.trim() {
        "T" | "t" | "tcp" | "TCP" => Protocol::Tcp,
        "U" | "u" | "udp" | "UDP" => Protocol::Udp,
        _ => return None,
    };
    Some((proto, rest.trim()))
}

fn parse_entry(spec: &str, item: &str, sink: &mut BTreeSet<u16>) -> Result<()> {
    let bad = |reason: &str| Error::invalid_ports(spec, format!("{item:?}: {reason}"));

    if item == "-" {
        sink.extend(1..=u16::MAX);
        return Ok(());
    }

    if let Some((lo, hi)) = item.split_once('-') {
        if lo.contains('-') || hi.contains('-') {
            return Err(bad("a range has exactly one hyphen"));
        }
        let lo = if lo.is_empty() {
            1
        } else {
            parse_port(lo).ok_or_else(|| bad("range start is not a port in 1-65535"))?
        };
        let hi = if hi.is_empty() {
            u16::MAX
        } else {
            parse_port(hi).ok_or_else(|| bad("range end is not a port in 1-65535"))?
        };
        if lo > hi {
            return Err(bad("range start is greater than range end"));
        }
        sink.extend(lo..=hi);
        return Ok(());
    }

    let port = parse_port(item).ok_or_else(|| bad("not a port in 1-65535"))?;
    sink.insert(port);
    Ok(())
}

fn parse_port(s: &str) -> Option<u16> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match s.parse::<u16>() {
        Ok(0) | Err(_) => None,
        Ok(p) => Some(p),
    }
}

fn sorted_unique(ports: impl IntoIterator<Item = u16>) -> Vec<u16> {
    let set: BTreeSet<u16> = ports.into_iter().filter(|&p| p != 0).collect();
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(spec: &str) -> Vec<u16> {
        PortSpec::parse(spec).expect("test literal parses").ports(Protocol::Tcp).to_vec()
    }

    #[test]
    fn parses_single_ports_and_lists() {
        assert_eq!(tcp("80"), vec![80]);
        assert_eq!(tcp("80,443,22"), vec![22, 80, 443]);
    }

    #[test]
    fn parses_ranges() {
        assert_eq!(tcp("20-23"), vec![20, 21, 22, 23]);
        assert_eq!(tcp("1-1024").len(), 1024);
    }

    #[test]
    fn parses_open_ended_ranges() {
        assert_eq!(tcp("-3"), vec![1, 2, 3]);
        assert_eq!(tcp("65533-"), vec![65533, 65534, 65535]);
    }

    #[test]
    fn dash_means_every_port() {
        assert_eq!(tcp("-").len(), 65535);
        assert_eq!(PortSpec::all(Protocol::Tcp).ports(Protocol::Tcp).len(), 65535);
    }

    #[test]
    fn deduplicates_and_sorts() {
        assert_eq!(tcp("443,80,443,79-81"), vec![79, 80, 81, 443]);
    }

    #[test]
    fn honours_protocol_prefixes() {
        let spec = PortSpec::parse("T:80,443,U:53,161").expect("parses");
        assert_eq!(spec.ports(Protocol::Tcp), &[80, 443]);
        assert_eq!(spec.ports(Protocol::Udp), &[53, 161]);
    }

    #[test]
    fn bare_prefix_switches_protocol() {
        let spec = PortSpec::parse("80,U:,53").expect("parses");
        assert_eq!(spec.ports(Protocol::Tcp), &[80]);
        assert_eq!(spec.ports(Protocol::Udp), &[53]);
    }

    #[test]
    fn default_protocol_can_be_udp() {
        let spec = PortSpec::parse_for("53,123", Protocol::Udp).expect("parses");
        assert!(spec.ports(Protocol::Tcp).is_empty());
        assert_eq!(spec.ports(Protocol::Udp), &[53, 123]);
    }

    #[test]
    fn rejects_malformed_specifications() {
        for bad in [
            "", "   ", "0", "65536", "80,", ",80", "80,,443", "abc", "80-", // fine
        ]
        .iter()
        .filter(|s| **s != "80-")
        {
            assert!(PortSpec::parse(bad).is_err(), "{bad:?} should not parse");
        }
        for bad in ["100-50", "1-2-3", "-0", "8o", "0-10", "80 443", "+80", "80.0"] {
            assert!(PortSpec::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn excluding_ports_removes_them() {
        let mut spec = PortSpec::parse("20-25").expect("parses");
        let excl = PortSpec::parse("22,24").expect("parses");
        spec.exclude(&excl);
        assert_eq!(spec.ports(Protocol::Tcp), &[20, 21, 23, 25]);
    }

    #[test]
    fn merging_unions_both_protocols() {
        let mut spec = PortSpec::parse("80").expect("parses");
        spec.merge(&PortSpec::parse("U:53").expect("parses"));
        assert_eq!(spec.ports(Protocol::Tcp), &[80]);
        assert_eq!(spec.ports(Protocol::Udp), &[53]);
        assert_eq!(spec.len(), 2);
        assert_eq!(spec.protocols(), vec![Protocol::Tcp, Protocol::Udp]);
    }

    #[test]
    fn embedded_top_ports_table_parses() {
        let entries = parse_top_ports_table(TOP_PORTS_CSV).expect("shipped table is valid");
        assert!(entries.len() > 200, "table looks truncated: {}", entries.len());
        assert!(top_ports_available(Protocol::Tcp) > 100);
        assert!(top_ports_available(Protocol::Udp) > 50);
    }

    #[test]
    fn top_ports_are_ranked_and_start_with_http() {
        let ports = top_ports(Protocol::Tcp, 5);
        assert_eq!(ports.len(), 5);
        assert_eq!(ports[0], 80);
        assert!(ports.contains(&443));
        assert_eq!(service_name(Protocol::Tcp, 22), Some("ssh"));
        assert_eq!(service_name(Protocol::Udp, 53), Some("domain"));
    }

    #[test]
    fn top_ports_table_has_unique_rows_and_dense_ranks() {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let rows: Vec<_> = TOP_PORTS.iter().filter(|e| e.protocol == protocol).collect();
            let mut ports: Vec<u16> = rows.iter().map(|e| e.port).collect();
            ports.sort_unstable();
            let before = ports.len();
            ports.dedup();
            assert_eq!(before, ports.len(), "duplicate {protocol} port in the table");
            for (i, row) in rows.iter().enumerate() {
                assert_eq!(row.rank as usize, i + 1, "ranks must be dense and ordered");
            }
        }
    }

    #[test]
    fn top_spec_is_capped_by_the_table() {
        let available = top_ports_available(Protocol::Tcp);
        let spec = PortSpec::top(Protocol::Tcp, available + 1000).expect("clamps");
        assert_eq!(spec.ports(Protocol::Tcp).len(), available);
        assert!(PortSpec::top(Protocol::Tcp, 0).is_err());
    }

    #[test]
    fn malformed_tables_are_rejected() {
        for bad in [
            "80,tcp,1",
            "80,tcp,1,http,extra",
            "80,sctp,1,http",
            "0,tcp,1,zero",
            "65536,tcp,1,toobig",
            "eighty,tcp,1,http",
            "80,tcp,x,http",
        ] {
            assert!(parse_top_ports_table(bad).is_err(), "{bad:?} should not parse");
        }
        assert!(parse_top_ports_table("# only a comment\n\n").expect("valid").is_empty());
    }
}
