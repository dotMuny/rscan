//! nmap-compatible XML output.
//!
//! The point of this format is that tools which already parse nmap XML —
//! Metasploit's `db_import`, Faraday, dozens of internal scripts — work with
//! `rscan` output without a line of change. That means matching nmap's DTD
//! exactly, including `scanner="nmap"`, which the DTD declares as a fixed
//! enumeration of one value. `rscan` identifies itself in the `args` attribute
//! and in an XML comment instead. The trade-off is recorded in
//! `docs/decisions.md`.
//!
//! The document is buffered: nmap XML nests ports inside hosts inside a single
//! root, so nothing can be written until every host is finished.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::IpAddr;

use anyhow::Result;
use rscan_core::{HostStatus, PortResult, PortState, ScanSummary};

use super::{xml_escape, Output, ScanMeta, Sink};

/// The `xmloutputversion` nmap 7.x emits; consumers key off it.
const XML_OUTPUT_VERSION: &str = "1.05";

/// Buffers results and writes one nmap-compatible document at the end.
pub struct XmlSink {
    out: Output,
    meta: Option<ScanMeta>,
    hosts: BTreeMap<IpAddr, HostRecord>,
}

#[derive(Default)]
struct HostRecord {
    hostname: Option<String>,
    up: bool,
    reason: String,
    ports: Vec<PortResult>,
    ignored: BTreeMap<String, u64>,
}

impl XmlSink {
    /// Build a sink writing to `out`.
    pub fn new(out: Output) -> Self {
        Self { out, meta: None, hosts: BTreeMap::new() }
    }

    fn entry(&mut self, addr: IpAddr) -> &mut HostRecord {
        self.hosts.entry(addr).or_default()
    }
}

impl Sink for XmlSink {
    fn start(&mut self, meta: &ScanMeta) -> Result<()> {
        self.meta = Some(meta.clone());
        Ok(())
    }

    fn host_up(&mut self, status: &HostStatus) -> Result<()> {
        let hostname = status.hostname.clone();
        let reason = status.method_reason();
        let entry = self.entry(status.addr);
        entry.up = true;
        entry.reason = reason;
        entry.hostname = hostname;
        Ok(())
    }

    fn host_down(&mut self, status: &HostStatus) -> Result<()> {
        let hostname = status.hostname.clone();
        let entry = self.entry(status.addr);
        entry.up = false;
        entry.reason = "no-response".to_string();
        entry.hostname = hostname;
        Ok(())
    }

    fn port(&mut self, result: &PortResult) -> Result<()> {
        let hostname = result.hostname.clone();
        let entry = self.entry(result.addr);
        if hostname.is_some() {
            entry.hostname = hostname;
        }
        // A port result implies the host answered, even if discovery was
        // skipped and no host_up event was ever emitted.
        entry.up = true;
        if entry.reason.is_empty() {
            entry.reason = "user-set".to_string();
        }
        if result.state.is_interesting() {
            entry.ports.push(result.clone());
        } else {
            *entry.ignored.entry(result.state.as_str().to_string()).or_default() += 1;
        }
        Ok(())
    }

    fn finish(&mut self, summary: &ScanSummary) -> Result<()> {
        let meta = self.meta.clone().unwrap_or_else(|| ScanMeta {
            command_line: "rscan".into(),
            started_at: String::new(),
            started_unix: 0,
            mode: "connect".into(),
            hosts_total: 0,
            probes_total: 0,
            tcp_ports: Vec::new(),
            udp_ports: Vec::new(),
            version: rscan_core::VERSION.to_string(),
        });

        let out = &mut self.out;
        writeln!(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
        writeln!(out, "<!DOCTYPE nmaprun>")?;
        writeln!(
            out,
            "<!-- Produced by rscan {} in nmap-compatible format; scanner=\"nmap\" is required by the DTD -->",
            xml_escape(&meta.version)
        )?;
        writeln!(
            out,
            "<nmaprun scanner=\"nmap\" args=\"{}\" start=\"{}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"{XML_OUTPUT_VERSION}\">",
            xml_escape(&meta.command_line),
            meta.started_unix,
            xml_escape(&meta.started_at),
            xml_escape(&meta.version),
        )?;

        if !meta.tcp_ports.is_empty() {
            let scan_type = if meta.mode == "syn" { "syn" } else { "connect" };
            writeln!(
                out,
                "<scaninfo type=\"{scan_type}\" protocol=\"tcp\" numservices=\"{}\" services=\"{}\"/>",
                meta.tcp_ports.len(),
                compress_ports(&meta.tcp_ports)
            )?;
        }
        if !meta.udp_ports.is_empty() {
            writeln!(
                out,
                "<scaninfo type=\"udp\" protocol=\"udp\" numservices=\"{}\" services=\"{}\"/>",
                meta.udp_ports.len(),
                compress_ports(&meta.udp_ports)
            )?;
        }
        writeln!(out, "<verbose level=\"0\"/>")?;
        writeln!(out, "<debugging level=\"0\"/>")?;

        for (addr, record) in &self.hosts {
            writeln!(out, "<host>")?;
            writeln!(
                out,
                "<status state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>",
                if record.up { "up" } else { "down" },
                xml_escape(&record.reason)
            )?;
            writeln!(
                out,
                "<address addr=\"{}\" addrtype=\"{}\"/>",
                addr,
                if addr.is_ipv4() { "ipv4" } else { "ipv6" }
            )?;
            if let Some(hostname) = &record.hostname {
                writeln!(out, "<hostnames>")?;
                writeln!(out, "<hostname name=\"{}\" type=\"user\"/>", xml_escape(hostname))?;
                writeln!(out, "</hostnames>")?;
            } else {
                writeln!(out, "<hostnames/>")?;
            }

            if !record.ports.is_empty() || !record.ignored.is_empty() {
                writeln!(out, "<ports>")?;
                for (state, count) in &record.ignored {
                    writeln!(
                        out,
                        "<extraports state=\"{}\" count=\"{count}\"/>",
                        xml_escape(state)
                    )?;
                }
                for result in &record.ports {
                    write_port(out, result)?;
                }
                writeln!(out, "</ports>")?;
            }
            writeln!(out, "</host>")?;
        }

        writeln!(out, "<runstats>")?;
        writeln!(
            out,
            "<finished time=\"{}\" timestr=\"{}\" elapsed=\"{:.2}\" summary=\"{}\" exit=\"success\"/>",
            meta.started_unix + summary.elapsed.as_secs(),
            xml_escape(&rscan_core::state::now_rfc3339()),
            summary.elapsed.as_secs_f64(),
            xml_escape(&format!(
                "rscan done at {}; {} host(s) up, {} open port(s), {} packet(s) sent",
                rscan_core::state::now_rfc3339(),
                summary.hosts_up,
                summary.ports_open,
                summary.packets_sent
            ))
        )?;
        writeln!(
            out,
            "<hosts up=\"{}\" down=\"{}\" total=\"{}\"/>",
            summary.hosts_up,
            summary.hosts_total.saturating_sub(summary.hosts_up),
            summary.hosts_total
        )?;
        writeln!(out, "</runstats>")?;
        writeln!(out, "</nmaprun>")?;
        out.flush()?;
        Ok(())
    }
}

fn write_port(out: &mut Output, result: &PortResult) -> Result<()> {
    writeln!(out, "<port protocol=\"{}\" portid=\"{}\">", result.protocol, result.port)?;
    writeln!(
        out,
        "<state state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>",
        result.state.as_str(),
        result.reason
    )?;

    if let Some(service) = &result.service {
        let name = service
            .name
            .clone()
            .or_else(|| {
                rscan_core::ports::service_name(result.protocol, result.port).map(str::to_string)
            })
            .unwrap_or_else(|| "unknown".to_string());
        // nmap's `method`: "table" means guessed from the port number,
        // "probed" means something actually answered.
        let method = if service.confidence.unwrap_or(0) <= 1 { "table" } else { "probed" };
        let mut attributes = format!(
            " name=\"{}\" conf=\"{}\" method=\"{method}\"",
            xml_escape(&name),
            service.confidence.unwrap_or(3).min(10)
        );
        if let Some(product) = &service.product {
            attributes.push_str(&format!(" product=\"{}\"", xml_escape(product)));
        }
        if let Some(version) = &service.version {
            attributes.push_str(&format!(" version=\"{}\"", xml_escape(version)));
        }
        if let Some(info) = &service.info {
            attributes.push_str(&format!(" extrainfo=\"{}\"", xml_escape(info)));
        }
        if service.tls.is_some() {
            attributes.push_str(" tunnel=\"ssl\"");
        }
        if let Some(cn) = service.tls.as_ref().and_then(|t| t.subject_cn.as_ref()) {
            attributes.push_str(&format!(" hostname=\"{}\"", xml_escape(cn)));
        }
        writeln!(out, "<service{attributes}/>")?;
    }

    writeln!(out, "</port>")?;
    Ok(())
}

/// Render a port list the way nmap's `services` attribute does: `1-3,8,20-25`.
fn compress_ports(ports: &[u16]) -> String {
    let mut parts = Vec::new();
    let mut index = 0;
    while index < ports.len() {
        let start = ports[index];
        let mut end = start;
        while index + 1 < ports.len() && ports[index + 1] == end + 1 {
            index += 1;
            end = ports[index];
        }
        if start == end {
            parts.push(start.to_string());
        } else {
            parts.push(format!("{start}-{end}"));
        }
        index += 1;
    }
    parts.join(",")
}

/// Helper on [`HostStatus`] for nmap's `reason` vocabulary.
trait MethodReason {
    fn method_reason(&self) -> String;
}

impl MethodReason for HostStatus {
    fn method_reason(&self) -> String {
        use rscan_core::DiscoveryMethod;
        match self.method {
            DiscoveryMethod::IcmpEcho => "echo-reply",
            DiscoveryMethod::TcpConnect => "syn-ack",
            DiscoveryMethod::TcpAck => "reset",
            DiscoveryMethod::Arp => "arp-response",
            DiscoveryMethod::Assumed => "user-set",
        }
        .to_string()
    }
}

/// Never constructed; keeps the unused-import checker honest about
/// [`PortState`] being part of this module's vocabulary.
#[allow(dead_code)]
fn _state_vocabulary(state: PortState) -> &'static str {
    state.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests_support::{
        host_status, meta, sample_result, summary, tls_result, SharedBuffer,
    };

    fn render(results: &[PortResult]) -> String {
        let buffer = SharedBuffer::new();
        let mut sink = XmlSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        sink.host_up(&host_status(true)).expect("host");
        for result in results {
            sink.port(result).expect("port");
        }
        sink.finish(&summary()).expect("finish");
        buffer.contents()
    }

    #[test]
    fn emits_an_nmap_shaped_document() {
        let xml = render(&[sample_result()]);
        assert!(xml.contains("<?xml version=\"1.0\""), "{xml}");
        assert!(xml.contains("<!DOCTYPE nmaprun>"), "{xml}");
        assert!(xml.contains("scanner=\"nmap\""), "{xml}");
        assert!(xml.contains("xmloutputversion=\"1.05\""), "{xml}");
        assert!(xml.contains("<port protocol=\"tcp\" portid=\"22\">"), "{xml}");
        assert!(xml.contains("<state state=\"open\" reason=\"syn-ack\""), "{xml}");
        assert!(xml.contains("product=\"OpenSSH\""), "{xml}");
        assert!(xml.contains("</nmaprun>"), "{xml}");
    }

    #[test]
    fn identifies_itself_despite_the_required_scanner_name() {
        let xml = render(&[sample_result()]);
        assert!(xml.contains("Produced by rscan"), "{xml}");
        assert!(xml.contains("args=\"rscan"), "{xml}");
    }

    #[test]
    fn tls_services_are_tunnelled() {
        let xml = render(&[tls_result()]);
        assert!(xml.contains("tunnel=\"ssl\""), "{xml}");
        assert!(xml.contains("hostname=\"example.com\""), "{xml}");
    }

    #[test]
    fn uninteresting_ports_become_extraports() {
        let mut closed = sample_result();
        closed.state = PortState::Closed;
        closed.service = None;
        let xml = render(&[sample_result(), closed]);
        assert!(xml.contains("<extraports state=\"closed\" count=\"1\"/>"), "{xml}");
    }

    #[test]
    fn special_characters_are_escaped() {
        let mut result = sample_result();
        if let Some(service) = result.service.as_mut() {
            service.product = Some("Acme & <Co> \"quoted\"".into());
        }
        let xml = render(&[result]);
        assert!(xml.contains("product=\"Acme &amp; &lt;Co&gt; &quot;quoted&quot;\""), "{xml}");
        assert!(!xml.contains("product=\"Acme & <"), "{xml}");
    }

    #[test]
    fn port_lists_are_compressed_like_nmap() {
        assert_eq!(compress_ports(&[1, 2, 3, 8, 20, 21, 22]), "1-3,8,20-22");
        assert_eq!(compress_ports(&[80]), "80");
        assert_eq!(compress_ports(&[]), "");
    }

    #[test]
    fn a_scan_with_no_results_still_produces_a_document() {
        let xml = render(&[]);
        assert!(xml.contains("<runstats>"), "{xml}");
        assert!(xml.contains("</nmaprun>"), "{xml}");
    }
}
