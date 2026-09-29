//! Human-readable table output.
//!
//! Streams: a host header is printed the first time a result for that host
//! arrives, and each port on its own line as it is found. That matters on a
//! long scan — a format that only prints at the end gives no feedback at all.

use std::collections::HashSet;
use std::io::Write;
use std::net::IpAddr;

use anyhow::Result;
use owo_colors::OwoColorize;
use rscan_core::{HostStatus, PortResult, PortState, ScanSummary};

use super::{format_elapsed, Output, ScanMeta, Sink};

/// Writes a coloured table.
pub struct TextSink {
    out: Output,
    color: bool,
    seen_hosts: HashSet<IpAddr>,
    wrote_any_port: bool,
}

impl TextSink {
    /// Build a sink. `color` is decided by the caller from TTY detection and
    /// `NO_COLOR`.
    pub fn new(out: Output, color: bool) -> Self {
        Self { out, color, seen_hosts: HashSet::new(), wrote_any_port: false }
    }

    fn host_header(&mut self, result: &PortResult) -> Result<()> {
        if !self.seen_hosts.insert(result.addr) {
            return Ok(());
        }
        let label = match &result.hostname {
            Some(name) => format!("{name} ({})", result.addr),
            None => result.addr.to_string(),
        };
        writeln!(self.out)?;
        if self.color {
            writeln!(self.out, "{} {}", "Scan report for".bold(), label.bold().cyan())?;
        } else {
            writeln!(self.out, "Scan report for {label}")?;
        }
        writeln!(self.out, "{:<11}{:<15}{:<16}VERSION", "PORT", "STATE", "SERVICE")?;
        Ok(())
    }

    fn colour_state(&self, state: PortState) -> String {
        let text = state.as_str().to_string();
        if !self.color {
            return text;
        }
        match state {
            PortState::Open => text.green().bold().to_string(),
            PortState::Closed => text.red().to_string(),
            PortState::Filtered | PortState::OpenFiltered => text.yellow().to_string(),
            PortState::Unfiltered => text.blue().to_string(),
        }
    }
}

impl Sink for TextSink {
    fn start(&mut self, meta: &ScanMeta) -> Result<()> {
        writeln!(
            self.out,
            "Starting rscan {} at {} ({} scan, {} host(s), {} probe(s))",
            meta.version, meta.started_at, meta.mode, meta.hosts_total, meta.probes_total
        )?;
        Ok(())
    }

    fn port(&mut self, result: &PortResult) -> Result<()> {
        self.host_header(result)?;
        self.wrote_any_port = true;

        let port_label = format!("{}/{}", result.port, result.protocol);
        let service = result.service.as_ref();
        let name = service
            .and_then(|s| s.name.clone())
            .or_else(|| {
                rscan_core::ports::service_name(result.protocol, result.port).map(str::to_string)
            })
            .unwrap_or_else(|| "unknown".to_string());
        let version = service.map(|s| s.summary()).unwrap_or_default();

        // Width-aware padding: the coloured state string carries escape codes,
        // so it has to be padded before colouring, not after.
        let state_plain = result.state.as_str();
        let padding = 15usize.saturating_sub(state_plain.chars().count());
        writeln!(
            self.out,
            "{port_label:<11}{}{:padding$}{name:<16}{version}",
            self.colour_state(result.state),
            "",
        )?;

        if let Some(tls) = service.and_then(|s| s.tls.as_ref()) {
            let mut details = Vec::new();
            if let Some(version) = &tls.version {
                details.push(version.clone());
            }
            if let Some(alpn) = &tls.alpn {
                details.push(format!("alpn={alpn}"));
            }
            if let Some(cn) = &tls.subject_cn {
                details.push(format!("cn={cn}"));
            }
            if !tls.sans.is_empty() {
                details.push(format!("sans={}", tls.sans.join(",")));
            }
            writeln!(self.out, "{:<11}|_ tls: {}", "", details.join(" "))?;
        }
        if let Some(http) = service.and_then(|s| s.http.as_ref()) {
            let mut details = Vec::new();
            if let Some(status) = http.status {
                details.push(format!("status={status}"));
            }
            if let Some(title) = &http.title {
                details.push(format!("title={title:?}"));
            }
            if http.redirects_to_https {
                details.push("redirects to https".to_string());
            }
            if !details.is_empty() {
                writeln!(self.out, "{:<11}|_ http: {}", "", details.join(" "))?;
            }
        }
        Ok(())
    }

    fn host_up(&mut self, status: &HostStatus) -> Result<()> {
        let _ = status;
        Ok(())
    }

    fn finish(&mut self, summary: &ScanSummary) -> Result<()> {
        if !self.wrote_any_port {
            writeln!(self.out, "\nNo interesting ports found.")?;
        }
        writeln!(
            self.out,
            "\nrscan done: {} host(s) up of {} scanned in {}",
            summary.hosts_up,
            summary.hosts_total,
            format_elapsed(summary.elapsed)
        )?;
        writeln!(
            self.out,
            "  {} open, {} closed, {} filtered across {} probes ({} packets sent)",
            summary.ports_open,
            summary.ports_closed,
            summary.ports_filtered,
            summary.ports_scanned,
            summary.packets_sent
        )?;
        writeln!(
            self.out,
            "  settled at {} concurrent probes, {:.0} packets/second",
            summary.final_concurrency, summary.final_rate_pps
        )?;
        self.out.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests_support::{meta, sample_result, summary};
    use rscan_core::{Protocol, Reason};

    fn render(results: &[PortResult], color: bool) -> String {
        let buffer = crate::output::tests_support::SharedBuffer::new();
        let mut sink = TextSink::new(buffer.writer(), color);
        sink.start(&meta()).expect("start");
        for result in results {
            sink.port(result).expect("port");
        }
        sink.finish(&summary()).expect("finish");
        buffer.contents()
    }

    #[test]
    fn renders_a_table_with_a_host_header() {
        let text = render(&[sample_result()], false);
        assert!(text.contains("Scan report for 192.0.2.1"), "{text}");
        assert!(text.contains("PORT"), "{text}");
        assert!(text.contains("22/tcp"), "{text}");
        assert!(text.contains("open"), "{text}");
        assert!(text.contains("OpenSSH 9.6p1"), "{text}");
    }

    #[test]
    fn prints_the_host_header_once_per_host() {
        let mut second = sample_result();
        second.port = 80;
        let text = render(&[sample_result(), second], false);
        assert_eq!(text.matches("Scan report for").count(), 1, "{text}");
    }

    #[test]
    fn reports_the_summary() {
        let text = render(&[sample_result()], false);
        assert!(text.contains("rscan done"), "{text}");
        assert!(text.contains("1 open"), "{text}");
        assert!(text.contains("packets/second"), "{text}");
    }

    #[test]
    fn says_so_when_nothing_was_found() {
        let text = render(&[], false);
        assert!(text.contains("No interesting ports found"), "{text}");
    }

    #[test]
    fn colour_can_be_turned_off() {
        assert!(!render(&[sample_result()], false).contains('\x1b'));
        assert!(render(&[sample_result()], true).contains('\x1b'));
    }

    #[test]
    fn open_filtered_is_rendered_verbatim() {
        let mut result = sample_result();
        result.state = rscan_core::PortState::OpenFiltered;
        result.protocol = Protocol::Udp;
        result.reason = Reason::NoResponse;
        result.service = None;
        let text = render(&[result], false);
        assert!(text.contains("open|filtered"), "{text}");
        assert!(text.contains("22/udp"), "{text}");
    }
}
