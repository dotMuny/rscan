//! CSV and grepable output.
//!
//! Both are "one line you can `grep`" formats. CSV is for spreadsheets and
//! `pandas`; grepable mirrors nmap's `-oG` so existing one-liners keep working.

use std::io::Write;

use anyhow::Result;
use rscan_core::{HostStatus, PortResult, ScanSummary};

use super::{Output, ScanMeta, Sink};

/// Writes comma-separated values, one row per port result.
pub struct CsvSink {
    writer: csv::Writer<Output>,
    rows: u64,
}

impl CsvSink {
    /// Build a sink writing to `out`.
    pub fn new(out: Output) -> Self {
        Self { writer: csv::Writer::from_writer(out), rows: 0 }
    }
}

impl Sink for CsvSink {
    fn start(&mut self, _meta: &ScanMeta) -> Result<()> {
        self.writer.write_record([
            "address",
            "hostname",
            "port",
            "protocol",
            "state",
            "reason",
            "rtt_ms",
            "attempts",
            "service",
            "product",
            "version",
            "extra_info",
            "tls_version",
            "tls_subject_cn",
            "http_status",
            "http_server",
            "banner",
        ])?;
        Ok(())
    }

    fn port(&mut self, result: &PortResult) -> Result<()> {
        let service = result.service.as_ref();
        let tls = service.and_then(|s| s.tls.as_ref());
        let http = service.and_then(|s| s.http.as_ref());
        self.writer.write_record([
            result.addr.to_string(),
            result.hostname.clone().unwrap_or_default(),
            result.port.to_string(),
            result.protocol.to_string(),
            result.state.to_string(),
            result.reason.to_string(),
            result.rtt.map(|d| format!("{:.3}", d.as_secs_f64() * 1000.0)).unwrap_or_default(),
            result.attempts.to_string(),
            service.and_then(|s| s.name.clone()).unwrap_or_default(),
            service.and_then(|s| s.product.clone()).unwrap_or_default(),
            service.and_then(|s| s.version.clone()).unwrap_or_default(),
            service.and_then(|s| s.info.clone()).unwrap_or_default(),
            tls.and_then(|t| t.version.clone()).unwrap_or_default(),
            tls.and_then(|t| t.subject_cn.clone()).unwrap_or_default(),
            http.and_then(|h| h.status).map(|s| s.to_string()).unwrap_or_default(),
            http.and_then(|h| h.server.clone()).unwrap_or_default(),
            service.and_then(|s| s.banner.clone()).unwrap_or_default(),
        ])?;
        self.rows += 1;
        // Flush per row so CSV is usable in a pipeline too.
        self.writer.flush()?;
        Ok(())
    }

    fn finish(&mut self, _summary: &ScanSummary) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}

/// Writes nmap-style grepable output: one line per host.
pub struct GrepableSink {
    out: Output,
    current: Option<HostLine>,
}

struct HostLine {
    addr: String,
    hostname: String,
    ports: Vec<String>,
}

impl GrepableSink {
    /// Build a sink writing to `out`.
    pub fn new(out: Output) -> Self {
        Self { out, current: None }
    }

    fn flush_host(&mut self) -> Result<()> {
        let Some(host) = self.current.take() else {
            return Ok(());
        };
        writeln!(
            self.out,
            "Host: {} ({})\tPorts: {}",
            host.addr,
            host.hostname,
            host.ports.join(", ")
        )?;
        self.out.flush()?;
        Ok(())
    }
}

impl Sink for GrepableSink {
    fn start(&mut self, meta: &ScanMeta) -> Result<()> {
        writeln!(self.out, "# rscan {} scan initiated {}", meta.version, meta.started_at)?;
        writeln!(self.out, "# Command: {}", meta.command_line)?;
        Ok(())
    }

    fn host_up(&mut self, status: &HostStatus) -> Result<()> {
        writeln!(
            self.out,
            "Host: {} ({})\tStatus: Up",
            status.addr,
            status.hostname.clone().unwrap_or_default()
        )?;
        Ok(())
    }

    fn host_down(&mut self, status: &HostStatus) -> Result<()> {
        writeln!(
            self.out,
            "Host: {} ({})\tStatus: Down",
            status.addr,
            status.hostname.clone().unwrap_or_default()
        )?;
        Ok(())
    }

    fn port(&mut self, result: &PortResult) -> Result<()> {
        let addr = result.addr.to_string();
        if self.current.as_ref().is_some_and(|h| h.addr != addr) {
            self.flush_host()?;
        }
        let entry = self.current.get_or_insert_with(|| HostLine {
            addr: addr.clone(),
            hostname: result.hostname.clone().unwrap_or_default(),
            ports: Vec::new(),
        });

        let service = result.service.as_ref();
        // nmap's field order: port/state/protocol/owner/service/rpc/version/
        let name = service.and_then(|s| s.name.clone()).unwrap_or_default();
        let version = service.map(|s| s.summary()).unwrap_or_default();
        entry.ports.push(format!(
            "{}/{}/{}//{}//{}/",
            result.port,
            result.state,
            result.protocol,
            sanitise_field(&name),
            sanitise_field(&version)
        ));
        Ok(())
    }

    fn finish(&mut self, summary: &ScanSummary) -> Result<()> {
        self.flush_host()?;
        writeln!(
            self.out,
            "# rscan done: {} host(s) up, {} open port(s) in {}",
            summary.hosts_up,
            summary.ports_open,
            super::format_elapsed(summary.elapsed)
        )?;
        self.out.flush()?;
        Ok(())
    }
}

/// Remove the characters that would break the grepable field structure.
fn sanitise_field(text: &str) -> String {
    text.replace(['/', '\t', '\n', '\r', ','], " ").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests_support::{host_status, meta, sample_result, summary, SharedBuffer};

    #[test]
    fn csv_has_a_header_and_one_row_per_result() {
        let buffer = SharedBuffer::new();
        let mut sink = CsvSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        sink.port(&sample_result()).expect("port");
        sink.finish(&summary()).expect("finish");

        let text = buffer.contents();
        let mut lines = text.lines();
        let header = lines.next().expect("header");
        assert!(header.starts_with("address,hostname,port,protocol,state"), "{header}");
        let row = lines.next().expect("row");
        assert!(row.starts_with("192.0.2.1,,22,tcp,open,syn-ack"), "{row}");
        assert!(row.contains("OpenSSH"), "{row}");
    }

    #[test]
    fn csv_quotes_fields_that_need_it() {
        let buffer = SharedBuffer::new();
        let mut sink = CsvSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        let mut result = sample_result();
        if let Some(service) = result.service.as_mut() {
            service.product = Some("Weird, \"quoted\" product".into());
        }
        sink.port(&result).expect("port");
        sink.finish(&summary()).expect("finish");

        let text = buffer.contents();
        let row = text.lines().nth(1).expect("row");
        assert!(row.contains("\"Weird, \"\"quoted\"\" product\""), "{row}");
        // And it must still parse back.
        let mut reader = csv::Reader::from_reader(text.as_bytes());
        let record = reader.records().next().expect("row").expect("parses");
        assert_eq!(&record[9], "Weird, \"quoted\" product");
    }

    #[test]
    fn grepable_groups_ports_per_host() {
        let buffer = SharedBuffer::new();
        let mut sink = GrepableSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        sink.host_up(&host_status(true)).expect("host");
        sink.port(&sample_result()).expect("port");
        let mut second = sample_result();
        second.port = 80;
        second.service = None;
        sink.port(&second).expect("port");
        sink.finish(&summary()).expect("finish");

        let text = buffer.contents();
        assert!(text.contains("Host: 192.0.2.1 (host.example.com)\tStatus: Up"), "{text}");
        let ports_line = text.lines().find(|l| l.contains("Ports:")).expect("a ports line");
        assert!(ports_line.contains("22/open/tcp//ssh//OpenSSH 9.6p1 (Ubuntu)/"), "{ports_line}");
        assert!(ports_line.contains("80/open/tcp"), "{ports_line}");
        assert!(text.contains("# rscan done"), "{text}");
    }

    #[test]
    fn grepable_starts_a_new_line_for_each_host() {
        let buffer = SharedBuffer::new();
        let mut sink = GrepableSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        sink.port(&sample_result()).expect("port");
        let mut other = sample_result();
        other.addr = "192.0.2.2".parse().expect("literal");
        sink.port(&other).expect("port");
        sink.finish(&summary()).expect("finish");

        let text = buffer.contents();
        assert_eq!(text.matches("Ports:").count(), 2, "{text}");
    }

    #[test]
    fn grepable_fields_cannot_be_broken_by_a_hostile_banner() {
        assert_eq!(sanitise_field("a/b\tc\nd,e"), "a b c d e");
        assert_eq!(sanitise_field("  padded  "), "padded");
    }
}
