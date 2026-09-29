//! Buffered JSON document output.
//!
//! A single, well-formed document, which most consumers find easier than JSON
//! Lines — at the cost of producing nothing until the scan ends. Use `jsonl`
//! when that matters.

use std::io::Write;

use anyhow::Result;
use rscan_core::{HostStatus, PortResult, ScanSummary, SCHEMA_VERSION};
use serde::Serialize;

use super::{Output, ScanMeta, Sink};

/// Collects results and writes one JSON document at the end.
pub struct JsonSink {
    out: Output,
    document: Document,
}

#[derive(Debug, Default, Serialize)]
struct Document {
    schema_version: u32,
    scanner: String,
    version: String,
    command_line: String,
    started_at: String,
    mode: String,
    hosts_total: usize,
    probes_total: u64,
    tcp_ports: Vec<u16>,
    udp_ports: Vec<u16>,
    hosts_up: Vec<HostStatus>,
    hosts_down: Vec<HostStatus>,
    results: Vec<PortResult>,
    summary: Option<ScanSummary>,
}

impl JsonSink {
    /// Build a sink writing to `out`.
    pub fn new(out: Output) -> Self {
        Self { out, document: Document::default() }
    }
}

impl Sink for JsonSink {
    fn start(&mut self, meta: &ScanMeta) -> Result<()> {
        self.document = Document {
            schema_version: SCHEMA_VERSION,
            scanner: "rscan".to_string(),
            version: meta.version.clone(),
            command_line: meta.command_line.clone(),
            started_at: meta.started_at.clone(),
            mode: meta.mode.clone(),
            hosts_total: meta.hosts_total,
            probes_total: meta.probes_total,
            tcp_ports: meta.tcp_ports.clone(),
            udp_ports: meta.udp_ports.clone(),
            ..Default::default()
        };
        Ok(())
    }

    fn host_up(&mut self, status: &HostStatus) -> Result<()> {
        self.document.hosts_up.push(status.clone());
        Ok(())
    }

    fn host_down(&mut self, status: &HostStatus) -> Result<()> {
        self.document.hosts_down.push(status.clone());
        Ok(())
    }

    fn port(&mut self, result: &PortResult) -> Result<()> {
        self.document.results.push(result.clone());
        Ok(())
    }

    fn finish(&mut self, summary: &ScanSummary) -> Result<()> {
        self.document.summary = Some(summary.clone());
        serde_json::to_writer_pretty(&mut self.out, &self.document)?;
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests_support::{host_status, meta, sample_result, summary, SharedBuffer};

    #[test]
    fn writes_one_document_at_the_end() {
        let buffer = SharedBuffer::new();
        let mut sink = JsonSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        sink.host_up(&host_status(true)).expect("host");
        sink.port(&sample_result()).expect("port");
        assert!(buffer.contents().is_empty(), "nothing is written before finish()");

        sink.finish(&summary()).expect("finish");
        let parsed: serde_json::Value =
            serde_json::from_str(&buffer.contents()).expect("valid JSON");
        assert_eq!(parsed["scanner"], "rscan");
        assert_eq!(parsed["schema_version"], SCHEMA_VERSION);
        assert_eq!(parsed["results"][0]["port"], 22);
        assert_eq!(parsed["results"][0]["service"]["product"], "OpenSSH");
        assert_eq!(parsed["hosts_up"][0]["hostname"], "host.example.com");
        assert_eq!(parsed["summary"]["ports_open"], 1);
    }

    #[test]
    fn an_empty_scan_still_produces_a_valid_document() {
        let buffer = SharedBuffer::new();
        let mut sink = JsonSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        sink.finish(&summary()).expect("finish");
        let parsed: serde_json::Value =
            serde_json::from_str(&buffer.contents()).expect("valid JSON");
        assert!(parsed["results"].as_array().expect("array").is_empty());
    }
}
