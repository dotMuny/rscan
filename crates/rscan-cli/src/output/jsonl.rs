//! Streaming JSON Lines output.
//!
//! One JSON object per line, flushed immediately. This is the format built for
//! pipelines: `rscan -o jsonl … | jq -r 'select(.event=="port")'` starts
//! producing output with the first open port rather than when the scan ends.
//!
//! The line-per-event shape means a consumer never has to parse a partial
//! document, and a scan killed halfway still leaves a file of valid records.

use std::io::Write;

use anyhow::Result;
use rscan_core::{HostStatus, PortResult, ScanSummary, SCHEMA_VERSION};
use serde::Serialize;

use super::{Output, ScanMeta, Sink};

/// Writes one JSON object per line.
pub struct JsonlSink {
    out: Output,
}

impl JsonlSink {
    /// Build a sink writing to `out`.
    pub fn new(out: Output) -> Self {
        Self { out }
    }

    fn emit<T: Serialize>(&mut self, value: &T) -> Result<()> {
        serde_json::to_writer(&mut self.out, value)?;
        self.out.write_all(b"\n")?;
        // Flushing every line is the whole point: a buffered pipe would
        // reintroduce exactly the latency this format exists to remove.
        self.out.flush()?;
        Ok(())
    }
}

#[derive(Serialize)]
struct StartLine<'a> {
    event: &'static str,
    schema_version: u32,
    scanner: &'static str,
    version: &'a str,
    command_line: &'a str,
    started_at: &'a str,
    mode: &'a str,
    hosts_total: usize,
    probes_total: u64,
}

#[derive(Serialize)]
struct HostLine<'a> {
    event: &'static str,
    #[serde(flatten)]
    status: &'a HostStatus,
}

#[derive(Serialize)]
struct PortLine<'a> {
    event: &'static str,
    #[serde(flatten)]
    result: &'a PortResult,
}

#[derive(Serialize)]
struct FinishLine<'a> {
    event: &'static str,
    #[serde(flatten)]
    summary: &'a ScanSummary,
}

impl Sink for JsonlSink {
    fn start(&mut self, meta: &ScanMeta) -> Result<()> {
        self.emit(&StartLine {
            event: "start",
            schema_version: SCHEMA_VERSION,
            scanner: "rscan",
            version: &meta.version,
            command_line: &meta.command_line,
            started_at: &meta.started_at,
            mode: &meta.mode,
            hosts_total: meta.hosts_total,
            probes_total: meta.probes_total,
        })
    }

    fn host_up(&mut self, status: &HostStatus) -> Result<()> {
        self.emit(&HostLine { event: "host-up", status })
    }

    fn host_down(&mut self, status: &HostStatus) -> Result<()> {
        self.emit(&HostLine { event: "host-down", status })
    }

    fn port(&mut self, result: &PortResult) -> Result<()> {
        self.emit(&PortLine { event: "port", result })
    }

    fn finish(&mut self, summary: &ScanSummary) -> Result<()> {
        self.emit(&FinishLine { event: "finish", summary })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::tests_support::{host_status, meta, sample_result, summary, SharedBuffer};

    #[test]
    fn every_line_is_a_standalone_json_object() {
        let buffer = SharedBuffer::new();
        let mut sink = JsonlSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        sink.host_up(&host_status(true)).expect("host");
        sink.port(&sample_result()).expect("port");
        sink.finish(&summary()).expect("finish");

        let text = buffer.contents();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4, "{text}");
        for line in &lines {
            let parsed: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("{line}: {e}"));
            assert!(parsed.get("event").is_some(), "{line}");
        }
        assert!(lines[0].contains("\"event\":\"start\""), "{}", lines[0]);
        assert!(lines[2].contains("\"event\":\"port\""), "{}", lines[2]);
        assert!(lines[2].contains("\"state\":\"open\""), "{}", lines[2]);
        assert!(lines[3].contains("\"event\":\"finish\""), "{}", lines[3]);
    }

    #[test]
    fn results_are_flushed_as_they_are_written() {
        let buffer = SharedBuffer::new();
        let mut sink = JsonlSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        assert!(!buffer.contents().is_empty(), "the start line must be visible immediately");
        sink.port(&sample_result()).expect("port");
        assert_eq!(buffer.contents().lines().count(), 2, "a result must appear before finish()");
    }

    #[test]
    fn the_schema_version_is_declared() {
        let buffer = SharedBuffer::new();
        let mut sink = JsonlSink::new(buffer.writer());
        sink.start(&meta()).expect("start");
        let first = buffer.contents();
        assert!(first.contains(&format!("\"schema_version\":{SCHEMA_VERSION}")), "{first}");
    }
}
