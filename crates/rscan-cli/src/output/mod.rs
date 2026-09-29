//! Output formats.
//!
//! Every format implements [`Sink`]. The distinction that matters is *when*
//! output is produced:
//!
//! - **Streaming** ([`jsonl`], [`text`]) write each result the moment it
//!   arrives. A pipeline consuming JSONL sees the first open port seconds into
//!   a scan that will run for an hour.
//! - **Buffered** ([`json`], [`xml`], [`csv_out`]) need the whole scan before
//!   they can produce a well-formed document.
//!
//! Data always goes to stdout (or `--output-file`); progress and diagnostics
//! always go to stderr. Nothing else is allowed to write to stdout, or piping
//! into `jq` breaks.

pub mod csv_out;
pub mod json;
pub mod jsonl;
pub mod text;
pub mod xml;

use std::io::Write;

use anyhow::Result;
use rscan_core::{HostStatus, PortResult, ScanSummary};

/// Metadata about a scan, passed to sinks before any results.
#[derive(Debug, Clone)]
pub struct ScanMeta {
    /// The full command line, for reproducibility.
    pub command_line: String,
    /// RFC 3339 start time.
    pub started_at: String,
    /// Unix timestamp of the start.
    pub started_unix: u64,
    /// Technique in use.
    pub mode: String,
    /// Number of addresses in scope.
    pub hosts_total: usize,
    /// Number of port probes in scope.
    pub probes_total: u64,
    /// TCP ports being scanned.
    pub tcp_ports: Vec<u16>,
    /// UDP ports being scanned.
    pub udp_ports: Vec<u16>,
    /// `rscan` version.
    pub version: String,
}

/// Something that turns scan events into bytes.
pub trait Sink: Send {
    /// Called once, before any results.
    fn start(&mut self, meta: &ScanMeta) -> Result<()>;

    /// Called for each host that answered discovery.
    fn host_up(&mut self, _status: &HostStatus) -> Result<()> {
        Ok(())
    }

    /// Called for each host that did not.
    fn host_down(&mut self, _status: &HostStatus) -> Result<()> {
        Ok(())
    }

    /// Called for each port result the scan chose to report.
    fn port(&mut self, result: &PortResult) -> Result<()>;

    /// Called once, last. Sinks that buffer write their document here.
    fn finish(&mut self, summary: &ScanSummary) -> Result<()>;
}

/// Where a sink writes.
pub type Output = Box<dyn Write + Send>;

/// Escape a string for inclusion in XML text or an attribute value.
pub fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            // XML 1.0 cannot represent most control characters at all, not even
            // as numeric references, so they are dropped rather than emitted.
            c if (c as u32) < 0x20 && c != '\t' && c != '\n' && c != '\r' => {}
            c => out.push(c),
        }
    }
    out
}

/// Seconds as a compact human string, e.g. `"1.35s"`.
pub fn format_elapsed(duration: std::time::Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds < 60.0 {
        format!("{seconds:.2}s")
    } else {
        let minutes = (seconds / 60.0).floor();
        format!("{}m{:.2}s", minutes as u64, seconds - minutes * 60.0)
    }
}

/// Shared fixtures for the output-format tests.
///
/// Test-only scaffolding, so the crate's `missing_docs` requirement is relaxed
/// here rather than documenting each fixture twice.
#[cfg(test)]
#[allow(missing_docs)]
pub mod tests_support {
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rscan_core::{
        HttpInfo, PortResult, PortState, Protocol, Reason, ScanSummary, ServiceInfo, TlsInfo,
    };

    use super::{Output, ScanMeta};

    /// An in-memory `Write` that the test can read back afterwards.
    #[derive(Clone, Default)]
    pub struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn writer(&self) -> Output {
            Box::new(self.clone())
        }

        pub fn contents(&self) -> String {
            let guard = self.0.lock().expect("buffer lock");
            String::from_utf8_lossy(&guard).into_owned()
        }
    }

    impl Write for SharedBuffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut guard = self.0.lock().expect("buffer lock");
            guard.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub fn meta() -> ScanMeta {
        ScanMeta {
            command_line: "rscan -p 22 192.0.2.1".into(),
            started_at: "2026-09-24T10:00:00.000Z".into(),
            started_unix: 1_790_244_000,
            mode: "connect".into(),
            hosts_total: 1,
            probes_total: 1,
            tcp_ports: vec![22],
            udp_ports: vec![],
            version: "0.1.0".into(),
        }
    }

    pub fn sample_result() -> PortResult {
        PortResult {
            addr: "192.0.2.1".parse().expect("literal"),
            hostname: None,
            port: 22,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            reason: Reason::SynAck,
            rtt: Some(Duration::from_micros(1200)),
            attempts: 1,
            service: Some(ServiceInfo {
                name: Some("ssh".into()),
                product: Some("OpenSSH".into()),
                version: Some("9.6p1".into()),
                info: Some("Ubuntu".into()),
                confidence: Some(10),
                banner: Some("SSH-2.0-OpenSSH_9.6p1".into()),
                tls: None,
                http: None,
            }),
        }
    }

    pub fn tls_result() -> PortResult {
        let mut result = sample_result();
        result.port = 443;
        result.service = Some(ServiceInfo {
            name: Some("https".into()),
            product: Some("nginx".into()),
            confidence: Some(10),
            tls: Some(TlsInfo {
                version: Some("TLSv1_3".into()),
                alpn: Some("h2".into()),
                subject_cn: Some("example.com".into()),
                issuer_cn: Some("Let\u{27}s Encrypt".into()),
                sans: vec!["example.com".into(), "www.example.com".into()],
                not_before: Some("2026-01-01T00:00:00+00:00".into()),
                not_after: Some("2026-04-01T00:00:00+00:00".into()),
            }),
            http: Some(HttpInfo {
                status: Some(200),
                server: Some("nginx/1.24.0".into()),
                title: Some("Example & <Co>".into()),
                location: None,
                redirects_to_https: false,
            }),
            ..Default::default()
        });
        result
    }

    pub fn host_status(up: bool) -> rscan_core::HostStatus {
        rscan_core::HostStatus {
            addr: "192.0.2.1".parse().expect("literal"),
            hostname: Some("host.example.com".into()),
            up,
            method: rscan_core::DiscoveryMethod::IcmpEcho,
            rtt: Some(Duration::from_micros(900)),
        }
    }

    pub fn summary() -> ScanSummary {
        ScanSummary {
            hosts_total: 1,
            hosts_up: 1,
            ports_scanned: 1,
            ports_open: 1,
            ports_closed: 0,
            ports_filtered: 0,
            packets_sent: 1,
            elapsed: Duration::from_millis(350),
            final_concurrency: 64,
            final_rate_pps: 500.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escaping_covers_every_special_character() {
        assert_eq!(xml_escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(xml_escape("plain"), "plain");
    }

    #[test]
    fn xml_escaping_drops_characters_xml_cannot_hold() {
        assert_eq!(xml_escape("a\x00b\x1bc"), "abc");
        assert_eq!(xml_escape("tab\there"), "tab\there", "tab is legal in XML 1.0");
    }

    #[test]
    fn elapsed_renders_readably() {
        assert_eq!(format_elapsed(std::time::Duration::from_millis(1350)), "1.35s");
        assert_eq!(format_elapsed(std::time::Duration::from_secs(90)), "1m30.00s");
    }
}
