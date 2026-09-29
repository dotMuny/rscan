//! Service detection: banner grabbing, active probes, TLS and HTTP.
//!
//! The detector runs a fixed sequence against an open port, cheapest first, and
//! stops as soon as it has a confident answer:
//!
//! 1. **Banner grab** — read whatever the service volunteers on the connection
//!    the scan already opened. Costs nothing and identifies SSH, SMTP, FTP,
//!    POP3, IMAP, MySQL, VNC and Telnet outright.
//! 2. **TLS handshake** — if the port is quiet, try TLS. A successful handshake
//!    yields the version, ALPN and certificate names, and opens the door to
//!    speaking HTTP inside it.
//! 3. **HTTP** — one `GET /`, reporting status, `Server`, title and redirects.
//! 4. **Active probes** — payloads from the embedded database, port-specific
//!    ones first, filtered by the requested intensity.
//!
//! The whole sequence is bounded by [`ServiceDetection::timeout`], because an
//! open port that never answers must not be able to stall a scan.

pub mod db;
pub mod http;
pub mod matcher;
pub mod tls;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::ServiceDetection;
use crate::model::{Protocol, ServiceInfo};
use crate::probe::db::{Probe, ProbeDb};
use crate::probe::matcher::{banner_text, match_response, merge_service};

/// Confidence at which the detector stops looking.
const GOOD_ENOUGH: u8 = 9;

/// Cap on how much of a probe response to read.
const MAX_RESPONSE: usize = 16 * 1024;

/// Runs the detection sequence against open ports.
#[derive(Debug, Clone)]
pub struct Detector {
    db: Arc<ProbeDb>,
    config: ServiceDetection,
}

impl Detector {
    /// A detector over the embedded probe database.
    pub fn new(config: ServiceDetection) -> Self {
        Self { db: Arc::new(ProbeDb::embedded().clone()), config }
    }

    /// A detector over a caller-supplied database.
    pub fn with_db(db: Arc<ProbeDb>, config: ServiceDetection) -> Self {
        Self { db, config }
    }

    /// The probe database in use.
    pub fn db(&self) -> &ProbeDb {
        &self.db
    }

    /// Identify the service behind an open TCP port.
    ///
    /// `stream` is the connection the scan already established; it is consumed
    /// for the banner grab. Everything after that opens fresh connections,
    /// because a probe payload sent to the wrong protocol usually kills the
    /// connection.
    pub async fn detect_tcp(
        &self,
        addr: IpAddr,
        port: u16,
        hostname: Option<&str>,
        stream: Option<TcpStream>,
    ) -> Option<ServiceInfo> {
        if !self.config.enabled {
            return None;
        }
        let deadline = Instant::now() + self.config.timeout;
        let mut info = ServiceInfo::default();

        if self.config.banner {
            if let Some(mut stream) = stream {
                let budget = remaining(deadline).min(Duration::from_millis(2000));
                if !budget.is_zero() {
                    let banner = read_response(&mut stream, budget).await;
                    if !banner.is_empty() {
                        info.banner = banner_text(&banner);
                        if let Some(null_probe) = self.db.probe("NULL") {
                            if let Some(matched) = match_response(null_probe, &banner) {
                                merge_service(&mut info, matched);
                            }
                        }
                    }
                }
            }
        }

        if self.is_confident(&info) {
            return Some(info);
        }

        if self.config.tls && !expired(deadline) {
            if let Some(tls_info) = self.try_tls(addr, port, hostname, deadline, &mut info).await {
                merge_service(&mut info, tls_info);
            }
        }

        if self.config.http && info.tls.is_none() && !expired(deadline) && !self.is_confident(&info)
        {
            if let Some(mut stream) = connect(addr, port, remaining(deadline)).await {
                let budget = remaining(deadline);
                let host = host_header(addr, hostname);
                if let Some((http_info, raw)) = http::probe(&mut stream, &host, budget).await {
                    let mut extra = ServiceInfo {
                        name: Some("http".to_string()),
                        confidence: Some(10),
                        http: Some(http_info),
                        ..Default::default()
                    };
                    if let Some(get_probe) = self.db.probe("GetRequest") {
                        if let Some(matched) = match_response(get_probe, &raw) {
                            extra.product = matched.product;
                            if matched.name.as_deref() != Some("http") {
                                extra.name = matched.name;
                            }
                        }
                    }
                    merge_service(&mut info, extra);
                }
            }
        }

        if self.config.probes {
            for probe in self.db.select(Protocol::Tcp, port, self.config.intensity) {
                if probe.is_banner_grab() || expired(deadline) || self.is_confident(&info) {
                    continue;
                }
                if let Some(matched) = self.run_tcp_probe(addr, port, probe, deadline).await {
                    merge_service(&mut info, matched);
                }
            }
        }

        if info.is_empty() {
            // Fall back to the conventional name for the port, clearly marked
            // as a guess rather than an observation.
            let guess = crate::ports::service_name(Protocol::Tcp, port)?;
            return Some(ServiceInfo {
                name: Some(guess.to_string()),
                info: Some("guessed from port number".to_string()),
                confidence: Some(1),
                ..Default::default()
            });
        }
        Some(info)
    }

    /// The UDP probe to send to `port`, if the database has one.
    pub fn udp_probe_for(&self, port: u16) -> Option<&Probe> {
        let candidates = self.db.select(Protocol::Udp, port, self.config.intensity.max(1));
        candidates.iter().find(|p| p.targets_port(port)).or_else(|| candidates.first()).copied()
    }

    /// Every UDP probe that could apply to `port`, best first.
    pub fn udp_probes_for(&self, port: u16) -> Vec<&Probe> {
        let mut probes = self.db.select(Protocol::Udp, port, self.config.intensity.max(1));
        probes.retain(|p| p.targets_port(port));
        probes
    }

    /// Match a UDP response against the probe that elicited it.
    pub fn match_udp(&self, probe_name: &str, response: &[u8]) -> Option<ServiceInfo> {
        let probe = self.db.probe(probe_name)?;
        let mut info = match_response(probe, response)?;
        info.banner = banner_text(response);
        Some(info)
    }

    async fn try_tls(
        &self,
        addr: IpAddr,
        port: u16,
        hostname: Option<&str>,
        deadline: Instant,
        current: &mut ServiceInfo,
    ) -> Option<ServiceInfo> {
        let stream = connect(addr, port, remaining(deadline)).await?;
        let probe = tls::handshake(stream, addr, hostname, remaining(deadline)).await?;
        let mut extra = ServiceInfo {
            name: Some("ssl".to_string()),
            confidence: Some(9),
            tls: Some(probe.info),
            ..Default::default()
        };

        if self.config.http && !expired(deadline) {
            let mut stream = probe.stream;
            let host = host_header(addr, hostname);
            if let Some((http_info, raw)) =
                http::probe(&mut stream, &host, remaining(deadline)).await
            {
                extra.name = Some("https".to_string());
                extra.confidence = Some(10);
                extra.http = Some(http_info);
                if let Some(get_probe) = self.db.probe("GetRequest") {
                    if let Some(matched) = match_response(get_probe, &raw) {
                        extra.product = matched.product;
                    }
                }
            }
        }
        // Keep whatever the banner already established as the underlying
        // service; TLS is a wrapper, not a replacement.
        if current.name.is_some() && current.confidence.unwrap_or(0) >= 9 {
            extra.name = None;
        }
        Some(extra)
    }

    async fn run_tcp_probe(
        &self,
        addr: IpAddr,
        port: u16,
        probe: &Probe,
        deadline: Instant,
    ) -> Option<ServiceInfo> {
        let mut stream = connect(addr, port, remaining(deadline)).await?;
        tokio::time::timeout(remaining(deadline), stream.write_all(&probe.payload))
            .await
            .ok()?
            .ok()?;
        let _ = stream.flush().await;
        let budget = remaining(deadline).min(probe.read_timeout);
        let response = read_response(&mut stream, budget).await;
        if response.is_empty() {
            return None;
        }
        let mut info = match_response(probe, &response)?;
        if info.banner.is_none() {
            info.banner = banner_text(&response);
        }
        Some(info)
    }

    fn is_confident(&self, info: &ServiceInfo) -> bool {
        info.confidence.unwrap_or(0) >= GOOD_ENOUGH && info.name.is_some()
    }
}

fn host_header(addr: IpAddr, hostname: Option<&str>) -> String {
    match hostname {
        Some(name) => name.to_string(),
        None => match addr {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        },
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn expired(deadline: Instant) -> bool {
    remaining(deadline).is_zero()
}

async fn connect(addr: IpAddr, port: u16, timeout: Duration) -> Option<TcpStream> {
    if timeout.is_zero() {
        return None;
    }
    crate::scan::connect::reconnect(addr, port, timeout.min(Duration::from_secs(5))).await
}

/// Read until the peer stops talking, the buffer is full or the budget runs out.
async fn read_response<S>(stream: &mut S, budget: Duration) -> Vec<u8>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(1024);
    if budget.is_zero() {
        return buffer;
    }
    let deadline = tokio::time::Instant::now() + budget;
    let mut chunk = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buffer.extend_from_slice(&chunk[..n]);
                if buffer.len() >= MAX_RESPONSE {
                    buffer.truncate(MAX_RESPONSE);
                    break;
                }
                // One read is usually the whole banner; going round again only
                // to wait out the budget would make detection needlessly slow.
                if buffer.len() > 16 {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn detection() -> ServiceDetection {
        ServiceDetection {
            enabled: true,
            timeout: Duration::from_secs(4),
            intensity: 9,
            ..ServiceDetection::all()
        }
    }

    /// A listener that answers every connection with fixed bytes, optionally
    /// after reading a request first.
    async fn fake_service(reply: &'static [u8], read_first: bool) -> u16 {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    if read_first {
                        let mut discard = [0u8; 2048];
                        let _ = tokio::time::timeout(
                            Duration::from_millis(500),
                            socket.read(&mut discard),
                        )
                        .await;
                    }
                    let _ = socket.write_all(reply).await;
                    let _ = socket.flush().await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn detection_is_off_unless_enabled() {
        let detector = Detector::new(ServiceDetection::default());
        assert!(detector.detect_tcp(LOCALHOST, 22, None, None).await.is_none());
    }

    #[tokio::test]
    async fn a_banner_identifies_ssh_from_the_existing_connection() {
        let port = fake_service(b"SSH-2.0-OpenSSH_9.6p1 Debian-2\r\n", false).await;
        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .expect("connect");
        let detector = Detector::new(detection());
        let info = detector
            .detect_tcp(LOCALHOST, port, None, Some(stream))
            .await
            .expect("something detected");
        assert_eq!(info.name.as_deref(), Some("ssh"));
        assert_eq!(info.product.as_deref(), Some("OpenSSH_9.6p1 Debian-2"));
        assert!(info.banner.is_some());
    }

    #[tokio::test]
    async fn an_http_server_is_identified_with_status_and_title() {
        let port = fake_service(
            b"HTTP/1.1 200 OK\r\nServer: rscan-test/2.0\r\n\r\n<title>Test Page</title>",
            true,
        )
        .await;
        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .expect("connect");
        let detector = Detector::new(detection());
        let info = detector
            .detect_tcp(LOCALHOST, port, None, Some(stream))
            .await
            .expect("something detected");
        assert_eq!(info.name.as_deref(), Some("http"));
        let http = info.http.expect("http details");
        assert_eq!(http.status, Some(200));
        assert_eq!(http.title.as_deref(), Some("Test Page"));
        assert_eq!(http.server.as_deref(), Some("rscan-test/2.0"));
    }

    #[tokio::test]
    async fn an_active_probe_identifies_a_service_that_says_nothing_first() {
        // Redis: silent on connect, answers PING.
        let port = fake_service(b"+PONG\r\n", true).await;
        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .expect("connect");
        let detector = Detector::new(detection());
        let info = detector
            .detect_tcp(LOCALHOST, port, None, Some(stream))
            .await
            .expect("something detected");
        assert_eq!(info.name.as_deref(), Some("redis"));
    }

    #[tokio::test]
    async fn a_silent_port_falls_back_to_the_port_name_guess() {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .expect("connect");
        let detector =
            Detector::new(ServiceDetection { timeout: Duration::from_millis(600), ..detection() });
        let info = detector.detect_tcp(LOCALHOST, port, None, Some(stream)).await;
        // Ephemeral ports are not in the top-ports table, so there is nothing
        // even to guess; either outcome is correct, but it must not hang.
        if let Some(info) = info {
            assert!(info.confidence.unwrap_or(0) <= 1);
        }
    }

    #[tokio::test]
    async fn detection_respects_its_overall_deadline() {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let detector =
            Detector::new(ServiceDetection { timeout: Duration::from_millis(500), ..detection() });
        let started = Instant::now();
        let _ = detector.detect_tcp(LOCALHOST, port, None, None).await;
        assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    }

    #[test]
    fn udp_probe_selection_prefers_the_port_specific_probe() {
        let detector = Detector::new(detection());
        let probe = detector.udp_probe_for(53).expect("a DNS probe exists");
        assert_eq!(probe.name, "DNSVersionBind");
        assert_eq!(detector.udp_probe_for(161).map(|p| p.name.as_str()), Some("SNMPv2cPublic"));
        assert_eq!(detector.udp_probe_for(123).map(|p| p.name.as_str()), Some("NTPClient"));
    }

    #[test]
    fn udp_responses_are_matched_against_the_probe_that_caused_them() {
        let detector = Detector::new(detection());
        let info = detector
            .match_udp("DNSVersionBind", b"\x124\x81\x80\x00\x01\x00\x00")
            .expect("dns reply matches");
        assert_eq!(info.name.as_deref(), Some("domain"));
        assert!(detector.match_udp("DNSVersionBind", b"nonsense").is_none());
        assert!(detector.match_udp("NoSuchProbe", b"anything").is_none());
    }

    #[test]
    fn a_host_header_brackets_ipv6() {
        assert_eq!(host_header(LOCALHOST, None), "127.0.0.1");
        assert_eq!(host_header("2001:db8::1".parse().expect("literal"), None), "[2001:db8::1]");
        assert_eq!(host_header(LOCALHOST, Some("example.com")), "example.com");
    }
}
