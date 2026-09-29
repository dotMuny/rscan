//! TCP connect scan: a full handshake through the operating system's stack.
//!
//! This is the default technique because it needs no privileges and, contrary
//! to folklore, it loses nothing in accuracy: the kernel reports
//! `ECONNREFUSED` for a RST and nothing at all for a dropped packet, which is
//! precisely the `closed` / `filtered` distinction. What it costs is a socket
//! per in-flight probe (hence [`crate::limits`]) and a fully established
//! connection on the target, which is noisier in logs than a SYN scan.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::model::{PortState, Reason};
use crate::scan::{classify_io_error, Verdict};

/// The outcome of one connect attempt.
#[derive(Debug)]
pub struct ConnectProbe {
    /// What the attempt concluded.
    pub verdict: Verdict,
    /// Time from `connect()` to the conclusion.
    pub rtt: Duration,
    /// The established connection, when the port turned out to be open.
    ///
    /// Service detection reuses it so that grabbing a banner costs no extra
    /// handshake.
    pub stream: Option<TcpStream>,
}

impl ConnectProbe {
    /// `true` when the port is open.
    pub fn is_open(&self) -> bool {
        self.verdict.state == PortState::Open
    }
}

/// Probe one TCP port with a full handshake.
///
/// `timeout` is the deadline for the whole handshake; on expiry the port is
/// `filtered`, which the caller may retry.
pub async fn probe(addr: IpAddr, port: u16, timeout: Duration) -> ConnectProbe {
    let target = SocketAddr::new(addr, port);
    let started = Instant::now();

    match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => {
            // Nagle would delay the first probe payload service detection sends.
            let _ = stream.set_nodelay(true);
            ConnectProbe {
                verdict: Verdict::responded(PortState::Open, Reason::SynAck),
                rtt: started.elapsed(),
                stream: Some(stream),
            }
        }
        Ok(Err(err)) => {
            if is_resource_exhaustion(&err) {
                // Not the target's fault: this machine ran out of descriptors
                // or buffers. Reporting it as `filtered` would be a false
                // negative, so it is surfaced loudly instead.
                tracing::warn!(
                    %addr, port, error = %err,
                    "local resource exhaustion during connect; lower --concurrency or raise RLIMIT_NOFILE"
                );
            }
            ConnectProbe { verdict: classify_io_error(&err), rtt: started.elapsed(), stream: None }
        }
        Err(_elapsed) => ConnectProbe { verdict: Verdict::timed_out(), rtt: timeout, stream: None },
    }
}

/// Open a connection to `addr:port` for service detection, outside the scan's
/// verdict logic.
///
/// Returns `None` rather than an error when the port will not accept a second
/// connection, because that is a normal outcome for single-connection services.
pub async fn reconnect(addr: IpAddr, port: u16, timeout: Duration) -> Option<TcpStream> {
    let target = SocketAddr::new(addr, port);
    match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Some(stream)
        }
        _ => None,
    }
}

/// `true` when the error means the local machine has run out of resources,
/// which the scanner treats as a reason to slow down rather than as a result.
pub(crate) fn is_resource_exhaustion(err: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            err.raw_os_error(),
            Some(libc::EMFILE) | Some(libc::ENFILE) | Some(libc::ENOBUFS) | Some(libc::ENOMEM)
        )
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    const LOCALHOST: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    const LOCALHOST6: IpAddr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);

    async fn listener_on(addr: IpAddr) -> (TcpListener, u16) {
        let listener =
            TcpListener::bind(SocketAddr::new(addr, 0)).await.expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        (listener, port)
    }

    /// Bind a port, learn its number, then drop the listener so nothing is
    /// listening there. On loopback that reliably produces a RST.
    async fn closed_port(addr: IpAddr) -> u16 {
        let (listener, port) = listener_on(addr).await;
        drop(listener);
        port
    }

    #[tokio::test]
    async fn an_accepting_port_is_open() {
        let (_listener, port) = listener_on(LOCALHOST).await;
        let probe = probe(LOCALHOST, port, Duration::from_secs(2)).await;
        assert_eq!(probe.verdict.state, PortState::Open);
        assert_eq!(probe.verdict.reason, Reason::SynAck);
        assert!(probe.stream.is_some(), "an open port must hand back its stream");
    }

    #[tokio::test]
    async fn a_refusing_port_is_closed_not_filtered() {
        let port = closed_port(LOCALHOST).await;
        let probe = probe(LOCALHOST, port, Duration::from_secs(2)).await;
        assert_eq!(probe.verdict.state, PortState::Closed, "reason: {}", probe.verdict.reason);
        assert!(!probe.verdict.is_retryable());
        assert!(probe.stream.is_none());
    }

    #[tokio::test]
    async fn a_black_hole_is_filtered_and_retryable() {
        // 198.51.100.0/24 is TEST-NET-2: routable nowhere, so packets vanish.
        let probe =
            probe("198.51.100.1".parse().expect("literal"), 65000, Duration::from_millis(300))
                .await;
        assert!(
            probe.verdict.state == PortState::Filtered,
            "expected filtered, got {:?}",
            probe.verdict
        );
    }

    #[tokio::test]
    async fn ipv6_loopback_works_on_the_same_path() {
        // Some CI images have no IPv6 at all; that is not a test failure.
        let Ok(_listener) = TcpListener::bind(SocketAddr::new(LOCALHOST6, 0)).await else {
            return;
        };
        let Ok(local) = _listener.local_addr() else { return };
        let probe = probe(LOCALHOST6, local.port(), Duration::from_secs(2)).await;
        assert_eq!(probe.verdict.state, PortState::Open);
    }

    #[tokio::test]
    async fn timeouts_are_bounded_by_the_deadline() {
        let start = Instant::now();
        let _ = probe("198.51.100.2".parse().expect("literal"), 65001, Duration::from_millis(150))
            .await;
        assert!(start.elapsed() < Duration::from_secs(1), "took {:?}", start.elapsed());
    }

    #[tokio::test]
    async fn reconnect_returns_none_for_a_closed_port() {
        let port = closed_port(LOCALHOST).await;
        assert!(reconnect(LOCALHOST, port, Duration::from_millis(500)).await.is_none());
    }
}
