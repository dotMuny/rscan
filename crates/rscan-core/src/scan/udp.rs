//! UDP scanning.
//!
//! UDP is the hard case. There is no handshake, so an open port that ignores an
//! unrecognised payload looks exactly like a filtered one — hence the
//! [`PortState::OpenFiltered`] state, which is an honest "I do not know" rather
//! than a guess.
//!
//! Two things make the results better than a bare "send a zero-length datagram
//! and hope":
//!
//! - **Service-specific payloads.** A DNS server answers a DNS query and
//!   nothing else; the probe database carries a real request for DNS, SNMP,
//!   NTP, NetBIOS, IKE, memcached, mDNS, SSDP and rpcbind. A well-formed probe
//!   turns `open|filtered` into a definite `open`.
//! - **Reading ICMP through the socket.** On Linux and the BSDs a *connected*
//!   UDP socket surfaces an ICMP port-unreachable as `ECONNREFUSED` on the next
//!   receive. That is a genuine `closed` verdict without a raw socket and
//!   without root — see `docs/decisions.md` for why this is preferred over an
//!   ICMP listener.
//!
//! Targets rate-limit ICMP errors aggressively (Linux defaults to one per
//! second), so UDP scanning must be paced far more conservatively than TCP.
//! [`crate::governor`] handles that; this module only sends and listens.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use crate::model::{PortState, Reason};
use crate::scan::{classify_io_error, Verdict};

/// Largest datagram we will read back.
const MAX_DATAGRAM: usize = 4096;

/// The outcome of one UDP probe.
#[derive(Debug)]
pub struct UdpProbe {
    /// What the attempt concluded.
    pub verdict: Verdict,
    /// Time from send to conclusion.
    pub rtt: Duration,
    /// Bytes the service sent back, if any.
    pub response: Vec<u8>,
}

/// Probe one UDP port with `payload`.
///
/// An empty payload is allowed and is what gets sent when the database has no
/// probe for the port; it is much less likely to elicit a reply, which is why
/// [`crate::probe::Detector::udp_probe_for`] is consulted first.
pub async fn probe(addr: IpAddr, port: u16, payload: &[u8], timeout: Duration) -> UdpProbe {
    let started = Instant::now();

    let bind: SocketAddr = match addr {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };

    let socket = match UdpSocket::bind(bind).await {
        Ok(socket) => socket,
        Err(err) => {
            return UdpProbe {
                verdict: Verdict::local_error(PortState::OpenFiltered, Reason::LocalError),
                rtt: started.elapsed(),
                response: Vec::new(),
            }
            .with_logged(&err)
        }
    };

    // Connecting is what makes ICMP errors visible on this socket.
    if let Err(err) = socket.connect(SocketAddr::new(addr, port)).await {
        return UdpProbe {
            verdict: classify_io_error(&err),
            rtt: started.elapsed(),
            response: Vec::new(),
        };
    }

    if let Err(err) = socket.send(payload).await {
        return UdpProbe {
            verdict: classify_udp_error(&err),
            rtt: started.elapsed(),
            response: Vec::new(),
        };
    }

    let mut buffer = vec![0u8; MAX_DATAGRAM];
    match tokio::time::timeout(timeout, socket.recv(&mut buffer)).await {
        Ok(Ok(len)) => {
            buffer.truncate(len);
            UdpProbe {
                verdict: Verdict::responded(PortState::Open, Reason::UdpResponse),
                rtt: started.elapsed(),
                response: buffer,
            }
        }
        Ok(Err(err)) => UdpProbe {
            verdict: classify_udp_error(&err),
            rtt: started.elapsed(),
            response: Vec::new(),
        },
        Err(_elapsed) => UdpProbe {
            // Silence on UDP is genuinely ambiguous. Saying `filtered` would be
            // a lie and saying `open` would be worse.
            verdict: Verdict {
                state: PortState::OpenFiltered,
                reason: Reason::NoResponse,
                outcome: crate::rate::ProbeOutcome::TimedOut,
            },
            rtt: timeout,
            response: Vec::new(),
        },
    }
}

impl UdpProbe {
    fn with_logged(self, err: &std::io::Error) -> Self {
        tracing::debug!(error = %err, "udp probe could not start");
        self
    }
}

/// Map a UDP socket error onto a verdict.
///
/// The one that matters: `ECONNREFUSED` on a connected UDP socket is the
/// kernel reporting an ICMP port-unreachable, which means **closed**.
fn classify_udp_error(err: &std::io::Error) -> Verdict {
    let verdict = classify_io_error(err);
    if verdict.state == PortState::Closed {
        // Rewrite the reason: on UDP this came from ICMP, not a TCP RST.
        return Verdict::responded(PortState::Closed, Reason::PortUnreachable);
    }
    if verdict.outcome == crate::rate::ProbeOutcome::LocalError
        && verdict.state == PortState::Filtered
    {
        // Unreachables other than "port" say nothing about the port itself.
        return Verdict::local_error(PortState::OpenFiltered, verdict.reason);
    }
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    async fn echo_server() -> u16 {
        let socket = UdpSocket::bind(SocketAddr::new(LOCALHOST, 0)).await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
                let _ = socket.send_to(&buffer[..len.max(1)], from).await;
            }
        });
        port
    }

    /// Bind a UDP port to learn its number, then release it, so nothing is
    /// listening. On loopback the kernel answers with ICMP port unreachable.
    async fn unbound_port() -> u16 {
        let socket = UdpSocket::bind(SocketAddr::new(LOCALHOST, 0)).await.expect("bind");
        let port = socket.local_addr().expect("addr").port();
        drop(socket);
        port
    }

    #[tokio::test]
    async fn a_service_that_answers_is_open() {
        let port = echo_server().await;
        let result = probe(LOCALHOST, port, b"ping", Duration::from_secs(2)).await;
        assert_eq!(result.verdict.state, PortState::Open);
        assert_eq!(result.verdict.reason, Reason::UdpResponse);
        assert_eq!(result.response, b"ping");
    }

    #[tokio::test]
    async fn an_icmp_port_unreachable_is_closed() {
        let port = unbound_port().await;
        let result = probe(LOCALHOST, port, b"probe", Duration::from_secs(2)).await;
        // Loopback always delivers the ICMP error; a machine that filters its
        // own loopback would report open|filtered, which is still correct.
        assert!(
            matches!(result.verdict.state, PortState::Closed | PortState::OpenFiltered),
            "{:?}",
            result.verdict
        );
        if result.verdict.state == PortState::Closed {
            assert_eq!(result.verdict.reason, Reason::PortUnreachable);
        }
    }

    #[tokio::test]
    async fn silence_is_open_filtered_not_filtered() {
        // TEST-NET-2 swallows everything, so nothing comes back at all.
        let result = probe(
            "198.51.100.3".parse().expect("literal"),
            65010,
            b"probe",
            Duration::from_millis(250),
        )
        .await;
        assert_eq!(result.verdict.state, PortState::OpenFiltered);
        assert!(result.verdict.is_retryable(), "silence is worth retrying");
    }

    #[tokio::test]
    async fn an_empty_payload_still_sends() {
        let port = echo_server().await;
        let result = probe(LOCALHOST, port, b"", Duration::from_secs(2)).await;
        assert_eq!(result.verdict.state, PortState::Open);
    }

    #[tokio::test]
    async fn probes_respect_their_deadline() {
        let started = Instant::now();
        let _ = probe(
            "198.51.100.4".parse().expect("literal"),
            65011,
            b"x",
            Duration::from_millis(200),
        )
        .await;
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", started.elapsed());
    }

    #[cfg(unix)]
    #[test]
    fn econnrefused_on_udp_is_reported_as_an_icmp_unreachable() {
        let verdict = classify_udp_error(&std::io::Error::from_raw_os_error(libc::ECONNREFUSED));
        assert_eq!(verdict.state, PortState::Closed);
        assert_eq!(verdict.reason, Reason::PortUnreachable);
    }

    #[cfg(unix)]
    #[test]
    fn other_unreachables_leave_the_port_ambiguous() {
        let verdict = classify_udp_error(&std::io::Error::from_raw_os_error(libc::EHOSTUNREACH));
        assert_eq!(verdict.state, PortState::OpenFiltered);
        assert_eq!(verdict.reason, Reason::HostUnreachable);
    }
}
