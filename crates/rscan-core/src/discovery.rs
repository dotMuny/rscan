//! Host discovery: deciding which addresses are worth scanning.
//!
//! Scanning 65535 ports on 254 addresses when three of them exist wastes almost
//! all of the work, so a sweep runs first. Four techniques, tried cheapest and
//! most reliable first:
//!
//! | technique | privileges | notes |
//! |---|---|---|
//! | ARP (neighbour table) | none | local segment only, IPv4, Linux |
//! | ICMP echo | none or `CAP_NET_RAW` | unprivileged `SOCK_DGRAM` first |
//! | TCP connect | none | works wherever ICMP is filtered |
//! | TCP ACK | `CAP_NET_RAW` | a RST proves the host is up |
//!
//! `--skip-discovery` turns the lot off and assumes every target is up, which
//! is the right answer when you already know the hosts exist and the network
//! drops probes.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::DiscoveryConfig;
use crate::model::{DiscoveryMethod, HostStatus};
use crate::scan::syn::SynScanner;
use crate::target::Target;

/// Runs discovery probes against targets.
#[derive(Debug, Clone)]
pub struct Discoverer {
    config: DiscoveryConfig,
    syn: Option<Arc<SynScanner>>,
}

impl Discoverer {
    /// Build a discoverer.
    ///
    /// `syn` is the raw-socket scanner, when one could be opened; without it
    /// the ACK technique is silently skipped.
    pub fn new(config: DiscoveryConfig, syn: Option<Arc<SynScanner>>) -> Self {
        Self { config, syn }
    }

    /// Determine whether `target` is up.
    ///
    /// Returns as soon as any technique succeeds.
    pub async fn probe(&self, target: &Target) -> HostStatus {
        let addr = target.addr;
        let hostname = target.hostname.clone();

        if !self.config.enabled {
            return HostStatus {
                addr,
                hostname,
                up: true,
                method: DiscoveryMethod::Assumed,
                rtt: None,
            };
        }

        if self.config.arp {
            if let Some(rtt) = arp::probe(addr, self.config.timeout).await {
                return HostStatus {
                    addr,
                    hostname,
                    up: true,
                    method: DiscoveryMethod::Arp,
                    rtt: Some(rtt),
                };
            }
        }

        if self.config.icmp_echo {
            if let Some(rtt) = icmp::echo(addr, self.config.timeout).await {
                return HostStatus {
                    addr,
                    hostname,
                    up: true,
                    method: DiscoveryMethod::IcmpEcho,
                    rtt: Some(rtt),
                };
            }
        }

        if self.config.tcp_connect {
            if let Some(rtt) = tcp_connect(addr, &self.config.tcp_ports, self.config.timeout).await
            {
                return HostStatus {
                    addr,
                    hostname,
                    up: true,
                    method: DiscoveryMethod::TcpConnect,
                    rtt: Some(rtt),
                };
            }
        }

        if self.config.tcp_ack {
            if let Some(syn) = &self.syn {
                for &port in &self.config.tcp_ports {
                    let started = Instant::now();
                    if syn.ack_probe(addr, port, self.config.timeout).await {
                        return HostStatus {
                            addr,
                            hostname,
                            up: true,
                            method: DiscoveryMethod::TcpAck,
                            rtt: Some(started.elapsed()),
                        };
                    }
                }
            }
        }

        HostStatus { addr, hostname, up: false, method: DiscoveryMethod::TcpConnect, rtt: None }
    }
}

/// Try to open a TCP connection to any of `ports`.
///
/// Both an accepted connection and a refused one prove the host is up; only
/// silence does not.
async fn tcp_connect(addr: IpAddr, ports: &[u16], timeout: Duration) -> Option<Duration> {
    use crate::model::PortState;

    for &port in ports {
        let probe = crate::scan::connect::probe(addr, port, timeout).await;
        match probe.verdict.state {
            PortState::Open | PortState::Closed => return Some(probe.rtt),
            _ => continue,
        }
    }
    None
}

/// ICMP echo, preferring the unprivileged datagram socket.
pub mod icmp {
    use std::net::IpAddr;
    use std::time::Duration;

    #[cfg(unix)]
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    #[cfg(unix)]
    use std::time::Instant;

    /// Build an ICMP echo request.
    ///
    /// `ipv6` selects ICMPv6 (type 128) over ICMPv4 (type 8). The ICMPv6
    /// checksum needs the IPv6 pseudo-header, which only the kernel knows, so
    /// it is left zero and the kernel fills it in.
    pub fn echo_request(ipv6: bool, identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8 + payload.len());
        packet.push(if ipv6 { 128 } else { 8 }); // type
        packet.push(0); // code
        packet.extend_from_slice(&[0, 0]); // checksum placeholder
        packet.extend_from_slice(&identifier.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());
        packet.extend_from_slice(payload);
        if !ipv6 {
            let sum = checksum(&packet);
            packet[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        packet
    }

    /// The standard internet checksum (RFC 1071).
    pub fn checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = bytes.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += u32::from(u16::from_be_bytes([last, 0]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// `true` when `reply` is an echo reply carrying `sequence`.
    ///
    /// The identifier is deliberately not checked: a `SOCK_DGRAM` ICMP socket
    /// rewrites it to the socket's port, so the sequence number is the only
    /// field that survives both socket types.
    pub fn is_echo_reply(reply: &[u8], ipv6: bool, sequence: u16) -> bool {
        // A raw IPv4 socket hands back the IP header as well.
        let icmp = if !ipv6 && reply.len() >= 20 && reply[0] >> 4 == 4 {
            let header_len = ((reply[0] & 0x0f) as usize) * 4;
            reply.get(header_len..).unwrap_or(&[])
        } else {
            reply
        };
        if icmp.len() < 8 {
            return false;
        }
        let expected_type = if ipv6 { 129 } else { 0 };
        icmp[0] == expected_type
            && icmp[1] == 0
            && u16::from_be_bytes([icmp[6], icmp[7]]) == sequence
    }

    /// Send one echo request and wait for the reply.
    ///
    /// Returns the round-trip time, or `None` if nothing came back or ICMP is
    /// unavailable to this process.
    #[cfg(unix)]
    pub async fn echo(addr: IpAddr, timeout: Duration) -> Option<Duration> {
        use socket2::{Domain, Protocol, Socket, Type};
        use tokio::io::unix::AsyncFd;

        let (domain, protocol, ipv6) = match addr {
            IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4, false),
            IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6, true),
        };

        // `SOCK_DGRAM` ICMP needs no privileges when net.ipv4.ping_group_range
        // allows it, which is the default on most distributions. Raw is the
        // fallback for everything else.
        let socket = Socket::new(domain, Type::DGRAM, Some(protocol))
            .or_else(|_| Socket::new(domain, Type::RAW, Some(protocol)))
            .ok()?;
        socket.set_nonblocking(true).ok()?;

        let bind: SocketAddr = if ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        socket.bind(&bind.into()).ok()?;

        let identifier = rand::random::<u16>();
        let sequence = rand::random::<u16>();
        let request = echo_request(ipv6, identifier, sequence, b"rscan-discovery");

        let fd = AsyncFd::new(socket).ok()?;
        let destination = SocketAddr::new(addr, 0);
        let started = Instant::now();
        fd.get_ref().send_to(&request, &destination.into()).ok()?;

        let deadline = tokio::time::Instant::now() + timeout;
        let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let guard = tokio::time::timeout(left, fd.readable()).await.ok()?.ok()?;
            let mut guard = guard;
            let read = guard.try_io(|inner| inner.get_ref().recv_from(&mut buffer));
            let Ok(Ok((len, from))) = read else {
                continue;
            };
            // SAFETY: `recv_from` reported `len` initialised bytes at the start
            // of `buffer`. `MaybeUninit<u8>` and `u8` have identical layout and
            // the slice does not outlive `buffer`.
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), len) };
            if from.as_socket().map(|s| s.ip()) != Some(addr) {
                continue;
            }
            if is_echo_reply(bytes, ipv6, sequence) {
                return Some(started.elapsed());
            }
        }
    }

    /// ICMP is unavailable on this platform.
    #[cfg(not(unix))]
    pub async fn echo(_addr: IpAddr, _timeout: Duration) -> Option<Duration> {
        None
    }
}

/// ARP discovery through the kernel's neighbour table.
///
/// Rather than building ARP frames on an `AF_PACKET` socket — which needs
/// `CAP_NET_RAW` and a pile of `unsafe` — this sends a single datagram to the
/// target, which makes the kernel resolve the address for us, then reads the
/// answer out of the neighbour table. Same information, no privileges, no
/// `unsafe`. The trade-off is recorded in `docs/decisions.md`.
pub mod arp {
    use std::net::IpAddr;
    use std::time::{Duration, Instant};

    /// Probe `addr` via the neighbour table. IPv4 on Linux only.
    pub async fn probe(addr: IpAddr, timeout: Duration) -> Option<Duration> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let IpAddr::V4(_) = addr else {
            return None;
        };

        let started = Instant::now();
        if has_neighbour(addr).await {
            return Some(started.elapsed());
        }

        // Poke the address so the kernel starts resolving it. Port 9 (discard)
        // is chosen because nothing acts on it; the datagram never has to
        // arrive, it only has to make the kernel do a lookup.
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let _ = socket.send_to(b"", (addr, 9)).await;

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(40)).await;
            if has_neighbour(addr).await {
                return Some(started.elapsed());
            }
        }
        None
    }

    async fn has_neighbour(addr: IpAddr) -> bool {
        let Ok(table) = tokio::fs::read_to_string("/proc/net/arp").await else {
            return false;
        };
        parse_arp_table(&table).into_iter().any(|entry| entry == addr.to_string())
    }

    /// Extract the resolved addresses from `/proc/net/arp`.
    ///
    /// Incomplete entries have flag `0x0` and an all-zero hardware address;
    /// those mean "we asked and got nothing", which is the opposite of a host
    /// being up.
    pub fn parse_arp_table(table: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in table.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let [address, _hw_type, flags, hw_address, ..] = fields.as_slice() else {
                continue;
            };
            if *flags == "0x0" || *hw_address == "00:00:00:00:00:00" {
                continue;
            }
            out.push((*address).to_string());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::net::TcpListener;

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn config() -> DiscoveryConfig {
        DiscoveryConfig {
            arp: false,
            timeout: Duration::from_millis(500),
            ..DiscoveryConfig::default()
        }
    }

    #[tokio::test]
    async fn skipping_discovery_assumes_every_host_is_up() {
        let discoverer = Discoverer::new(DiscoveryConfig { enabled: false, ..config() }, None);
        let status = discoverer.probe(&Target::new("198.51.100.9".parse().expect("literal"))).await;
        assert!(status.up);
        assert_eq!(status.method, DiscoveryMethod::Assumed);
    }

    #[tokio::test]
    async fn loopback_is_found_up() {
        let discoverer = Discoverer::new(config(), None);
        let status = discoverer.probe(&Target::new(LOCALHOST)).await;
        assert!(status.up, "loopback must always be discoverable: {status:?}");
    }

    #[tokio::test]
    async fn a_black_hole_is_found_down() {
        let discoverer = Discoverer::new(
            DiscoveryConfig {
                icmp_echo: false,
                tcp_ports: vec![65020],
                timeout: Duration::from_millis(200),
                ..config()
            },
            None,
        );
        let status = discoverer.probe(&Target::new("198.51.100.5".parse().expect("literal"))).await;
        assert!(!status.up);
    }

    #[tokio::test]
    async fn a_listening_port_proves_a_host_is_up_without_icmp() {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let discoverer = Discoverer::new(
            DiscoveryConfig { icmp_echo: false, tcp_ports: vec![port], ..config() },
            None,
        );
        let status = discoverer.probe(&Target::new(LOCALHOST)).await;
        assert!(status.up);
        assert_eq!(status.method, DiscoveryMethod::TcpConnect);
    }

    #[tokio::test]
    async fn a_refused_port_also_proves_a_host_is_up() {
        // Bind then release, so the port refuses rather than accepting.
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let discoverer = Discoverer::new(
            DiscoveryConfig { icmp_echo: false, tcp_ports: vec![port], ..config() },
            None,
        );
        assert!(discoverer.probe(&Target::new(LOCALHOST)).await.up);
    }

    #[test]
    fn the_internet_checksum_matches_a_known_value() {
        // RFC 1071 worked example.
        assert_eq!(icmp::checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
        // A packet plus its own checksum sums to zero.
        let mut packet = vec![0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let sum = icmp::checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(icmp::checksum(&packet), 0);
    }

    #[test]
    fn checksums_handle_an_odd_length() {
        assert_ne!(icmp::checksum(&[0x08, 0x00, 0x01]), 0);
    }

    #[test]
    fn echo_requests_have_the_right_shape() {
        let v4 = icmp::echo_request(false, 0x1234, 0x0001, b"abcd");
        assert_eq!(v4[0], 8);
        assert_eq!(v4[1], 0);
        assert_eq!(&v4[4..6], &[0x12, 0x34]);
        assert_eq!(&v4[6..8], &[0x00, 0x01]);
        assert_eq!(&v4[8..], b"abcd");
        assert_eq!(icmp::checksum(&v4), 0, "the embedded checksum must be correct");

        let v6 = icmp::echo_request(true, 1, 2, b"");
        assert_eq!(v6[0], 128);
        // The kernel supplies the ICMPv6 checksum.
        assert_eq!(&v6[2..4], &[0, 0]);
    }

    #[test]
    fn echo_replies_are_recognised_through_both_socket_types() {
        // Datagram socket: the ICMP message alone.
        let reply = [0u8, 0, 0, 0, 0x12, 0x34, 0xab, 0xcd];
        assert!(icmp::is_echo_reply(&reply, false, 0xabcd));
        assert!(!icmp::is_echo_reply(&reply, false, 0x0001));

        // Raw socket: a 20-byte IPv4 header in front.
        let mut raw = vec![0x45u8, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0, 127, 0, 0, 1, 127, 0, 0, 1];
        raw.extend_from_slice(&reply);
        assert!(icmp::is_echo_reply(&raw, false, 0xabcd));

        // ICMPv6 echo reply is type 129.
        let v6 = [129u8, 0, 0, 0, 0, 1, 0x00, 0x07];
        assert!(icmp::is_echo_reply(&v6, true, 7));
        assert!(!icmp::is_echo_reply(&v6, false, 7));

        // Anything too short, or an unreachable rather than a reply.
        assert!(!icmp::is_echo_reply(&[0, 0], false, 1));
        assert!(!icmp::is_echo_reply(&[3u8, 3, 0, 0, 0, 0, 0, 1], false, 1));
    }

    #[test]
    fn the_arp_table_parser_skips_incomplete_entries() {
        let table = "IP address       HW type     Flags       HW address            Mask     Device\n\
                     192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                     192.168.1.55     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
                     192.168.1.9      0x1         0x2         11:22:33:44:55:66     *        eth0\n";
        let found = arp::parse_arp_table(table);
        assert_eq!(found, vec!["192.168.1.1", "192.168.1.9"]);
    }

    #[test]
    fn the_arp_table_parser_tolerates_rubbish() {
        assert!(arp::parse_arp_table("").is_empty());
        assert!(arp::parse_arp_table("header only\n").is_empty());
        assert!(arp::parse_arp_table("header\nshort line\n").is_empty());
    }

    #[tokio::test]
    async fn icmp_never_hangs_past_its_timeout() {
        let started = Instant::now();
        let _ =
            icmp::echo("198.51.100.6".parse().expect("literal"), Duration::from_millis(200)).await;
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }
}
