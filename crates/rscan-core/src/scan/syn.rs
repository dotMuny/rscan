//! TCP SYN (half-open) scan over raw sockets.
//!
//! A SYN scan sends a bare SYN and reads the answer without ever completing the
//! handshake: `SYN/ACK` means open, `RST` means closed, silence means filtered.
//! It is faster than a connect scan because it does not pay for a full
//! handshake plus teardown, and it never hands the target application a
//! connection to log.
//!
//! # Privileges
//!
//! Raw sockets need `CAP_NET_RAW`. When it is missing, [`SynScanner::new`]
//! returns [`crate::Error::Privileges`] with the `setcap` line to fix it, and the
//! caller may fall back to a connect scan.
//!
//! # Correlating replies
//!
//! Replies arrive on a shared socket with no connection state to hang them on,
//! so each SYN carries its identity in its own sequence number:
//! `seq = H(secret, dst_ip, dst_port, src_port)`. A reply is ours only if its
//! acknowledgement number is `seq + 1`. The secret is random per scan, which
//! means a host cannot forge a reply for a port we did not probe without
//! guessing it.
//!
//! # The kernel's RST
//!
//! The local kernel has no socket for the `SYN/ACK` that comes back, so it
//! answers with a `RST` of its own. That is harmless — we have already learned
//! what we needed — but it does mean a SYN scan is not actually invisible. See
//! `docs/decisions.md`.
//!
//! # Safety
//!
//! This module contains the crate's only `unsafe` block: turning the
//! `MaybeUninit` receive buffer that `socket2` fills into an initialised slice.
//! It is justified inline.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::model::{PortState, Reason};
use crate::scan::Verdict;

#[cfg(unix)]
pub use unix::SynScanner;

#[cfg(not(unix))]
pub use fallback::SynScanner;

/// Advice printed whenever raw sockets are unavailable.
pub const PRIVILEGE_HINT: &str = "raw sockets require CAP_NET_RAW: grant it once with \
     `sudo setcap cap_net_raw+ep $(command -v rscan)`, run as root, or use the default \
     connect scan (`--scan-type connect`), which needs no privileges";

/// TCP flags we care about.
pub(crate) mod flags {
    pub(crate) const FIN: u8 = 0x01;
    pub(crate) const SYN: u8 = 0x02;
    pub(crate) const RST: u8 = 0x04;
    pub(crate) const ACK: u8 = 0x10;
}

/// What a reply packet told us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynReply {
    /// `SYN/ACK`: the port is open.
    SynAck,
    /// `RST`: the port is closed.
    Reset,
}

impl SynReply {
    /// The verdict this reply implies.
    pub fn verdict(self) -> Verdict {
        match self {
            SynReply::SynAck => Verdict::responded(PortState::Open, Reason::SynAck),
            SynReply::Reset => Verdict::responded(PortState::Closed, Reason::Reset),
        }
    }
}

/// Raw-socket machinery. Unix only: everything here needs `AsyncFd`, which has
/// no Windows equivalent for raw sockets.
#[cfg(unix)]
mod unix {
    use std::collections::HashMap;
    use std::io;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use parking_lot::Mutex;
    use socket2::{Domain, Protocol as SockProtocol, Socket, Type};
    use tokio::io::unix::AsyncFd;
    use tokio::sync::oneshot;

    use crate::error::{Error, Result};
    use crate::scan::syn::{
        build_tcp_segment, flags, parse_reply, source_address_for, ParsedReply, SynReply,
        PRIVILEGE_HINT,
    };
    use crate::scan::Verdict;

    /// Key identifying an outstanding probe.
    type ProbeKey = (IpAddr, u16);

    /// A raw-socket SYN scanner.
    ///
    /// One instance owns the sockets and the reply-correlation table for a whole
    /// scan; clone the `Arc` to use it from many tasks.
    pub struct SynScanner {
        v4: Option<Arc<AsyncFd<Socket>>>,
        v6: Option<Arc<AsyncFd<Socket>>>,
        source_port: u16,
        secret: u64,
        pending: Arc<Mutex<HashMap<ProbeKey, oneshot::Sender<SynReply>>>>,
        shutdown: Arc<AtomicBool>,
    }

    impl std::fmt::Debug for SynScanner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SynScanner")
                .field("ipv4", &self.v4.is_some())
                .field("ipv6", &self.v6.is_some())
                .field("source_port", &self.source_port)
                .finish()
        }
    }

    impl SynScanner {
        /// Open the raw sockets and start the receive loops.
        ///
        /// Returns [`Error::Privileges`] when the process lacks `CAP_NET_RAW`, and
        /// [`Error::Unsupported`] on platforms without raw socket support.
        pub fn new(want_v4: bool, want_v6: bool) -> Result<Arc<Self>> {
            if !cfg!(unix) {
                return Err(Error::Unsupported(
                    "SYN scanning needs raw sockets, which this build does not support".into(),
                ));
            }

            let v4 = if want_v4 { Some(open_raw(Domain::IPV4)?) } else { None };
            let v6 = if want_v6 {
                // A machine with no IPv6 is not a privilege problem, so a failure
                // here only disables IPv6 SYN scanning.
                open_raw(Domain::IPV6).ok()
            } else {
                None
            };

            if v4.is_none() && v6.is_none() {
                return Err(Error::Privileges(format!(
                    "no raw socket could be opened. {PRIVILEGE_HINT}"
                )));
            }

            let scanner = Arc::new(Self {
                v4: v4.map(Arc::new),
                v6: v6.map(Arc::new),
                // An ephemeral-range source port that no local service is likely to
                // be using, so the kernel's RSTs do not disturb anything.
                source_port: 32768 + (rand::random::<u16>() % 28000),
                secret: rand::random(),
                pending: Arc::new(Mutex::new(HashMap::new())),
                shutdown: Arc::new(AtomicBool::new(false)),
            });

            if let Some(socket) = scanner.v4.clone() {
                spawn_receiver(Arc::clone(&scanner), socket, false);
            }
            if let Some(socket) = scanner.v6.clone() {
                spawn_receiver(Arc::clone(&scanner), socket, true);
            }
            Ok(scanner)
        }

        /// `true` when the process can open raw sockets at all.
        ///
        /// Used by the CLI to report the situation before a scan starts rather than
        /// after the first probe fails.
        pub fn is_available() -> bool {
            open_raw(Domain::IPV4).is_ok()
        }

        /// Probe one port and wait up to `timeout` for a reply.
        pub async fn probe(
            &self,
            addr: IpAddr,
            port: u16,
            timeout: Duration,
        ) -> (Verdict, Duration) {
            let started = Instant::now();
            let (tx, rx) = oneshot::channel();
            self.pending.lock().insert((addr, port), tx);

            if let Err(err) = self.send_syn(addr, port) {
                self.pending.lock().remove(&(addr, port));
                return (crate::scan::classify_io_error(&err), started.elapsed());
            }

            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(reply)) => (reply.verdict(), started.elapsed()),
                // The sender was dropped: the receive loop stopped. Treat as silence.
                Ok(Err(_)) | Err(_) => {
                    self.pending.lock().remove(&(addr, port));
                    (Verdict::timed_out(), started.elapsed())
                }
            }
        }

        /// Send a bare ACK and interpret the answer as host discovery.
        ///
        /// A host that is up answers an unsolicited ACK with a RST, whether or not
        /// the port is open; a host that is down answers nothing. This gets through
        /// firewalls that drop ICMP echo.
        pub async fn ack_probe(&self, addr: IpAddr, port: u16, timeout: Duration) -> bool {
            let (tx, rx) = oneshot::channel();
            self.pending.lock().insert((addr, port), tx);
            if self.send_flagged(addr, port, flags::ACK).is_err() {
                self.pending.lock().remove(&(addr, port));
                return false;
            }
            let answered = matches!(tokio::time::timeout(timeout, rx).await, Ok(Ok(_)));
            if !answered {
                self.pending.lock().remove(&(addr, port));
            }
            answered
        }

        fn send_syn(&self, addr: IpAddr, port: u16) -> io::Result<()> {
            self.send_flagged(addr, port, flags::SYN)
        }

        fn send_flagged(&self, addr: IpAddr, port: u16, tcp_flags: u8) -> io::Result<()> {
            let source = source_address_for(addr)?;
            let seq = self.cookie(addr, port);
            let segment = build_tcp_segment(source, addr, self.source_port, port, seq, tcp_flags)?;

            let socket = match addr {
                IpAddr::V4(_) => self.v4.as_ref(),
                IpAddr::V6(_) => self.v6.as_ref(),
            }
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "no raw socket for this family")
            })?;

            let destination = SocketAddr::new(addr, port);
            socket.get_ref().send_to(&segment, &destination.into()).map(|_| ())
        }

        /// The sequence number that identifies our probe of `addr:port`.
        ///
        /// A 64-bit FNV-1a over the secret and the tuple, truncated to 32 bits. It
        /// does not need to be cryptographic — it needs to be unguessable enough
        /// that a host cannot claim a port we never probed.
        fn cookie(&self, addr: IpAddr, port: u16) -> u32 {
            let mut hash: u64 = 0xcbf2_9ce4_8422_2325 ^ self.secret;
            let mut mix = |byte: u8| {
                hash ^= byte as u64;
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            };
            match addr {
                IpAddr::V4(v4) => v4.octets().iter().for_each(|b| mix(*b)),
                IpAddr::V6(v6) => v6.octets().iter().for_each(|b| mix(*b)),
            }
            port.to_be_bytes().iter().for_each(|b| mix(*b));
            self.source_port.to_be_bytes().iter().for_each(|b| mix(*b));
            (hash ^ (hash >> 32)) as u32
        }

        /// Deliver a parsed reply to whoever is waiting for it.
        fn deliver(&self, addr: IpAddr, reply: ParsedReply) {
            if reply.destination_port != self.source_port {
                return;
            }
            let expected = self.cookie(addr, reply.source_port).wrapping_add(1);
            if reply.ack_number != expected {
                // Not ours: either another process's traffic or a forged reply.
                return;
            }
            let kind = if reply.flags & flags::RST != 0 {
                SynReply::Reset
            } else if reply.flags & flags::SYN != 0 && reply.flags & flags::ACK != 0 {
                SynReply::SynAck
            } else {
                return;
            };
            if let Some(waiter) = self.pending.lock().remove(&(addr, reply.source_port)) {
                let _ = waiter.send(kind);
            }
        }

        /// Stop the receive loops.
        pub fn shutdown(&self) {
            self.shutdown.store(true, Ordering::Relaxed);
            self.pending.lock().clear();
        }
    }

    impl Drop for SynScanner {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::Relaxed);
        }
    }

    fn open_raw(domain: Domain) -> Result<AsyncFd<Socket>> {
        let protocol = SockProtocol::from(libc::IPPROTO_TCP);
        let socket = Socket::new(domain, Type::RAW, Some(protocol)).map_err(|err| {
            if matches!(err.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
                Error::Privileges(format!("cannot open a raw socket ({err}). {PRIVILEGE_HINT}"))
            } else {
                Error::Io(err)
            }
        })?;
        socket.set_nonblocking(true).map_err(Error::Io)?;
        AsyncFd::new(socket).map_err(Error::Io)
    }

    fn spawn_receiver(scanner: Arc<SynScanner>, socket: Arc<AsyncFd<Socket>>, is_v6: bool) {
        tokio::spawn(async move {
            let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 2048];
            loop {
                if scanner.shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(mut guard) = socket.readable().await else {
                    break;
                };
                match guard.try_io(|inner| inner.get_ref().recv_from(&mut buffer)) {
                    Err(_would_block) => continue,
                    Ok(Err(_)) => continue,
                    Ok(Ok((len, from))) => {
                        // SAFETY: `recv_from` reported `len` initialised bytes at
                        // the start of `buffer`, so this slice is fully
                        // initialised. `MaybeUninit<u8>` has the same layout as
                        // `u8`, and the reference does not outlive `buffer`.
                        let bytes: &[u8] = unsafe {
                            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), len)
                        };
                        let Some(source) = from.as_socket().map(|s| s.ip()) else {
                            continue;
                        };
                        if let Some(reply) = parse_reply(bytes, is_v6) {
                            scanner.deliver(source, reply);
                        }
                    }
                }
            }
        });
    }
}

/// Stub used where raw sockets are unavailable, so the rest of the crate can
/// refer to `SynScanner` unconditionally.
#[cfg(not(unix))]
mod fallback {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::error::{Error, Result};
    use crate::scan::Verdict;

    /// Placeholder SYN scanner for platforms without raw socket support.
    #[derive(Debug)]
    pub struct SynScanner;

    impl SynScanner {
        /// Always fails: this platform has no raw socket support.
        pub fn new(_want_v4: bool, _want_v6: bool) -> Result<Arc<Self>> {
            Err(Error::Unsupported(
                "SYN scanning needs raw sockets, which are not supported on this platform; \
                 use the default connect scan"
                    .into(),
            ))
        }

        /// Always `false` on this platform.
        pub fn is_available() -> bool {
            false
        }

        /// Never called; present so callers compile unconditionally.
        pub async fn probe(
            &self,
            _addr: IpAddr,
            _port: u16,
            _timeout: Duration,
        ) -> (Verdict, Duration) {
            (Verdict::timed_out(), Duration::ZERO)
        }

        /// Never called; present so callers compile unconditionally.
        pub async fn ack_probe(&self, _addr: IpAddr, _port: u16, _timeout: Duration) -> bool {
            false
        }

        /// No-op.
        pub fn shutdown(&self) {}
    }
}

/// The fields of a TCP reply that matter for correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedReply {
    /// Port the reply came from, i.e. the port we probed.
    pub source_port: u16,
    /// Port the reply went to, i.e. our source port.
    pub destination_port: u16,
    /// Acknowledgement number; must be our sequence number plus one.
    pub ack_number: u32,
    /// TCP flags byte.
    pub flags: u8,
}

/// Parse a raw-socket read into a [`ParsedReply`].
///
/// IPv4 raw sockets deliver the IP header; IPv6 raw sockets do not.
pub fn parse_reply(bytes: &[u8], is_v6: bool) -> Option<ParsedReply> {
    let tcp = if is_v6 {
        bytes
    } else {
        let (header, rest) = etherparse::Ipv4Header::from_slice(bytes).ok()?;
        if header.protocol != etherparse::IpNumber::TCP {
            return None;
        }
        rest
    };
    let (tcp_header, _) = etherparse::TcpHeader::from_slice(tcp).ok()?;
    let mut flags = 0u8;
    if tcp_header.fin {
        flags |= flags::FIN;
    }
    if tcp_header.syn {
        flags |= flags::SYN;
    }
    if tcp_header.rst {
        flags |= flags::RST;
    }
    if tcp_header.ack {
        flags |= flags::ACK;
    }
    Some(ParsedReply {
        source_port: tcp_header.source_port,
        destination_port: tcp_header.destination_port,
        ack_number: tcp_header.acknowledgment_number,
        flags,
    })
}

/// Build a bare TCP segment with the given flags and a correct checksum.
pub fn build_tcp_segment(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    tcp_flags: u8,
) -> io::Result<Vec<u8>> {
    let mut header = etherparse::TcpHeader::new(source_port, destination_port, sequence, 64240);
    header.syn = tcp_flags & flags::SYN != 0;
    header.ack = tcp_flags & flags::ACK != 0;
    header.rst = tcp_flags & flags::RST != 0;
    header.fin = tcp_flags & flags::FIN != 0;

    let checksum = match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => header
            .calc_checksum_ipv4_raw(src.octets(), dst.octets(), &[])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
        (IpAddr::V6(src), IpAddr::V6(dst)) => header
            .calc_checksum_ipv6_raw(src.octets(), dst.octets(), &[])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and destination address families differ",
            ))
        }
    };
    header.checksum = checksum;

    let mut out = Vec::with_capacity(header.header_len());
    header
        .write(&mut out)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(out)
}

/// Ask the routing table which local address would be used to reach `target`.
///
/// Connecting a UDP socket performs the route lookup without sending anything,
/// which is the portable way to answer this question.
pub fn source_address_for(target: IpAddr) -> io::Result<IpAddr> {
    let bind: SocketAddr = match target {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(SocketAddr::new(target, 9))?;
    Ok(socket.local_addr()?.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().expect("test literal")
    }

    #[test]
    fn a_syn_segment_round_trips_through_the_parser() {
        let segment =
            build_tcp_segment(v4("10.0.0.1"), v4("10.0.0.2"), 40000, 443, 0xdead_beef, flags::SYN)
                .expect("builds");
        let parsed = parse_reply(&segment, true).expect("parses as a bare TCP segment");
        assert_eq!(parsed.source_port, 40000);
        assert_eq!(parsed.destination_port, 443);
        assert_eq!(parsed.flags, flags::SYN);
    }

    #[test]
    fn an_ack_segment_sets_only_the_ack_flag() {
        let segment = build_tcp_segment(v4("10.0.0.1"), v4("10.0.0.2"), 1, 80, 7, flags::ACK)
            .expect("builds");
        let parsed = parse_reply(&segment, true).expect("parses");
        assert_eq!(parsed.flags, flags::ACK);
    }

    #[test]
    fn checksums_differ_by_destination() {
        let a = build_tcp_segment(v4("10.0.0.1"), v4("10.0.0.2"), 1, 80, 1, flags::SYN).expect("a");
        let b = build_tcp_segment(v4("10.0.0.1"), v4("10.0.0.3"), 1, 80, 1, flags::SYN).expect("b");
        assert_ne!(a, b, "the pseudo-header must feed into the checksum");
    }

    #[test]
    fn ipv6_segments_build_too() {
        let segment =
            build_tcp_segment(v4("2001:db8::1"), v4("2001:db8::2"), 1234, 22, 99, flags::SYN)
                .expect("builds");
        let parsed = parse_reply(&segment, true).expect("parses");
        assert_eq!(parsed.destination_port, 22);
    }

    #[test]
    fn mixed_address_families_are_rejected() {
        assert!(build_tcp_segment(v4("10.0.0.1"), v4("2001:db8::1"), 1, 80, 1, flags::SYN).is_err());
    }

    #[test]
    fn an_ipv4_reply_is_parsed_past_its_ip_header() {
        let tcp = build_tcp_segment(
            v4("10.0.0.2"),
            v4("10.0.0.1"),
            443,
            40000,
            5,
            flags::SYN | flags::ACK,
        )
        .expect("builds");
        let ip = etherparse::Ipv4Header::new(
            tcp.len() as u16,
            64,
            etherparse::IpNumber::TCP,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
        )
        .expect("valid header");
        let mut packet = Vec::new();
        ip.write(&mut packet).expect("writes");
        packet.extend_from_slice(&tcp);

        let parsed = parse_reply(&packet, false).expect("parses");
        assert_eq!(parsed.source_port, 443);
        assert_eq!(parsed.flags, flags::SYN | flags::ACK);
    }

    #[test]
    fn non_tcp_packets_are_ignored() {
        let ip = etherparse::Ipv4Header::new(
            0,
            64,
            etherparse::IpNumber::UDP,
            [1, 1, 1, 1],
            [2, 2, 2, 2],
        )
        .expect("valid header");
        let mut packet = Vec::new();
        ip.write(&mut packet).expect("writes");
        assert!(parse_reply(&packet, false).is_none());
        assert!(parse_reply(b"", false).is_none());
        assert!(parse_reply(b"\x00\x01", true).is_none());
    }

    #[test]
    fn replies_map_onto_the_right_verdicts() {
        assert_eq!(SynReply::SynAck.verdict().state, PortState::Open);
        assert_eq!(SynReply::Reset.verdict().state, PortState::Closed);
        assert_eq!(SynReply::Reset.verdict().reason, Reason::Reset);
    }

    #[test]
    fn the_route_lookup_finds_a_source_address() {
        let source = source_address_for(v4("127.0.0.1")).expect("loopback is always routable");
        assert!(source.is_loopback(), "{source}");
    }

    #[test]
    fn the_privilege_hint_is_actionable() {
        assert!(PRIVILEGE_HINT.contains("setcap cap_net_raw+ep"));
        assert!(PRIVILEGE_HINT.contains("connect"));
    }

    #[tokio::test]
    async fn opening_without_privileges_explains_how_to_fix_it() {
        match SynScanner::new(true, false) {
            Ok(scanner) => {
                // Running as root or with the capability: the scanner must work.
                assert!(SynScanner::is_available());
                scanner.shutdown();
            }
            Err(err) => {
                assert!(err.is_privileges(), "unexpected error: {err}");
                assert!(err.to_string().contains("setcap"), "{err}");
            }
        }
    }
}
