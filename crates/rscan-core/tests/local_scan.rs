//! Integration tests against real listeners on loopback.
//!
//! These are the tests that would catch the failure mode that matters most in a
//! port scanner: reporting the wrong state. Everything here binds real sockets
//! on ephemeral ports, so it runs anywhere with no privileges and no fixtures.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures::StreamExt;
use rscan_core::config::ServiceDetection;
use rscan_core::ports::PortSpec;
use rscan_core::target::{TargetSet, TargetSpec};
use rscan_core::{PortResult, PortState, Protocol, Reason, ScanConfig, ScanEvent, Scanner};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

/// A listener held open for the duration of a test.
struct Fixture {
    _listeners: Vec<TcpListener>,
    /// Ports that are accepting connections.
    open: Vec<u16>,
    /// Ports that were bound and then released, so they refuse.
    closed: Vec<u16>,
}

async fn bind() -> (TcpListener, u16) {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("binding an ephemeral port on loopback");
    let port = listener.local_addr().expect("local address").port();
    (listener, port)
}

/// `open_count` accepting listeners and `closed_count` refusing ports.
async fn fixture(open_count: usize, closed_count: usize) -> Fixture {
    let mut listeners = Vec::new();
    let mut open = Vec::new();
    for _ in 0..open_count {
        let (listener, port) = bind().await;
        listeners.push(listener);
        open.push(port);
    }

    let mut closed = Vec::new();
    for _ in 0..closed_count {
        let (listener, port) = bind().await;
        drop(listener);
        closed.push(port);
    }

    open.sort_unstable();
    closed.sort_unstable();
    Fixture { _listeners: listeners, open, closed }
}

fn config_for(ports: &[u16]) -> ScanConfig {
    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("127.0.0.1").expect("loopback literal"));
    let spec = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse(&spec).expect("port list"))
        .skip_discovery(true)
        .retries(0)
        .fixed_timeout(Duration::from_millis(500))
        .report_all_states(true)
        .build()
        .expect("valid configuration")
}

async fn scan(config: ScanConfig) -> Vec<PortResult> {
    let scanner = Scanner::new(config).await.expect("scanner");
    let (mut results, _) = scanner.run_to_completion().await;
    results.sort_by_key(|r| r.port);
    results
}

/// The headline test: exactly the open ports, and nothing else.
#[tokio::test]
async fn finds_exactly_the_listening_ports() {
    let fixture = fixture(5, 5).await;
    let mut all: Vec<u16> = fixture.open.iter().chain(&fixture.closed).copied().collect();
    all.sort_unstable();

    let results = scan(config_for(&all)).await;
    assert_eq!(results.len(), all.len(), "every probed port must produce a result");

    let by_state: BTreeMap<u16, PortState> = results.iter().map(|r| (r.port, r.state)).collect();

    for port in &fixture.open {
        assert_eq!(by_state.get(port), Some(&PortState::Open), "port {port} should be open");
    }
    for port in &fixture.closed {
        assert_eq!(by_state.get(port), Some(&PortState::Closed), "port {port} should be closed");
    }

    let found_open: Vec<u16> =
        results.iter().filter(|r| r.state == PortState::Open).map(|r| r.port).collect();
    assert_eq!(found_open, fixture.open, "no port may be reported open that is not listening");
}

/// The distinction the whole project turns on.
#[tokio::test]
async fn closed_is_distinguished_from_filtered() {
    let fixture = fixture(1, 1).await;
    let results = scan(config_for(&[fixture.open[0], fixture.closed[0]])).await;

    let closed =
        results.iter().find(|r| r.port == fixture.closed[0]).expect("a result for the closed port");
    assert_eq!(closed.state, PortState::Closed);
    assert_eq!(closed.reason, Reason::ConnRefused, "a RST must be reported as such");
    assert_ne!(closed.state, PortState::Filtered);

    // A black hole, by contrast, must come back filtered with a different
    // reason. TEST-NET-2 is reserved and routed nowhere.
    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("198.51.100.11").expect("literal"));
    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse("65100").expect("literal"))
        .skip_discovery(true)
        .retries(0)
        .fixed_timeout(Duration::from_millis(300))
        .report_all_states(true)
        .build()
        .expect("valid");
    let filtered = scan(config).await;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].state, PortState::Filtered);
    assert_ne!(filtered[0].reason, Reason::ConnRefused);
}

/// A port that completes the handshake and then says nothing is still open —
/// and service detection must give up on it rather than stall the scan.
#[tokio::test]
async fn a_silent_listener_is_open_and_does_not_stall_detection() {
    let (listener, silent_port) = bind().await;
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = listener.accept().await {
            // Accept, then never write anything.
            held.push(socket);
        }
    });

    let (talker, talking_port) = bind().await;
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = talker.accept().await {
            let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.6p1\r\n").await;
            let _ = socket.flush().await;
        }
    });

    let mut config = config_for(&[silent_port, talking_port]);
    config.service_detection =
        ServiceDetection { timeout: Duration::from_millis(800), ..ServiceDetection::all() };

    let started = Instant::now();
    let results = scan(config).await;
    let elapsed = started.elapsed();

    let silent = results.iter().find(|r| r.port == silent_port).expect("silent port result");
    assert_eq!(silent.state, PortState::Open, "a silent listener is still open");

    let talking = results.iter().find(|r| r.port == talking_port).expect("talking port result");
    assert_eq!(
        talking.service.as_ref().and_then(|s| s.name.as_deref()),
        Some("ssh"),
        "the talkative listener must be identified"
    );

    assert!(elapsed < Duration::from_secs(6), "detection stalled the scan: {elapsed:?}");
}

/// A port that accepts and immediately closes is open, not closed: the
/// handshake completed.
#[tokio::test]
async fn a_listener_that_hangs_up_immediately_is_open() {
    let (listener, port) = bind().await;
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            drop(socket);
        }
    });

    let results = scan(config_for(&[port])).await;
    assert_eq!(results[0].state, PortState::Open);
    assert_eq!(results[0].reason, Reason::SynAck);
}

/// Acceptance criterion: results are produced while the scan is still running.
#[tokio::test]
async fn the_first_result_arrives_long_before_the_scan_ends() {
    let (_listener, open_port) = bind().await;

    // One fast, reachable host and one black hole with enough ports that the
    // scan takes several seconds.
    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("127.0.0.1").expect("literal"));
    targets.add(TargetSpec::parse("198.51.100.12").expect("literal"));

    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse(&format!("{open_port},65200-65240")).expect("literal"))
        .skip_discovery(true)
        .retries(0)
        .fixed_timeout(Duration::from_millis(900))
        .concurrency(4)
        .report_all_states(true)
        .build()
        .expect("valid");

    let scanner = Scanner::new(config).await.expect("scanner");
    let started = Instant::now();
    let mut first_result_at = None;
    let mut results = 0;

    let mut events = Box::pin(scanner.run());
    while let Some(event) = events.next().await {
        if let ScanEvent::Port(_) = event {
            results += 1;
            if first_result_at.is_none() {
                first_result_at = Some(started.elapsed());
            }
        }
    }
    let total = started.elapsed();
    let first = first_result_at.expect("at least one result");

    assert!(results > 40, "the scan should have produced many results, got {results}");
    assert!(
        first < total / 2,
        "the first result took {first:?} of a {total:?} scan; output is not streaming"
    );
    assert!(total > Duration::from_secs(1), "the scan was too short to prove anything: {total:?}");
}

/// Acceptance criterion: `--resume` does not repeat completed work.
#[tokio::test]
async fn resuming_skips_work_already_done() {
    use rscan_core::state::{self, ScanState};

    let fixture = fixture(2, 2).await;
    let mut ports: Vec<u16> = fixture.open.iter().chain(&fixture.closed).copied().collect();
    ports.sort_unstable();

    let dir = std::env::temp_dir().join(format!("rscan-resume-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await.expect("mkdir");
    let path = dir.join("scan.state");

    let mut config = config_for(&ports);
    config.resume_path = Some(path.clone());

    // First run: complete the scan and checkpoint.
    let scanner = Scanner::new(config.clone()).await.expect("scanner");
    let (first_results, first_summary) = scanner.run_to_completion().await;
    assert_eq!(first_results.len(), ports.len());
    assert_eq!(first_summary.packets_sent, ports.len() as u64);

    let saved = ScanState::load(&path).await.expect("state was written");
    assert!(saved.matches(&state::fingerprint(&config)));
    assert_eq!(saved.completed_count(), ports.len() as u64);

    // Second run over the same state: nothing may be probed again.
    let scanner = Scanner::new(config.clone()).await.expect("scanner");
    let (second_results, second_summary) = scanner.run_to_completion().await;
    assert_eq!(second_summary.packets_sent, 0, "a resumed scan must not re-probe finished ports");
    assert_eq!(
        second_summary.ports_scanned,
        ports.len() as u64,
        "already-completed probes still count towards progress"
    );

    // The open ports found in the first run are still reported.
    let open_again: Vec<u16> =
        second_results.iter().filter(|r| r.state == PortState::Open).map(|r| r.port).collect();
    assert_eq!(open_again, fixture.open, "a resumed scan must still report earlier findings");

    // A state file from a different scan must be refused, not silently misused.
    let mut other = config.clone();
    other.ports = PortSpec::parse("1-10").expect("literal");
    let err = Scanner::new(other).await.expect_err("mismatched fingerprint");
    assert!(err.to_string().contains("different scan"), "{err}");

    tokio::fs::remove_dir_all(&dir).await.ok();
}

/// A resumed scan that was interrupted part-way continues from where it was.
#[tokio::test]
async fn a_partial_resume_completes_the_remaining_ports() {
    use rscan_core::state::{self, ScanState};

    let fixture = fixture(3, 0).await;
    let dir = std::env::temp_dir().join(format!("rscan-partial-{}", std::process::id()));
    tokio::fs::create_dir_all(&dir).await.expect("mkdir");
    let path = dir.join("scan.state");

    let mut config = config_for(&fixture.open);
    config.resume_path = Some(path.clone());

    // Pretend an earlier run finished the first port only.
    let mut state = ScanState::new(state::fingerprint(&config));
    let addr = "127.0.0.1".parse().expect("literal");
    state.mark_done(addr, Protocol::Tcp, fixture.open[0]);
    state.save(&path).await.expect("save");

    let scanner = Scanner::new(config).await.expect("scanner");
    let (results, summary) = scanner.run_to_completion().await;

    assert_eq!(summary.packets_sent, 2, "only the two unfinished ports should be probed");
    let found: Vec<u16> =
        results.iter().filter(|r| r.state == PortState::Open).map(|r| r.port).collect();
    assert_eq!(found, fixture.open[1..].to_vec());

    tokio::fs::remove_dir_all(&dir).await.ok();
}

/// Scanning several hosts at once still attributes results correctly.
#[tokio::test]
async fn results_are_attributed_to_the_right_host() {
    let fixture = fixture(2, 0).await;

    let mut targets = TargetSet::new();
    // 127.0.0.1 and 127.0.0.2 are both loopback, and a listener bound to
    // 127.0.0.1 is not reachable on 127.0.0.2.
    targets.add(TargetSpec::parse("127.0.0.1").expect("literal"));
    targets.add(TargetSpec::parse("127.0.0.2").expect("literal"));

    let spec = fixture.open.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse(&spec).expect("literal"))
        .skip_discovery(true)
        .retries(0)
        .fixed_timeout(Duration::from_millis(500))
        .report_all_states(true)
        .build()
        .expect("valid");

    let results = scan(config).await;
    assert_eq!(results.len(), fixture.open.len() * 2);

    for result in &results {
        if result.addr.to_string() == "127.0.0.1" {
            assert_eq!(result.state, PortState::Open, "{result:?}");
        }
    }
}

/// IPv6 loopback goes through the same code path.
#[tokio::test]
async fn ipv6_loopback_is_scanned_like_ipv4() {
    let Ok(listener) =
        TcpListener::bind(SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0))).await
    else {
        // No IPv6 on this machine; not a failure.
        return;
    };
    let port = listener.local_addr().expect("addr").port();

    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("::1").expect("literal"));
    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse(&port.to_string()).expect("literal"))
        .skip_discovery(true)
        .retries(0)
        .fixed_timeout(Duration::from_millis(500))
        .report_all_states(true)
        .build()
        .expect("valid");

    let results = scan(config).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].state, PortState::Open);
    assert!(results[0].addr.is_ipv6());
}

/// UDP against loopback: an echo service is open, an unbound port is closed.
#[tokio::test]
async fn udp_ports_are_classified() {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
    let open_port = socket.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 2048];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            let _ = socket.send_to(&buffer[..len.max(1)], from).await;
        }
    });

    let spare = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
    let closed_port = spare.local_addr().expect("addr").port();
    drop(spare);

    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("127.0.0.1").expect("literal"));
    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse(&format!("U:{open_port},{closed_port}")).expect("literal"))
        .skip_discovery(true)
        .retries(0)
        .fixed_timeout(Duration::from_millis(400))
        .report_all_states(true)
        .build()
        .expect("valid");

    let results = scan(config).await;
    assert_eq!(results.len(), 2);
    let open = results.iter().find(|r| r.port == open_port).expect("open result");
    assert_eq!(open.state, PortState::Open);
    assert_eq!(open.protocol, Protocol::Udp);

    let closed = results.iter().find(|r| r.port == closed_port).expect("closed result");
    assert!(
        matches!(closed.state, PortState::Closed | PortState::OpenFiltered),
        "unbound UDP port reported as {:?}",
        closed.state
    );
}
