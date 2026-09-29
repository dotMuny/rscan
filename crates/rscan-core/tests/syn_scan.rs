//! SYN-scan tests, which need `CAP_NET_RAW`.
//!
//! Raw sockets cannot be opened by an unprivileged process, so these tests
//! check for the capability and return early without it — loudly, on stderr,
//! rather than silently. Nothing runs them automatically, so to exercise the
//! SYN engine at all you have to grant the capability yourself:
//!
//! ```sh
//! sudo -E "$(command -v cargo)" test -p rscan-core --test syn_scan -- --nocapture
//! ```
//!
//! The unprivileged half — packet construction, reply parsing, the privilege
//! error and its `setcap` advice — is covered by the unit tests in
//! `src/scan/syn.rs`, which run everywhere.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rscan_core::ports::PortSpec;
use rscan_core::scan::syn::SynScanner;
use rscan_core::target::{TargetSet, TargetSpec};
use rscan_core::{PortState, Reason, ScanConfig, ScanMode, Scanner};
use tokio::net::TcpListener;

/// `true` when this process can open raw sockets.
fn have_raw_sockets() -> bool {
    SynScanner::is_available()
}

/// Print why a test did nothing, so a skipped run is visible.
fn skip(test: &str) {
    eprintln!(
        "skipping {test}: this process cannot open raw sockets. \
         Run with CAP_NET_RAW (see the module docs) to exercise the SYN scan."
    );
}

async fn bind() -> (TcpListener, u16) {
    let listener =
        TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    (listener, port)
}

#[tokio::test]
async fn a_syn_scan_finds_listening_ports() {
    if !have_raw_sockets() {
        skip("a_syn_scan_finds_listening_ports");
        return;
    }

    // Two accepting ports and one that refuses.
    let (_a, open_a) = bind().await;
    let (_b, open_b) = bind().await;
    let (spare, closed) = bind().await;
    drop(spare);

    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("127.0.0.1").expect("literal"));
    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse(&format!("{open_a},{open_b},{closed}")).expect("literal"))
        .mode(ScanMode::Syn)
        // A fallback would make a failure here look like a pass.
        .fallback_to_connect(false)
        .skip_discovery(true)
        .retries(1)
        .fixed_timeout(Duration::from_millis(800))
        .report_all_states(true)
        .build()
        .expect("valid configuration");

    let scanner = Scanner::new(config).await.expect("a SYN scanner with CAP_NET_RAW");
    assert_eq!(scanner.effective_mode(), ScanMode::Syn, "must not have fallen back");

    let (mut results, summary) = scanner.run_to_completion().await;
    results.sort_by_key(|r| r.port);

    let state_of = |port: u16| -> PortState {
        results.iter().find(|r| r.port == port).map(|r| r.state).unwrap_or(PortState::Filtered)
    };

    assert_eq!(state_of(open_a), PortState::Open, "{results:?}");
    assert_eq!(state_of(open_b), PortState::Open, "{results:?}");
    assert_eq!(state_of(closed), PortState::Closed, "{results:?}");
    assert_eq!(summary.ports_open, 2);
}

#[tokio::test]
async fn syn_replies_carry_the_right_reasons() {
    if !have_raw_sockets() {
        skip("syn_replies_carry_the_right_reasons");
        return;
    }

    let (_listener, open) = bind().await;
    let (spare, closed) = bind().await;
    drop(spare);

    let scanner = SynScanner::new(true, false).expect("raw sockets");

    let localhost = "127.0.0.1".parse().expect("literal");
    let (verdict, _) = scanner.probe(localhost, open, Duration::from_secs(2)).await;
    assert_eq!(verdict.state, PortState::Open);
    assert_eq!(verdict.reason, Reason::SynAck, "an open port answers with SYN/ACK");

    let (verdict, _) = scanner.probe(localhost, closed, Duration::from_secs(2)).await;
    assert_eq!(verdict.state, PortState::Closed);
    assert_eq!(verdict.reason, Reason::Reset, "a closed port answers with RST");

    scanner.shutdown();
}

#[tokio::test]
async fn an_ack_probe_proves_a_host_is_up() {
    if !have_raw_sockets() {
        skip("an_ack_probe_proves_a_host_is_up");
        return;
    }

    let (_listener, port) = bind().await;
    let scanner = SynScanner::new(true, false).expect("raw sockets");
    let localhost = "127.0.0.1".parse().expect("literal");

    // Loopback answers an unsolicited ACK with a RST, whatever the port state.
    assert!(
        scanner.ack_probe(localhost, port, Duration::from_secs(2)).await,
        "loopback must answer an ACK probe"
    );
    scanner.shutdown();
}

#[tokio::test]
async fn a_syn_scan_of_a_black_hole_reports_filtered() {
    if !have_raw_sockets() {
        skip("a_syn_scan_of_a_black_hole_reports_filtered");
        return;
    }

    let scanner = SynScanner::new(true, false).expect("raw sockets");
    // TEST-NET-2: reserved, routed nowhere.
    let unreachable = "198.51.100.20".parse().expect("literal");
    let (verdict, _) = scanner.probe(unreachable, 65300, Duration::from_millis(400)).await;
    assert_ne!(verdict.state, PortState::Open, "{verdict:?}");
    scanner.shutdown();
}

/// Without the capability, the scanner must explain itself and fall back —
/// this half runs everywhere, privileges or not.
#[tokio::test]
async fn without_privileges_the_scan_falls_back_and_says_so() {
    if have_raw_sockets() {
        eprintln!(
            "skipping without_privileges_the_scan_falls_back_and_says_so: \
             this process has raw socket access, so there is no fallback to observe"
        );
        return;
    }

    let base = || {
        ScanConfig::builder()
            .targets({
                let mut set = TargetSet::new();
                set.add(TargetSpec::parse("127.0.0.1").expect("literal"));
                set
            })
            .ports(PortSpec::parse("80").expect("literal"))
            .mode(ScanMode::Syn)
            .skip_discovery(true)
    };

    // With the fallback allowed: a connect scan, plus a warning that names the fix.
    let scanner = Scanner::new(base().fallback_to_connect(true).build().expect("valid"))
        .await
        .expect("must fall back rather than fail");
    assert_eq!(scanner.effective_mode(), ScanMode::Connect);
    let warnings = scanner.warnings().join("\n");
    assert!(warnings.contains("setcap cap_net_raw+ep"), "{warnings}");
    assert!(warnings.contains("falling back"), "{warnings}");

    // With the fallback forbidden: a hard error, still with the advice.
    let err = Scanner::new(base().fallback_to_connect(false).build().expect("valid"))
        .await
        .expect_err("must refuse rather than silently downgrade");
    assert!(err.is_privileges(), "{err}");
    assert!(err.to_string().contains("setcap cap_net_raw+ep"), "{err}");
}
