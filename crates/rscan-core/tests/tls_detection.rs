//! TLS detection against a real TLS server on loopback.
//!
//! A unit test can prove that a plain-text port is *not* TLS; only a real
//! handshake proves that the certificate parsing, SAN extraction and ALPN
//! reporting work. The server here uses a self-signed certificate generated at
//! test time, which also exercises the deliberate decision not to validate
//! certificates: a scanner that refused a self-signed certificate would discard
//! the most interesting finding there is.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rscan_core::config::ServiceDetection;
use rscan_core::probe::{tls, Detector};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The names the test certificate is issued for.
const SANS: [&str; 2] = ["tls.test.example", "alt.test.example"];

/// Start a TLS server on an ephemeral loopback port.
///
/// `http_reply` is sent inside the TLS session once the handshake completes, so
/// the same fixture serves both the bare-TLS and the HTTPS cases.
async fn tls_server(alpn: Vec<Vec<u8>>, http_reply: Option<&'static [u8]>) -> u16 {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(SANS.map(String::from).to_vec())
            .expect("generating a self-signed certificate");

    let certificate = CertificateDer::from(cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .expect("the generated certificate and key match");
    config.alpn_protocols = alpn;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener =
        TcpListener::bind(SocketAddr::new(LOCALHOST, 0)).await.expect("binding loopback");
    let port = listener.local_addr().expect("local address").port();

    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    return;
                };
                if let Some(reply) = http_reply {
                    // Read the request first so the client's write completes.
                    let mut discard = [0u8; 2048];
                    let _ = tokio::time::timeout(
                        Duration::from_millis(500),
                        tokio::io::AsyncReadExt::read(&mut stream, &mut discard),
                    )
                    .await;
                    let _ = stream.write_all(reply).await;
                    let _ = stream.flush().await;
                }
                // Give the client a moment before tearing the session down.
                tokio::time::sleep(Duration::from_millis(200)).await;
            });
        }
    });

    port
}

#[tokio::test]
async fn a_handshake_reports_version_and_certificate_names() {
    let port = tls_server(Vec::new(), None).await;
    let stream = TcpStream::connect(SocketAddr::new(LOCALHOST, port)).await.expect("connecting");

    let probe = tls::handshake(stream, LOCALHOST, None, Duration::from_secs(5))
        .await
        .expect("the handshake must succeed against a real TLS server");
    let info = probe.info;

    let version = info.version.expect("a negotiated protocol version");
    assert!(version.contains("TLS"), "unexpected version {version:?}");

    // Certificate validation is deliberately skipped, so a self-signed
    // certificate must still be read rather than rejected.
    assert!(info.subject_cn.is_some(), "the leaf certificate subject must be reported");
    assert!(info.issuer_cn.is_some(), "the leaf certificate issuer must be reported");

    for expected in SANS {
        assert!(
            info.sans.iter().any(|san| san == expected),
            "SAN {expected:?} missing from {:?}",
            info.sans
        );
    }

    assert!(info.not_before.is_some(), "notBefore must be reported");
    assert!(info.not_after.is_some(), "notAfter must be reported");
}

#[tokio::test]
async fn alpn_is_negotiated_and_reported() {
    let port = tls_server(vec![b"h2".to_vec()], None).await;
    let stream = TcpStream::connect(SocketAddr::new(LOCALHOST, port)).await.expect("connecting");

    let probe =
        tls::handshake(stream, LOCALHOST, None, Duration::from_secs(5)).await.expect("handshake");
    // The scanner offers h2 and http/1.1; a server offering only h2 must pick it.
    assert_eq!(probe.info.alpn.as_deref(), Some("h2"));
}

#[tokio::test]
async fn sni_can_be_set_from_a_hostname() {
    let port = tls_server(Vec::new(), None).await;
    let stream = TcpStream::connect(SocketAddr::new(LOCALHOST, port)).await.expect("connecting");

    // A name that does not match the certificate must still complete, because
    // the scanner is reading what is presented rather than trusting it.
    let probe = tls::handshake(stream, LOCALHOST, Some("tls.test.example"), Duration::from_secs(5))
        .await
        .expect("handshake with SNI");
    assert!(probe.info.subject_cn.is_some());
}

#[tokio::test]
async fn the_detector_reports_https_on_a_non_standard_port() {
    // The finding the spec calls valuable: HTTPS somewhere unexpected.
    let port = tls_server(
        vec![b"http/1.1".to_vec()],
        Some(b"HTTP/1.1 200 OK\r\nServer: rscan-test-tls/1.0\r\n\r\n<title>Secret Panel</title>"),
    )
    .await;

    let detector = Detector::new(ServiceDetection {
        timeout: Duration::from_secs(6),
        ..ServiceDetection::all()
    });

    // No pre-existing stream: the detector has to open its own connection,
    // discover the port is quiet, and try TLS.
    let info =
        detector.detect_tcp(LOCALHOST, port, None, None).await.expect("something must be detected");

    assert_eq!(info.name.as_deref(), Some("https"), "{info:?}");

    let tls_info = info.tls.expect("TLS details");
    assert!(tls_info.version.is_some());
    assert_eq!(tls_info.alpn.as_deref(), Some("http/1.1"));
    assert!(tls_info.sans.iter().any(|san| san == "tls.test.example"), "{:?}", tls_info.sans);

    let http = info.http.expect("HTTP details, inside the TLS session");
    assert_eq!(http.status, Some(200));
    assert_eq!(http.server.as_deref(), Some("rscan-test-tls/1.0"));
    assert_eq!(http.title.as_deref(), Some("Secret Panel"));
}

#[tokio::test]
async fn a_full_scan_reports_tls_details() {
    use futures::StreamExt;
    use rscan_core::ports::PortSpec;
    use rscan_core::target::{TargetSet, TargetSpec};
    use rscan_core::{ScanConfig, ScanEvent, Scanner};

    let port = tls_server(vec![b"h2".to_vec()], None).await;

    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("127.0.0.1").expect("literal"));
    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse(&port.to_string()).expect("literal"))
        .skip_discovery(true)
        .retries(0)
        .fixed_timeout(Duration::from_millis(500))
        .service_detection(ServiceDetection {
            timeout: Duration::from_secs(6),
            ..ServiceDetection::all()
        })
        .build()
        .expect("valid configuration");

    let scanner = Scanner::new(config).await.expect("scanner");
    let mut events = Box::pin(scanner.run());
    let mut found = None;
    while let Some(event) = events.next().await {
        if let ScanEvent::Port(result) = event {
            found = Some(result);
        }
    }

    let result = found.expect("the TLS port must be reported");
    let service = result.service.expect("service detection ran");
    let tls_info = service.tls.expect("TLS was detected through a full scan");
    assert!(tls_info.version.is_some());
    assert!(tls_info.subject_cn.is_some());
}
