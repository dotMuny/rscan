//! TLS detection.
//!
//! A TLS handshake against a port tells you three useful things at once: that
//! the port speaks TLS at all, which version and ALPN it negotiated, and whose
//! certificate it presents. The certificate is the valuable part — a service on
//! a non-standard port whose certificate says `*.internal.example.com` has just
//! identified itself.
//!
//! Certificate validation is deliberately **not** performed. The scanner is not
//! establishing a trusted channel; it is reading what the server presents. A
//! self-signed or expired certificate is a finding, not an error, so refusing
//! the handshake would throw away exactly the information worth having. The
//! bytes that come back are treated as untrusted data and never as trust.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, IpAddr as PkiIpAddr, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

use crate::model::TlsInfo;
use crate::probe::matcher::sanitise;

/// The result of a successful TLS handshake, plus the wrapped stream so the
/// caller can keep talking (to send an HTTP request, say).
pub struct TlsProbe<S> {
    /// What the handshake revealed.
    pub info: TlsInfo,
    /// The negotiated stream.
    pub stream: tokio_rustls::client::TlsStream<S>,
}

/// Build a client configuration that accepts any certificate.
///
/// Cached, because building one compiles the cipher suite tables.
fn client_config() -> Arc<ClientConfig> {
    static CONFIG: once_cell::sync::Lazy<Arc<ClientConfig>> = once_cell::sync::Lazy::new(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(AcceptAnyServerCert { provider: Arc::clone(&provider) });
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map(|builder| {
                builder.dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth()
            })
            // `with_safe_default_protocol_versions` only fails if the provider
            // supports no versions at all, which the ring provider always does.
            .unwrap_or_else(|_| {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let verifier = Arc::new(AcceptAnyServerCert { provider: Arc::clone(&provider) });
                ClientConfig::builder_with_provider(provider)
                    .with_protocol_versions(&[&rustls::version::TLS12])
                    .map(|b| {
                        b.dangerous()
                            .with_custom_certificate_verifier(verifier)
                            .with_no_client_auth()
                    })
                    .unwrap_or_else(|_| unreachable_config())
            });
        // Offer the protocols a real client would, so the server tells us what
        // it actually speaks.
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(config)
    });
    Arc::clone(&CONFIG)
}

/// Only reachable if rustls supports no TLS version at all, which cannot
/// happen with the ring provider compiled in.
fn unreachable_config() -> ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(AcceptAnyServerCert { provider: Arc::clone(&provider) });
    #[allow(clippy::expect_used)]
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map(|b| b.dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth())
        .expect("the ring provider always supports TLS 1.3")
}

/// Attempt a TLS handshake over an already-connected stream.
///
/// `server_name` is used for SNI; pass the hostname when one is known,
/// otherwise the address is used, which is what a real client would do.
pub async fn handshake<S>(
    stream: S,
    addr: IpAddr,
    server_name: Option<&str>,
    timeout: Duration,
) -> Option<TlsProbe<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let name = match server_name.and_then(|n| ServerName::try_from(n.to_string()).ok()) {
        Some(name) => name,
        None => ServerName::IpAddress(match addr {
            IpAddr::V4(v4) => PkiIpAddr::V4(v4.into()),
            IpAddr::V6(v6) => PkiIpAddr::V6(v6.into()),
        }),
    };

    let connector = TlsConnector::from(client_config());
    let stream = tokio::time::timeout(timeout, connector.connect(name, stream)).await.ok()?.ok()?;

    let info = {
        let (_, session) = stream.get_ref();
        let mut info = TlsInfo {
            version: session.protocol_version().map(|v| format!("{v:?}")),
            alpn: session.alpn_protocol().map(|p| sanitise(p, 32)),
            ..Default::default()
        };
        if let Some(certs) = session.peer_certificates() {
            if let Some(leaf) = certs.first() {
                fill_from_certificate(&mut info, leaf);
            }
        }
        info
    };

    Some(TlsProbe { info, stream })
}

/// Pull the human-meaningful fields out of a DER certificate.
///
/// Parsing failures are not errors: a malformed certificate is itself a
/// finding, and the version and ALPN are already worth reporting.
fn fill_from_certificate(info: &mut TlsInfo, cert: &CertificateDer<'_>) {
    use x509_parser::prelude::*;

    let Ok((_, parsed)) = X509Certificate::from_der(cert.as_ref()) else {
        info.subject_cn = Some("<unparseable certificate>".to_string());
        return;
    };

    info.subject_cn = first_common_name(parsed.subject());
    info.issuer_cn = first_common_name(parsed.issuer());
    info.not_before = Some(parsed.validity().not_before.to_string());
    info.not_after = Some(parsed.validity().not_after.to_string());

    if let Ok(Some(san)) = parsed.subject_alternative_name() {
        for name in &san.value.general_names {
            let rendered = match name {
                GeneralName::DNSName(dns) => Some((*dns).to_string()),
                GeneralName::IPAddress(bytes) => render_ip(bytes),
                GeneralName::RFC822Name(mail) => Some((*mail).to_string()),
                GeneralName::URI(uri) => Some((*uri).to_string()),
                _ => None,
            };
            if let Some(rendered) = rendered {
                let clean = sanitise(rendered.as_bytes(), 253);
                if !clean.is_empty() && !info.sans.contains(&clean) {
                    info.sans.push(clean);
                }
            }
        }
    }
}

fn first_common_name(name: &x509_parser::x509::X509Name<'_>) -> Option<String> {
    let cn = name.iter_common_name().next()?;
    let value = cn.as_str().ok()?;
    let clean = sanitise(value.as_bytes(), 253);
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn render_ip(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(std::net::Ipv4Addr::from(octets).to_string())
        }
        16 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

/// A certificate verifier that accepts everything.
///
/// See the module documentation for why this is the correct behaviour for a
/// scanner and why it would be a serious bug anywhere else.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn the_client_config_builds_and_offers_alpn() {
        let config = client_config();
        assert_eq!(config.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[tokio::test]
    async fn a_plaintext_service_fails_the_handshake_without_hanging() {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // A plain-text greeting is not a ServerHello.
                let _ = stream.write_all(b"220 plain text service\r\n").await;
                let _ = stream.flush().await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .expect("connect");
        let probe =
            handshake(stream, IpAddr::V4(Ipv4Addr::LOCALHOST), None, Duration::from_secs(2)).await;
        assert!(probe.is_none(), "a plain-text port must not report TLS");
    }

    #[tokio::test]
    async fn a_silent_port_times_out_rather_than_blocking_forever() {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(stream);
            }
        });

        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .expect("connect");
        let started = std::time::Instant::now();
        let probe =
            handshake(stream, IpAddr::V4(Ipv4Addr::LOCALHOST), None, Duration::from_millis(300))
                .await;
        assert!(probe.is_none());
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    #[test]
    fn san_ip_rendering_handles_both_families() {
        assert_eq!(render_ip(&[192, 0, 2, 1]).as_deref(), Some("192.0.2.1"));
        assert_eq!(render_ip(&[0u8; 16]).as_deref(), Some("::"));
        assert_eq!(render_ip(&[1, 2, 3]), None);
    }
}
