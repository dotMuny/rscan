//! HTTP detection: status line, `Server`, page title and redirects.
//!
//! Deliberately hand-rolled rather than pulling in an HTTP client. A scanner
//! talks to things that are only approximately HTTP, and a strict client either
//! refuses them or follows redirects it was never asked to follow. Here the
//! request is one fixed line, exactly one response is read, and redirects are
//! *reported* rather than followed.

use std::time::Duration;

use once_cell::sync::Lazy;
use regex::bytes::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::model::HttpInfo;
use crate::probe::matcher::sanitise;

/// Cap on how much of a response body to read. Enough for a `<title>` in any
/// reasonable page, small enough that a hostile endpoint streaming gigabytes
/// cannot stall the scan.
const MAX_RESPONSE: usize = 64 * 1024;

static STATUS_RE: Lazy<Option<Regex>> = Lazy::new(|| Regex::new(r"(?i)^HTTP/\d\.\d (\d{3})").ok());
static TITLE_RE: Lazy<Option<Regex>> =
    Lazy::new(|| Regex::new(r"(?is)<title[^>]*>(.{0,512}?)</title>").ok());

/// Send one HTTP request and interpret the response.
///
/// `host` goes into the `Host` header; pass the hostname when one is known so
/// that name-based virtual hosts answer with their real content.
///
/// Returns the parsed information and the raw response bytes, so the caller can
/// also run the response through the probe matcher.
pub async fn probe<S>(stream: &mut S, host: &str, timeout: Duration) -> Option<(HttpInfo, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rscan/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        crate::VERSION
    );

    tokio::time::timeout(timeout, stream.write_all(request.as_bytes())).await.ok()?.ok()?;
    let _ = tokio::time::timeout(timeout, stream.flush()).await;

    let response = read_bounded(stream, timeout).await?;
    if response.is_empty() {
        return None;
    }
    let info = parse_response(&response)?;
    Some((info, response))
}

async fn read_bounded<S>(stream: &mut S, timeout: Duration) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buffer = Vec::with_capacity(8192);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut chunk = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => {
                buffer.extend_from_slice(&chunk[..n]);
                if buffer.len() >= MAX_RESPONSE {
                    buffer.truncate(MAX_RESPONSE);
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    Some(buffer)
}

/// Parse a raw HTTP response.
///
/// Returns `None` when the bytes are not an HTTP response at all, which is how
/// the caller distinguishes "this port is not HTTP" from "this port is HTTP and
/// said 500".
pub fn parse_response(response: &[u8]) -> Option<HttpInfo> {
    let status = STATUS_RE
        .as_ref()?
        .captures(response)
        .and_then(|caps| caps.get(1))
        .and_then(|m| std::str::from_utf8(m.as_bytes()).ok())
        .and_then(|s| s.parse::<u16>().ok())?;

    let split = find_header_end(response);
    let (head, body) = response.split_at(split.min(response.len()));

    let server = header_value(head, b"server").map(|v| sanitise(&v, 128));
    let location = header_value(head, b"location").map(|v| sanitise(&v, 512));
    let redirects_to_https = location
        .as_deref()
        .map(|l| l.to_ascii_lowercase().starts_with("https://"))
        .unwrap_or(false);

    let title = TITLE_RE
        .as_ref()
        .and_then(|re| re.captures(body))
        .and_then(|caps| caps.get(1))
        .map(|m| sanitise(m.as_bytes(), 128))
        .filter(|t| !t.is_empty());

    Some(HttpInfo {
        status: Some(status),
        server: server.filter(|s| !s.is_empty()),
        title,
        location: location.filter(|s| !s.is_empty()),
        redirects_to_https,
    })
}

/// Offset just past the blank line that ends the headers, or the whole length.
fn find_header_end(response: &[u8]) -> usize {
    response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| response.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
        .unwrap_or(response.len())
}

/// Case-insensitive header lookup over raw header bytes.
fn header_value(head: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (key, value) = line.split_at(colon);
        if key.len() == name.len() && key.iter().zip(name).all(|(a, b)| a.eq_ignore_ascii_case(b)) {
            let value = &value[1..];
            let start = value.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(value.len());
            return Some(value[start..].to_vec());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_response() {
        let response = b"HTTP/1.1 200 OK\r\n\
            Server: nginx/1.24.0\r\n\
            Content-Type: text/html\r\n\r\n\
            <html><head><title>Welcome to nginx!</title></head><body></body></html>";
        let info = parse_response(response).expect("valid HTTP");
        assert_eq!(info.status, Some(200));
        assert_eq!(info.server.as_deref(), Some("nginx/1.24.0"));
        assert_eq!(info.title.as_deref(), Some("Welcome to nginx!"));
        assert!(!info.redirects_to_https);
    }

    #[test]
    fn detects_a_redirect_to_https() {
        let response = b"HTTP/1.1 301 Moved Permanently\r\n\
            Location: https://example.com/\r\n\
            Server: Apache\r\n\r\n";
        let info = parse_response(response).expect("valid HTTP");
        assert_eq!(info.status, Some(301));
        assert!(info.redirects_to_https);
        assert_eq!(info.location.as_deref(), Some("https://example.com/"));
    }

    #[test]
    fn a_plain_redirect_is_not_an_https_redirect() {
        let response = b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n";
        let info = parse_response(response).expect("valid HTTP");
        assert!(!info.redirects_to_https);
    }

    #[test]
    fn header_lookup_is_case_insensitive_and_trims() {
        let head = b"HTTP/1.0 200 OK\r\nSERVER:   lighttpd/1.4.76  \r\n\r\n";
        let info = parse_response(head).expect("valid HTTP");
        assert_eq!(info.server.as_deref(), Some("lighttpd/1.4.76"));
    }

    #[test]
    fn handles_lf_only_responses() {
        let response = b"HTTP/1.0 404 Not Found\nServer: tiny\n\n<title>Nope</title>";
        let info = parse_response(response).expect("valid HTTP");
        assert_eq!(info.status, Some(404));
        assert_eq!(info.server.as_deref(), Some("tiny"));
        assert_eq!(info.title.as_deref(), Some("Nope"));
    }

    #[test]
    fn non_http_is_rejected() {
        assert!(parse_response(b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
        assert!(parse_response(b"").is_none());
        assert!(parse_response(b"\x00\x01\x02\x03").is_none());
        assert!(parse_response(b"HTTP/1.1 20 OK\r\n\r\n").is_none());
    }

    #[test]
    fn titles_are_sanitised_and_bounded() {
        let mut response = b"HTTP/1.1 200 OK\r\n\r\n<title>".to_vec();
        response.extend(std::iter::repeat_n(b'A', 4096));
        response.extend_from_slice(b"</title>");
        let info = parse_response(&response).expect("valid HTTP");
        // The regex itself caps at 512 characters and sanitise caps at 128.
        assert!(info.title.map(|t| t.chars().count()).unwrap_or(0) <= 129);

        let hostile = b"HTTP/1.1 200 OK\r\n\r\n<title>a\x1b[2Jb</title>";
        let info = parse_response(hostile).expect("valid HTTP");
        assert_eq!(info.title.as_deref(), Some("a [2Jb"));
    }

    #[test]
    fn a_response_with_no_body_has_no_title() {
        let info = parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").expect("valid HTTP");
        assert_eq!(info.status, Some(204));
        assert!(info.title.is_none());
        assert!(info.server.is_none());
    }

    #[tokio::test]
    async fn round_trips_against_a_local_server() {
        use std::net::{Ipv4Addr, SocketAddr};
        use tokio::net::{TcpListener, TcpStream};

        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut discard = [0u8; 1024];
                let _ = socket.read(&mut discard).await;
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nServer: rscan-test/1.0\r\n\r\n<title>Hello</title>",
                    )
                    .await;
            }
        });

        let mut stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .expect("connect");
        let (info, raw) =
            probe(&mut stream, "127.0.0.1", Duration::from_secs(2)).await.expect("http detected");
        assert_eq!(info.status, Some(200));
        assert_eq!(info.server.as_deref(), Some("rscan-test/1.0"));
        assert_eq!(info.title.as_deref(), Some("Hello"));
        assert!(raw.starts_with(b"HTTP/1.1 200"));
    }
}
