//! Matching probe responses and extracting version information.

use regex::bytes::Captures;

use crate::model::ServiceInfo;
use crate::probe::db::{Probe, ProbeMatch};

/// Maximum length of any string lifted out of a response.
///
/// Banners are attacker-controlled input. Truncating keeps a hostile service
/// from turning a scan report into a megabyte of terminal escape sequences.
const MAX_FIELD_LEN: usize = 256;

/// Maximum length of the stored raw banner.
const MAX_BANNER_LEN: usize = 512;

/// Test `response` against every pattern of `probe`, best confidence first.
///
/// Returns `None` when nothing matched.
pub fn match_response(probe: &Probe, response: &[u8]) -> Option<ServiceInfo> {
    if response.is_empty() {
        return None;
    }
    let mut best: Option<(u8, ServiceInfo)> = None;
    for rule in &probe.matches {
        if let Some(info) = apply(rule, response) {
            let confidence = rule.confidence;
            if best.as_ref().is_none_or(|(c, _)| confidence > *c) {
                best = Some((confidence, info));
            }
        }
    }
    best.map(|(_, info)| info)
}

fn apply(rule: &ProbeMatch, response: &[u8]) -> Option<ServiceInfo> {
    let caps = rule.pattern.captures(response)?;
    Some(ServiceInfo {
        name: Some(rule.service.clone()),
        product: rule.product.as_deref().and_then(|t| expand(t, &caps)),
        version: rule.version.as_deref().and_then(|t| expand(t, &caps)),
        info: rule.info.as_deref().and_then(|t| expand(t, &caps)),
        confidence: Some(rule.confidence),
        banner: None,
        tls: None,
        http: None,
    })
}

/// Expand `$1`-style capture references in a template.
///
/// `$$` is a literal `$`. A reference to a group that did not participate in
/// the match makes the whole template yield `None`, because half-substituted
/// output like `"OpenSSH $2"` is worse than no output at all.
fn expand(template: &str, caps: &Captures<'_>) -> Option<String> {
    let bytes = template.as_bytes();
    let mut out = String::with_capacity(template.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            Some(b'$') => {
                out.push('$');
                i += 2;
            }
            Some(d @ b'1'..=b'9') => {
                let group = (d - b'0') as usize;
                let value = caps.get(group)?;
                out.push_str(&sanitise(value.as_bytes(), MAX_FIELD_LEN));
                i += 2;
            }
            _ => {
                out.push('$');
                i += 1;
            }
        }
    }
    let trimmed = out.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Turn arbitrary response bytes into a safe, bounded display string.
///
/// Control characters become spaces (so a banner cannot move the cursor or
/// change colours), invalid UTF-8 is replaced, and the result is truncated.
pub fn sanitise(bytes: &[u8], limit: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len().min(limit));
    for ch in text.chars() {
        if out.chars().count() >= limit {
            out.push('…');
            break;
        }
        if ch.is_control() {
            // Collapse runs of control characters into a single space.
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(ch);
        }
    }
    out.trim().to_string()
}

/// Render a raw banner for reporting.
pub fn banner_text(bytes: &[u8]) -> Option<String> {
    let text = sanitise(bytes, MAX_BANNER_LEN);
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Merge `extra` into `base`, keeping whichever fields are already populated.
pub fn merge_service(base: &mut ServiceInfo, extra: ServiceInfo) {
    let better = extra.confidence.unwrap_or(0) > base.confidence.unwrap_or(0);
    if extra.name.is_some() && (base.name.is_none() || better) {
        base.name = extra.name;
    }
    if extra.product.is_some() && (base.product.is_none() || better) {
        base.product = extra.product;
    }
    if extra.version.is_some() && base.version.is_none() {
        base.version = extra.version;
    }
    if extra.info.is_some() && base.info.is_none() {
        base.info = extra.info;
    }
    if extra.banner.is_some() && base.banner.is_none() {
        base.banner = extra.banner;
    }
    if extra.tls.is_some() {
        base.tls = extra.tls;
    }
    if extra.http.is_some() {
        base.http = extra.http;
    }
    base.confidence = Some(base.confidence.unwrap_or(0).max(extra.confidence.unwrap_or(0)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Protocol;
    use crate::probe::db::ProbeDb;

    fn probe(name: &str) -> &'static Probe {
        ProbeDb::embedded().probe(name).expect("probe exists in the embedded database")
    }

    #[test]
    fn ssh_banners_yield_product_and_protocol() {
        let info = match_response(probe("NULL"), b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
            .expect("ssh banner matches");
        assert_eq!(info.name.as_deref(), Some("ssh"));
        assert_eq!(info.product.as_deref(), Some("OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"));
        assert_eq!(info.info.as_deref(), Some("protocol 2.0"));
    }

    #[test]
    fn ftp_banners_match() {
        let info = match_response(probe("NULL"), b"220 ProFTPD 1.3.8 Server ready.\r\n")
            .expect("ftp banner matches");
        assert_eq!(info.name.as_deref(), Some("ftp"));
    }

    #[test]
    fn smtp_banners_match() {
        let info =
            match_response(probe("NULL"), b"220 mail.example.com ESMTP Postfix (Debian)\r\n")
                .expect("smtp banner matches");
        assert_eq!(info.name.as_deref(), Some("smtp"));
        assert_eq!(info.product.as_deref(), Some("Postfix (Debian)"));
    }

    #[test]
    fn mysql_handshakes_yield_a_version() {
        // 3-byte length, sequence 0, protocol 10, NUL-terminated version.
        let mut response = vec![0x4a, 0x00, 0x00, 0x00, 0x0a];
        response.extend_from_slice(b"8.0.36-0ubuntu0.22.04.1\x00");
        response.extend_from_slice(&[0u8; 20]);
        let info = match_response(probe("NULL"), &response).expect("mysql handshake matches");
        assert_eq!(info.name.as_deref(), Some("mysql"));
        assert_eq!(info.version.as_deref(), Some("8.0.36-0ubuntu0.22.04.1"));
    }

    #[test]
    fn vnc_and_telnet_banners_match() {
        let vnc = match_response(probe("NULL"), b"RFB 003.008\n").expect("vnc");
        assert_eq!(vnc.name.as_deref(), Some("vnc"));
        let telnet = match_response(probe("NULL"), b"\xff\xfd\x18\xff\xfd\x20").expect("telnet");
        assert_eq!(telnet.name.as_deref(), Some("telnet"));
    }

    #[test]
    fn http_responses_yield_the_server_header() {
        let response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n";
        let info = match_response(probe("GetRequest"), response).expect("http matches");
        assert_eq!(info.name.as_deref(), Some("http"));
        assert_eq!(info.product.as_deref(), Some("nginx/1.24.0"));
    }

    #[test]
    fn http_without_a_server_header_still_matches_with_lower_confidence() {
        let info = match_response(probe("GetRequest"), b"HTTP/1.0 404 Not Found\r\n\r\n")
            .expect("http matches");
        assert_eq!(info.name.as_deref(), Some("http"));
        assert!(info.product.is_none());
        assert_eq!(info.confidence, Some(8));
    }

    #[test]
    fn redis_answers_ping() {
        let info = match_response(probe("RedisPing"), b"+PONG\r\n").expect("redis matches");
        assert_eq!(info.name.as_deref(), Some("redis"));
        let authed = match_response(probe("RedisPing"), b"-NOAUTH Authentication required.\r\n")
            .expect("redis auth matches");
        assert_eq!(authed.name.as_deref(), Some("redis"));
    }

    #[test]
    fn rdp_and_smb_binary_responses_match() {
        let rdp = match_response(probe("RDPCookie"), b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00")
            .expect("rdp matches");
        assert_eq!(rdp.name.as_deref(), Some("ms-wbt-server"));

        let smb2 = match_response(probe("SMBNegotiate"), b"\x00\x00\x00\x44\xfeSMB\x40\x00")
            .expect("smb2 matches");
        assert_eq!(smb2.name.as_deref(), Some("smb"));

        let smb1 = match_response(probe("SMBNegotiate"), b"\x00\x00\x00\x44\xffSMB\x72\x00")
            .expect("smb1 matches");
        assert_eq!(smb1.name.as_deref(), Some("netbios-ssn"));
    }

    #[test]
    fn udp_probes_match_their_replies() {
        let dns = match_response(probe("DNSVersionBind"), b"\x124\x81\x80\x00\x01\x00\x01")
            .expect("dns matches");
        assert_eq!(dns.name.as_deref(), Some("domain"));

        let ntp = match_response(probe("NTPClient"), b"\x24\x02\x00\xe9").expect("ntp matches");
        assert_eq!(ntp.name.as_deref(), Some("ntp"));

        let nbns = match_response(probe("NetBIOSNodeStatus"), b"\x80\xf0\x84\x00\x00\x00")
            .expect("nbns matches");
        assert_eq!(nbns.name.as_deref(), Some("netbios-ns"));
    }

    #[test]
    fn unrelated_data_does_not_match() {
        assert!(match_response(probe("NULL"), b"just some bytes").is_none());
        assert!(match_response(probe("NULL"), b"").is_none());
        assert!(match_response(probe("RedisPing"), b"HTTP/1.1 200 OK\r\n\r\n").is_none());
    }

    #[test]
    fn the_highest_confidence_match_wins() {
        // This banner matches both the specific FTP rule (9) and the generic one (6).
        let info = match_response(probe("NULL"), b"220 vsFTPd 3.0.5 FTP server ready\r\n")
            .expect("ftp matches");
        assert_eq!(info.confidence, Some(9));
        assert!(info.product.is_some());
    }

    #[test]
    fn templates_expand_capture_groups() {
        let pattern = regex::bytes::Regex::new(r"v(\d+)\.(\d+)").expect("valid pattern");
        let caps = pattern.captures(b"v3.14").expect("matches");
        assert_eq!(expand("$1.$2", &caps).as_deref(), Some("3.14"));
        assert_eq!(expand("$$literal", &caps).as_deref(), Some("$literal"));
        assert_eq!(expand("cost: $", &caps).as_deref(), Some("cost: $"));
        // A reference to a group that does not exist yields nothing at all.
        assert_eq!(expand("$5", &caps), None);
    }

    #[test]
    fn extracted_fields_are_sanitised_and_bounded() {
        assert_eq!(sanitise(b"a\x1b[31mb", 100), "a [31mb");
        assert_eq!(sanitise(b"  padded  ", 100), "padded");
        assert_eq!(sanitise(b"", 100), "");
        let long = vec![b'x'; 10_000];
        let rendered = sanitise(&long, 64);
        assert!(rendered.chars().count() <= 65, "{}", rendered.chars().count());
    }

    #[test]
    fn a_hostile_banner_cannot_inject_escape_sequences() {
        let hostile = b"SSH-2.0-\x1b]0;pwned\x07\x1b[2J evil";
        let info = match_response(probe("NULL"), hostile).expect("still matches");
        let product = info.product.expect("has a product");
        assert!(!product.contains('\x1b'), "{product:?}");
        assert!(!product.contains('\x07'), "{product:?}");
    }

    #[test]
    fn merging_prefers_higher_confidence_and_fills_gaps() {
        let mut base =
            ServiceInfo { name: Some("http".into()), confidence: Some(5), ..Default::default() };
        merge_service(
            &mut base,
            ServiceInfo {
                name: Some("https".into()),
                product: Some("nginx".into()),
                confidence: Some(9),
                ..Default::default()
            },
        );
        assert_eq!(base.name.as_deref(), Some("https"));
        assert_eq!(base.product.as_deref(), Some("nginx"));
        assert_eq!(base.confidence, Some(9));

        // A weaker later match must not overwrite a stronger earlier one.
        merge_service(
            &mut base,
            ServiceInfo { name: Some("unknown".into()), confidence: Some(1), ..Default::default() },
        );
        assert_eq!(base.name.as_deref(), Some("https"));
    }

    #[test]
    fn every_embedded_pattern_is_exercised_against_noise_without_panicking() {
        let db = ProbeDb::embedded();
        let noise: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for probe in db.select(protocol, 80, 9) {
                let _ = match_response(probe, &noise);
                let _ = match_response(probe, b"");
            }
        }
    }
}
