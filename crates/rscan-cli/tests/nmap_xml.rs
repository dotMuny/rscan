//! nmap-XML output validated against nmap's DTD.
//!
//! The first half of this file is a minimal DTD validator; the second half
//! feeds real scan output through it.
//!
//! # Why a hand-written validator
//!
//! There is no pure-Rust validating XML parser on crates.io, and shelling out
//! to `xmllint` would make the test depend on whatever happens to be installed
//! on the machine. So this module implements the part of DTD validation that
//! the check actually needs:
//!
//! - element content models (`(a, b*, c?)`, `EMPTY`, `(#PCDATA)`, choices),
//!   compiled into a regular expression over the child element sequence;
//! - attribute declarations: `#REQUIRED` presence, unknown-attribute
//!   rejection, and enumerated value checking.
//!
//! It does not implement entities, parameter entities, notations or IDs,
//! because `data/nmap.dtd` does not use them.
//!
//! Enumerations are split on `" | "` — space, pipe, space — rather than on a
//! bare pipe, because nmap's own DTD writes `open|filtered` as a single value.

use std::collections::BTreeMap;

use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use regex::Regex;

/// A parsed element declaration.
#[derive(Debug, Clone)]
pub struct ElementDecl {
    /// Element name.
    pub name: String,
    /// The content model exactly as written in the DTD.
    pub model: String,
    /// Regular expression over the `child;child;` sequence, or `None` for
    /// `EMPTY`, `ANY` and `(#PCDATA)`.
    pub children: Option<Regex>,
    /// `true` for `EMPTY`.
    pub empty: bool,
    /// `true` when the model permits character data.
    pub pcdata: bool,
}

/// A parsed attribute declaration.
#[derive(Debug, Clone)]
pub struct AttrDecl {
    /// Attribute name.
    pub name: String,
    /// Permitted values, when the declaration was an enumeration.
    pub values: Option<Vec<String>>,
    /// `true` for `#REQUIRED`.
    pub required: bool,
}

/// A DTD, reduced to what this validator understands.
#[derive(Debug, Default)]
pub struct Dtd {
    elements: BTreeMap<String, ElementDecl>,
    attributes: BTreeMap<String, Vec<AttrDecl>>,
}

impl Dtd {
    /// Parse a DTD document.
    pub fn parse(source: &str) -> Result<Self, String> {
        let source = strip_comments(source);
        let mut dtd = Dtd::default();

        for declaration in split_declarations(&source) {
            let trimmed = declaration.trim();
            if let Some(rest) = trimmed.strip_prefix("<!ELEMENT") {
                dtd.parse_element(rest.trim_end_matches('>').trim())?;
            } else if let Some(rest) = trimmed.strip_prefix("<!ATTLIST") {
                dtd.parse_attlist(rest.trim_end_matches('>').trim())?;
            }
        }

        if dtd.elements.is_empty() {
            return Err("the DTD declared no elements".to_string());
        }
        Ok(dtd)
    }

    fn parse_element(&mut self, body: &str) -> Result<(), String> {
        let mut parts = body.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or_default().trim().to_string();
        let model = parts.next().unwrap_or("EMPTY").trim().to_string();
        if name.is_empty() {
            return Err(format!("unnamed element declaration: {body:?}"));
        }

        let normalised: String = model.split_whitespace().collect::<Vec<_>>().join(" ");
        let empty = normalised == "EMPTY";
        let pcdata = normalised.contains("#PCDATA");
        let children = if empty || pcdata || normalised == "ANY" {
            None
        } else {
            Some(compile_model(&normalised).map_err(|e| format!("{name}: {e}"))?)
        };

        self.elements
            .insert(name.clone(), ElementDecl { name, model: normalised, children, empty, pcdata });
        Ok(())
    }

    fn parse_attlist(&mut self, body: &str) -> Result<(), String> {
        let mut tokens = tokenise_attlist(body);
        if tokens.is_empty() {
            return Err(format!("empty ATTLIST: {body:?}"));
        }
        let element = tokens.remove(0);

        let mut declarations = Vec::new();
        let mut index = 0;
        while index + 2 < tokens.len() + 1 {
            let Some(name) = tokens.get(index) else { break };
            let Some(kind) = tokens.get(index + 1) else {
                return Err(format!("attribute {name} has no type"));
            };
            let Some(default) = tokens.get(index + 2) else {
                return Err(format!("attribute {name} has no default declaration"));
            };

            let values = if kind.starts_with('(') {
                Some(
                    kind.trim_matches(['(', ')'].as_slice())
                        .split(" | ")
                        .map(|v| v.trim().to_string())
                        .filter(|v| !v.is_empty())
                        .collect(),
                )
            } else {
                None
            };

            declarations.push(AttrDecl {
                name: name.clone(),
                values,
                required: default == "#REQUIRED",
            });
            index += 3;
        }

        self.attributes.entry(element).or_default().extend(declarations);
        Ok(())
    }

    /// Validate an XML document against this DTD.
    ///
    /// Returns every problem found, so a failing test reports all of them at
    /// once rather than one per run.
    pub fn validate(&self, xml: &str, root: &str) -> Vec<String> {
        let mut errors = Vec::new();
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        // Stack of (element name, accumulated child sequence, saw text).
        let mut stack: Vec<(String, String, bool)> = Vec::new();
        let mut saw_root = false;

        loop {
            match reader.read_event() {
                Err(err) => {
                    errors.push(format!("not well-formed XML: {err}"));
                    break;
                }
                Ok(Event::Eof) => break,
                Ok(Event::Start(start)) => {
                    let name = local_name(start.name().as_ref());
                    self.check_open(&name, &start, &mut stack, &mut saw_root, root, &mut errors);
                    stack.push((name, String::new(), false));
                }
                Ok(Event::Empty(start)) => {
                    let name = local_name(start.name().as_ref());
                    self.check_open(&name, &start, &mut stack, &mut saw_root, root, &mut errors);
                    // An empty-element tag closes immediately with no children.
                    if let Some(decl) = self.elements.get(&name) {
                        if let Some(pattern) = &decl.children {
                            if !pattern.is_match("") {
                                errors.push(format!(
                                    "<{name}/> is empty but its content model is {}",
                                    decl.model
                                ));
                            }
                        }
                    }
                }
                Ok(Event::End(end)) => {
                    let name = local_name(end.name().as_ref());
                    match stack.pop() {
                        Some((open, children, saw_text)) if open == name => {
                            self.check_close(&name, &children, saw_text, &mut errors);
                        }
                        Some((open, _, _)) => {
                            errors.push(format!("</{name}> closes <{open}>"));
                        }
                        None => errors.push(format!("</{name}> with no matching open tag")),
                    }
                }
                Ok(Event::Text(text)) => {
                    let bytes: &[u8] = &text;
                    if !bytes.iter().all(|b| b.is_ascii_whitespace()) {
                        if let Some(top) = stack.last_mut() {
                            top.2 = true;
                        }
                    }
                }
                _ => {}
            }
        }

        if !stack.is_empty() {
            errors.push(format!(
                "unclosed elements: {:?}",
                stack.iter().map(|s| &s.0).collect::<Vec<_>>()
            ));
        }
        if !saw_root {
            errors.push(format!("the document has no <{root}> root element"));
        }
        errors
    }

    fn check_open(
        &self,
        name: &str,
        start: &quick_xml::events::BytesStart<'_>,
        stack: &mut [(String, String, bool)],
        saw_root: &mut bool,
        root: &str,
        errors: &mut Vec<String>,
    ) {
        if stack.is_empty() {
            if name == root {
                *saw_root = true;
            } else {
                errors.push(format!("root element is <{name}>, expected <{root}>"));
            }
        }
        if let Some(parent) = stack.last_mut() {
            parent.1.push_str(name);
            parent.1.push(';');
        }

        let Some(_decl) = self.elements.get(name) else {
            errors.push(format!("<{name}> is not declared in the DTD"));
            return;
        };
        self.check_attributes(name, start, errors);
    }

    fn check_attributes(
        &self,
        name: &str,
        start: &quick_xml::events::BytesStart<'_>,
        errors: &mut Vec<String>,
    ) {
        let declared = self.attributes.get(name);
        let mut present: BTreeMap<String, String> = BTreeMap::new();

        for attribute in start.attributes() {
            let Ok(attribute) = attribute else {
                errors.push(format!("<{name}> has a malformed attribute"));
                continue;
            };
            let key = local_name(attribute.key.as_ref());
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map(|v| v.into_owned())
                .unwrap_or_else(|_| String::from_utf8_lossy(&attribute.value).into_owned());
            present.insert(key, value);
        }

        let Some(declared) = declared else {
            if !present.is_empty() {
                errors.push(format!("<{name}> has attributes but none are declared"));
            }
            return;
        };

        for (key, value) in &present {
            let Some(decl) = declared.iter().find(|d| &d.name == key) else {
                errors.push(format!("<{name}> has undeclared attribute {key:?}"));
                continue;
            };
            if let Some(values) = &decl.values {
                if !values.iter().any(|v| v == value) {
                    errors.push(format!("<{name} {key}={value:?}> is not one of {values:?}"));
                }
            }
        }

        for decl in declared.iter().filter(|d| d.required) {
            if !present.contains_key(&decl.name) {
                errors.push(format!("<{name}> is missing required attribute {:?}", decl.name));
            }
        }
    }

    fn check_close(&self, name: &str, children: &str, saw_text: bool, errors: &mut Vec<String>) {
        let Some(decl) = self.elements.get(name) else {
            return;
        };
        if decl.empty && (!children.is_empty() || saw_text) {
            errors.push(format!("<{name}> is declared EMPTY but has content"));
            return;
        }
        if saw_text && !decl.pcdata && !decl.empty {
            errors.push(format!("<{name}> contains text but its model {} forbids it", decl.model));
        }
        if let Some(pattern) = &decl.children {
            if !pattern.is_match(children) {
                errors.push(format!(
                    "<{name}> children {children:?} do not match content model {}",
                    decl.model
                ));
            }
        }
    }
}

fn local_name(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    text.rsplit(':').next().unwrap_or(&text).to_string()
}

fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("<!--") {
        out.push_str(&rest[..start]);
        match rest[start..].find("-->") {
            Some(end) => rest = &rest[start + end + 3..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Split a DTD into `<!...>` declarations, respecting quotes and nesting.
fn split_declarations(source: &str) -> Vec<String> {
    let mut declarations = Vec::new();
    let bytes = source.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'<' {
            index += 1;
            continue;
        }
        let start = index;
        let mut depth = 0usize;
        let mut quote: Option<u8> = None;
        while index < bytes.len() {
            let byte = bytes[index];
            match quote {
                Some(q) if byte == q => quote = None,
                Some(_) => {}
                None => match byte {
                    b'"' | b'\'' => quote = Some(byte),
                    b'(' => depth += 1,
                    b')' => depth = depth.saturating_sub(1),
                    b'>' if depth == 0 => {
                        index += 1;
                        declarations.push(source[start..index].to_string());
                        break;
                    }
                    _ => {}
                },
            }
            index += 1;
        }
    }
    declarations
}

/// Split an ATTLIST body into tokens, keeping parenthesised groups whole.
fn tokenise_attlist(body: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut depth = 0usize;
    for ch in body.chars() {
        match ch {
            '(' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                depth = depth.saturating_sub(1);
                current.push(ch);
            }
            c if c.is_whitespace() && depth == 0 => {
                if !current.is_empty() {
                    tokens.push(normalise_group(&current));
                    current.clear();
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(normalise_group(&current));
    }
    tokens
}

/// Collapse whitespace runs inside a parenthesised group so that `" | "`
/// separators are uniform regardless of how the DTD was laid out.
///
/// Crucially this does **not** re-split on `|`: nmap writes `open|filtered`
/// with no surrounding spaces to mean one value, and that distinction is the
/// only thing telling it apart from two separate values.
fn normalise_group(token: &str) -> String {
    if !token.starts_with('(') {
        return token.to_string();
    }
    let inner = token.trim_matches(['(', ')'].as_slice());
    format!("({})", inner.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Compile a content model into a regular expression over `child;child;`.
fn compile_model(model: &str) -> Result<Regex, String> {
    let mut pattern = String::from("^");
    let mut name = String::new();

    let flush = |name: &mut String, pattern: &mut String| {
        if !name.is_empty() {
            pattern.push_str("(?:");
            pattern.push_str(&regex::escape(name));
            pattern.push_str(";)");
            name.clear();
        }
    };

    for ch in model.chars() {
        match ch {
            '(' => {
                flush(&mut name, &mut pattern);
                pattern.push_str("(?:");
            }
            ')' => {
                flush(&mut name, &mut pattern);
                pattern.push(')');
            }
            ',' => {
                flush(&mut name, &mut pattern);
            }
            '|' => {
                flush(&mut name, &mut pattern);
                pattern.push('|');
            }
            '*' | '+' | '?' => {
                flush(&mut name, &mut pattern);
                pattern.push(ch);
            }
            c if c.is_whitespace() => {
                flush(&mut name, &mut pattern);
            }
            c => name.push(c),
        }
    }
    flush(&mut name, &mut pattern);
    pattern.push('$');

    Regex::new(&pattern).map_err(|e| format!("content model {model:?} -> {pattern:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        <!-- a comment -->
        <!ELEMENT root (a, b*, c?)>
        <!ATTLIST root
            id    CDATA              #REQUIRED
            kind  (one | two)        #IMPLIED
        >
        <!ELEMENT a EMPTY>
        <!ELEMENT b EMPTY>
        <!ELEMENT c (#PCDATA)>
    "#;

    fn dtd() -> Dtd {
        Dtd::parse(SAMPLE).expect("sample DTD parses")
    }

    #[test]
    fn a_conforming_document_validates() {
        let errors = dtd().validate(r#"<root id="x"><a/><b/><b/><c>text</c></root>"#, "root");
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn a_minimal_document_validates() {
        assert!(dtd().validate(r#"<root id="x"><a/></root>"#, "root").is_empty());
    }

    #[test]
    fn missing_required_attributes_are_caught() {
        let errors = dtd().validate("<root><a/></root>", "root");
        assert!(errors.iter().any(|e| e.contains("missing required attribute")), "{errors:?}");
    }

    #[test]
    fn undeclared_attributes_are_caught() {
        let errors = dtd().validate(r#"<root id="x" bogus="1"><a/></root>"#, "root");
        assert!(errors.iter().any(|e| e.contains("undeclared attribute")), "{errors:?}");
    }

    #[test]
    fn bad_enumerated_values_are_caught() {
        let errors = dtd().validate(r#"<root id="x" kind="three"><a/></root>"#, "root");
        assert!(errors.iter().any(|e| e.contains("not one of")), "{errors:?}");
        assert!(dtd().validate(r#"<root id="x" kind="two"><a/></root>"#, "root").is_empty());
    }

    #[test]
    fn content_model_violations_are_caught() {
        // `a` is required.
        let errors = dtd().validate(r#"<root id="x"><b/></root>"#, "root");
        assert!(errors.iter().any(|e| e.contains("content model")), "{errors:?}");
        // `c` may appear at most once.
        let errors = dtd().validate(r#"<root id="x"><a/><c/><c/></root>"#, "root");
        assert!(errors.iter().any(|e| e.contains("content model")), "{errors:?}");
        // Order matters.
        let errors = dtd().validate(r#"<root id="x"><b/><a/></root>"#, "root");
        assert!(errors.iter().any(|e| e.contains("content model")), "{errors:?}");
    }

    #[test]
    fn empty_elements_may_not_have_content() {
        let errors = dtd().validate(r#"<root id="x"><a>oops</a></root>"#, "root");
        assert!(errors.iter().any(|e| e.contains("EMPTY")), "{errors:?}");
    }

    #[test]
    fn undeclared_elements_are_caught() {
        let errors = dtd().validate(r#"<root id="x"><a/><zzz/></root>"#, "root");
        assert!(errors.iter().any(|e| e.contains("not declared")), "{errors:?}");
    }

    #[test]
    fn a_wrong_root_is_caught() {
        let errors = dtd().validate("<a/>", "root");
        assert!(errors.iter().any(|e| e.contains("root element")), "{errors:?}");
    }

    #[test]
    fn values_containing_a_bare_pipe_survive_enumeration_parsing() {
        let source = r#"
            <!ELEMENT s EMPTY>
            <!ATTLIST s state (open | closed | open|filtered) #REQUIRED>
        "#;
        let dtd = Dtd::parse(source).expect("parses");
        assert!(dtd.validate(r#"<s state="open|filtered"/>"#, "s").is_empty());
        assert!(dtd.validate(r#"<s state="open"/>"#, "s").is_empty());
        assert!(!dtd.validate(r#"<s state="banana"/>"#, "s").is_empty());
    }

    #[test]
    fn the_shipped_nmap_dtd_parses() {
        let source = include_str!("../data/nmap.dtd");
        let dtd = Dtd::parse(source).expect("the vendored nmap DTD must parse");
        assert!(dtd.elements.contains_key("nmaprun"));
        assert!(dtd.elements.contains_key("port"));
        assert!(dtd.attributes.contains_key("state"));
    }
}

// ---------------------------------------------------------------------------
// The actual acceptance test: rscan's nmap-XML output validates.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod output_validates {
    use super::Dtd;

    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use futures::StreamExt;
    use rscan_cli::output::xml::XmlSink;
    use rscan_cli::output::{ScanMeta, Sink};
    use rscan_core::config::ServiceDetection;
    use rscan_core::ports::PortSpec;
    use rscan_core::target::{TargetSet, TargetSpec};
    use rscan_core::{
        DiscoveryMethod, HostStatus, HttpInfo, PortResult, PortState, Protocol, Reason, ScanConfig,
        ScanEvent, ScanSummary, Scanner, ServiceInfo, TlsInfo,
    };
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    const NMAP_DTD: &str = include_str!("../data/nmap.dtd");

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("lock").extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn meta() -> ScanMeta {
        ScanMeta {
            command_line: "rscan -p 1-100 -s 192.0.2.0/30".into(),
            started_at: "2026-09-24T10:00:00.000Z".into(),
            started_unix: 1_790_244_000,
            mode: "connect".into(),
            hosts_total: 4,
            probes_total: 400,
            tcp_ports: (1..=100).collect(),
            udp_ports: vec![53, 161],
            version: "0.1.0".into(),
        }
    }

    fn summary() -> ScanSummary {
        ScanSummary {
            hosts_total: 4,
            hosts_up: 2,
            ports_scanned: 400,
            ports_open: 3,
            ports_closed: 390,
            ports_filtered: 7,
            packets_sent: 412,
            elapsed: Duration::from_millis(4321),
            final_concurrency: 128,
            final_rate_pps: 900.0,
        }
    }

    fn assert_valid(xml: &str) {
        let dtd = Dtd::parse(NMAP_DTD).expect("the vendored nmap DTD parses");
        let errors = dtd.validate(xml, "nmaprun");
        assert!(
            errors.is_empty(),
            "XML failed DTD validation:\n  {}\n\n{xml}",
            errors.join("\n  ")
        );
    }

    /// Every port state, service shape and address family the scanner can
    /// produce, in one document.
    #[test]
    fn a_document_covering_every_feature_validates() {
        let buffer = Buffer::default();
        let mut sink = XmlSink::new(Box::new(buffer.clone()));
        sink.start(&meta()).expect("start");

        sink.host_up(&HostStatus {
            addr: "192.0.2.1".parse().expect("literal"),
            hostname: Some("host-one.example.com".into()),
            up: true,
            method: DiscoveryMethod::IcmpEcho,
            rtt: Some(Duration::from_micros(800)),
        })
        .expect("host up");

        sink.host_down(&HostStatus {
            addr: "192.0.2.2".parse().expect("literal"),
            hostname: None,
            up: false,
            method: DiscoveryMethod::TcpConnect,
            rtt: None,
        })
        .expect("host down");

        sink.host_up(&HostStatus {
            addr: "2001:db8::1".parse().expect("literal"),
            hostname: None,
            up: true,
            method: DiscoveryMethod::Arp,
            rtt: Some(Duration::from_micros(300)),
        })
        .expect("host up");

        let base = |port, state, reason| PortResult {
            addr: "192.0.2.1".parse().expect("literal"),
            hostname: Some("host-one.example.com".into()),
            port,
            protocol: Protocol::Tcp,
            state,
            reason,
            rtt: Some(Duration::from_micros(1500)),
            attempts: 1,
            service: None,
        };

        // Open with a fully populated service, including nasty characters.
        let mut ssh = base(22, PortState::Open, Reason::SynAck);
        ssh.service = Some(ServiceInfo {
            name: Some("ssh".into()),
            product: Some("OpenSSH <\"weird\" & 'quoted'>".into()),
            version: Some("9.6p1".into()),
            info: Some("Ubuntu \u{1}control\u{7}".into()),
            confidence: Some(10),
            banner: Some("SSH-2.0-OpenSSH_9.6p1".into()),
            tls: None,
            http: None,
        });
        sink.port(&ssh).expect("port");

        // Open behind TLS, with HTTP details.
        let mut https = base(443, PortState::Open, Reason::SynAck);
        https.service = Some(ServiceInfo {
            name: Some("https".into()),
            product: Some("nginx".into()),
            confidence: Some(10),
            tls: Some(TlsInfo {
                version: Some("TLSv1_3".into()),
                alpn: Some("h2".into()),
                subject_cn: Some("*.example.com".into()),
                issuer_cn: Some("Example CA".into()),
                sans: vec!["example.com".into()],
                not_before: None,
                not_after: None,
            }),
            http: Some(HttpInfo {
                status: Some(200),
                server: Some("nginx/1.24.0".into()),
                title: Some("Home & <away>".into()),
                location: None,
                redirects_to_https: false,
            }),
            ..Default::default()
        });
        sink.port(&https).expect("port");

        // Closed, filtered and open|filtered all have to round-trip.
        sink.port(&base(25, PortState::Closed, Reason::ConnRefused)).expect("port");
        sink.port(&base(139, PortState::Filtered, Reason::NoResponse)).expect("port");

        let mut udp = base(53, PortState::OpenFiltered, Reason::NoResponse);
        udp.protocol = Protocol::Udp;
        sink.port(&udp).expect("port");

        let mut unfiltered = base(80, PortState::Unfiltered, Reason::Reset);
        unfiltered.service = Some(ServiceInfo {
            name: Some("http".into()),
            confidence: Some(1),
            ..Default::default()
        });
        sink.port(&unfiltered).expect("port");

        // A port on the IPv6 host, with no hostname.
        let mut v6 = base(22, PortState::Open, Reason::SynAck);
        v6.addr = "2001:db8::1".parse().expect("literal");
        v6.hostname = None;
        sink.port(&v6).expect("port");

        sink.finish(&summary()).expect("finish");

        let xml = buffer.contents();
        assert_valid(&xml);
        assert!(xml.contains(r#"state="open|filtered""#), "{xml}");
        assert!(xml.contains(r#"addrtype="ipv6""#), "{xml}");
        assert!(xml.contains(r#"tunnel="ssl""#), "{xml}");
        assert!(!xml.contains('\u{1}'), "control characters must not reach the document");
    }

    /// A scan with nothing to report still produces a valid document.
    #[test]
    fn an_empty_document_validates() {
        let buffer = Buffer::default();
        let mut sink = XmlSink::new(Box::new(buffer.clone()));
        sink.start(&meta()).expect("start");
        sink.finish(&ScanSummary::default()).expect("finish");
        assert_valid(&buffer.contents());
    }

    /// End to end: run a real scan against real listeners and validate what
    /// comes out.
    #[tokio::test]
    async fn output_from_a_real_scan_validates() {
        let mut listeners = Vec::new();
        let mut ports = Vec::new();
        for _ in 0..3 {
            let listener =
                TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
            ports.push(listener.local_addr().expect("addr").port());
            listeners.push(listener);
        }
        // One of them talks, so service detection has something to report.
        let talker = listeners.pop().expect("a listener");
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = talker.accept().await {
                let _ = socket.write_all(b"220 mail.example.com ESMTP Postfix\r\n").await;
                let _ = socket.flush().await;
            }
        });

        // Plus a port that is definitely closed.
        let spare =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let closed = spare.local_addr().expect("addr").port();
        drop(spare);
        ports.push(closed);

        let mut targets = TargetSet::new();
        targets.add(TargetSpec::parse("127.0.0.1").expect("literal"));
        let spec = ports.iter().map(u16::to_string).collect::<Vec<_>>().join(",");
        let config = ScanConfig::builder()
            .targets(targets)
            .ports(PortSpec::parse(&spec).expect("literal"))
            .skip_discovery(true)
            .retries(0)
            .fixed_timeout(Duration::from_millis(500))
            .report_all_states(true)
            .service_detection(ServiceDetection {
                timeout: Duration::from_secs(2),
                ..ServiceDetection::all()
            })
            .build()
            .expect("valid");

        let scanner = Scanner::new(config).await.expect("scanner");
        let buffer = Buffer::default();
        let mut sink = XmlSink::new(Box::new(buffer.clone()));
        sink.start(&meta()).expect("start");

        let mut events = Box::pin(scanner.run());
        while let Some(event) = events.next().await {
            match event {
                ScanEvent::HostUp(status) => sink.host_up(&status).expect("host"),
                ScanEvent::HostDown(status) => sink.host_down(&status).expect("host"),
                ScanEvent::Port(result) => sink.port(&result).expect("port"),
                ScanEvent::Finished(done) => {
                    sink.finish(&done).expect("finish");
                    break;
                }
                _ => {}
            }
        }

        let xml = buffer.contents();
        assert_valid(&xml);
        assert!(xml.contains("<service "), "service detection produced nothing:\n{xml}");
    }
}
