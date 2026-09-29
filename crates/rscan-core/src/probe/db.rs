//! The probe database: parsing, escape decoding and pattern compilation.
//!
//! The shipped database lives in `data/probes.toml` and is embedded at compile
//! time. The format is documented in that file; this module is the reader.

use once_cell::sync::Lazy;
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::Protocol;

/// The embedded probe database source.
const PROBES_TOML: &str = include_str!("../../data/probes.toml");

/// Highest schema version this build understands.
const SUPPORTED_SCHEMA: u32 = 1;

/// A compiled probe: a payload plus the patterns its reply is tested against.
#[derive(Debug, Clone)]
pub struct Probe {
    /// Unique probe name.
    pub name: String,
    /// Transport this probe is sent over.
    pub protocol: Protocol,
    /// Decoded payload bytes. Empty means "connect and listen".
    pub payload: Vec<u8>,
    /// Rarity, 0..=9. Only run when `rarity <= intensity`.
    pub rarity: u8,
    /// Ports this probe is tried against before any others.
    pub ports: Vec<u16>,
    /// How long to wait for a reply.
    pub read_timeout: std::time::Duration,
    /// Patterns, in the order they are tried.
    pub matches: Vec<ProbeMatch>,
}

impl Probe {
    /// `true` when this probe just listens instead of sending anything.
    pub fn is_banner_grab(&self) -> bool {
        self.payload.is_empty()
    }

    /// `true` when this probe explicitly targets `port`.
    pub fn targets_port(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }
}

/// One pattern and the fields it fills in when it matches.
#[derive(Debug, Clone)]
pub struct ProbeMatch {
    /// Service name reported on a match.
    pub service: String,
    /// The compiled pattern, matched against raw response bytes.
    pub pattern: Regex,
    /// Product template, with `$1`-style capture references.
    pub product: Option<String>,
    /// Version template.
    pub version: Option<String>,
    /// Extra-information template.
    pub info: Option<String>,
    /// Confidence, 0..=10.
    pub confidence: u8,
}

/// A loaded, validated probe database.
#[derive(Debug, Clone)]
pub struct ProbeDb {
    schema_version: u32,
    probes: Vec<Probe>,
}

impl ProbeDb {
    /// Parse a database from TOML source.
    pub fn parse(source: &str) -> Result<Self> {
        let raw: RawDb =
            toml::from_str(source).map_err(|e| Error::ProbeDb(format!("invalid TOML: {e}")))?;

        if raw.version > SUPPORTED_SCHEMA {
            return Err(Error::ProbeDb(format!(
                "probe database schema version {} is newer than the supported {SUPPORTED_SCHEMA}",
                raw.version
            )));
        }

        let mut probes = Vec::with_capacity(raw.probe.len());
        let mut names: Vec<String> = Vec::with_capacity(raw.probe.len());
        for raw_probe in raw.probe {
            let name = raw_probe.name.clone();
            if names.contains(&name) {
                return Err(Error::ProbeDb(format!("duplicate probe name {name:?}")));
            }
            if raw_probe.rarity > 9 {
                return Err(Error::ProbeDb(format!("probe {name:?}: rarity must be 0..=9")));
            }
            if raw_probe.matches.is_empty() {
                return Err(Error::ProbeDb(format!("probe {name:?}: no match patterns")));
            }

            let protocol = match raw_probe.protocol.as_str() {
                "tcp" => Protocol::Tcp,
                "udp" => Protocol::Udp,
                other => {
                    return Err(Error::ProbeDb(format!(
                        "probe {name:?}: unknown protocol {other:?}"
                    )))
                }
            };

            let payload = decode_payload(&raw_probe.payload)
                .map_err(|e| Error::ProbeDb(format!("probe {name:?}: payload: {e}")))?;

            if protocol == Protocol::Udp && payload.is_empty() {
                return Err(Error::ProbeDb(format!(
                    "probe {name:?}: a UDP probe with an empty payload cannot elicit a reply"
                )));
            }

            let mut matches = Vec::with_capacity(raw_probe.matches.len());
            for raw_match in raw_probe.matches {
                if raw_match.confidence > 10 {
                    return Err(Error::ProbeDb(format!(
                        "probe {name:?}: confidence must be 0..=10"
                    )));
                }
                let pattern = compile_pattern(&raw_match.pattern).map_err(|e| {
                    Error::ProbeDb(format!("probe {name:?}: pattern {:?}: {e}", raw_match.pattern))
                })?;
                matches.push(ProbeMatch {
                    service: raw_match.service,
                    pattern,
                    product: raw_match.product,
                    version: raw_match.version,
                    info: raw_match.info,
                    confidence: raw_match.confidence,
                });
            }

            names.push(name);
            probes.push(Probe {
                name: raw_probe.name,
                protocol,
                payload,
                rarity: raw_probe.rarity,
                ports: raw_probe.ports,
                read_timeout: std::time::Duration::from_millis(raw_probe.read_timeout_ms),
                matches,
            });
        }

        Ok(Self { schema_version: raw.version, probes })
    }

    /// The database shipped with this build.
    ///
    /// Parsed once, lazily. A broken embedded database yields an empty one
    /// rather than a panic; the test suite makes sure that never ships.
    pub fn embedded() -> &'static ProbeDb {
        static DB: Lazy<ProbeDb> = Lazy::new(|| {
            ProbeDb::parse(PROBES_TOML).unwrap_or_else(|_| ProbeDb {
                schema_version: SUPPORTED_SCHEMA,
                probes: Vec::new(),
            })
        });
        &DB
    }

    /// Schema version of the loaded database.
    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Every probe in the database.
    pub fn probes(&self) -> &[Probe] {
        &self.probes
    }

    /// Look a probe up by name.
    pub fn probe(&self, name: &str) -> Option<&Probe> {
        self.probes.iter().find(|p| p.name == name)
    }

    /// Probes to run against `port`, best first.
    ///
    /// Ordering is: the banner grab (it costs nothing), then probes that name
    /// this port, then the rest by ascending rarity. Probes rarer than
    /// `intensity` are dropped.
    pub fn select(&self, protocol: Protocol, port: u16, intensity: u8) -> Vec<&Probe> {
        let mut selected: Vec<&Probe> = self
            .probes
            .iter()
            .filter(|p| p.protocol == protocol && p.rarity <= intensity)
            .collect();
        selected.sort_by_key(|p| {
            let tier = if p.is_banner_grab() {
                0
            } else if p.targets_port(port) {
                1
            } else {
                2
            };
            (tier, p.rarity, p.name.clone())
        });
        selected
    }
}

impl Default for ProbeDb {
    fn default() -> Self {
        ProbeDb::embedded().clone()
    }
}

fn compile_pattern(pattern: &str) -> std::result::Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        // Bytes mode with Unicode off: `.` is one byte and `\xNN` means that
        // byte, which is what a protocol pattern needs.
        .unicode(false)
        .dot_matches_new_line(false)
        .size_limit(1 << 20)
        .build()
}

/// Decode rscan's payload escape syntax into bytes.
///
/// Supported escapes: `\r`, `\n`, `\t`, `\0`, `\\` and `\xNN`. Any other
/// backslash sequence is an error, so a typo in the database is caught at load
/// time instead of silently sending the wrong bytes.
///
/// ```
/// use rscan_core::probe::db::decode_payload;
///
/// assert_eq!(decode_payload(r"GET /\r\n")?, b"GET /\r\n");
/// assert_eq!(decode_payload(r"\x00\xff")?, vec![0x00, 0xff]);
/// assert!(decode_payload(r"\q").is_err());
/// # Ok::<(), String>(())
/// ```
pub fn decode_payload(source: &str) -> std::result::Result<Vec<u8>, String> {
    let bytes = source.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let Some(&kind) = bytes.get(i + 1) else {
            return Err("trailing backslash".to_string());
        };
        match kind {
            b'r' => out.push(b'\r'),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'0' => out.push(0),
            b'\\' => out.push(b'\\'),
            b'x' => {
                let hi = bytes.get(i + 2).copied().ok_or("truncated \\x escape")?;
                let lo = bytes.get(i + 3).copied().ok_or("truncated \\x escape")?;
                let hi = hex_nibble(hi).ok_or_else(|| format!("bad hex digit {:?}", hi as char))?;
                let lo = hex_nibble(lo).ok_or_else(|| format!("bad hex digit {:?}", lo as char))?;
                out.push(hi << 4 | lo);
                i += 4;
                continue;
            }
            other => return Err(format!("unknown escape \\{}", other as char)),
        }
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---- serde shapes ---------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawDb {
    version: u32,
    #[serde(default)]
    probe: Vec<RawProbe>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProbe {
    name: String,
    protocol: String,
    payload: String,
    #[serde(default)]
    rarity: u8,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default = "default_read_timeout")]
    read_timeout_ms: u64,
    #[serde(rename = "match", default)]
    matches: Vec<RawMatch>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMatch {
    service: String,
    pattern: String,
    product: Option<String>,
    version: Option<String>,
    info: Option<String>,
    #[serde(default = "default_confidence")]
    confidence: u8,
}

fn default_read_timeout() -> u64 {
    2000
}

fn default_confidence() -> u8 {
    5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_database_parses() {
        let db = ProbeDb::parse(PROBES_TOML).expect("shipped probe database must be valid");
        assert_eq!(db.schema_version(), 1);
        assert!(db.probes().len() >= 15, "only {} probes", db.probes().len());
    }

    #[test]
    fn the_embedded_database_covers_the_required_services() {
        let db = ProbeDb::parse(PROBES_TOML).expect("valid");
        let services: Vec<&str> =
            db.probes().iter().flat_map(|p| p.matches.iter()).map(|m| m.service.as_str()).collect();
        for required in [
            "http",
            "ssh",
            "ftp",
            "smtp",
            "pop3",
            "imap",
            "mysql",
            "postgresql",
            "redis",
            "mongodb",
            "ms-wbt-server",
            "vnc",
            "smb",
            "telnet",
            "domain",
            "snmp",
            "ntp",
            "netbios-ns",
            "isakmp",
            "memcached",
            "mdns",
        ] {
            assert!(services.contains(&required), "no probe matches {required:?}");
        }
    }

    #[test]
    fn the_lazily_loaded_database_is_not_empty() {
        // Guards the `unwrap_or_else(empty)` fallback in `embedded()`.
        assert!(!ProbeDb::embedded().probes().is_empty());
    }

    #[test]
    fn a_banner_grab_probe_sends_nothing() {
        let db = ProbeDb::embedded();
        let null = db.probe("NULL").expect("the NULL probe exists");
        assert!(null.is_banner_grab());
        assert!(null.payload.is_empty());
    }

    #[test]
    fn selection_puts_the_banner_grab_first_then_port_specific_probes() {
        let db = ProbeDb::embedded();
        let selected = db.select(Protocol::Tcp, 6379, 9);
        assert_eq!(selected[0].name, "NULL");
        let redis_pos = selected.iter().position(|p| p.name == "RedisPing").expect("redis probe");
        let generic_pos =
            selected.iter().position(|p| p.name == "GenericLines").expect("generic probe");
        assert!(
            redis_pos < generic_pos,
            "a port-specific probe must be tried before a generic one"
        );
    }

    #[test]
    fn intensity_filters_rare_probes() {
        let db = ProbeDb::embedded();
        let low = db.select(Protocol::Tcp, 80, 1);
        let high = db.select(Protocol::Tcp, 80, 9);
        assert!(low.len() < high.len());
        assert!(low.iter().all(|p| p.rarity <= 1));
    }

    #[test]
    fn udp_and_tcp_probes_are_kept_apart() {
        let db = ProbeDb::embedded();
        assert!(db.select(Protocol::Udp, 53, 9).iter().all(|p| p.protocol == Protocol::Udp));
        assert!(db.select(Protocol::Tcp, 53, 9).iter().all(|p| p.protocol == Protocol::Tcp));
    }

    #[test]
    fn payload_escapes_decode() {
        assert_eq!(decode_payload("").expect("empty"), b"");
        assert_eq!(decode_payload(r"abc").expect("plain"), b"abc");
        assert_eq!(decode_payload(r"a\r\nb").expect("crlf"), b"a\r\nb");
        assert_eq!(decode_payload(r"\0\t").expect("nul tab"), vec![0, 9]);
        assert_eq!(decode_payload(r"\\").expect("backslash"), b"\\");
        assert_eq!(decode_payload(r"\x41\x62\xFF").expect("hex"), vec![0x41, 0x62, 0xff]);
    }

    #[test]
    fn malformed_payload_escapes_are_rejected() {
        for bad in [r"\", r"\q", r"\x", r"\x4", r"\xzz", r"\x4g", r"ab\"] {
            assert!(decode_payload(bad).is_err(), "{bad:?} should not decode");
        }
    }

    #[test]
    fn malformed_databases_are_rejected() {
        let cases = [
            ("not toml at all [[", "invalid TOML"),
            ("version = 999\n", "newer than"),
            ("version = 1\n[[probe]]\nname='a'\nprotocol='sctp'\npayload=''\n[[probe.match]]\nservice='x'\npattern='a'\n", "unknown protocol"),
            ("version = 1\n[[probe]]\nname='a'\nprotocol='tcp'\npayload='\\q'\n[[probe.match]]\nservice='x'\npattern='a'\n", "payload"),
            ("version = 1\n[[probe]]\nname='a'\nprotocol='tcp'\npayload=''\n[[probe.match]]\nservice='x'\npattern='('\n", "pattern"),
            ("version = 1\n[[probe]]\nname='a'\nprotocol='tcp'\npayload=''\nrarity=50\n[[probe.match]]\nservice='x'\npattern='a'\n", "rarity"),
            ("version = 1\n[[probe]]\nname='a'\nprotocol='tcp'\npayload=''\n", "no match patterns"),
            ("version = 1\n[[probe]]\nname='a'\nprotocol='udp'\npayload=''\n[[probe.match]]\nservice='x'\npattern='a'\n", "cannot elicit"),
        ];
        for (source, expected) in cases {
            let err = ProbeDb::parse(source).expect_err(&format!("{source:?} should be rejected"));
            let message = err.to_string();
            assert!(message.contains(expected), "{message:?} should mention {expected:?}");
        }
    }

    #[test]
    fn duplicate_probe_names_are_rejected() {
        let source = "version = 1\n\
            [[probe]]\nname='dup'\nprotocol='tcp'\npayload=''\n[[probe.match]]\nservice='x'\npattern='a'\n\
            [[probe]]\nname='dup'\nprotocol='tcp'\npayload=''\n[[probe.match]]\nservice='y'\npattern='b'\n";
        assert!(ProbeDb::parse(source).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let source = "version = 1\n[[probe]]\nname='a'\nprotocol='tcp'\npayload=''\nwhoops=1\n\
            [[probe.match]]\nservice='x'\npattern='a'\n";
        assert!(ProbeDb::parse(source).is_err(), "a typo in a field name must not be ignored");
    }

    #[test]
    fn an_empty_database_is_valid_but_useless() {
        let db = ProbeDb::parse("version = 1\n").expect("valid");
        assert!(db.probes().is_empty());
        assert!(db.select(Protocol::Tcp, 80, 9).is_empty());
    }
}
