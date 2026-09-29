//! Resume state.
//!
//! A scan of a large range takes long enough that it will eventually be
//! interrupted — a dropped SSH session, a laptop lid, a deploy. Without resume,
//! the only options are to start again or to accept partial results, and on a
//! `/16` both are bad.
//!
//! The state file records which `(host, protocol, port)` probes have already
//! been completed, as **merged ranges** rather than one entry per port: a
//! finished `/24` at 65535 ports each is 16 million probes, which as individual
//! entries would be a state file larger than the scan. As ranges it is a few
//! kilobytes.
//!
//! Writes are atomic (write to a sibling temporary file, then rename), so a
//! crash mid-checkpoint leaves the previous good state rather than a truncated
//! file.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ScanConfig;
use crate::error::{Error, Result};
use crate::model::{PortResult, Protocol};

/// Version of the state file format.
pub const STATE_VERSION: u32 = 1;

/// A set of ports stored as merged inclusive ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PortRanges {
    ranges: Vec<(u16, u16)>,
}

impl PortRanges {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a port, merging with any adjacent range.
    pub fn insert(&mut self, port: u16) {
        match self.ranges.binary_search_by(|(lo, hi)| {
            if port < *lo {
                std::cmp::Ordering::Greater
            } else if port > *hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(_) => {}
            Err(index) => {
                self.ranges.insert(index, (port, port));
                self.merge_around(index);
            }
        }
    }

    fn merge_around(&mut self, index: usize) {
        // Merge with the following range first so indices stay valid.
        if index + 1 < self.ranges.len() {
            let (lo, hi) = self.ranges[index];
            let (next_lo, next_hi) = self.ranges[index + 1];
            if hi.saturating_add(1) >= next_lo {
                self.ranges[index] = (lo, hi.max(next_hi));
                self.ranges.remove(index + 1);
            }
        }
        if index > 0 {
            let (prev_lo, prev_hi) = self.ranges[index - 1];
            let (lo, hi) = self.ranges[index];
            if prev_hi.saturating_add(1) >= lo {
                self.ranges[index - 1] = (prev_lo, prev_hi.max(hi));
                self.ranges.remove(index);
            }
        }
    }

    /// `true` when `port` is in the set.
    pub fn contains(&self, port: u16) -> bool {
        self.ranges
            .binary_search_by(|(lo, hi)| {
                if port < *lo {
                    std::cmp::Ordering::Greater
                } else if port > *hi {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Number of ports in the set.
    pub fn len(&self) -> usize {
        self.ranges.iter().map(|(lo, hi)| (*hi as usize) - (*lo as usize) + 1).sum()
    }

    /// `true` when nothing has been inserted.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The merged ranges, for inspection and tests.
    pub fn ranges(&self) -> &[(u16, u16)] {
        &self.ranges
    }
}

/// Per-host record of what has been probed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProgress {
    /// TCP ports already probed.
    #[serde(default, skip_serializing_if = "PortRanges::is_empty")]
    pub tcp: PortRanges,
    /// UDP ports already probed.
    #[serde(default, skip_serializing_if = "PortRanges::is_empty")]
    pub udp: PortRanges,
    /// `true` once host discovery has run for this address.
    #[serde(default)]
    pub discovered: bool,
    /// Result of that discovery.
    #[serde(default)]
    pub up: bool,
}

/// The contents of a resume file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanState {
    /// Format version.
    pub version: u32,
    /// Fingerprint of the configuration this state belongs to.
    ///
    /// Resuming with a different target or port list would silently produce a
    /// wrong answer, so a mismatch is refused.
    pub fingerprint: String,
    /// RFC 3339 time the original scan started.
    pub started_at: String,
    /// RFC 3339 time of the last checkpoint.
    pub updated_at: String,
    /// Probes completed, per host.
    pub hosts: BTreeMap<String, HostProgress>,
    /// Results worth keeping, so a resumed scan can still report everything.
    #[serde(default)]
    pub results: Vec<PortResult>,
    /// Probes completed in total, across all runs.
    #[serde(default)]
    pub probes_completed: u64,
    /// Probes transmitted in total, retransmissions included.
    #[serde(default)]
    pub packets_sent: u64,
}

impl ScanState {
    /// A fresh state for a configuration.
    pub fn new(fingerprint: String) -> Self {
        let now = now_rfc3339();
        Self {
            version: STATE_VERSION,
            fingerprint,
            started_at: now.clone(),
            updated_at: now,
            hosts: BTreeMap::new(),
            results: Vec::new(),
            probes_completed: 0,
            packets_sent: 0,
        }
    }

    /// Read a state file.
    pub async fn load(path: &Path) -> Result<Self> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|e| Error::State(format!("cannot read {}: {e}", path.display())))?;
        let state: ScanState = serde_json::from_slice(&bytes).map_err(|e| {
            Error::State(format!("{} is not a valid state file: {e}", path.display()))
        })?;
        if state.version != STATE_VERSION {
            return Err(Error::State(format!(
                "state file version {} is not supported (this build writes version {STATE_VERSION})",
                state.version
            )));
        }
        Ok(state)
    }

    /// Write the state file atomically.
    pub async fn save(&self, path: &Path) -> Result<()> {
        let mut state = self.clone();
        state.updated_at = now_rfc3339();
        let json = serde_json::to_vec_pretty(&state)
            .map_err(|e| Error::State(format!("cannot serialise state: {e}")))?;

        let temporary = temporary_path(path);
        tokio::fs::write(&temporary, &json)
            .await
            .map_err(|e| Error::State(format!("cannot write {}: {e}", temporary.display())))?;
        tokio::fs::rename(&temporary, path)
            .await
            .map_err(|e| Error::State(format!("cannot replace {}: {e}", path.display())))?;
        Ok(())
    }

    /// `true` when this state was produced by an equivalent configuration.
    pub fn matches(&self, fingerprint: &str) -> bool {
        self.fingerprint == fingerprint
    }

    /// Record that a probe finished.
    pub fn mark_done(&mut self, addr: std::net::IpAddr, protocol: Protocol, port: u16) {
        let entry = self.hosts.entry(addr.to_string()).or_default();
        match protocol {
            Protocol::Tcp => entry.tcp.insert(port),
            Protocol::Udp => entry.udp.insert(port),
        }
        self.probes_completed += 1;
    }

    /// `true` when this probe was completed in an earlier run.
    pub fn is_done(&self, addr: std::net::IpAddr, protocol: Protocol, port: u16) -> bool {
        self.hosts.get(&addr.to_string()).is_some_and(|host| match protocol {
            Protocol::Tcp => host.tcp.contains(port),
            Protocol::Udp => host.udp.contains(port),
        })
    }

    /// Record the outcome of host discovery.
    pub fn mark_discovered(&mut self, addr: std::net::IpAddr, up: bool) {
        let entry = self.hosts.entry(addr.to_string()).or_default();
        entry.discovered = true;
        entry.up = up;
    }

    /// Discovery result from an earlier run, if there is one.
    pub fn discovery_result(&self, addr: std::net::IpAddr) -> Option<bool> {
        self.hosts.get(&addr.to_string()).filter(|h| h.discovered).map(|h| h.up)
    }

    /// Keep a result so that a resumed scan can still report it.
    pub fn record(&mut self, result: &PortResult) {
        self.results.push(result.clone());
    }

    /// Total probes recorded as complete.
    pub fn completed_count(&self) -> u64 {
        self.hosts.values().map(|h| (h.tcp.len() + h.udp.len()) as u64).sum()
    }
}

/// A stable fingerprint of the parts of a configuration that must not change
/// between a scan and its resumption.
///
/// Deliberately ignores pacing: resuming with a different rate limit is fine,
/// resuming with different ports is not.
pub fn fingerprint(config: &ScanConfig) -> String {
    let mut parts = Vec::new();
    parts.push(format!("v{STATE_VERSION}"));
    parts.push(format!("mode={}", config.mode.as_str()));
    for spec in config.targets.specs() {
        parts.push(format!("t={spec}"));
    }
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let ports = config.ports.ports(protocol);
        parts.push(format!("p{protocol}={}:{:?}", ports.len(), digest(ports)));
    }
    format!("{:016x}", digest_str(&parts.join("|")))
}

/// FNV-1a over the port list, so the fingerprint stays short.
fn digest(ports: &[u16]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for port in ports {
        for byte in port.to_be_bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

fn digest_str(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Current time as an RFC 3339 string, without pulling in a date library.
pub fn now_rfc3339() -> String {
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    format_rfc3339(now.as_secs(), now.subsec_millis())
}

/// Format a Unix timestamp as RFC 3339 UTC.
///
/// Hand-rolled with the civil-from-days algorithm so the crate does not take a
/// dependency on a date library for one format string.
pub fn format_rfc3339(unix_seconds: u64, millis: u32) -> String {
    let days = (unix_seconds / 86_400) as i64;
    let seconds_of_day = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    )
}

/// Howard Hinnant's `civil_from_days`, for days since the Unix epoch.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortState, Reason};
    use crate::ports::PortSpec;
    use crate::target::{TargetSet, TargetSpec};
    use std::net::IpAddr;

    fn addr(last: u8) -> IpAddr {
        format!("192.0.2.{last}").parse().expect("literal")
    }

    fn config_for(targets: &str, ports: &str) -> ScanConfig {
        let mut set = TargetSet::new();
        set.add(TargetSpec::parse(targets).expect("literal"));
        ScanConfig::builder()
            .targets(set)
            .ports(PortSpec::parse(ports).expect("literal"))
            .build()
            .expect("valid")
    }

    #[test]
    fn port_ranges_merge_adjacent_entries() {
        let mut ranges = PortRanges::new();
        for port in [1u16, 2, 3, 10, 11, 5] {
            ranges.insert(port);
        }
        assert_eq!(ranges.ranges(), &[(1, 3), (5, 5), (10, 11)]);
        ranges.insert(4);
        assert_eq!(ranges.ranges(), &[(1, 5), (10, 11)]);
        assert_eq!(ranges.len(), 7);
    }

    #[test]
    fn port_ranges_answer_membership() {
        let mut ranges = PortRanges::new();
        for port in 100u16..=200 {
            ranges.insert(port);
        }
        assert_eq!(ranges.ranges(), &[(100, 200)]);
        assert!(ranges.contains(100));
        assert!(ranges.contains(150));
        assert!(ranges.contains(200));
        assert!(!ranges.contains(99));
        assert!(!ranges.contains(201));
    }

    #[test]
    fn port_ranges_stay_compact_for_a_full_scan() {
        let mut ranges = PortRanges::new();
        for port in 1u16..=u16::MAX {
            ranges.insert(port);
        }
        assert_eq!(ranges.ranges().len(), 1, "a full scan must collapse to one range");
        assert_eq!(ranges.len(), 65535);
        assert!(ranges.contains(u16::MAX));
    }

    #[test]
    fn inserting_twice_is_idempotent() {
        let mut ranges = PortRanges::new();
        ranges.insert(80);
        ranges.insert(80);
        assert_eq!(ranges.ranges(), &[(80, 80)]);
    }

    #[test]
    fn state_tracks_completed_probes() {
        let mut state = ScanState::new("fp".into());
        assert!(!state.is_done(addr(1), Protocol::Tcp, 80));
        state.mark_done(addr(1), Protocol::Tcp, 80);
        assert!(state.is_done(addr(1), Protocol::Tcp, 80));
        // Protocol and host are both part of the key.
        assert!(!state.is_done(addr(1), Protocol::Udp, 80));
        assert!(!state.is_done(addr(2), Protocol::Tcp, 80));
        assert_eq!(state.completed_count(), 1);
    }

    #[test]
    fn discovery_results_survive_a_restart() {
        let mut state = ScanState::new("fp".into());
        assert_eq!(state.discovery_result(addr(1)), None);
        state.mark_discovered(addr(1), false);
        assert_eq!(state.discovery_result(addr(1)), Some(false));
        state.mark_discovered(addr(2), true);
        assert_eq!(state.discovery_result(addr(2)), Some(true));
    }

    #[tokio::test]
    async fn state_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!("rscan-state-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.expect("mkdir");
        let path = dir.join("scan.state");

        let mut state = ScanState::new("fingerprint".into());
        for port in [22u16, 80, 443] {
            state.mark_done(addr(1), Protocol::Tcp, port);
        }
        state.record(&PortResult::new(addr(1), 22, Protocol::Tcp, PortState::Open, Reason::SynAck));
        state.save(&path).await.expect("save");

        let loaded = ScanState::load(&path).await.expect("load");
        assert!(loaded.matches("fingerprint"));
        assert!(loaded.is_done(addr(1), Protocol::Tcp, 443));
        assert!(!loaded.is_done(addr(1), Protocol::Tcp, 444));
        assert_eq!(loaded.results.len(), 1);

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn saving_leaves_no_temporary_file_behind() {
        let dir = std::env::temp_dir().join(format!("rscan-tmp-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.expect("mkdir");
        let path = dir.join("scan.state");
        ScanState::new("f".into()).save(&path).await.expect("save");
        assert!(path.exists());
        assert!(!temporary_path(&path).exists(), "the temporary file must be renamed away");
        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[tokio::test]
    async fn a_corrupt_state_file_is_an_error_not_a_panic() {
        let dir = std::env::temp_dir().join(format!("rscan-bad-{}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await.expect("mkdir");
        let path = dir.join("scan.state");
        tokio::fs::write(&path, b"{not json").await.expect("write");
        assert!(ScanState::load(&path).await.is_err());

        tokio::fs::write(
            &path,
            br#"{"version":99,"fingerprint":"x","started_at":"","updated_at":"","hosts":{}}"#,
        )
        .await
        .expect("write");
        let err = ScanState::load(&path).await.expect_err("version mismatch");
        assert!(err.to_string().contains("version"), "{err}");

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

    #[test]
    fn fingerprints_distinguish_incompatible_scans() {
        let base = fingerprint(&config_for("192.0.2.0/24", "1-1024"));
        assert_eq!(base, fingerprint(&config_for("192.0.2.0/24", "1-1024")));
        assert_ne!(base, fingerprint(&config_for("192.0.2.0/25", "1-1024")));
        assert_ne!(base, fingerprint(&config_for("192.0.2.0/24", "1-1025")));
        assert_ne!(base, fingerprint(&config_for("198.51.100.0/24", "1-1024")));
    }

    #[test]
    fn fingerprints_ignore_pacing() {
        let mut a = config_for("192.0.2.1", "80");
        let b = config_for("192.0.2.1", "80");
        a.aimd.max_rate_pps = 9999.0;
        a.retries = 5;
        assert_eq!(fingerprint(&a), fingerprint(&b), "pacing changes must not block a resume");
    }

    #[test]
    fn timestamps_render_as_rfc_3339() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(1_000_000_000, 500), "2001-09-09T01:46:40.500Z");
        assert_eq!(format_rfc3339(1_700_000_000, 0), "2023-11-14T22:13:20.000Z");
        // A leap day, which the civil-from-days conversion must get right.
        assert_eq!(format_rfc3339(1_709_164_800, 0), "2024-02-29T00:00:00.000Z");
        assert!(now_rfc3339().ends_with('Z'));
    }
}
