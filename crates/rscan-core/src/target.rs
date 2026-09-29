//! Target parsing and expansion.
//!
//! Everything a user can type as a target — a bare address, a CIDR block, a
//! hyphenated range, a hostname — is normalised into a list of inclusive
//! [`AddrRange`]s. Expansion is then a lazy iterator, which matters: `10/8` is
//! sixteen million addresses and an IPv6 `/64` is not enumerable at all, so
//! nothing is ever materialised into a `Vec` by this module.
//!
//! IPv6 is handled on the same code path as IPv4 rather than bolted on: ranges
//! are compared as `u128` with an explicit family tag.
//!
//! ```
//! use rscan_core::target::{TargetSet, TargetSpec};
//!
//! let mut set = TargetSet::new();
//! set.add(TargetSpec::parse("192.0.2.0/30")?);
//! set.exclude(TargetSpec::parse("192.0.2.1")?);
//!
//! let plan = set.resolve_blocking()?;
//! let addrs: Vec<_> = plan.iter().map(|t| t.addr.to_string()).collect();
//! assert_eq!(addrs, ["192.0.2.0", "192.0.2.2", "192.0.2.3"]);
//! # Ok::<(), rscan_core::Error>(())
//! ```

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// One address in scope, with the hostname it came from (if any).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Target {
    /// The address to probe.
    pub addr: IpAddr,
    /// The hostname this address was resolved from, for reporting.
    pub hostname: Option<String>,
}

impl Target {
    /// Construct a target with no associated hostname.
    pub fn new(addr: IpAddr) -> Self {
        Self { addr, hostname: None }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.hostname {
            Some(h) => write!(f, "{h} ({})", self.addr),
            None => write!(f, "{}", self.addr),
        }
    }
}

/// An inclusive range of addresses of a single family.
///
/// This is the normalised form every target specification collapses into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddrRange {
    /// First address, inclusive.
    pub start: IpAddr,
    /// Last address, inclusive.
    pub end: IpAddr,
}

impl AddrRange {
    /// Build a range, normalising reversed endpoints.
    ///
    /// Returns an error when the endpoints are of different families.
    pub fn new(start: IpAddr, end: IpAddr) -> Result<Self> {
        if start.is_ipv4() != end.is_ipv4() {
            return Err(Error::invalid_target(
                format!("{start}-{end}"),
                "range endpoints must be of the same address family",
            ));
        }
        let (start, end) = if to_u128(start) <= to_u128(end) { (start, end) } else { (end, start) };
        Ok(Self { start, end })
    }

    /// A range containing exactly one address.
    pub fn single(addr: IpAddr) -> Self {
        Self { start: addr, end: addr }
    }

    /// Number of addresses in the range.
    pub fn len(&self) -> u128 {
        to_u128(self.end) - to_u128(self.start) + 1
    }

    /// Always `false`; ranges are inclusive and therefore never empty.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// `true` when `addr` falls inside the range (same family included).
    pub fn contains(&self, addr: IpAddr) -> bool {
        if addr.is_ipv4() != self.start.is_ipv4() {
            return false;
        }
        let v = to_u128(addr);
        v >= to_u128(self.start) && v <= to_u128(self.end)
    }

    /// Lazily iterate every address in the range.
    pub fn iter(&self) -> AddrRangeIter {
        AddrRangeIter {
            next: Some(to_u128(self.start)),
            end: to_u128(self.end),
            v4: self.start.is_ipv4(),
        }
    }
}

impl fmt::Display for AddrRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

/// Iterator over the addresses of an [`AddrRange`].
#[derive(Debug, Clone)]
pub struct AddrRangeIter {
    next: Option<u128>,
    end: u128,
    v4: bool,
}

impl Iterator for AddrRangeIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        let current = self.next?;
        if current > self.end {
            self.next = None;
            return None;
        }
        self.next = if current == self.end { None } else { Some(current + 1) };
        Some(from_u128(current, self.v4))
    }
}

/// Convert an address to its numeric value. IPv4 occupies the low 32 bits.
fn to_u128(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u32::from(v4) as u128,
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Inverse of [`to_u128`]; `v4` selects the family.
fn from_u128(value: u128, v4: bool) -> IpAddr {
    if v4 {
        IpAddr::V4(Ipv4Addr::from(value as u32))
    } else {
        IpAddr::V6(Ipv6Addr::from(value))
    }
}

/// A target as the user wrote it, parsed but not yet resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetSpec {
    /// A literal address, or a CIDR block, or a hyphenated range: anything that
    /// is already a range of addresses.
    Range(AddrRange),
    /// A hostname that still needs a DNS lookup. Both A and AAAA records are
    /// used when available.
    Hostname(String),
}

impl TargetSpec {
    /// Parse one target specification.
    ///
    /// Accepted forms:
    ///
    /// | form | example |
    /// |---|---|
    /// | literal address | `192.0.2.7`, `2001:db8::1` |
    /// | CIDR | `10.0.0.0/24`, `2001:db8::/126` |
    /// | last-component range | `10.0.0.1-50`, `2001:db8::1-ff` |
    /// | full range | `10.0.0.1-10.0.3.255` |
    /// | hostname | `example.com` |
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            return Err(Error::invalid_target(spec, "empty specification"));
        }

        if let Ok(addr) = IpAddr::from_str(spec) {
            return Ok(TargetSpec::Range(AddrRange::single(addr)));
        }

        if spec.contains('/') {
            return parse_cidr(spec).map(TargetSpec::Range);
        }

        // A hyphen means a range — except inside a hostname such as
        // `my-host.example.com`, which we detect by the absence of any digit
        // group that parses as an address component.
        if let Some(range) = try_parse_range(spec)? {
            return Ok(TargetSpec::Range(range));
        }

        if is_plausible_hostname(spec) {
            return Ok(TargetSpec::Hostname(spec.to_string()));
        }

        Err(Error::invalid_target(spec, "not an address, CIDR block, range or hostname"))
    }

    /// Number of addresses this specification covers, or `None` for a hostname
    /// (unknown until resolved).
    pub fn count(&self) -> Option<u128> {
        match self {
            TargetSpec::Range(r) => Some(r.len()),
            TargetSpec::Hostname(_) => None,
        }
    }
}

impl FromStr for TargetSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        TargetSpec::parse(s)
    }
}

impl fmt::Display for TargetSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetSpec::Range(r) => write!(f, "{r}"),
            TargetSpec::Hostname(h) => write!(f, "{h}"),
        }
    }
}

fn parse_cidr(spec: &str) -> Result<AddrRange> {
    let net = IpNet::from_str(spec)
        .map_err(|e| Error::invalid_target(spec, format!("invalid CIDR block: {e}")))?;
    AddrRange::new(net.network(), net.broadcast())
}

/// Try to interpret `spec` as a hyphenated range. Returns `Ok(None)` when the
/// string contains no hyphen at all, so the caller can fall through to the
/// hostname branch.
fn try_parse_range(spec: &str) -> Result<Option<AddrRange>> {
    let Some(hyphen) = spec.rfind('-') else {
        return Ok(None);
    };
    let (left, right) = (&spec[..hyphen], &spec[hyphen + 1..]);
    if left.is_empty() || right.is_empty() {
        return Ok(None);
    }

    let Ok(start) = IpAddr::from_str(left) else {
        return Ok(None);
    };

    // Full form: both endpoints are complete addresses.
    if let Ok(end) = IpAddr::from_str(right) {
        return AddrRange::new(start, end).map(Some);
    }

    // Shorthand: only the last component of the address is given.
    match start {
        IpAddr::V4(v4) => {
            let last: u8 = right.parse().map_err(|_| {
                Error::invalid_target(spec, "range end must be an octet in 0-255 or a full address")
            })?;
            let octets = v4.octets();
            if last < octets[3] {
                return Err(Error::invalid_target(spec, "range end is below range start"));
            }
            let end = Ipv4Addr::new(octets[0], octets[1], octets[2], last);
            AddrRange::new(IpAddr::V4(v4), IpAddr::V4(end)).map(Some)
        }
        IpAddr::V6(v6) => {
            let last = u16::from_str_radix(right, 16).map_err(|_| {
                Error::invalid_target(
                    spec,
                    "range end must be a hex group in 0-ffff or a full address",
                )
            })?;
            let mut segments = v6.segments();
            if last < segments[7] {
                return Err(Error::invalid_target(spec, "range end is below range start"));
            }
            segments[7] = last;
            AddrRange::new(IpAddr::V6(v6), IpAddr::V6(Ipv6Addr::from(segments))).map(Some)
        }
    }
}

/// A conservative syntactic check. DNS is the real authority on whether a name
/// exists; this only rejects strings that cannot be names at all.
fn is_plausible_hostname(spec: &str) -> bool {
    if spec.len() > 253 || spec.starts_with('.') || spec.starts_with('-') || spec.ends_with('-') {
        return false;
    }
    let mut last_label = "";
    for label in spec.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return false;
        }
        last_label = label;
    }
    // RFC 1123: the rightmost label may not be all-numeric. This is also what
    // separates a hostname from a botched address such as `999.1.1.1`, which
    // must be an error rather than a DNS lookup for a name that cannot exist.
    !last_label.bytes().all(|b| b.is_ascii_digit())
}

/// A collection of target specifications plus exclusions, before resolution.
#[derive(Debug, Clone, Default)]
pub struct TargetSet {
    specs: Vec<TargetSpec>,
    excludes: Vec<TargetSpec>,
}

impl TargetSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a specification to scan.
    pub fn add(&mut self, spec: TargetSpec) -> &mut Self {
        self.specs.push(spec);
        self
    }

    /// Add a specification to exclude from the scan.
    ///
    /// Exclusions are applied after expansion, so excluding a hostname excludes
    /// every address it resolves to.
    pub fn exclude(&mut self, spec: TargetSpec) -> &mut Self {
        self.excludes.push(spec);
        self
    }

    /// Parse and add each whitespace- or comma-separated specification in a
    /// line, ignoring `#` comments and blank lines.
    ///
    /// This is what `-iL` and stdin input go through.
    pub fn add_line(&mut self, line: &str) -> Result<&mut Self> {
        for token in split_tokens(line) {
            self.add(TargetSpec::parse(token)?);
        }
        Ok(self)
    }

    /// Parse and add every specification in a multi-line document.
    pub fn add_list(&mut self, text: &str) -> Result<&mut Self> {
        for line in text.lines() {
            self.add_line(line)?;
        }
        Ok(self)
    }

    /// Parse and exclude each specification in a line.
    pub fn exclude_line(&mut self, line: &str) -> Result<&mut Self> {
        for token in split_tokens(line) {
            self.exclude(TargetSpec::parse(token)?);
        }
        Ok(self)
    }

    /// `true` when nothing has been added.
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// The specifications added so far.
    pub fn specs(&self) -> &[TargetSpec] {
        &self.specs
    }

    /// Resolve every hostname and produce an expandable [`TargetPlan`].
    ///
    /// DNS lookups run on the blocking pool because `getaddrinfo` is a blocking
    /// call; a hostname that fails to resolve is an error rather than a silent
    /// omission.
    pub async fn resolve(&self) -> Result<TargetPlan> {
        let specs = self.specs.clone();
        let excludes = self.excludes.clone();
        tokio::task::spawn_blocking(move || resolve_sync(&specs, &excludes))
            .await
            .map_err(|e| Error::config(format!("resolver task failed: {e}")))?
    }

    /// Synchronous counterpart of [`TargetSet::resolve`], for callers that are
    /// not inside a runtime (doctests, benchmarks, fuzzers).
    pub fn resolve_blocking(&self) -> Result<TargetPlan> {
        resolve_sync(&self.specs, &self.excludes)
    }
}

fn split_tokens(line: &str) -> impl Iterator<Item = &str> {
    let line = line.split('#').next().unwrap_or("");
    line.split([',', ' ', '\t']).map(str::trim).filter(|t| !t.is_empty())
}

fn resolve_sync(specs: &[TargetSpec], excludes: &[TargetSpec]) -> Result<TargetPlan> {
    let mut ranges = Vec::new();
    let mut hostnames = Vec::new();
    for spec in specs {
        match spec {
            TargetSpec::Range(r) => ranges.push(*r),
            TargetSpec::Hostname(name) => {
                let addrs = resolve_hostname(name)?;
                for addr in addrs {
                    hostnames.push(Target { addr, hostname: Some(name.clone()) });
                }
            }
        }
    }

    let mut exclude_ranges = Vec::new();
    for spec in excludes {
        match spec {
            TargetSpec::Range(r) => exclude_ranges.push(*r),
            TargetSpec::Hostname(name) => {
                for addr in resolve_hostname(name)? {
                    exclude_ranges.push(AddrRange::single(addr));
                }
            }
        }
    }

    Ok(TargetPlan { ranges, hostnames, excludes: exclude_ranges })
}

/// Resolve a hostname to every A and AAAA address it has.
fn resolve_hostname(name: &str) -> Result<Vec<IpAddr>> {
    // Port 0 keeps `getaddrinfo` happy without implying anything about ports.
    let addrs: Vec<IpAddr> = (name, 0u16)
        .to_socket_addrs()
        .map_err(|e| Error::Resolve { host: name.to_string(), reason: e.to_string() })?
        .map(|sa| sa.ip())
        .collect();
    if addrs.is_empty() {
        return Err(Error::Resolve {
            host: name.to_string(),
            reason: "no A or AAAA records".into(),
        });
    }
    let mut seen = Vec::with_capacity(addrs.len());
    for addr in addrs {
        if !seen.contains(&addr) {
            seen.push(addr);
        }
    }
    Ok(seen)
}

/// A fully resolved set of targets, ready to iterate.
///
/// Iteration is lazy and de-duplicating: the same address reached through two
/// specifications is yielded once.
#[derive(Debug, Clone, Default)]
pub struct TargetPlan {
    ranges: Vec<AddrRange>,
    hostnames: Vec<Target>,
    excludes: Vec<AddrRange>,
}

impl TargetPlan {
    /// Build a plan directly from already-resolved pieces.
    pub fn from_parts(
        ranges: Vec<AddrRange>,
        hostnames: Vec<Target>,
        excludes: Vec<AddrRange>,
    ) -> Self {
        Self { ranges, hostnames, excludes }
    }

    /// The ranges in scope, before exclusions.
    pub fn ranges(&self) -> &[AddrRange] {
        &self.ranges
    }

    /// The exclusion ranges.
    pub fn excludes(&self) -> &[AddrRange] {
        &self.excludes
    }

    /// Upper bound on the number of targets, ignoring de-duplication.
    ///
    /// Used for progress accounting and for the large-range confirmation
    /// prompt; exact only when the specifications do not overlap.
    pub fn approx_len(&self) -> u128 {
        let ranges: u128 = self.ranges.iter().map(|r| r.len()).sum();
        let excluded: u128 = self
            .excludes
            .iter()
            .map(|e| self.ranges.iter().map(|r| overlap_len(r, e)).sum::<u128>())
            .sum();
        ranges.saturating_sub(excluded) + self.hostnames.len() as u128
    }

    /// The size of the largest single range, as a CIDR prefix length.
    ///
    /// The CLI uses this to decide whether a scan is big enough to warrant a
    /// confirmation prompt.
    pub fn largest_range_len(&self) -> u128 {
        self.ranges.iter().map(|r| r.len()).max().unwrap_or(0)
    }

    /// `true` when `addr` is excluded.
    pub fn is_excluded(&self, addr: IpAddr) -> bool {
        self.excludes.iter().any(|e| e.contains(addr))
    }

    /// Lazily iterate every target, de-duplicated and exclusion-filtered.
    pub fn iter(&self) -> TargetPlanIter<'_> {
        TargetPlanIter {
            plan: self,
            range_idx: 0,
            current: None,
            host_idx: 0,
            seen: std::collections::HashSet::new(),
        }
    }
}

impl<'a> IntoIterator for &'a TargetPlan {
    type Item = Target;
    type IntoIter = TargetPlanIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

fn overlap_len(a: &AddrRange, b: &AddrRange) -> u128 {
    if a.start.is_ipv4() != b.start.is_ipv4() {
        return 0;
    }
    let lo = to_u128(a.start).max(to_u128(b.start));
    let hi = to_u128(a.end).min(to_u128(b.end));
    if lo > hi {
        0
    } else {
        hi - lo + 1
    }
}

/// Iterator produced by [`TargetPlan::iter`].
#[derive(Debug)]
pub struct TargetPlanIter<'a> {
    plan: &'a TargetPlan,
    range_idx: usize,
    current: Option<AddrRangeIter>,
    host_idx: usize,
    seen: std::collections::HashSet<IpAddr>,
}

impl Iterator for TargetPlanIter<'_> {
    type Item = Target;

    fn next(&mut self) -> Option<Target> {
        loop {
            if let Some(iter) = self.current.as_mut() {
                match iter.next() {
                    Some(addr) => {
                        if self.plan.is_excluded(addr) || !self.seen.insert(addr) {
                            continue;
                        }
                        return Some(Target::new(addr));
                    }
                    None => {
                        self.current = None;
                        continue;
                    }
                }
            }

            if self.range_idx < self.plan.ranges.len() {
                self.current = Some(self.plan.ranges[self.range_idx].iter());
                self.range_idx += 1;
                continue;
            }

            while self.host_idx < self.plan.hostnames.len() {
                let target = self.plan.hostnames[self.host_idx].clone();
                self.host_idx += 1;
                if self.plan.is_excluded(target.addr) || !self.seen.insert(target.addr) {
                    continue;
                }
                return Some(target);
            }

            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test literal is a valid address")
    }

    fn parse(s: &str) -> TargetSpec {
        TargetSpec::parse(s).expect("test literal parses")
    }

    fn expand(specs: &[&str]) -> Vec<IpAddr> {
        let mut set = TargetSet::new();
        for s in specs {
            set.add(parse(s));
        }
        let plan = set.resolve_blocking().expect("no hostnames in test");
        plan.iter().map(|t| t.addr).collect()
    }

    #[test]
    fn parses_single_ipv4() {
        assert_eq!(parse("192.0.2.1"), TargetSpec::Range(AddrRange::single(ip("192.0.2.1"))));
    }

    #[test]
    fn parses_single_ipv6() {
        assert_eq!(parse("2001:db8::1"), TargetSpec::Range(AddrRange::single(ip("2001:db8::1"))));
    }

    #[test]
    fn parses_ipv4_cidr() {
        assert_eq!(expand(&["192.0.2.0/30"]).len(), 4);
        assert_eq!(expand(&["192.0.2.0/32"]), vec![ip("192.0.2.0")]);
    }

    #[test]
    fn parses_ipv6_cidr() {
        let addrs = expand(&["2001:db8::/126"]);
        assert_eq!(addrs.len(), 4);
        assert_eq!(addrs[0], ip("2001:db8::"));
        assert_eq!(addrs[3], ip("2001:db8::3"));
    }

    #[test]
    fn parses_last_octet_range() {
        let addrs = expand(&["10.0.0.5-8"]);
        assert_eq!(addrs, vec![ip("10.0.0.5"), ip("10.0.0.6"), ip("10.0.0.7"), ip("10.0.0.8")]);
    }

    #[test]
    fn parses_full_ipv4_range_across_octets() {
        let addrs = expand(&["10.0.0.254-10.0.1.1"]);
        assert_eq!(addrs, vec![ip("10.0.0.254"), ip("10.0.0.255"), ip("10.0.1.0"), ip("10.0.1.1")]);
    }

    #[test]
    fn parses_ipv6_last_group_range() {
        let addrs = expand(&["2001:db8::a-c"]);
        assert_eq!(addrs, vec![ip("2001:db8::a"), ip("2001:db8::b"), ip("2001:db8::c")]);
    }

    #[test]
    fn parses_full_ipv6_range() {
        let addrs = expand(&["2001:db8::1-2001:db8::3"]);
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn recognises_hostnames() {
        assert_eq!(parse("example.com"), TargetSpec::Hostname("example.com".into()));
        assert_eq!(
            parse("my-host.example.com"),
            TargetSpec::Hostname("my-host.example.com".into())
        );
        assert_eq!(parse("localhost"), TargetSpec::Hostname("localhost".into()));
    }

    #[test]
    fn rejects_malformed_specifications() {
        for bad in [
            "",
            "   ",
            "999.1.1.1",
            "10.0.0.0/33",
            "2001:db8::/129",
            "10.0.0.1-999",
            "10.0.0.50-10",
            "2001:db8::1-zz",
            ".example.com",
            "-example.com",
            "example-.com",
            "exa mple.com",
            "12345",
            "10.0.0.1/",
            "a..b",
        ] {
            assert!(TargetSpec::parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn rejects_mixed_family_ranges() {
        assert!(TargetSpec::parse("10.0.0.1-2001:db8::1").is_err());
    }

    #[test]
    fn applies_exclusions() {
        let mut set = TargetSet::new();
        set.add(parse("192.0.2.0/29"));
        set.exclude(parse("192.0.2.2-4"));
        let plan = set.resolve_blocking().expect("no hostnames");
        let addrs: Vec<_> = plan.iter().map(|t| t.addr).collect();
        assert_eq!(
            addrs,
            vec![
                ip("192.0.2.0"),
                ip("192.0.2.1"),
                ip("192.0.2.5"),
                ip("192.0.2.6"),
                ip("192.0.2.7")
            ]
        );
        assert_eq!(plan.approx_len(), 5);
    }

    #[test]
    fn deduplicates_overlapping_specifications() {
        let addrs = expand(&["192.0.2.0/31", "192.0.2.1", "192.0.2.1-2"]);
        assert_eq!(addrs, vec![ip("192.0.2.0"), ip("192.0.2.1"), ip("192.0.2.2")]);
    }

    #[test]
    fn exclusions_do_not_cross_families() {
        let mut set = TargetSet::new();
        set.add(parse("192.0.2.1"));
        set.exclude(parse("::c000:201"));
        let plan = set.resolve_blocking().expect("no hostnames");
        assert_eq!(plan.iter().count(), 1);
    }

    #[test]
    fn parses_target_lists_with_comments_and_separators() {
        let mut set = TargetSet::new();
        set.add_list("192.0.2.1, 192.0.2.2 # a comment\n\n# only a comment\n192.0.2.3\n")
            .expect("list parses");
        assert_eq!(set.specs().len(), 3);
    }

    #[test]
    fn huge_ranges_are_not_materialised() {
        // A /8 must be describable without enumerating sixteen million entries.
        let mut set = TargetSet::new();
        set.add(parse("10.0.0.0/8"));
        let plan = set.resolve_blocking().expect("no hostnames");
        assert_eq!(plan.approx_len(), 16_777_216);
        assert_eq!(plan.iter().take(3).count(), 3);
    }

    #[test]
    fn range_iteration_terminates_at_the_numeric_maximum() {
        let range =
            AddrRange::new(ip("255.255.255.254"), ip("255.255.255.255")).expect("same family");
        assert_eq!(range.iter().count(), 2);

        let range = AddrRange::new(
            ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe"),
            ip("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        )
        .expect("same family");
        assert_eq!(range.iter().count(), 2);
    }

    #[test]
    fn reversed_full_ranges_are_normalised() {
        let range = AddrRange::new(ip("10.0.0.5"), ip("10.0.0.1")).expect("same family");
        assert_eq!(range.start, ip("10.0.0.1"));
        assert_eq!(range.end, ip("10.0.0.5"));
    }
}
