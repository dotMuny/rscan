//! The scan orchestrator.
//!
//! [`Scanner`] wires together everything else: it expands targets, runs host
//! discovery, issues port probes under the [`Governor`]'s pacing, retries what
//! times out, hands open ports to the [`Detector`], checkpoints resume state,
//! and emits the whole thing as a stream of [`ScanEvent`]s.
//!
//! # Why a stream
//!
//! Returning a `Vec` at the end would mean a `/16` produces nothing at all for
//! an hour and then everything at once. A stream lets a JSONL consumer start
//! working on the first open port, lets a progress bar be accurate, and lets a
//! caller stop early without losing what has been found.
//!
//! # Work ordering
//!
//! Probes are issued **round-robin across a window of hosts** rather than host
//! by host. With a per-target rate limit, issuing all of one host's ports first
//! would stall the queue behind that one host. Round-robin keeps every host's
//! token bucket busy at once.
//!
//! This is load spreading, not evasion: the order is deterministic and the
//! scanner makes no attempt to look like anything other than a scanner.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use futures::Stream;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;

use crate::config::{ScanConfig, ScanMode};
use crate::discovery::Discoverer;
use crate::error::{Error, Result};
use crate::governor::{Governor, GovernorConfig};
use crate::limits::{self, FdBudget};
use crate::model::{
    PortResult, PortState, ProgressSnapshot, Protocol, ScanEvent, ScanSummary, ServiceInfo,
    SCHEMA_VERSION,
};
use crate::probe::Detector;
use crate::scan::syn::SynScanner;
use crate::scan::{connect, udp, Verdict};
use crate::state::{self, ScanState};
use crate::target::{Target, TargetPlan};

/// How many hosts are kept in flight for round-robin issuance.
const HOST_WINDOW: usize = 64;

/// Capacity of the event channel. Large enough that a slow consumer does not
/// immediately throttle the scan, small enough to bound memory.
const EVENT_BUFFER: usize = 1024;

/// A configured, ready-to-run scan.
///
/// Construction resolves targets, reconciles the descriptor budget and opens
/// raw sockets if the mode needs them, so every problem that can be reported
/// before probing starts is reported by [`Scanner::new`].
pub struct Scanner {
    config: Arc<ScanConfig>,
    plan: Arc<TargetPlan>,
    governor: Arc<Governor>,
    detector: Arc<Detector>,
    syn: Option<Arc<SynScanner>>,
    state: Arc<Mutex<ScanState>>,
    fd_budget: FdBudget,
    warnings: Vec<String>,
    effective_mode: ScanMode,
}

impl std::fmt::Debug for Scanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("mode", &self.effective_mode)
            .field("hosts", &self.plan.approx_len())
            .field("ports", &self.config.ports.len())
            .field("warnings", &self.warnings.len())
            .finish()
    }
}

impl Scanner {
    /// Prepare a scan.
    ///
    /// Resolves hostnames, reconciles requested concurrency against
    /// `RLIMIT_NOFILE`, loads resume state when configured, and opens raw
    /// sockets when the mode needs them — falling back to a connect scan with a
    /// warning when privileges are missing and
    /// [`ScanConfig::fallback_to_connect`] allows it.
    pub async fn new(config: ScanConfig) -> Result<Self> {
        let config = config.normalised();
        config.validate()?;

        let plan = config.targets.resolve().await?;
        if plan.approx_len() == 0 {
            return Err(Error::config("every target was excluded"));
        }

        let mut warnings = Vec::new();

        let fd_budget = limits::reconcile_concurrency(config.aimd.initial_concurrency);
        if let Some(warning) = &fd_budget.warning {
            warnings.push(warning.clone());
        }

        let mut effective_mode = config.mode;
        let syn = if config.mode == ScanMode::Syn {
            let want_v6 = plan.iter().take(256).any(|t| t.addr.is_ipv6())
                || plan.ranges().iter().any(|r| !r.start.is_ipv4());
            match SynScanner::new(true, want_v6) {
                Ok(scanner) => Some(scanner),
                Err(err) if err.is_privileges() && config.fallback_to_connect => {
                    warnings.push(format!("{err}; falling back to a TCP connect scan"));
                    effective_mode = ScanMode::Connect;
                    None
                }
                Err(err) => return Err(err),
            }
        } else {
            None
        };

        let state = match &config.resume_path {
            Some(path) if path.exists() => {
                let loaded = ScanState::load(path).await?;
                let fingerprint = state::fingerprint(&config);
                if !loaded.matches(&fingerprint) {
                    return Err(Error::State(format!(
                        "{} belongs to a different scan (targets or ports changed); \
                         delete it or pick another path",
                        path.display()
                    )));
                }
                warnings.push(format!(
                    "resuming: {} probes already completed",
                    loaded.completed_count()
                ));
                loaded
            }
            _ => ScanState::new(state::fingerprint(&config)),
        };

        let governor = Governor::new(GovernorConfig {
            aimd: config.aimd,
            // Resolved here rather than in the config because the rule depends
            // on how many addresses the targets actually expanded to.
            per_target_pps: config.per_target_pps.resolve(plan.approx_len()),
            rtt: config.rtt,
            fd_ceiling: fd_budget.allowed,
        });

        Ok(Self {
            detector: Arc::new(Detector::new(config.service_detection.clone())),
            config: Arc::new(config),
            plan: Arc::new(plan),
            governor,
            syn,
            state: Arc::new(Mutex::new(state)),
            fd_budget,
            warnings,
            effective_mode,
        })
    }

    /// Non-fatal problems found while preparing the scan.
    ///
    /// The CLI prints these before the first result; a library caller can log
    /// or ignore them.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// The resolved targets.
    pub fn plan(&self) -> &TargetPlan {
        &self.plan
    }

    /// The technique actually in use, which may differ from the requested one
    /// if a SYN scan fell back to connect.
    pub fn effective_mode(&self) -> ScanMode {
        self.effective_mode
    }

    /// The descriptor budget reconciliation.
    pub fn fd_budget(&self) -> &FdBudget {
        &self.fd_budget
    }

    /// The ports being scanned for `protocol`.
    pub fn ports(&self, protocol: Protocol) -> &[u16] {
        self.config.ports.ports(protocol)
    }

    /// The configuration this scanner was built from, after normalisation.
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Number of port probes in scope.
    pub fn probes_total(&self) -> u64 {
        let hosts = self.plan.approx_len().min(u64::MAX as u128) as u64;
        hosts.saturating_mul(self.config.ports.len() as u64)
    }

    /// Run the scan, producing events as they happen.
    ///
    /// The returned stream ends after [`ScanEvent::Finished`]. Dropping it
    /// stops the scan: the driver task notices the closed channel and stops
    /// issuing work.
    pub fn run(&self) -> impl Stream<Item = ScanEvent> + Send + 'static {
        let (tx, rx) = mpsc::channel(EVENT_BUFFER);
        let context = Arc::new(Context {
            config: Arc::clone(&self.config),
            governor: Arc::clone(&self.governor),
            detector: Arc::clone(&self.detector),
            syn: self.syn.clone(),
            state: Arc::clone(&self.state),
            mode: self.effective_mode,
            counters: Counters::default(),
        });
        let plan = Arc::clone(&self.plan);
        let probes_total = self.probes_total();

        tokio::spawn(async move {
            drive(context, plan, probes_total, tx).await;
        });

        ReceiverStream::new(rx)
    }

    /// Run to completion and collect everything, for callers that genuinely
    /// want a `Vec`.
    ///
    /// Convenience only; prefer [`Scanner::run`].
    pub async fn run_to_completion(&self) -> (Vec<PortResult>, ScanSummary) {
        use futures::StreamExt;
        let mut results = Vec::new();
        let mut summary = ScanSummary::default();
        let mut events = Box::pin(self.run());
        while let Some(event) = events.next().await {
            match event {
                ScanEvent::Port(result) => results.push(*result),
                ScanEvent::Finished(done) => summary = *done,
                _ => {}
            }
        }
        (results, summary)
    }
}

#[derive(Debug, Default)]
struct Counters {
    completed: AtomicU64,
    open: AtomicU64,
    closed: AtomicU64,
    filtered: AtomicU64,
    hosts_up: AtomicU64,
    hosts_total: AtomicU64,
}

struct Context {
    config: Arc<ScanConfig>,
    governor: Arc<Governor>,
    detector: Arc<Detector>,
    syn: Option<Arc<SynScanner>>,
    state: Arc<Mutex<ScanState>>,
    mode: ScanMode,
    counters: Counters,
}

async fn drive(
    context: Arc<Context>,
    plan: Arc<TargetPlan>,
    probes_total: u64,
    tx: mpsc::Sender<ScanEvent>,
) {
    let started = Instant::now();
    let started_at = state::now_rfc3339();

    let hosts_total = plan.approx_len().min(usize::MAX as u128) as usize;
    if tx
        .send(ScanEvent::Started {
            schema_version: SCHEMA_VERSION,
            hosts_total,
            probes_total,
            started_at,
        })
        .await
        .is_err()
    {
        return;
    }

    // Replay results from an interrupted run so the report is complete.
    let replay: Vec<PortResult> = context.state.lock().results.clone();
    for result in replay {
        if tx.send(ScanEvent::Port(Box::new(result))).await.is_err() {
            return;
        }
    }

    let progress_task = spawn_progress(Arc::clone(&context), tx.clone(), probes_total);
    let checkpoint_task = spawn_checkpoint(Arc::clone(&context));

    // Stage one: discovery, feeding live hosts to stage two as they are found.
    let (live_tx, live_rx) = mpsc::channel::<Target>(256);
    let discovery = spawn_discovery(Arc::clone(&context), Arc::clone(&plan), tx.clone(), live_tx);

    // Stage two: port probes.
    scan_ports(Arc::clone(&context), live_rx, tx.clone()).await;

    let _ = discovery.await;
    progress_task.abort();
    checkpoint_task.abort();

    if let Some(decision) = context.governor.flush() {
        tracing::debug!(?decision, "final control decision");
    }

    if let Some(path) = &context.config.resume_path {
        let state = context.state.lock().clone();
        if let Err(err) = state.save(path).await {
            tracing::warn!(%err, "could not write the final resume checkpoint");
        }
    }

    if let Some(syn) = &context.syn {
        syn.shutdown();
    }

    let counters = &context.counters;
    let summary = ScanSummary {
        hosts_total: counters.hosts_total.load(Ordering::Relaxed) as usize,
        hosts_up: counters.hosts_up.load(Ordering::Relaxed) as usize,
        ports_scanned: counters.completed.load(Ordering::Relaxed),
        ports_open: counters.open.load(Ordering::Relaxed),
        ports_closed: counters.closed.load(Ordering::Relaxed),
        ports_filtered: counters.filtered.load(Ordering::Relaxed),
        packets_sent: context.governor.packets_sent(),
        elapsed: started.elapsed(),
        final_concurrency: context.governor.concurrency(),
        final_rate_pps: context.governor.rate_pps(),
    };
    let _ = tx.send(ScanEvent::Finished(Box::new(summary))).await;
}

fn spawn_progress(
    context: Arc<Context>,
    tx: mpsc::Sender<ScanEvent>,
    total: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(context.config.progress_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let snapshot = ProgressSnapshot {
                completed: context.counters.completed.load(Ordering::Relaxed),
                total,
                open: context.counters.open.load(Ordering::Relaxed),
                concurrency: context.governor.concurrency(),
                rate_pps: context.governor.rate_pps(),
                timeout_rate: context.governor.timeout_rate(),
            };
            if tx.send(ScanEvent::Progress(snapshot)).await.is_err() {
                break;
            }
        }
    })
}

fn spawn_checkpoint(context: Arc<Context>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Some(path) = context.config.resume_path.clone() else {
            // Nothing to checkpoint; park forever until aborted.
            std::future::pending::<()>().await;
            return;
        };
        let mut ticker = tokio::time::interval(context.config.checkpoint_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let state = context.state.lock().clone();
            if let Err(err) = state.save(&path).await {
                tracing::warn!(%err, "resume checkpoint failed");
            }
        }
    })
}

fn spawn_discovery(
    context: Arc<Context>,
    plan: Arc<TargetPlan>,
    events: mpsc::Sender<ScanEvent>,
    live: mpsc::Sender<Target>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let discoverer =
            Arc::new(Discoverer::new(context.config.discovery.clone(), context.syn.clone()));
        let mut tasks = JoinSet::new();
        let parallelism = context.governor.concurrency().clamp(8, 256);
        let permits = Arc::new(tokio::sync::Semaphore::new(parallelism));

        for target in plan.iter() {
            context.counters.hosts_total.fetch_add(1, Ordering::Relaxed);

            // A previous run already answered this question.
            let already = context.state.lock().discovery_result(target.addr);
            if let Some(up) = already {
                if up {
                    context.counters.hosts_up.fetch_add(1, Ordering::Relaxed);
                    if live.send(target).await.is_err() {
                        break;
                    }
                }
                continue;
            }

            let Ok(permit) = Arc::clone(&permits).acquire_owned().await else {
                break;
            };
            let discoverer = Arc::clone(&discoverer);
            let context = Arc::clone(&context);
            let events = events.clone();
            let live = live.clone();
            tasks.spawn(async move {
                let status = discoverer.probe(&target).await;
                drop(permit);
                context.state.lock().mark_discovered(status.addr, status.up);
                if status.up {
                    context.counters.hosts_up.fetch_add(1, Ordering::Relaxed);
                    let _ = events.send(ScanEvent::HostUp(status)).await;
                    let _ = live.send(target).await;
                } else {
                    let _ = events.send(ScanEvent::HostDown(status)).await;
                }
            });

            while tasks.try_join_next().is_some() {}
        }

        while tasks.join_next().await.is_some() {}
    })
}

async fn scan_ports(
    context: Arc<Context>,
    live: mpsc::Receiver<Target>,
    events: mpsc::Sender<ScanEvent>,
) {
    let mut queue = WorkQueue::new(live, port_list(&context.config), HOST_WINDOW);
    let mut tasks = JoinSet::new();

    while let Some((target, protocol, port)) = queue.next().await {
        let already_done = context.state.lock().is_done(target.addr, protocol, port);
        if already_done {
            context.counters.completed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if events.is_closed() {
            break;
        }

        let permit = context.governor.acquire(target.addr).await;
        let context_task = Arc::clone(&context);
        let events_task = events.clone();
        tasks.spawn(async move {
            let result = probe_port(&context_task, &target, protocol, port).await;
            drop(permit);

            {
                let mut state = context_task.state.lock();
                state.mark_done(target.addr, protocol, port);
                if result.state.is_interesting() {
                    state.record(&result);
                }
            }

            let counters = &context_task.counters;
            counters.completed.fetch_add(1, Ordering::Relaxed);
            match result.state {
                PortState::Open => counters.open.fetch_add(1, Ordering::Relaxed),
                PortState::Closed => counters.closed.fetch_add(1, Ordering::Relaxed),
                _ => counters.filtered.fetch_add(1, Ordering::Relaxed),
            };

            if result.state.is_interesting() || context_task.config.report_all_states {
                let _ = events_task.send(ScanEvent::Port(Box::new(result))).await;
            }
        });

        while tasks.try_join_next().is_some() {}
    }

    while tasks.join_next().await.is_some() {}
}

fn port_list(config: &ScanConfig) -> Arc<Vec<(Protocol, u16)>> {
    let mut list = Vec::with_capacity(config.ports.len());
    for &port in config.ports.ports(Protocol::Tcp) {
        list.push((Protocol::Tcp, port));
    }
    for &port in config.ports.ports(Protocol::Udp) {
        list.push((Protocol::Udp, port));
    }
    Arc::new(list)
}

/// Round-robin work queue over a sliding window of live hosts.
struct WorkQueue {
    live: mpsc::Receiver<Target>,
    ports: Arc<Vec<(Protocol, u16)>>,
    active: VecDeque<(Target, usize)>,
    window: usize,
    drained: bool,
}

impl WorkQueue {
    fn new(live: mpsc::Receiver<Target>, ports: Arc<Vec<(Protocol, u16)>>, window: usize) -> Self {
        Self { live, ports, active: VecDeque::new(), window: window.max(1), drained: false }
    }

    async fn next(&mut self) -> Option<(Target, Protocol, u16)> {
        loop {
            // Top the window up with whatever has already arrived.
            while !self.drained && self.active.len() < self.window {
                match self.live.try_recv() {
                    Ok(target) => self.active.push_back((target, 0)),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        self.drained = true;
                        break;
                    }
                }
            }

            if self.active.is_empty() {
                if self.drained {
                    return None;
                }
                match self.live.recv().await {
                    Some(target) => self.active.push_back((target, 0)),
                    None => {
                        self.drained = true;
                        return None;
                    }
                }
                continue;
            }

            let Some((target, index)) = self.active.pop_front() else {
                continue;
            };
            let Some(&(protocol, port)) = self.ports.get(index) else {
                // This host is finished; it simply does not go back on the ring.
                continue;
            };
            if index + 1 < self.ports.len() {
                self.active.push_back((target.clone(), index + 1));
            }
            return Some((target, protocol, port));
        }
    }
}

async fn probe_port(
    context: &Context,
    target: &Target,
    protocol: Protocol,
    port: u16,
) -> PortResult {
    let addr = target.addr;
    let attempts = context.config.retries + 1;

    let mut verdict = Verdict::timed_out();
    let mut rtt = None;
    let mut stream = None;
    let mut udp_response = Vec::new();
    let mut udp_probe_name = None;
    let mut used_attempts = 0u32;

    for attempt in 0..attempts {
        used_attempts = attempt + 1;
        if attempt > 0 {
            // The first attempt's token came with the concurrency permit;
            // every retransmission pays for its own.
            context.governor.pace(addr).await;
        }
        let timeout = context.governor.timeout_for(addr, attempt);

        let (attempt_verdict, attempt_rtt) = match (protocol, context.mode) {
            (Protocol::Tcp, ScanMode::Syn) => match &context.syn {
                Some(syn) => syn.probe(addr, port, timeout).await,
                None => {
                    let probe = connect::probe(addr, port, timeout).await;
                    stream = probe.stream;
                    (probe.verdict, probe.rtt)
                }
            },
            (Protocol::Tcp, ScanMode::Connect) => {
                let probe = connect::probe(addr, port, timeout).await;
                stream = probe.stream;
                (probe.verdict, probe.rtt)
            }
            (Protocol::Udp, _) => {
                let selected = context.detector.udp_probe_for(port);
                let payload = selected.map(|p| p.payload.clone()).unwrap_or_default();
                udp_probe_name = selected.map(|p| p.name.clone());
                let probe = udp::probe(addr, port, &payload, timeout).await;
                udp_response = probe.response;
                (probe.verdict, probe.rtt)
            }
        };

        verdict = attempt_verdict;
        if verdict.outcome == crate::rate::ProbeOutcome::Responded {
            rtt = Some(attempt_rtt);
        }
        context.governor.observe(addr, verdict.outcome, rtt);

        if !verdict.is_retryable() {
            break;
        }
    }

    let mut result = PortResult {
        addr,
        hostname: target.hostname.clone(),
        port,
        protocol,
        state: verdict.state,
        reason: verdict.reason,
        rtt,
        attempts: used_attempts,
        service: None,
    };

    if result.state == PortState::Open {
        result.service = match protocol {
            Protocol::Tcp => {
                context.detector.detect_tcp(addr, port, target.hostname.as_deref(), stream).await
            }
            Protocol::Udp => udp_service(context, port, udp_probe_name.as_deref(), &udp_response),
        };
    }

    result
}

fn udp_service(
    context: &Context,
    port: u16,
    probe_name: Option<&str>,
    response: &[u8],
) -> Option<ServiceInfo> {
    if !context.config.service_detection.enabled {
        return None;
    }
    if let Some(name) = probe_name {
        if let Some(info) = context.detector.match_udp(name, response) {
            return Some(info);
        }
    }
    let guess = crate::ports::service_name(Protocol::Udp, port)?;
    Some(ServiceInfo {
        name: Some(guess.to_string()),
        info: Some("guessed from port number".to_string()),
        confidence: Some(1),
        banner: crate::probe::matcher::banner_text(response),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DiscoveryConfig, ServiceDetection};
    use crate::ports::PortSpec;
    use crate::target::{TargetSet, TargetSpec};
    use futures::StreamExt;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;
    use tokio::net::TcpListener;

    fn localhost_targets() -> TargetSet {
        let mut set = TargetSet::new();
        set.add(TargetSpec::parse("127.0.0.1").expect("literal"));
        set
    }

    fn base_config(ports: &str) -> ScanConfig {
        ScanConfig::builder()
            .targets(localhost_targets())
            .ports(PortSpec::parse(ports).expect("literal"))
            .skip_discovery(true)
            .retries(0)
            .fixed_timeout(Duration::from_millis(400))
            .report_all_states(true)
            .build()
            .expect("valid configuration")
    }

    async fn open_listener() -> (TcpListener, u16) {
        let listener =
            TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        (listener, port)
    }

    #[tokio::test]
    async fn a_scan_emits_started_results_and_finished_in_order() {
        let (_listener, port) = open_listener().await;
        let scanner = Scanner::new(base_config(&port.to_string())).await.expect("scanner");
        let events: Vec<ScanEvent> = scanner.run().collect().await;

        assert!(matches!(events.first(), Some(ScanEvent::Started { .. })));
        assert!(matches!(events.last(), Some(ScanEvent::Finished(_))));

        let ports: Vec<&PortResult> = events
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Port(result) => Some(result.as_ref()),
                _ => None,
            })
            .collect();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].state, PortState::Open);
        assert_eq!(ports[0].port, port);
    }

    #[tokio::test]
    async fn the_summary_counts_what_was_found() {
        let (_listener, open) = open_listener().await;
        let (closed_listener, closed) = open_listener().await;
        drop(closed_listener);

        let scanner =
            Scanner::new(base_config(&format!("{open},{closed}"))).await.expect("scanner");
        let (results, summary) = scanner.run_to_completion().await;

        assert_eq!(summary.ports_scanned, 2);
        assert_eq!(summary.ports_open, 1);
        assert_eq!(summary.ports_closed, 1);
        assert_eq!(summary.hosts_up, 1);
        assert!(summary.packets_sent >= 2);
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn retries_are_counted_and_bounded() {
        let config = ScanConfig::builder()
            .targets({
                let mut set = TargetSet::new();
                set.add(TargetSpec::parse("198.51.100.7").expect("literal"));
                set
            })
            .ports(PortSpec::parse("65030").expect("literal"))
            .skip_discovery(true)
            .retries(2)
            .fixed_timeout(Duration::from_millis(120))
            .report_all_states(true)
            .build()
            .expect("valid");

        let scanner = Scanner::new(config).await.expect("scanner");
        let (results, summary) = scanner.run_to_completion().await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].state, PortState::Filtered);
        assert_eq!(results[0].attempts, 3, "one probe plus two retries");
        assert_eq!(summary.packets_sent, 3);
    }

    #[tokio::test]
    async fn closed_ports_are_not_retried() {
        let (listener, port) = open_listener().await;
        drop(listener);
        let mut config = base_config(&port.to_string());
        config.retries = 3;
        let scanner = Scanner::new(config).await.expect("scanner");
        let (results, _) = scanner.run_to_completion().await;
        assert_eq!(results[0].state, PortState::Closed);
        assert_eq!(results[0].attempts, 1, "a RST is conclusive");
    }

    #[tokio::test]
    async fn uninteresting_results_are_hidden_by_default() {
        let (listener, port) = open_listener().await;
        drop(listener);
        let mut config = base_config(&port.to_string());
        config.report_all_states = false;
        let scanner = Scanner::new(config).await.expect("scanner");
        let (results, summary) = scanner.run_to_completion().await;
        assert!(results.is_empty(), "closed ports must not be reported by default");
        assert_eq!(summary.ports_closed, 1, "but they are still counted");
    }

    #[tokio::test]
    async fn service_detection_runs_on_open_ports() {
        let (listener, port) = open_listener().await;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = socket.write_all(b"SSH-2.0-OpenSSH_9.6p1\r\n").await;
                let _ = socket.flush().await;
            }
        });

        let mut config = base_config(&port.to_string());
        config.service_detection =
            ServiceDetection { timeout: Duration::from_secs(3), ..ServiceDetection::all() };
        let scanner = Scanner::new(config).await.expect("scanner");
        let (results, _) = scanner.run_to_completion().await;
        let service = results[0].service.as_ref().expect("service detected");
        assert_eq!(service.name.as_deref(), Some("ssh"));
    }

    #[tokio::test]
    async fn discovery_marks_a_dead_host_down_without_scanning_it() {
        let mut set = TargetSet::new();
        set.add(TargetSpec::parse("198.51.100.8").expect("literal"));
        let config = ScanConfig::builder()
            .targets(set)
            .ports(PortSpec::parse("80,443").expect("literal"))
            .discovery(DiscoveryConfig {
                icmp_echo: false,
                arp: false,
                tcp_ports: vec![65031],
                timeout: Duration::from_millis(150),
                ..DiscoveryConfig::default()
            })
            .build()
            .expect("valid");

        let scanner = Scanner::new(config).await.expect("scanner");
        let events: Vec<ScanEvent> = scanner.run().collect().await;
        assert!(events.iter().any(|e| matches!(e, ScanEvent::HostDown(_))));
        assert!(
            !events.iter().any(|e| matches!(e, ScanEvent::Port(_))),
            "a host that is down must not be port-scanned"
        );
    }

    #[tokio::test]
    async fn a_configuration_with_no_reachable_targets_is_rejected_early() {
        let mut set = TargetSet::new();
        set.add(TargetSpec::parse("192.0.2.0/30").expect("literal"));
        set.exclude(TargetSpec::parse("192.0.2.0/30").expect("literal"));
        let config = ScanConfig::builder()
            .targets(set)
            .ports(PortSpec::parse("80").expect("literal"))
            .build()
            .expect("valid");
        assert!(Scanner::new(config).await.is_err());
    }

    #[tokio::test]
    async fn the_work_queue_interleaves_hosts() {
        let (tx, rx) = mpsc::channel(8);
        for last in 1..=3u8 {
            tx.send(Target::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))).await.expect("send");
        }
        drop(tx);

        let ports = Arc::new(vec![(Protocol::Tcp, 80), (Protocol::Tcp, 443)]);
        let mut queue = WorkQueue::new(rx, ports, 64);

        let mut issued = Vec::new();
        while let Some((target, _, port)) = queue.next().await {
            issued.push((target.addr.to_string(), port));
        }

        assert_eq!(issued.len(), 6);
        // Every host's first port is issued before any host's second port.
        let first_round: Vec<u16> = issued[..3].iter().map(|(_, p)| *p).collect();
        assert_eq!(first_round, vec![80, 80, 80], "{issued:?}");
        let second_round: Vec<u16> = issued[3..].iter().map(|(_, p)| *p).collect();
        assert_eq!(second_round, vec![443, 443, 443], "{issued:?}");
    }

    #[tokio::test]
    async fn the_work_queue_ends_when_the_source_closes() {
        let (tx, rx) = mpsc::channel::<Target>(1);
        drop(tx);
        let mut queue = WorkQueue::new(rx, Arc::new(vec![(Protocol::Tcp, 80)]), 4);
        assert!(queue.next().await.is_none());
    }

    #[tokio::test]
    async fn dropping_the_stream_stops_the_scan() {
        let mut set = TargetSet::new();
        set.add(TargetSpec::parse("127.0.0.1").expect("literal"));
        let config = ScanConfig::builder()
            .targets(set)
            .ports(PortSpec::parse("1-2000").expect("literal"))
            .skip_discovery(true)
            .fixed_timeout(Duration::from_millis(200))
            .build()
            .expect("valid");
        let scanner = Scanner::new(config).await.expect("scanner");
        {
            let mut events = Box::pin(scanner.run());
            let _ = events.next().await;
        }
        // Nothing to assert beyond "this returns"; a leaked driver task that
        // ignored the closed channel would keep the runtime busy.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
