//! `rscan` — the command-line front end.
//!
//! All the scanning logic lives in `rscan-core`; this crate parses arguments,
//! enforces the responsible-use guardrails, renders output and draws a progress
//! bar.
//!
//! Stream discipline: **data on stdout, everything else on stderr.** Progress
//! bars, warnings, the legal notice and log lines all go to stderr, so
//! `rscan -o jsonl … | jq` works exactly as expected.

use rscan_cli::{args, output, progress, safety};

use std::process::ExitCode;

use crate::args::{Args, OutputFormat};
use crate::output::{Output, ScanMeta, Sink};
use crate::progress::Progress;
use anyhow::{Context, Result};
use clap::Parser;
use futures::StreamExt;
use rscan_core::{Protocol, ScanEvent, ScanSummary, Scanner};

/// Exit code when the scan ran but found nothing at all.
const EXIT_NO_RESULTS: u8 = 1;
/// Exit code for a usage or runtime error.
const EXIT_ERROR: u8 = 2;

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    init_logging(&args);

    match run(args).await {
        Ok(found) => {
            if found {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_NO_RESULTS)
            }
        }
        Err(err) => {
            eprintln!("rscan: {err:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn init_logging(args: &Args) {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_env("RSCAN_LOG").unwrap_or_else(|_| EnvFilter::new(args.log_filter()));
    // Logs go to stderr so they never contaminate machine-readable output.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

/// Run a scan. Returns `true` when at least one result was reported.
async fn run(args: Args) -> Result<bool> {
    safety::show_first_run_notice(args.no_banner);

    let stdin_targets = read_stdin_targets(&args)?;
    let config = args.to_config(stdin_targets.as_deref())?;

    // Size check before anything touches the network.
    let plan = config.targets.resolve().await.context("resolving targets")?;
    let address_count = plan.approx_len();
    match safety::assess_scan_size(address_count, args.yes, safety::is_interactive()) {
        safety::LargeScanDecision::Proceed | safety::LargeScanDecision::ProceedConfirmed => {}
        safety::LargeScanDecision::NeedsConfirmation => {
            if !safety::confirm_large_scan(address_count)? {
                eprintln!("rscan: cancelled.");
                return Ok(false);
            }
        }
        safety::LargeScanDecision::RefuseNonInteractive => {
            anyhow::bail!(
                "refusing to scan {address_count} addresses (more than a /16) without a terminal \
                 to confirm on; pass --yes if you are authorised to scan all of them"
            );
        }
    }

    let scanner = Scanner::new(config).await.context("preparing the scan")?;

    let progress = if args.wants_progress() {
        Progress::new(scanner.probes_total())
    } else {
        Progress::disabled()
    };

    for warning in scanner.warnings() {
        progress.note(&format!("rscan: warning: {warning}"));
    }

    if !args.output.is_streaming() && !args.quiet {
        progress.note(&format!(
            "rscan: the {:?} format buffers, so results appear only when the scan finishes; \
             use -o jsonl to stream them",
            args.output
        ));
    }

    let mut sink = build_sink(&args)?;
    let meta = build_meta(&scanner);
    sink.start(&meta)?;

    let mut summary: Option<ScanSummary> = None;
    let mut reported = 0u64;
    let mut interrupted = false;

    {
        let mut events = Box::pin(scanner.run());
        let mut interrupt = Box::pin(tokio::signal::ctrl_c());

        loop {
            tokio::select! {
                biased;
                _ = &mut interrupt, if !interrupted => {
                    interrupted = true;
                    progress.note(
                        "rscan: interrupted; finishing what is in flight and writing results",
                    );
                    break;
                }
                event = events.next() => {
                    let Some(event) = event else { break };
                    match event {
                        ScanEvent::Started { .. } => {}
                        ScanEvent::HostUp(status) => sink.host_up(&status)?,
                        ScanEvent::HostDown(status) => sink.host_down(&status)?,
                        ScanEvent::Port(result) => {
                            reported += 1;
                            sink.port(&result)?;
                        }
                        ScanEvent::Progress(snapshot) => progress.update(&snapshot),
                        ScanEvent::Finished(done) => {
                            summary = Some(*done);
                            break;
                        }
                    }
                }
            }
        }
    }

    progress.finish();
    let summary = summary.unwrap_or_default();
    sink.finish(&summary)?;

    if interrupted {
        eprintln!("rscan: scan interrupted after {} result(s).", reported);
        if let Some(path) = &args.resume {
            eprintln!("rscan: resume with --resume {}", path.display());
        }
    }

    Ok(reported > 0)
}

fn read_stdin_targets(args: &Args) -> Result<Option<String>> {
    let wants_stdin = args.target_file.as_ref().is_some_and(|p| p.as_os_str() == "-");
    if !wants_stdin {
        return Ok(None);
    }
    let mut buffer = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin().lock(), &mut buffer)
        .context("reading targets from stdin")?;
    Ok(Some(buffer))
}

fn build_sink(args: &Args) -> Result<Box<dyn Sink>> {
    let out: Output = match &args.output_file {
        Some(path) => Box::new(std::io::BufWriter::new(
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => Box::new(std::io::stdout()),
    };

    Ok(match args.output {
        OutputFormat::Text => Box::new(output::text::TextSink::new(out, args.wants_color())),
        OutputFormat::Json => Box::new(output::json::JsonSink::new(out)),
        OutputFormat::Jsonl => Box::new(output::jsonl::JsonlSink::new(out)),
        OutputFormat::NmapXml => Box::new(output::xml::XmlSink::new(out)),
        OutputFormat::Csv => Box::new(output::csv_out::CsvSink::new(out)),
        OutputFormat::Grepable => Box::new(output::csv_out::GrepableSink::new(out)),
    })
}

fn build_meta(scanner: &Scanner) -> ScanMeta {
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    ScanMeta {
        command_line: std::env::args().collect::<Vec<_>>().join(" "),
        started_at: rscan_core::state::now_rfc3339(),
        started_unix: now.as_secs(),
        mode: scanner.effective_mode().as_str().to_string(),
        hosts_total: scanner.plan().approx_len().min(usize::MAX as u128) as usize,
        probes_total: scanner.probes_total(),
        tcp_ports: scanner.ports(Protocol::Tcp).to_vec(),
        udp_ports: scanner.ports(Protocol::Udp).to_vec(),
        version: rscan_core::VERSION.to_string(),
    }
}
