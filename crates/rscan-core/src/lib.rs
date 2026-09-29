//! `rscan-core` — an asynchronous port scanning and service detection engine.
//!
//! This crate is the whole scanner minus the command line: target and port
//! parsing, the TCP connect / TCP SYN / UDP scan engines, host discovery,
//! adaptive pacing, service and TLS detection, and resume state. It has no
//! dependency on `clap`, on terminal rendering or on any output format, so it
//! can be embedded in other tools.
//!
//! # The shape of the API
//!
//! A scan is a [`Scanner`] built from a [`ScanConfig`], and it produces a
//! `Stream` of [`ScanEvent`]s rather than a `Vec` at the end. That is the
//! central design decision: results are useful the moment they are found, and a
//! consumer writing JSONL to a pipeline never has to wait for a `/16` to
//! finish.
//!
//! ```no_run
//! use futures::StreamExt;
//! use rscan_core::{ScanConfig, ScanEvent, Scanner};
//! use rscan_core::ports::PortSpec;
//! use rscan_core::target::{TargetSet, TargetSpec};
//!
//! # async fn example() -> Result<(), rscan_core::Error> {
//! let mut targets = TargetSet::new();
//! targets.add(TargetSpec::parse("127.0.0.1")?);
//!
//! let config = ScanConfig::builder()
//!     .targets(targets)
//!     .ports(PortSpec::parse("22,80,443")?)
//!     .build()?;
//!
//! let scanner = Scanner::new(config).await?;
//! let mut events = scanner.run();
//! while let Some(event) = events.next().await {
//!     if let ScanEvent::Port(result) = event {
//!         println!("{}:{} is {}", result.addr, result.port, result.state);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Pacing
//!
//! The interesting engineering in this crate is in [`rate`]: a token bucket, a
//! Jacobson/Karels RTT estimator and an AIMD congestion controller, all pure
//! logic that can be tested without a network. [`governor`] couples them to a
//! Tokio semaphore whose size changes while the scan runs. See
//! `docs/concurrency.md` in the repository for the full model.
//!
//! # Responsible use
//!
//! Scanning hosts you do not own or have written permission to test is illegal
//! in most jurisdictions. The defaults here are deliberately conservative and
//! this crate implements no IDS evasion, no source spoofing and no
//! vulnerability exploitation; see the repository README.

#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(missing_docs)]
#![forbid(unsafe_op_in_unsafe_fn)]

pub mod discovery;
pub mod error;
pub mod governor;
pub mod limits;
pub mod model;
pub mod ports;
pub mod probe;
pub mod rate;
pub mod scan;
pub mod state;
pub mod target;

pub mod config;
mod scanner;

pub use config::{
    DiscoveryConfig, PerTargetRate, ScanConfig, ScanConfigBuilder, ScanMode, ServiceDetection,
};
pub use error::{Error, Result};
pub use model::{
    DiscoveryMethod, HostStatus, HttpInfo, PortResult, PortState, ProgressSnapshot, Protocol,
    Reason, ScanEvent, ScanSummary, ServiceInfo, TlsInfo, SCHEMA_VERSION,
};
pub use ports::PortSpec;
pub use scanner::Scanner;

pub use target::{Target, TargetSet, TargetSpec};

/// The version of this crate, for user agents and output metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
