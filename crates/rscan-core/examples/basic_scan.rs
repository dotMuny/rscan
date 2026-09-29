//! Scan a few ports on localhost and print the open ones.
//!
//! ```sh
//! cargo run --example basic_scan -p rscan-core
//! ```

use futures::StreamExt;
use rscan_core::ports::PortSpec;
use rscan_core::target::{TargetSet, TargetSpec};
use rscan_core::{ScanConfig, ScanEvent, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("127.0.0.1")?);

    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse("22,80,443,3306,5432,6379,8080")?)
        // Localhost is obviously up; do not spend a probe proving it.
        .skip_discovery(true)
        .build()?;

    let scanner = Scanner::new(config).await?;
    for warning in scanner.warnings() {
        eprintln!("warning: {warning}");
    }

    // Results arrive as they are found, not at the end.
    let mut events = Box::pin(scanner.run());
    while let Some(event) = events.next().await {
        match event {
            ScanEvent::Port(result) => {
                println!("{}:{} is {}", result.addr, result.port, result.state);
            }
            ScanEvent::Finished(summary) => {
                println!(
                    "\n{} open of {} probed in {:.2}s",
                    summary.ports_open,
                    summary.ports_scanned,
                    summary.elapsed.as_secs_f64()
                );
            }
            _ => {}
        }
    }

    Ok(())
}
