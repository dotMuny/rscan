//! Identify the services behind whatever is listening on localhost.
//!
//! ```sh
//! cargo run --example service_detection -p rscan-core
//! ```

use std::time::Duration;

use futures::StreamExt;
use rscan_core::config::ServiceDetection;
use rscan_core::ports::PortSpec;
use rscan_core::target::{TargetSet, TargetSpec};
use rscan_core::{Protocol, ScanConfig, ScanEvent, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("127.0.0.1")?);

    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::top(Protocol::Tcp, 100)?)
        .skip_discovery(true)
        .service_detection(ServiceDetection {
            // Raise the intensity to run the rarer probes as well.
            intensity: 7,
            timeout: Duration::from_secs(4),
            ..ServiceDetection::all()
        })
        .build()?;

    let scanner = Scanner::new(config).await?;
    let mut events = Box::pin(scanner.run());

    while let Some(event) = events.next().await {
        let ScanEvent::Port(result) = event else {
            continue;
        };
        let Some(service) = &result.service else {
            continue;
        };

        println!("{}/{}  {}", result.port, result.protocol, service.summary());

        if let Some(tls) = &service.tls {
            println!(
                "    tls: {} alpn={} cn={}",
                tls.version.as_deref().unwrap_or("?"),
                tls.alpn.as_deref().unwrap_or("-"),
                tls.subject_cn.as_deref().unwrap_or("-")
            );
        }
        if let Some(http) = &service.http {
            println!(
                "    http: {} {}",
                http.status.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                http.title.as_deref().unwrap_or("")
            );
        }
    }

    Ok(())
}
