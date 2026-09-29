# rscan-core

The scanning engine behind `rscan`, as a library. No CLI dependencies, no terminal rendering, no output formats — just
the parts you would want to embed.

```toml
[dependencies]
rscan-core = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
futures = "0.3"
```

## What it does

- **Targets and ports.** Addresses, CIDR blocks, hyphenated ranges, hostnames
  (A and AAAA), exclusions, `--top-ports`-style frequency lists. IPv6 on the
  same code path as IPv4. Expansion is a lazy iterator, so a `/8` costs nothing
  to describe.
- **Three scan engines.** TCP connect (no privileges), TCP SYN over raw sockets
  (`CAP_NET_RAW`), and UDP with per-service payloads.
- **Honest port states.** `open`, `closed`, `filtered` and `open|filtered` are
  distinguished, with the evidence (`syn-ack`, `reset`, `conn-refused`,
  `port-unreach`, `no-response`) reported alongside.
- **Adaptive pacing.** A token bucket, a Jacobson/Karels RTT estimator and an
  AIMD congestion controller, all pure logic and unit-testable without a
  network.
- **Service detection.** Banner grabbing, an embedded probe database, version
  extraction, TLS handshake details (version, ALPN, certificate names) and HTTP
  (status, `Server`, title, redirects).
- **Host discovery** and **resume state**.

## Usage

Results arrive as a `Stream`, not a `Vec` at the end:

```rust,no_run
use futures::StreamExt;
use rscan_core::ports::PortSpec;
use rscan_core::target::{TargetSet, TargetSpec};
use rscan_core::{ScanConfig, ScanEvent, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut targets = TargetSet::new();
    targets.add(TargetSpec::parse("192.168.1.0/24")?);

    let config = ScanConfig::builder()
        .targets(targets)
        .ports(PortSpec::parse("22,80,443")?)
        .max_rate_pps(500.0)
        .build()?;

    let scanner = Scanner::new(config).await?;
    let mut events = Box::pin(scanner.run());

    while let Some(event) = events.next().await {
        if let ScanEvent::Port(result) = event {
            println!("{}:{} {}", result.addr, result.port, result.state);
        }
    }
    Ok(())
}
```

See `examples/` for service detection and for driving the adaptive controller
directly with synthetic observations.

## Guarantees

- No `unwrap()` or `expect()` outside tests: enforced with
  `#![deny(clippy::unwrap_used, clippy::expect_used)]`.
- One `unsafe` block, in the raw-socket receive path, with a `// SAFETY:`
  justification.
- Every public item documented; doc examples compile and run under
  `cargo test --doc`.

## Responsible use

Scanning hosts you do not own or have written permission to test is illegal in
most jurisdictions. Defaults here are deliberately conservative, and this crate
implements no IDS evasion, no source spoofing and no vulnerability exploitation.

## Licence

MIT.
