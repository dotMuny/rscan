<div align="center">

```
██████  ███████  ██████  █████  ███    ██
██   ██ ██      ██      ██   ██ ████   ██
██████  ███████ ██      ███████ ██ ██  ██
██   ██      ██ ██      ██   ██ ██  ██ ██
██   ██ ███████  ██████ ██   ██ ██   ████
```

**A port scanner that is fast *and* tells you the truth.**

TCP connect · SYN · UDP — with adaptive congestion control, service detection and resume

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![rust](https://img.shields.io/badge/rust-1.82%2B-orange?style=flat-square&logo=rust)
![tests](https://img.shields.io/badge/tests-296%20passing-brightgreen?style=flat-square)
![coverage](https://img.shields.io/badge/coverage-86.7%25-brightgreen?style=flat-square)
![unsafe](https://img.shields.io/badge/unsafe-1%20block-yellow?style=flat-square)

</div>

---

## The point

Opening sockets is easy. Deciding **how many at once and how fast** is the whole
problem — and getting it wrong does not make a scanner slow, it makes it *lie*.
Fire ten thousand simultaneous connections and you exhaust conntrack tables,
your packets get dropped in transit, and open ports come back `filtered`.

`rscan` runs a TCP-style congestion control loop over its own concurrency and
rate. Here is what that is worth, scanning all 65 535 ports of `localhost`:

<div align="center">

| | wall time | probes/sec |
|---|--:|--:|
| adaptation **off**, pinned at the conservative default | `131 s` | 500 |
| adaptation **on**, same defaults | **`3.76 s`** | ~17 400 |
| adaptation on, `-T aggressive` | **`1.15 s`** | ~57 000 |

</div>

**35× faster, with zero false negatives** — every run reported the same open
ports and `0 filtered`. The control loop is documented in
[`docs/concurrency.md`](docs/concurrency.md), and it is the part of this
repository worth reading.

---

## ⚠️ Before you use this

> **Scanning hosts you do not own, or do not have written authorisation to test,
> is illegal in most jurisdictions** — and a reliable way to have your network
> access revoked.
>
> Port scanning is a necessary tool for administering and auditing your *own*
> infrastructure. It is not a legitimate tool for probing someone else's.

Use `rscan` on systems you own, systems you have written permission to test, or
nothing at all.

The guardrails are deliberately in the way:

| safeguard | behaviour |
|---|---|
| 🐢 **Conservative defaults** | 500 probes/second, 64 concurrent. Faster requires an explicit flag. |
| 📜 **First-run notice** | Shown once, recorded in `$XDG_STATE_HOME/rscan/first-run`. `--no-banner` silences it. |
| 🛑 **Large-scan confirmation** | Anything above a `/16` prompts. With no terminal to prompt on it **refuses** rather than assuming yes. `--yes` to proceed. |

<details>
<summary><b>What is deliberately missing, and why</b></summary>

<br>

No decoy addresses, no source spoofing, no packet fragmentation, no bad
checksums, no idle/zombie scanning, no timing patterns designed to slip under
IDS thresholds. No vulnerability detection or exploitation either — service and
version identification is where the scope ends.

These exist in nmap with a research justification. Here they would add nothing
technically that the rest of the project does not already demonstrate, and they
change what the repository *is*. The timing presets
(`-T polite|normal|aggressive|insane`) move rate and concurrency and nothing
else. Full reasoning in [`docs/decisions.md §10`](docs/decisions.md).

</details>

---

## Quick start

```bash
cargo build --release                    # target/release/rscan
cargo install --path crates/rscan-cli    # …or onto your PATH
```

```bash
rscan 192.168.1.0/24                          # top 100 TCP ports of a /24
rscan -p- --service-detection host.internal   # every port, identify services
rscan -iL hosts.txt -o jsonl -O out.jsonl     # stream into a pipeline
rscan --udp -p 53,123,161,500,11211 10.0.0.1  # UDP with real payloads
rscan -p T:80,443,U:53,161 10.0.0.0/28        # both protocols at once
rscan -p- 10.0.0.0/22 --resume scan.state     # interrupt and pick up later
```

The default connect scan, UDP and service detection all run **unprivileged**.
SYN scanning needs `CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw+ep target/release/rscan    # or: just setcap
```

Without it, `--scan-type syn` says so and falls back to a connect scan rather
than silently producing garbage.

### What it looks like

```console
$ rscan -p 22,80,443,3306,8080 --service-detection 10.0.0.5
Starting rscan 0.1.0 at 2026-09-26T09:12:03.418Z (connect scan, 1 host(s), 5 probe(s))

Scan report for 10.0.0.5
PORT       STATE          SERVICE         VERSION
22/tcp     open           ssh             OpenSSH_9.6p1 Ubuntu-3ubuntu13.5 (protocol 2.0)
80/tcp     open           http            nginx/1.24.0
           |_ http: status=301 title="301 Moved Permanently" redirects to https
443/tcp    open           https           nginx/1.24.0
           |_ tls: TLSv1_3 alpn=h2 cn=*.internal.example sans=internal.example,*.internal.example
           |_ http: status=200 title="Internal Dashboard"
3306/tcp   open           mysql           MySQL 8.0.36-0ubuntu0.22.04.1
8080/tcp   closed

rscan done: 1 host(s) up of 1 scanned in 1.42s
  4 open, 1 closed, 0 filtered across 5 probes (5 packets sent)
  settled at 72 concurrent probes, 625 packets/second
```

---

## Features

| | |
|---|---|
| 🎯 **Three scan engines** | TCP connect (unprivileged), half-open SYN over raw sockets, UDP with per-service payloads |
| 🧠 **Adaptive pacing** | Token buckets, Jacobson/Karels RTT estimation, AIMD congestion control — all pure, testable logic |
| 🔍 **Service detection** | Banners, an embedded probe database, version extraction, TLS certificates, HTTP |
| 🌐 **IPv6 throughout** | Same code path as IPv4, not an afterthought |
| 📡 **Host discovery** | ICMP echo, TCP connect, TCP ACK, ARP via the neighbour table |
| 💾 **Resume** | Interrupt a `/22` and continue without repeating a single probe |
| 📤 **Six output formats** | `text` `jsonl` `json` `nmap-xml` `csv` `grepable` |
| 📦 **Embeddable** | The whole engine is [`rscan-core`](crates/rscan-core), with no CLI dependencies |

### Port states you can trust

Most hobby scanners collapse `closed` and `filtered`. That single shortcut
destroys most of the value of a scan — one means a host actively refused you,
the other means something ate your packet.

| state | meaning | evidence |
|---|---|---|
| 🟢 `open` | something accepted or answered | `syn-ack`, `udp-response` |
| 🔴 `closed` | the host actively refused | `reset`, `conn-refused`, `port-unreach` |
| 🟡 `filtered` | nothing came back, after every retransmission | `no-response`, `admin-prohibited`, `host-unreach` |
| 🟠 `open\|filtered` | UDP silence — genuinely ambiguous, and said so | `no-response` |

A local failure — out of descriptors, no route — is **never** reported as a port
state. That is the classic way a scanner produces confident false negatives, and
[`limits.rs`](crates/rscan-core/src/limits.rs) exists to prevent it.

### Output that pipes

Data on stdout, everything else on stderr — so this works with a progress bar on
screen:

```bash
rscan -p- 10.0.0.0/24 -o jsonl | jq -r 'select(.event=="port") | "\(.addr):\(.port)"'
```

`jsonl` is flushed line by line: the first open port reaches your pipeline
seconds into a scan that will run for an hour. `nmap-xml` validates against
nmap's DTD, so Metasploit and Faraday import it unchanged.

---

## How the pacing works

```
                    ┌──────────────────────────────────────┐
   probe ──────────►│  ① global token bucket    (rate)     │──────► socket
                    │  ② per-target bucket      (rate)     │
                    │  ③ Tokio semaphore, resized live     │
                    └───────────────┬──────────────────────┘
                                    │ responded / timed out / local error
                                    ▼
                    ┌──────────────────────────────────────┐
                    │   AIMD controller  +  RTT estimator  │
                    │   pure logic · no I/O · unit-tested  │
                    └───────────────┬──────────────────────┘
                                    └──────► new concurrency, rate, timeout
```

Three mechanisms, each solving a different failure:

**① ② Token buckets** bound packets *per second*. Two of them: a global limit,
and a per-target limit so a wide scan cannot dump its whole budget on one
fragile host. A probe blocked by its target's bucket refunds its global token.

**③ A live-resized semaphore** bounds packets *outstanding*, which is what
conntrack tables and `RLIMIT_NOFILE` actually care about. Tokio's semaphore can
only reclaim permits that are not currently held, so a reduction is reconciled
on *every* observation rather than once per decision — without that, backing off
during a burst is silently discarded.

**The AIMD controller** decides the numbers. Every 64 network-attributable
observations it measures the timeout ratio:

- above **15 %** → both limits × 0.6, and a cooldown starts
- below **5 %** → concurrency + 8, rate × 1.25
- in between → hold

Back off hard, recover slowly — the same asymmetry TCP uses, for the same
reason. Probing upwards as fast as you retreat produces oscillation, and
oscillation in a scanner means the same port is `open` on one run and `filtered`
on the next.

Because the controllers never touch a socket, you can watch one work with no
network at all:

```console
$ cargo run --example adaptive_control -p rscan-core
window timeouts  action      concurrency rate/s
0      0%        speed up    72          625
1      0%        speed up    80          781
…
5      0%        speed up    112         1907
6      70%       back off    67          1144   ← congestion appears
7      70%       back off    40          687
8      70%       back off    24          412
9      70%       back off    15          247
10     70%       back off    9           148
11     70%       back off    5           89
12     0%        hold        5           89     ← cooldown: no premature recovery
13     0%        hold        5           89
14     0%        speed up    13          111    ← congestion cleared
15     0%        speed up    21          139
…
23     0%        speed up    85          829
```

That behaviour is asserted by unit tests, not hoped for.

<details>
<summary><b>Adaptive timeouts, retransmissions and the descriptor budget</b></summary>

<br>

**Timeouts** are estimated per host with TCP's own RTO algorithm (RFC 6298,
Jacobson/Karels): `srtt + 4·rttvar`. Using the *deviation* rather than a multiple
of the mean is what makes it robust — a stable 200 ms link gets a tight timeout,
a jittery link with the same mean gets a generous one, with no tuning. A fixed
timeout is either glacial on a LAN or reports every port as `filtered` over a
satellite link.

**Retransmissions** (`--retries`, default 1) each take their own rate-limiter
token and are counted in `packets_sent`. A scanner whose retry path bypasses its
own rate limit sends three times the configured rate at precisely the moment the
network is already dropping packets. Retries happen only on timeouts — a RST is
conclusive.

**Descriptor budget**: before the first probe, `rscan` reads `RLIMIT_NOFILE`,
tries to raise the soft limit, and if it cannot, clamps concurrency and says so:

```
rscan: warning: concurrency reduced from 4096 to 992: RLIMIT_NOFILE is 1024
(hard limit 1048576) and each probe needs a descriptor. Raise it with
`ulimit -n 4128` to scan at the requested rate.
```

That is the difference between a scan that is slower than you asked for and a
scan that reports open ports as filtered.

**Work ordering**: probes are issued round-robin across a sliding window of 64
hosts, so a per-target rate limit cannot stall the queue behind one host. To be
explicit, because it is the kind of thing that gets misread: this is load
spreading, not evasion. The order is deterministic and the source address is
real.

</details>

---

## Benchmarks

<div align="center">

**AMD Ryzen 7 6800U** · 4 cores · Linux 7.0.14 x86-64 · Rust 1.98.1 release
(`opt-level=3`, thin LTO) · `ulimit -n` 524288

</div>

### Scanning all 65 535 TCP ports of localhost

| configuration | wall time | probes/sec | peak RSS |
|---|--:|--:|--:|
| `--no-adapt` (pinned at the 500 pps default) | 131 s | 500 | 8.7 MiB |
| default pacing | **3.76 s** | ~17 400 | 10.5 MiB |
| `-T aggressive` | **1.15 s** | ~57 000 | 19.9 MiB |

Every run found the same open ports and reported **0 filtered**. Going 35×
faster cost nothing in accuracy.

Loopback is deliberate: it removes the network, so what is measured is the
scanner's own per-probe overhead — the only number comparable between machines.
Reproduce with `just bench-scan`.

<details>
<summary><b>Parsing and probe matching (criterion)</b></summary>

<br>

| case | time |
|---|--:|
| parse `192.0.2.1` | 58 ns |
| parse `10.0.0.0/8` | 134 ns |
| parse `2001:db8::/64` | 425 ns |
| expand a `/24` (256 addresses) | 40 µs — **155 ns/addr** |
| expand a `/16` (65 536 addresses) | 9.1 ms — **139 ns/addr** |
| expand a `/16` with 16 exclusions | 11.8 ms — **180 ns/addr** |
| parse `22,80,443,8080` | 264 ns |
| parse `-` (all 65 535 ports) | 4.4 ms |
| match an SSH banner | 1.85 µs |
| match an HTTP response | 1.27 µs |
| 4 KiB of noise matching nothing | 855 ns |
| parse the whole probe database | 1.47 ms |

Expansion is what matters at scale: at ~140 ns per address a `/16` costs 9 ms to
enumerate, so target expansion never becomes the bottleneck. Port parsing is
dominated by the `BTreeSet` that de-duplicates, which is why `-p-` costs 4.4 ms —
paid once, at startup.

Reproduce with `just bench` (or `just bench-quick`).

</details>

---

## Service detection

`--service-detection` runs a fixed sequence against each open port, cheapest
first, stopping as soon as it is confident:

1. **Banner grab** on the connection the scan already opened — free, and
   identifies SSH, SMTP, FTP, POP3, IMAP, MySQL, VNC, Telnet and rsync outright.
2. **TLS handshake** — version, ALPN, certificate subject, issuer and SANs.
   Certificates are deliberately *not* validated: a self-signed or expired
   certificate is a finding, and refusing the handshake would throw away exactly
   the information worth having. A service on a non-standard port whose
   certificate reads `*.internal.example` has just identified itself.
3. **HTTP** — status, `Server`, `<title>`, and whether it redirects to HTTPS.
4. **Active probes** from [`probes.toml`](crates/rscan-core/data/probes.toml) —
   this project's own format, not nmap's data.

<div align="center">

**TCP** · HTTP · HTTPS · SSH · FTP · SMTP · POP3 · IMAP · MySQL · PostgreSQL ·
Redis · MongoDB · RDP · VNC · SMB · Telnet · DNS · memcached · Elasticsearch

**UDP** · DNS · SNMP · NTP · NetBIOS · IKE · memcached · mDNS · SSDP · rpcbind

</div>

Everything extracted from a response is sanitised and truncated first, so a
hostile banner cannot inject terminal escape sequences into your scan output or
break the field structure of the grepable format. There are tests for that.

---

## Using it as a library

The engine is [`rscan-core`](crates/rscan-core): no `clap`, no terminal
rendering, no output formats. Results are a `Stream`, not a `Vec` at the end.

```rust
use futures::StreamExt;
use rscan_core::ports::PortSpec;
use rscan_core::target::{TargetSet, TargetSpec};
use rscan_core::{ScanConfig, ScanEvent, Scanner};

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
```

Why a stream? A `/16` at the top 1000 ports is 65 million probes. A `Vec` means
the caller gets nothing for an hour and then everything at once, cannot draw an
honest progress bar, cannot feed a pipeline, and cannot stop early without
losing the work already done.

Runnable: [`basic_scan`](crates/rscan-core/examples/basic_scan.rs) ·
[`service_detection`](crates/rscan-core/examples/service_detection.rs) ·
[`adaptive_control`](crates/rscan-core/examples/adaptive_control.rs)

---

## Resume

```bash
rscan -p- 10.0.0.0/22 --resume scan.state     # ^C at any point
rscan -p- 10.0.0.0/22 --resume scan.state     # picks up where it stopped
```

Completed probes are stored as **merged port ranges**, so a finished host
collapses to a single entry instead of 65 535 of them. Writes are atomic. The
file records a fingerprint of the targets and ports, and resuming with different
ones is refused rather than silently producing a wrong answer.

---

## Development

```bash
just            # list the tasks
just test       # unit, integration and doc tests
just lint       # fmt --check and clippy -D warnings
just check      # lint + tests + dependency audit
just coverage   # line coverage of rscan-core, fails below 75%
just bench      # criterion
just fuzz-all   # every fuzz target, briefly
```

**Quality bar**, all of it reachable through `just check`:

- ✅ `cargo clippy --workspace --all-targets -- -D warnings` clean
- ✅ `cargo fmt --all --check` clean
- ✅ No `unwrap()` or `expect()` in `rscan-core` outside tests, enforced by
  `#![deny(clippy::unwrap_used, clippy::expect_used)]`
- ✅ **One** `unsafe` block in the whole engine — the raw-socket receive path —
  with a `// SAFETY:` comment justifying it
- ✅ `cargo deny check all` for licences and advisories; no OpenSSL, no
  `native-tls`
- ✅ Six `cargo-fuzz` targets: target parser, port parser, probe database,
  payload escape decoder, top-ports table, raw packet parser
- ✅ **296 tests**, **86.7 %** line coverage of `rscan-core`

### Tests worth knowing about

Everything binds real sockets on ephemeral loopback ports, or targets reserved
TEST-NET addresses. No network fixtures, no mocks.

| test | what it proves |
|---|---|
| `finds_exactly_the_listening_ports` | Binds N listeners, scans, finds exactly those open and no others. |
| `closed_is_distinguished_from_filtered` | A refused port is `closed` with reason `conn-refused`; a black hole is `filtered`. Not interchangeable. |
| `a_silent_listener_is_open_and_does_not_stall_detection` | A port that completes the handshake then says nothing is `open`, and detection gives up instead of hanging. |
| `the_first_result_arrives_long_before_the_scan_ends` | The first JSONL record is emitted in under half the total scan time. |
| `resuming_skips_work_already_done` | A resumed scan sends **zero** packets for completed work, and still reports the earlier findings. |
| `output_from_a_real_scan_validates` | The nmap-XML from a real scan validates against the vendored DTD. |
| `controller_recovers_after_congestion_clears` | Concurrency collapses under a high timeout rate and climbs back afterwards. |
| `the_detector_reports_https_on_a_non_standard_port` | Runs a real TLS server with a generated self-signed certificate; checks version, ALPN, SANs and the HTTP response inside the session. |

> [!IMPORTANT]
> **The SYN engine is not covered by a plain `cargo test`.** Its runtime path
> needs `CAP_NET_RAW`, so `tests/syn_scan.rs` announces on stderr that it is
> skipping and then passes. A green test run says nothing about whether the
> raw-socket path works. To actually exercise it:
>
> ```bash
> sudo -E "$(command -v cargo)" test -p rscan-core --test syn_scan -- --nocapture
> ```
>
> Everything checkable without privileges — packet construction, checksums,
> reply parsing and correlation, the privilege error and its `setcap` advice —
> is covered by the unit tests in `src/scan/syn.rs`, which do run everywhere.
> `src/scan/syn.rs` sits at 51 % line coverage as a result.

The nmap-XML check uses a small DTD validator written for the purpose
([`nmap_xml.rs`](crates/rscan-cli/tests/nmap_xml.rs)) — there is no pure-Rust
validating parser, and shelling out to `xmllint` would make the test depend on
whatever happens to be installed, skipping silently where it is not. A test that
silently skips is not a test.

---

## Design decisions

Where two reasonable options existed, [`docs/decisions.md`](docs/decisions.md)
records which was taken and why:

| decision | over |
|---|---|
| `etherparse` + `socket2` | `pnet` — no libpcap build dependency, smaller `unsafe` surface |
| Connected UDP sockets for ICMP unreachables | A raw ICMP listener — works unprivileged |
| The neighbour table for ARP | `AF_PACKET` — no `CAP_NET_RAW`, no `unsafe` |
| Count-based control windows | Time-based EWMA — deterministic, so the AIMD tests can assert exact values |
| Merged ranges for resume state | Per-port entries — a finished /24 would otherwise be 16 M rows |
| `scanner="nmap"` in nmap-XML | `scanner="rscan"` — the DTD declares a one-value enumeration, and compatibility is the entire point of that format |

---

<div align="center">

**Docs** · [Concurrency model](docs/concurrency.md) · [Design decisions](docs/decisions.md)

Released under the **MIT License**. See [LICENSE](LICENSE).

</div>
