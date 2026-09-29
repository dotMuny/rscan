# rscan development tasks. Run `just` for the list.

default:
    @just --list

# Build the workspace in debug mode.
build:
    cargo build --workspace --all-targets

# Build the optimised binary.
release:
    cargo build --release

# Run every test: unit, integration and doc.
test:
    cargo test --workspace --all-targets
    cargo test --workspace --doc

# Formatting and lints.
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings

# Reformat everything.
fmt:
    cargo fmt --all

# Lints, every test and the dependency audit, in one command.
check: lint test audit

# Licence and vulnerability audit of the dependency tree.
audit:
    cargo deny check all

# Line coverage of rscan-core. Fails below 75%.
coverage:
    cargo llvm-cov --package rscan-core --all-targets \
        --ignore-filename-regex '(benches|tests)/' \
        --fail-under-lines 75

# Coverage as a browsable HTML report.
coverage-html:
    cargo llvm-cov --package rscan-core --all-targets \
        --ignore-filename-regex '(benches|tests)/' --html
    @echo "report: target/llvm-cov/html/index.html"

# Criterion benchmarks.
bench:
    cargo bench --package rscan-core

# A quick benchmark run, for iterating.
bench-quick:
    cargo bench --package rscan-core -- --warm-up-time 1 --measurement-time 2 --sample-size 20

# The reproducible localhost scan benchmark quoted in the README.
bench-scan:
    cargo build --release
    ./scripts/bench-localhost.sh

# Fuzz one target, e.g. `just fuzz target_parse`. Needs nightly and cargo-fuzz.
fuzz target="target_parse" time="60":
    cargo +nightly fuzz run {{target}} -- -max_total_time={{time}}

# Briefly run every fuzz target, enough to catch one that stopped building.
fuzz-all:
    for t in target_parse port_parse probe_db probe_payload top_ports_table packet_parse; do \
        cargo +nightly fuzz run "$t" -- -max_total_time=20 || exit 1; \
    done

# Build and open the API documentation.
docs:
    cargo doc --workspace --no-deps --open

# Grant the release binary CAP_NET_RAW so SYN and ACK scans work unprivileged.
setcap:
    cargo build --release
    sudo setcap cap_net_raw+ep target/release/rscan
    @echo "target/release/rscan may now run SYN scans without sudo"

# Install the development tools these tasks need.
install-tools:
    cargo install cargo-deny cargo-llvm-cov
    cargo install cargo-fuzz --locked
