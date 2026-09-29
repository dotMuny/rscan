#!/usr/bin/env bash
#
# The reproducible scan benchmark quoted in the README: all 65535 TCP ports of
# localhost, with a handful of real listeners so the run is not purely negative.
#
# Localhost is the right target for a *reproducible* number precisely because it
# removes the network: what is being measured is the scanner's own overhead per
# probe, not the path. Numbers from a real network depend on the network and are
# not comparable between machines.

set -euo pipefail

BIN="${BIN:-./target/release/rscan}"
LISTENERS="${LISTENERS:-8}"

if [[ ! -x "$BIN" ]]; then
    echo "build it first: cargo build --release" >&2
    exit 1
fi

echo "== machine =="
if [[ -r /proc/cpuinfo ]]; then
    grep -m1 'model name' /proc/cpuinfo || true
    echo "cores: $(nproc)"
fi
echo "ulimit -n: $(ulimit -n)"
"$BIN" --version
echo

# Hold some ports open for the duration.
python3 - "$LISTENERS" <<'PY' &
import socket, sys, time
count = int(sys.argv[1])
socks = []
for _ in range(count):
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    s.listen(16)
    socks.append(s)
print("listening on:", ",".join(str(s.getsockname()[1]) for s in socks), flush=True)
time.sleep(600)
PY
HELPER=$!
trap 'kill "$HELPER" 2>/dev/null || true' EXIT
sleep 1

run() {
    local label="$1"; shift
    echo "== $label =="
    # shellcheck disable=SC2086
    /usr/bin/time -f "wall %e s, max rss %M KiB" \
        "$BIN" -p- 127.0.0.1 --skip-discovery --no-banner --no-progress "$@" \
        2>&1 | tail -6
    echo
}

run "default pacing"        -o text
run "aggressive"            -T aggressive -o text
# Pinned at the conservative starting rate. The point of this run is the
# contrast: adaptation is what turns this number into the one above.
run "adaptation off (pinned at the default 500 pps)" --no-adapt -c 1024 --timeout 200 -o text
