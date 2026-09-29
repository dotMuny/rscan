# The concurrency model

This is the part of `rscan` worth reading the source for. Opening sockets is
easy; deciding *how many at once and how fast* is the whole problem.

## The failure mode being avoided

The naive design is "spawn a task per port and let the runtime sort it out".
With 65535 ports across a /24 that is sixteen million concurrent connect
attempts. What actually happens:

1. **Descriptor exhaustion.** Each in-flight connect holds a file descriptor.
   Past `RLIMIT_NOFILE` the kernel returns `EMFILE`, and a scanner that does not
   special-case it reports those ports as `filtered`. Silent false negatives.
2. **Conntrack exhaustion.** Any stateful firewall on the path — including the
   local one — has a finite connection table. Once it is full it *drops* new
   flows rather than rejecting them, so the scanner sees timeouts and reports
   `filtered` again.
3. **Buffer drops.** Even without a firewall, a burst larger than the path's
   buffering is discarded by the first hop that runs out of queue.
4. **ICMP rate limits.** Linux limits ICMP error generation to roughly one per
   second by default (`net.ipv4.icmp_ratelimit`). A UDP scan faster than that
   gets `open|filtered` for ports that are demonstrably closed.

Every one of these turns into the same symptom: **timeouts that look like
filtered ports**. A fast scanner that reports false negatives is worse than a
slow one that does not, because the result is confidently wrong.

## The three controllers

```
                    ┌──────────────────────────────────────┐
                    │              Governor                │
   probe ──────────►│                                      │──────► socket
                    │  1. global token bucket  (rate)      │
                    │  2. per-target token bucket (rate)   │
                    │  3. Tokio semaphore      (in flight) │
                    └───────────────┬──────────────────────┘
                                    │ outcome (responded / timed out / error)
                                    ▼
                    ┌──────────────────────────────────────┐
                    │  AIMD controller   +  RTT estimator  │
                    │  (pure logic, no I/O, unit-tested)   │
                    └───────────────┬──────────────────────┘
                                    │ new concurrency, new rate, new timeout
                                    └───────────► back into the Governor
```

Everything in the lower box is in [`rate.rs`](../crates/rscan-core/src/rate.rs)
and takes observations in and returns decisions out. It never touches a socket,
never sleeps, and never reads the clock except through an argument. That is what
makes the control algorithm testable with synthetic observation series instead
of with a flaky network test.

The upper box is [`governor.rs`](../crates/rscan-core/src/governor.rs), which is
the only place the two meet.

### 1. Token buckets — smoothing the rate

A bucket holds `burst` tokens and refills at `rate` tokens per second. A probe
takes one token; if there are none, it waits exactly as long as one takes to
accrue. Burst is `rate / 10`, i.e. a tenth of a second's worth, which is enough
to absorb scheduler jitter without letting an idle period turn into a thousand
packets at once.

There are two buckets. The **global** one is the overall speed limit. The
**per-target** one exists because a scan of a /24 at 5000 pps must not mean 5000
pps *at one host*; without it, the largest and most fragile host on the network
absorbs the entire budget.

A probe that passes the global bucket but is then blocked by its target's bucket
**refunds** its global token. Otherwise a single slow host would quietly consume
global budget that other hosts could have used.

### 2. The semaphore — bounding what is in flight

Rate limits packets per second; the semaphore limits packets *outstanding*. They
are different constraints: 500 pps with 10-second timeouts is 5000 in flight.
Conntrack and descriptor tables care about the second number.

Tokio's `Semaphore` can be resized while it is held: `add_permits` to grow,
`forget_permits` to shrink. Shrinking can only reclaim permits that are not
currently held, so a reduction may be applied partially; the governor tracks the
target and reconciles on **every** observation, not only when the controller
makes a decision. That detail matters — without it, a back-off during a burst of
in-flight work would be silently discarded.

Order of acquisition is rate first, then the semaphore. Taking the permit first
would let a probe that is waiting on its rate limit hold a concurrency slot that
another target could be using.

### 3. AIMD — deciding the numbers

Observations are batched into windows of `window` (default 64)
*network-attributable* outcomes. Local errors — no route, out of descriptors —
are counted but excluded, because they say nothing about the path.

At the end of each window:

| observed timeout ratio | action |
|---|---|
| `> high` (default 0.15) | **multiplicative decrease**: concurrency ×= 0.6, rate ×= 0.6, start a cooldown |
| `< low` (default 0.05) and not cooling down | **additive increase**: concurrency += 8, rate ×= 1.25 |
| otherwise | hold |

This is TCP's congestion control, applied to a scanner. The asymmetry is the
whole point: back off hard, recover slowly. Probing upwards as aggressively as
you back off produces oscillation, and oscillation in a port scanner shows up as
a scan where the same port is `open` on one run and `filtered` on the next.

The cooldown (2 windows by default) stops the controller from immediately
undoing a decrease on the strength of one clean window that only looked clean
*because* it had backed off.

Both limits are clamped to `[min, max]`, and `max_concurrency` is additionally
clamped to whatever the descriptor budget allows.

### RTT estimation — the adaptive timeout

A fixed timeout is wrong in both directions. One second is glacial on a LAN
where every RTT is 200 microseconds; it is far too short over a satellite link,
and every port comes back `filtered`.

`rscan` estimates the timeout per host with the same algorithm TCP uses for its
RTO (RFC 6298, Jacobson/Karels):

```
srtt   ← (1 - 1/8)·srtt   + (1/8)·rtt
rttvar ← (1 - 1/4)·rttvar + (1/4)·|srtt - rtt|
timeout = clamp(srtt + 4·rttvar, min, max)
```

Using the *deviation* rather than a multiple of the mean is what makes this
robust. A stable 200 ms link converges to a tight timeout; a jittery link with
the same mean gets a generous one. No per-network tuning, no flags.

Retransmissions double the timeout each time (Karn's algorithm), so a host that
is merely slow is not written off on the strength of one late reply.

## Retransmissions

A port that times out is retried `--retries` times (default 1) before being
called `filtered`. Each retransmission takes its own rate-limiter token and is
counted in `packets_sent` — a scanner whose retry path bypasses its own rate
limit sends three times the configured rate at precisely the moment the network
is already dropping packets.

Retries happen **only** on timeouts. A RST is conclusive; retrying it would
double the work for no information.

## Descriptor budget

Before the first probe, `rscan` reads `RLIMIT_NOFILE`, tries to raise the soft
limit to fit the requested concurrency (never above the hard limit), and if it
still does not fit, clamps concurrency and says so:

```
rscan: warning: concurrency reduced from 4096 to 992: RLIMIT_NOFILE is 1024
(hard limit 1048576) and each probe needs a descriptor. Raise it with
`ulimit -n 4128` to scan at the requested rate.
```

This is the difference between a scan that is slower than you asked for and a
scan that reports open ports as filtered.

## Work ordering

Probes are issued **round-robin across a sliding window of 64 hosts** rather
than host by host. With a per-target rate limit, issuing all of one host's ports
first would stall the queue behind that host's bucket. Round-robin keeps every
bucket busy.

To be explicit, because it is the kind of thing that gets misread: this is load
spreading, not evasion. The order is deterministic, the source address is real,
and nothing here tries to look like something other than a scanner.

## What you can turn off

- `--no-adapt` pins concurrency and rate at their starting values. Useful for
  reproducible benchmarks, and for the case where you know the network better
  than the controller does.
- `--timeout MS` pins the timeout and disables RTT estimation.
- `-T polite|normal|aggressive|insane` moves the starting points. These change
  rate and concurrency and nothing else.
