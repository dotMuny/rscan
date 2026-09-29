//! Benchmarks for target and port parsing.
//!
//! These are on the hot path for large scans: expanding a `/8` walks sixteen
//! million addresses through the same iterator, so a per-address cost of a few
//! hundred nanoseconds is the difference between instant and a minute of
//! startup.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rscan_core::ports::PortSpec;
use rscan_core::target::{TargetSet, TargetSpec};

fn parse_targets(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_parse");
    for spec in [
        "192.0.2.1",
        "10.0.0.0/8",
        "10.0.0.1-250",
        "10.0.0.1-10.0.3.255",
        "2001:db8::/64",
        "2001:db8::1-ffff",
    ] {
        group.bench_function(spec, |b| {
            b.iter(|| TargetSpec::parse(black_box(spec)).expect("valid specification"))
        });
    }
    group.finish();
}

fn expand_targets(c: &mut Criterion) {
    let mut group = c.benchmark_group("target_expand");
    for (name, spec, count) in
        [("slash_24", "192.0.2.0/24", 256u64), ("slash_16", "10.1.0.0/16", 65_536)]
    {
        let mut set = TargetSet::new();
        set.add(TargetSpec::parse(spec).expect("valid"));
        let plan = set.resolve_blocking().expect("no hostnames");
        group.throughput(Throughput::Elements(count));
        group.bench_function(name, |b| b.iter(|| black_box(plan.iter().count())));
    }

    // Exclusions are checked per address, so their cost matters at scale.
    let mut set = TargetSet::new();
    set.add(TargetSpec::parse("10.2.0.0/16").expect("valid"));
    for last in 0..16u8 {
        set.exclude(TargetSpec::parse(&format!("10.2.{last}.0/24")).expect("valid"));
    }
    let plan = set.resolve_blocking().expect("no hostnames");
    group.throughput(Throughput::Elements(65_536));
    group.bench_function("slash_16_with_16_exclusions", |b| {
        b.iter(|| black_box(plan.iter().count()))
    });
    group.finish();
}

fn parse_ports(c: &mut Criterion) {
    let mut group = c.benchmark_group("port_parse");
    for (name, spec) in [
        ("single", "80"),
        ("short_list", "22,80,443,8080"),
        ("range_1024", "1-1024"),
        ("all_65535", "-"),
        ("mixed_protocols", "T:1-1024,U:53,123,161"),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| PortSpec::parse(black_box(spec)).expect("valid specification"))
        });
    }
    group.finish();
}

fn top_ports(c: &mut Criterion) {
    c.bench_function("top_ports_100", |b| {
        b.iter_batched(
            || (),
            |()| PortSpec::top(rscan_core::Protocol::Tcp, black_box(100)).expect("valid"),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, parse_targets, expand_targets, parse_ports, top_ports);
criterion_main!(benches);
