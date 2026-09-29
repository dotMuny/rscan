//! Benchmarks for the service-probe matcher.
//!
//! Every open port runs its response through every pattern of the probe that
//! produced it. On a scan that finds thousands of open ports, the regex work is
//! real, and a pathological pattern would show up here first.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use rscan_core::probe::db::ProbeDb;
use rscan_core::probe::matcher::match_response;
use rscan_core::Protocol;

const SSH_BANNER: &[u8] = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n";
const HTTP_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\nContent-Length: 615\r\n\r\n<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome</h1></body></html>";

fn match_known_banners(c: &mut Criterion) {
    let db = ProbeDb::embedded();
    let null = db.probe("NULL").expect("the NULL probe exists");
    let get = db.probe("GetRequest").expect("the GetRequest probe exists");

    let mut group = c.benchmark_group("probe_match");
    group.throughput(Throughput::Bytes(SSH_BANNER.len() as u64));
    group.bench_function("ssh_banner", |b| b.iter(|| match_response(null, black_box(SSH_BANNER))));

    group.throughput(Throughput::Bytes(HTTP_RESPONSE.len() as u64));
    group.bench_function("http_response", |b| {
        b.iter(|| match_response(get, black_box(HTTP_RESPONSE)))
    });

    // The worst case: a response that matches nothing, so every pattern runs to
    // completion.
    let noise: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
    group.throughput(Throughput::Bytes(noise.len() as u64));
    group.bench_function("no_match_4k", |b| b.iter(|| match_response(null, black_box(&noise))));
    group.finish();
}

fn select_probes(c: &mut Criterion) {
    let db = ProbeDb::embedded();
    let mut group = c.benchmark_group("probe_select");
    for port in [22u16, 80, 6379, 65000] {
        group.bench_function(format!("tcp_{port}"), |b| {
            b.iter(|| db.select(Protocol::Tcp, black_box(port), 9).len())
        });
    }
    group.finish();
}

fn parse_database(c: &mut Criterion) {
    let source = include_str!("../data/probes.toml");
    c.bench_function("probe_db_parse", |b| {
        b.iter(|| ProbeDb::parse(black_box(source)).expect("the shipped database is valid"))
    });
}

criterion_group!(benches, match_known_banners, select_probes, parse_database);
criterion_main!(benches);
