//! Fuzz the port-specification parser.
//!
//! The contract: never panic, never allocate more than 65535 ports per
//! protocol, never yield port 0, and always yield a sorted, de-duplicated list.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rscan_core::ports::PortSpec;
use rscan_core::Protocol;

fuzz_target!(|data: &str| {
    let Ok(spec) = PortSpec::parse(data) else {
        return;
    };
    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let ports = spec.ports(protocol);
        assert!(ports.len() <= 65535, "{data:?} produced {} ports", ports.len());
        assert!(ports.iter().all(|&p| p != 0), "port 0 is not scannable: {data:?}");
        assert!(ports.windows(2).all(|w| w[0] < w[1]), "unsorted or duplicated: {data:?}");
    }
    assert!(!spec.is_empty(), "a successful parse must select at least one port: {data:?}");
});
