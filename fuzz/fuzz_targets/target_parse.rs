//! Fuzz the target-specification parser.
//!
//! The contract: `TargetSpec::parse` either returns a specification or an
//! error. It must never panic, and it must never produce a range whose
//! endpoints are of different families or reversed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rscan_core::target::TargetSpec;

fuzz_target!(|data: &str| {
    let Ok(spec) = TargetSpec::parse(data) else {
        return;
    };
    match spec {
        TargetSpec::Range(range) => {
            assert_eq!(
                range.start.is_ipv4(),
                range.end.is_ipv4(),
                "mixed address families in {data:?}"
            );
            assert!(range.len() >= 1, "empty range from {data:?}");
            // The first address must be inside the range it came from.
            assert!(range.contains(range.start));
            assert!(range.contains(range.end));
        }
        TargetSpec::Hostname(name) => {
            assert!(!name.is_empty());
            assert!(name.len() <= 253);
        }
    }
});
