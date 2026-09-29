//! Fuzz the probe-database reader.
//!
//! A malformed database must be rejected with an error, never accepted with
//! nonsense in it and never a panic — including regex patterns that fail to
//! compile and payload escapes that do not decode.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rscan_core::probe::db::ProbeDb;
use rscan_core::Protocol;

fuzz_target!(|data: &str| {
    let Ok(db) = ProbeDb::parse(data) else {
        return;
    };
    for probe in db.probes() {
        assert!(probe.rarity <= 9);
        assert!(!probe.name.is_empty());
        assert!(!probe.matches.is_empty());
        if probe.protocol == Protocol::Udp {
            assert!(!probe.payload.is_empty(), "a UDP probe must send something");
        }
        for rule in &probe.matches {
            assert!(rule.confidence <= 10);
        }
    }
    // Selection must terminate and stay within the database.
    let selected = db.select(Protocol::Tcp, 80, 9);
    assert!(selected.len() <= db.probes().len());
});
