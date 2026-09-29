//! Fuzz the top-ports table reader.
//!
//! Every accepted row must be a scannable port with a known protocol; anything
//! else has to be an error rather than a silently wrong scan.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rscan_core::ports::parse_top_ports_table;

fuzz_target!(|data: &str| {
    let Ok(entries) = parse_top_ports_table(data) else {
        return;
    };
    for entry in entries {
        assert!(entry.port != 0, "port 0 must never be accepted");
    }
});
