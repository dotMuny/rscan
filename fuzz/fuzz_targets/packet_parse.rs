//! Fuzz the raw-packet parser used by the SYN scan.
//!
//! These bytes come straight off a raw socket, which means an attacker on the
//! path chooses them. Parsing must never panic or read out of bounds.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rscan_core::scan::syn::parse_reply;

fuzz_target!(|data: &[u8]| {
    // Both framings: with an IPv4 header and without.
    let _ = parse_reply(data, false);
    let _ = parse_reply(data, true);
});
