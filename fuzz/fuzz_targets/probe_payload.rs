//! Fuzz the payload escape decoder.
//!
//! `\r \n \t \0 \\ \xNN` decode; anything else is an error. The decoder must
//! never panic on a truncated or invalid escape, and must never produce more
//! bytes than it consumed.

#![no_main]

use libfuzzer_sys::fuzz_target;
use rscan_core::probe::db::decode_payload;

fuzz_target!(|data: &str| {
    match decode_payload(data) {
        Ok(bytes) => {
            assert!(
                bytes.len() <= data.len(),
                "decoding {data:?} produced more bytes than the source"
            );
        }
        Err(message) => assert!(!message.is_empty(), "an error must say what went wrong"),
    }
});
