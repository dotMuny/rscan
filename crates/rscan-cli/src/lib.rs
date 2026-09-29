//! Library half of the `rscan` binary.
//!
//! Everything the command-line tool does lives here so that it can be tested
//! directly — in particular the output formats, which are tested against
//! nmap's DTD and against golden expectations in `tests/`.
//!
//! Stream discipline for the whole crate: **data on stdout, everything else on
//! stderr.** Progress bars, warnings, the legal notice and log lines all go to
//! stderr, so `rscan -o jsonl … | jq` works exactly as expected.

#![warn(missing_docs)]

pub mod args;
pub mod output;
pub mod progress;
pub mod safety;
