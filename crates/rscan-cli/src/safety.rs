//! Responsible-use safeguards.
//!
//! A port scanner is a legitimate administration tool and also something people
//! point at systems they have no business touching. These are the guardrails,
//! and they are deliberately in the way rather than buried in a config file:
//!
//! - a one-time legal notice on first run, recorded so it does not nag;
//! - an interactive confirmation before scanning anything larger than a `/16`;
//! - conservative rate limits by default, with aggressive ones opt-in (that
//!   part lives in `rscan-core`'s defaults).

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::Result;

/// The first-run notice.
pub const LEGAL_NOTICE: &str = "\
rscan is a port scanner. Scanning hosts you do not own, or do not have written
authorisation to test, is illegal in most jurisdictions and is a good way to get
your network access revoked. Use it on your own systems, on systems you have
permission to test, or not at all.

Defaults here are deliberately conservative. This notice is shown once; pass
--no-banner to silence it.";

/// Anything larger than a /16 needs confirmation.
pub const CONFIRMATION_THRESHOLD: u128 = 65_536;

/// Where the "notice already shown" marker lives.
///
/// `$XDG_STATE_HOME/rscan/first-run`, falling back to `$HOME/.local/state`.
/// Returns `None` when neither is set, in which case the notice shows every
/// time — annoying but not wrong.
pub fn marker_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME").map(PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state"))
    })?;
    Some(base.join("rscan").join("first-run"))
}

/// Show the legal notice if it has not been shown before.
///
/// Returns `true` when it was shown.
pub fn show_first_run_notice(suppressed: bool) -> bool {
    if suppressed {
        return false;
    }
    let Some(path) = marker_path() else {
        eprintln!("{LEGAL_NOTICE}\n");
        return true;
    };
    if path.exists() {
        return false;
    }
    eprintln!("{LEGAL_NOTICE}\n");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, b"rscan has shown its first-run notice\n");
    true
}

/// What to do about a scan of `addresses` targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LargeScanDecision {
    /// Small enough; carry on.
    Proceed,
    /// Big, but `--yes` was given.
    ProceedConfirmed,
    /// Big, and confirmation is needed.
    NeedsConfirmation,
    /// Big, no `--yes`, and there is no terminal to ask on.
    RefuseNonInteractive,
}

/// Decide whether a scan of this size may start.
pub fn assess_scan_size(addresses: u128, assume_yes: bool, interactive: bool) -> LargeScanDecision {
    if addresses <= CONFIRMATION_THRESHOLD {
        return LargeScanDecision::Proceed;
    }
    if assume_yes {
        return LargeScanDecision::ProceedConfirmed;
    }
    if interactive {
        LargeScanDecision::NeedsConfirmation
    } else {
        LargeScanDecision::RefuseNonInteractive
    }
}

/// Ask on the terminal whether to proceed with a large scan.
pub fn confirm_large_scan(addresses: u128) -> Result<bool> {
    use std::io::{BufRead, Write};

    eprint!(
        "This will scan {addresses} addresses, which is more than a /16.\n\
         Confirm you are authorised to scan every one of them [y/N]: "
    );
    std::io::stderr().flush()?;

    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// `true` when both stdin and stderr are terminals, so a prompt can be shown
/// and answered.
pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_scans_need_no_confirmation() {
        assert_eq!(assess_scan_size(1, false, true), LargeScanDecision::Proceed);
        assert_eq!(assess_scan_size(256, false, false), LargeScanDecision::Proceed);
        // Exactly a /16 is still allowed.
        assert_eq!(assess_scan_size(65_536, false, false), LargeScanDecision::Proceed);
    }

    #[test]
    fn scans_larger_than_a_slash_16_need_confirmation() {
        assert_eq!(assess_scan_size(65_537, false, true), LargeScanDecision::NeedsConfirmation);
        assert_eq!(assess_scan_size(16_777_216, false, true), LargeScanDecision::NeedsConfirmation);
    }

    #[test]
    fn yes_skips_the_prompt() {
        assert_eq!(assess_scan_size(1_000_000, true, true), LargeScanDecision::ProceedConfirmed);
        assert_eq!(assess_scan_size(1_000_000, true, false), LargeScanDecision::ProceedConfirmed);
    }

    #[test]
    fn a_large_scan_in_a_pipeline_is_refused_rather_than_assumed() {
        assert_eq!(
            assess_scan_size(1_000_000, false, false),
            LargeScanDecision::RefuseNonInteractive,
            "an unattended run must not silently scan a /8"
        );
    }

    #[test]
    fn the_notice_says_what_it_needs_to() {
        assert!(LEGAL_NOTICE.contains("authorisation"));
        assert!(LEGAL_NOTICE.contains("illegal"));
        assert!(LEGAL_NOTICE.contains("--no-banner"));
    }

    #[test]
    fn suppressing_the_notice_works_without_touching_the_filesystem() {
        assert!(!show_first_run_notice(true));
    }

    #[test]
    fn the_marker_follows_xdg_when_set() {
        // Not using `std::env::set_var`: tests share a process. Just check the
        // shape of whatever the current environment produces.
        if let Some(path) = marker_path() {
            assert!(path.ends_with("rscan/first-run"), "{}", path.display());
        }
    }
}
