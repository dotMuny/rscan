//! The progress bar.
//!
//! Drawn on **stderr**, never stdout. That separation is what lets
//! `rscan -o jsonl … | jq` work while a progress bar is on screen; mixing the
//! two is the classic way a scanner's output becomes unpipeable.

use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rscan_core::ProgressSnapshot;

/// A progress bar, or a no-op when progress is disabled.
pub struct Progress {
    bar: Option<ProgressBar>,
}

impl Progress {
    /// A disabled progress reporter.
    pub fn disabled() -> Self {
        Self { bar: None }
    }

    /// A progress bar over `total` probes, drawn on stderr.
    pub fn new(total: u64) -> Self {
        let bar = ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr());
        bar.set_style(Self::style());
        bar.enable_steady_tick(Duration::from_millis(120));
        Self { bar: Some(bar) }
    }

    fn style() -> ProgressStyle {
        ProgressStyle::with_template(
            "{spinner} [{elapsed_precise}] [{bar:32}] {pos}/{len} {percent:>3}% | {msg} | ETA {eta}",
        )
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("=> ")
    }

    /// Update from a scan snapshot.
    pub fn update(&self, snapshot: &ProgressSnapshot) {
        let Some(bar) = &self.bar else {
            return;
        };
        bar.set_position(snapshot.completed);
        if snapshot.total > 0 {
            bar.set_length(snapshot.total);
        }
        bar.set_message(format!(
            "{} open | {} conc | {:.0} pps | {:.0}% timeouts",
            snapshot.open,
            snapshot.concurrency,
            snapshot.rate_pps,
            snapshot.timeout_rate * 100.0
        ));
    }

    /// Print a line above the bar without corrupting it.
    pub fn note(&self, message: &str) {
        match &self.bar {
            Some(bar) => bar.println(message),
            None => eprintln!("{message}"),
        }
    }

    /// Remove the bar from the screen.
    pub fn finish(&self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> ProgressSnapshot {
        ProgressSnapshot {
            completed: 5,
            total: 10,
            open: 2,
            concurrency: 64,
            rate_pps: 500.0,
            timeout_rate: 0.1,
        }
    }

    #[test]
    fn a_disabled_reporter_does_nothing() {
        let progress = Progress::disabled();
        progress.update(&snapshot());
        progress.finish();
    }

    #[test]
    fn the_style_template_is_valid() {
        // `with_template` returning an error would silently fall back to the
        // default bar, so assert the template really parses.
        assert!(ProgressStyle::with_template(
            "{spinner} [{elapsed_precise}] [{bar:32}] {pos}/{len} {percent:>3}% | {msg} | ETA {eta}"
        )
        .is_ok());
    }

    #[test]
    fn updating_a_hidden_bar_is_safe() {
        let bar = ProgressBar::with_draw_target(Some(10), ProgressDrawTarget::hidden());
        let progress = Progress { bar: Some(bar) };
        progress.update(&snapshot());
        progress.note("hello");
        progress.finish();
    }
}
