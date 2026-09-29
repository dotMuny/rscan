//! Watch the AIMD controller react to a burst of timeouts — no network needed.
//!
//! The controllers in `rscan_core::rate` are pure logic: they take observations
//! and return decisions. That is what makes the pacing algorithm testable, and
//! it also makes it easy to see what it does.
//!
//! ```sh
//! cargo run --example adaptive_control -p rscan-core
//! ```

use rscan_core::rate::{AimdConfig, AimdController, ControlAction, ProbeOutcome};

fn main() {
    let config = AimdConfig { window: 20, ..AimdConfig::default() };
    let mut controller = AimdController::new(config);

    println!("{:<7}{:<10}{:<12}{:<12}rate/s", "window", "timeouts", "action", "concurrency");

    for window in 0..24 {
        // Congestion appears in windows 6..12 and then clears.
        let timeouts = if (6..12).contains(&window) { 14 } else { 0 };

        let mut decision = None;
        for index in 0..20 {
            let outcome =
                if index < timeouts { ProbeOutcome::TimedOut } else { ProbeOutcome::Responded };
            if let Some(made) = controller.observe(outcome) {
                decision = Some(made);
            }
        }

        let Some(decision) = decision else { continue };
        let marker = match decision.action {
            ControlAction::Decrease => "back off",
            ControlAction::Increase => "speed up",
            ControlAction::Hold => "hold",
        };
        println!(
            "{window:<7}{:<10}{marker:<12}{:<12}{:.0}",
            format!("{:.0}%", decision.timeout_rate * 100.0),
            decision.concurrency,
            decision.rate_pps
        );
    }
}
