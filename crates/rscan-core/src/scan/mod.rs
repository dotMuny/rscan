//! The scan engines.
//!
//! Each engine answers one question — *what is the state of this port?* — and
//! nothing else. Pacing, retries, discovery and reporting live above them in
//! [`crate::Scanner`], so an engine is a thin, testable wrapper over one kind of
//! socket.
//!
//! - [`connect`] — full TCP handshake, no privileges required.
//! - [`syn`] — half-open SYN scan over raw sockets.
//! - [`udp`] — UDP with per-service payloads.

pub mod connect;
pub mod syn;
pub mod udp;

use std::io;

use crate::model::{PortState, Reason};
use crate::rate::ProbeOutcome;

/// What a single probe attempt concluded, before retries are considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The port state this attempt implies.
    pub state: PortState,
    /// The evidence behind it.
    pub reason: Reason,
    /// How the adaptive controller should account for this attempt.
    pub outcome: ProbeOutcome,
}

impl Verdict {
    /// A conclusive verdict backed by a response from the target.
    pub fn responded(state: PortState, reason: Reason) -> Self {
        Self { state, reason, outcome: ProbeOutcome::Responded }
    }

    /// Silence. Worth retrying, and evidence of congestion.
    pub fn timed_out() -> Self {
        Self {
            state: PortState::Filtered,
            reason: Reason::NoResponse,
            outcome: ProbeOutcome::TimedOut,
        }
    }

    /// A local failure. Not worth counting as congestion.
    pub fn local_error(state: PortState, reason: Reason) -> Self {
        Self { state, reason, outcome: ProbeOutcome::LocalError }
    }

    /// `true` when retrying could change the answer.
    pub fn is_retryable(self) -> bool {
        matches!(self.outcome, ProbeOutcome::TimedOut)
    }
}

/// Map an OS error from `connect(2)`/`send(2)` onto a port verdict.
///
/// The distinction this function draws is the reason the scanner is worth
/// using: `ECONNREFUSED` is a RST and means **closed**, an unreachable is an
/// ICMP error and means **filtered**, and a local resource failure means
/// neither and must not be reported as a port state at all.
pub(crate) fn classify_io_error(err: &io::Error) -> Verdict {
    if let Some(code) = err.raw_os_error() {
        if let Some(verdict) = classify_errno(code) {
            return verdict;
        }
    }
    match err.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
            Verdict::responded(PortState::Closed, Reason::ConnRefused)
        }
        io::ErrorKind::TimedOut => Verdict::timed_out(),
        io::ErrorKind::PermissionDenied => {
            Verdict::responded(PortState::Filtered, Reason::AdminProhibited)
        }
        _ => Verdict::local_error(PortState::Filtered, Reason::LocalError),
    }
}

#[cfg(unix)]
fn classify_errno(code: i32) -> Option<Verdict> {
    match code {
        libc::ECONNREFUSED => Some(Verdict::responded(PortState::Closed, Reason::ConnRefused)),
        libc::ECONNRESET => Some(Verdict::responded(PortState::Closed, Reason::Reset)),
        // The kernel turns ICMP admin-prohibited into EACCES on a connect().
        libc::EACCES | libc::EPERM => {
            Some(Verdict::responded(PortState::Filtered, Reason::AdminProhibited))
        }
        libc::EHOSTUNREACH | libc::ENETUNREACH | libc::ENETDOWN | libc::EHOSTDOWN => {
            // An ICMP unreachable is a real answer about the path, but it is not
            // congestion, so it must not push the controller around.
            Some(Verdict::local_error(PortState::Filtered, Reason::HostUnreachable))
        }
        libc::ETIMEDOUT => Some(Verdict::timed_out()),
        // Out of descriptors, out of ports, out of memory: our problem, not the
        // target's. Reporting these as `filtered` is exactly the false negative
        // the descriptor budget in `crate::limits` exists to prevent.
        libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EADDRNOTAVAIL => {
            Some(Verdict::local_error(PortState::Filtered, Reason::LocalError))
        }
        _ => None,
    }
}

#[cfg(not(unix))]
fn classify_errno(_code: i32) -> Option<Verdict> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_kind(kind: io::ErrorKind) -> Verdict {
        classify_io_error(&io::Error::new(kind, "test"))
    }

    #[test]
    fn refused_is_closed_not_filtered() {
        let verdict = from_kind(io::ErrorKind::ConnectionRefused);
        assert_eq!(verdict.state, PortState::Closed);
        assert_eq!(verdict.outcome, ProbeOutcome::Responded);
        assert!(!verdict.is_retryable());
    }

    #[test]
    fn timeouts_are_filtered_and_retryable() {
        let verdict = Verdict::timed_out();
        assert_eq!(verdict.state, PortState::Filtered);
        assert!(verdict.is_retryable());
    }

    #[test]
    fn local_failures_do_not_count_as_congestion() {
        let verdict = Verdict::local_error(PortState::Filtered, Reason::LocalError);
        assert_eq!(verdict.outcome, ProbeOutcome::LocalError);
        assert!(!verdict.is_retryable());
    }

    #[cfg(unix)]
    #[test]
    fn errno_classification_separates_the_three_cases() {
        let refused = classify_io_error(&io::Error::from_raw_os_error(libc::ECONNREFUSED));
        assert_eq!(refused.state, PortState::Closed);

        let unreachable = classify_io_error(&io::Error::from_raw_os_error(libc::EHOSTUNREACH));
        assert_eq!(unreachable.state, PortState::Filtered);
        assert_eq!(unreachable.reason, Reason::HostUnreachable);
        assert_eq!(unreachable.outcome, ProbeOutcome::LocalError);

        let exhausted = classify_io_error(&io::Error::from_raw_os_error(libc::EMFILE));
        assert_eq!(exhausted.outcome, ProbeOutcome::LocalError);
        assert_eq!(exhausted.reason, Reason::LocalError);

        let prohibited = classify_io_error(&io::Error::from_raw_os_error(libc::EACCES));
        assert_eq!(prohibited.state, PortState::Filtered);
        assert_eq!(prohibited.reason, Reason::AdminProhibited);
    }
}
