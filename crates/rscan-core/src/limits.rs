//! File-descriptor limit discovery and adjustment.
//!
//! Each in-flight TCP connect probe holds a socket, so the concurrency limit is
//! bounded by `RLIMIT_NOFILE`. Exceeding it does not produce a clean error at
//! the top level: it produces `EMFILE` on individual connects, which a naive
//! scanner reports as `filtered`. That is the classic way a port scanner
//! silently lies, so `rscan` checks up front, raises the soft limit when it can,
//! and clamps concurrency with a warning when it cannot.

use serde::{Deserialize, Serialize};

/// Descriptors reserved for everything that is not a probe socket: stdio, the
/// resume state file, the output file, DNS sockets, and slack.
const RESERVED_DESCRIPTORS: usize = 32;

/// The outcome of reconciling requested concurrency with `RLIMIT_NOFILE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdBudget {
    /// Concurrency the caller asked for.
    pub requested: usize,
    /// Concurrency that is actually safe to use.
    pub allowed: usize,
    /// Soft limit observed after any adjustment, if known.
    pub soft_limit: Option<u64>,
    /// Hard limit, if known.
    pub hard_limit: Option<u64>,
    /// `true` when this process raised its own soft limit to fit the request.
    pub raised: bool,
    /// A message to show the user, when something needed saying.
    pub warning: Option<String>,
}

impl FdBudget {
    /// `true` when the requested concurrency had to be reduced.
    pub fn was_clamped(&self) -> bool {
        self.allowed < self.requested
    }
}

/// Read the current `RLIMIT_NOFILE` as `(soft, hard)`.
///
/// Returns `None` on platforms without the limit (Windows).
pub fn nofile_limit() -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        // SAFETY: `getrlimit` writes into a caller-provided `rlimit` and does
        // not retain the pointer. The struct is fully initialised by the call
        // on success, and we only read it when the call reports success.
        unsafe {
            let mut lim = std::mem::zeroed::<libc::rlimit>();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
                Some((lim.rlim_cur as u64, lim.rlim_max as u64))
            } else {
                None
            }
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Try to raise the soft `RLIMIT_NOFILE` to `target`, never above the hard
/// limit. Returns the soft limit in force afterwards.
pub fn try_raise_nofile(target: u64) -> Option<u64> {
    #[cfg(unix)]
    {
        let (soft, hard) = nofile_limit()?;
        if soft >= target {
            return Some(soft);
        }
        let wanted = target.min(hard);
        // SAFETY: `setrlimit` reads a caller-provided `rlimit` and does not
        // retain the pointer. `wanted` is clamped to the hard limit, so the
        // call is permitted for an unprivileged process.
        let ok = unsafe {
            let lim =
                libc::rlimit { rlim_cur: wanted as libc::rlim_t, rlim_max: hard as libc::rlim_t };
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim) == 0
        };
        if ok {
            Some(wanted)
        } else {
            Some(soft)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = target;
        None
    }
}

/// Decide how much concurrency is safe, raising the soft limit if that helps.
///
/// The policy, in order:
///
/// 1. If there is no limit to observe (Windows), grant the request.
/// 2. If the request already fits in the soft limit, grant it.
/// 3. Otherwise try to raise the soft limit towards the request, up to the hard
///    limit.
/// 4. If it still does not fit, clamp the concurrency and say so.
pub fn reconcile_concurrency(requested: usize) -> FdBudget {
    let requested = requested.max(1);
    let Some((soft, hard)) = nofile_limit() else {
        return FdBudget {
            requested,
            allowed: requested,
            soft_limit: None,
            hard_limit: None,
            raised: false,
            warning: None,
        };
    };

    let needed = requested.saturating_add(RESERVED_DESCRIPTORS) as u64;
    if soft >= needed {
        return FdBudget {
            requested,
            allowed: requested,
            soft_limit: Some(soft),
            hard_limit: Some(hard),
            raised: false,
            warning: None,
        };
    }

    let new_soft = try_raise_nofile(needed).unwrap_or(soft);
    let raised = new_soft > soft;
    if new_soft >= needed {
        return FdBudget {
            requested,
            allowed: requested,
            soft_limit: Some(new_soft),
            hard_limit: Some(hard),
            raised,
            warning: None,
        };
    }

    let allowed = budget_from_limit(new_soft);
    let warning = Some(format!(
        "concurrency reduced from {requested} to {allowed}: RLIMIT_NOFILE is {new_soft} \
         (hard limit {hard}) and each probe needs a descriptor. \
         Raise it with `ulimit -n {needed}` to scan at the requested rate."
    ));
    FdBudget {
        requested,
        allowed,
        soft_limit: Some(new_soft),
        hard_limit: Some(hard),
        raised,
        warning,
    }
}

/// Concurrency that fits under a given descriptor limit, at least 1.
fn budget_from_limit(soft: u64) -> usize {
    let usable = soft.saturating_sub(RESERVED_DESCRIPTORS as u64);
    usize::try_from(usable).unwrap_or(usize::MAX).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_modest_request_is_granted_untouched() {
        let budget = reconcile_concurrency(8);
        assert_eq!(budget.allowed, 8);
        assert!(!budget.was_clamped());
        assert!(budget.warning.is_none());
    }

    #[test]
    fn an_impossible_request_is_clamped_with_an_explanation() {
        // Far beyond any plausible hard limit, so this exercises the clamp on
        // any machine the tests run on.
        let budget = reconcile_concurrency(usize::MAX / 2);
        if budget.hard_limit.is_some() {
            assert!(budget.was_clamped(), "{budget:?}");
            let warning = budget.warning.expect("clamping must explain itself");
            assert!(warning.contains("RLIMIT_NOFILE"), "{warning}");
            assert!(warning.contains("ulimit -n"), "actionable advice: {warning}");
        } else {
            // Platform without the limit: the request passes through.
            assert_eq!(budget.allowed, usize::MAX / 2);
        }
    }

    #[test]
    fn allowed_concurrency_is_never_zero() {
        assert!(reconcile_concurrency(0).allowed >= 1);
        assert_eq!(budget_from_limit(0), 1);
        assert_eq!(budget_from_limit(RESERVED_DESCRIPTORS as u64), 1);
        assert_eq!(budget_from_limit(1000), 1000 - RESERVED_DESCRIPTORS);
    }

    #[cfg(unix)]
    #[test]
    fn the_limit_is_observable_on_unix() {
        let (soft, hard) = nofile_limit().expect("unix always has RLIMIT_NOFILE");
        assert!(soft > 0);
        assert!(hard >= soft);
    }
}
