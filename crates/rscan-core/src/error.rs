//! Error types for `rscan-core`.
//!
//! Every fallible operation in this crate returns [`Error`]. The variants are
//! deliberately coarse: callers usually want to know *which stage* failed
//! (parsing, privileges, I/O) rather than the exact syscall.

use std::net::IpAddr;

/// Convenience alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The error type returned by every fallible `rscan-core` operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A target specification could not be parsed or expanded.
    #[error("invalid target {spec:?}: {reason}")]
    InvalidTarget {
        /// The offending specification, verbatim.
        spec: String,
        /// Human-readable explanation.
        reason: String,
    },

    /// A port specification could not be parsed.
    #[error("invalid port specification {spec:?}: {reason}")]
    InvalidPorts {
        /// The offending specification, verbatim.
        spec: String,
        /// Human-readable explanation.
        reason: String,
    },

    /// A hostname failed to resolve to any address.
    #[error("could not resolve host {host:?}: {reason}")]
    Resolve {
        /// The hostname that failed to resolve.
        host: String,
        /// Human-readable explanation.
        reason: String,
    },

    /// The configuration is internally inconsistent.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// An operation needs elevated privileges that the process does not have.
    ///
    /// The message always contains an actionable suggestion (typically
    /// `setcap cap_net_raw+ep`).
    #[error("insufficient privileges: {0}")]
    Privileges(String),

    /// The requested scan mode is not supported on this platform.
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),

    /// The embedded probe database (or a user-supplied one) is malformed.
    #[error("probe database error: {0}")]
    ProbeDb(String),

    /// Resume state could not be read, written or reconciled.
    #[error("resume state error: {0}")]
    State(String),

    /// An error occurred while talking to a specific host.
    #[error("{addr}: {source}")]
    Host {
        /// The address involved.
        addr: IpAddr,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A generic I/O error with no better classification.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// JSON serialisation or deserialisation failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl Error {
    /// Build an [`Error::InvalidTarget`].
    pub fn invalid_target(spec: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidTarget { spec: spec.into(), reason: reason.into() }
    }

    /// Build an [`Error::InvalidPorts`].
    pub fn invalid_ports(spec: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidPorts { spec: spec.into(), reason: reason.into() }
    }

    /// Build an [`Error::Config`].
    pub fn config(reason: impl Into<String>) -> Self {
        Self::Config(reason.into())
    }

    /// `true` when the error is about missing `CAP_NET_RAW`-style privileges,
    /// which the CLI uses to decide whether to fall back to a connect scan.
    pub fn is_privileges(&self) -> bool {
        matches!(self, Self::Privileges(_))
    }
}
