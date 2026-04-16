//! Error type used across mixrand.
//!
//! A single sum type captures the three failure modes the rest of the crate
//! wants to distinguish: operating-system I/O errors (wrapping
//! [`std::io::Error`]), entropy-source unavailability, and invalid
//! user-supplied arguments. Each variant carries enough detail for the
//! message emitted via `Display` to be actionable (e.g. which source failed,
//! which flag was invalid).
//!
//! A blanket `From<io::Error>` impl is provided so the common `?` patterns
//! in entropy-source code just work.

use std::fmt;
use std::io;

/// A unified error type for entropy collection, config parsing, and I/O.
///
/// # Examples
///
/// ```
/// use mixrand::error::Error;
/// let e = Error::NoEntropy("hwrng missing".into());
/// assert!(format!("{}", e).contains("entropy error"));
/// ```
#[derive(Debug)]
pub enum Error {
    /// Underlying `std::io::Error` from a file read, poll, write, or similar.
    Io(io::Error),
    /// An entropy source could not be read (device absent, empty, unhealthy,
    /// hardware disabled, insufficient pool, etc.).
    NoEntropy(String),
    /// User-supplied arguments (CLI flags, TOML config, env vars) were
    /// invalid or unparseable.
    InvalidArgs(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::NoEntropy(msg) => write!(f, "entropy error: {}", msg),
            Error::InvalidArgs(msg) => write!(f, "invalid arguments: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_io() {
        let err = Error::Io(io::Error::new(io::ErrorKind::NotFound, "gone"));
        let msg = format!("{}", err);
        assert!(msg.contains("I/O error"));
        assert!(msg.contains("gone"));
    }

    #[test]
    fn test_display_no_entropy() {
        let err = Error::NoEntropy("pool empty".into());
        let msg = format!("{}", err);
        assert!(msg.contains("entropy error"));
        assert!(msg.contains("pool empty"));
    }

    #[test]
    fn test_display_invalid_args() {
        let err = Error::InvalidArgs("bad value".into());
        let msg = format!("{}", err);
        assert!(msg.contains("invalid arguments"));
        assert!(msg.contains("bad value"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: Error = io_err.into();
        match err {
            Error::Io(e) => assert_eq!(e.kind(), io::ErrorKind::PermissionDenied),
            _ => panic!("expected Error::Io"),
        }
    }
}
