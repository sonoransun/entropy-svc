use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    NoEntropy(String),
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
