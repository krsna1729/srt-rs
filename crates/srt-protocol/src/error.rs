use std::backtrace::{Backtrace, BacktraceStatus};
use std::panic::Location;

/// The kind of error from an encode/decode operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// The data content is invalid or corrupted.
    InvalidData,

    /// Internal state (e.g. of a struct) is invalid, or the requested
    /// operation cannot be performed.
    InvalidState,

    /// The supplied buffer is too small to hold the encode/decode result.
    InsufficientBuffer,

    /// An encryption/decryption error.
    CryptoError,

    /// The handshake was rejected.
    HandshakeRejected,
}

/// The error type.
pub struct Error {
    /// The kind of error that occurred.
    pub kind: ErrorKind,

    /// The reason the error occurred.
    pub reason: String,

    /// The source location where the error was created.
    pub location: &'static Location<'static>,

    /// A backtrace pointing at where the error occurred.
    ///
    /// Not captured unless the `RUST_BACKTRACE` environment variable is set.
    pub backtrace: Backtrace,
}

impl Error {
    /// Create an [`Error`] instance.
    #[track_caller]
    pub fn new(kind: ErrorKind) -> Self {
        Self::with_reason(kind, String::new())
    }

    /// Create an [`Error`] instance with a reason.
    #[track_caller]
    pub fn with_reason<T: Into<String>>(kind: ErrorKind, reason: T) -> Self {
        Self {
            kind,
            reason: reason.into(),
            location: Location::caller(),
            backtrace: Backtrace::capture(),
        }
    }

    #[track_caller]
    pub(crate) fn invalid_data<T: Into<String>>(reason: T) -> Self {
        Self::with_reason(ErrorKind::InvalidData, reason)
    }

    #[track_caller]
    pub(crate) fn invalid_state<T: Into<String>>(reason: T) -> Self {
        Self::with_reason(ErrorKind::InvalidState, reason)
    }

    #[track_caller]
    pub(crate) fn insufficient_buffer() -> Self {
        Self::new(ErrorKind::InsufficientBuffer)
    }

    #[track_caller]
    pub(crate) fn crypto_error<T: Into<String>>(reason: T) -> Self {
        Self::with_reason(ErrorKind::CryptoError, reason)
    }

    #[track_caller]
    pub(crate) fn handshake_rejected<T: Into<String>>(reason: T) -> Self {
        Self::with_reason(ErrorKind::HandshakeRejected, reason)
    }

    #[track_caller]
    pub(crate) fn check_buffer_size(required_size: usize, buf: &[u8]) -> Result<(), Self> {
        if buf.len() < required_size {
            Err(Self::insufficient_buffer())
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.reason)?;
        write!(f, " (at {}:{})", self.location.file(), self.location.line())?;
        if self.backtrace.status() == BacktraceStatus::Captured {
            write!(f, "\n\nBacktrace:\n{}", self.backtrace)?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}
