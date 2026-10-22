//! Error type shared by every part of the vault.

use std::backtrace::Backtrace;
use std::fmt;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// An error raised by a vault operation.
///
/// Messages name secrets and describe what failed; they never contain secret values.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    backtrace: Backtrace,
}

/// The category of an [`Error`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// A secret name does not match the allowed pattern.
    InvalidName(String),
    /// A secret's user does not match the allowed pattern; the payload names the rule.
    InvalidUser(String),
    /// No secret with this name exists.
    UnknownName(String),
    /// A secret with this name exists and overwrite was not requested.
    NameExists(String),
    /// A secret value was rejected; the payload says why, never what.
    InvalidValue(String),
    /// The OS keyring could not be reached or is locked.
    Keyring(String),
    /// The system clipboard could not be used.
    Clipboard(String),
    /// The metadata index could not be read or written.
    Index(String),
    /// The OS random source failed.
    Random(String),
    /// A child process could not be started or awaited.
    Spawn(String),
    /// An I/O operation failed (for example the MCP transport).
    Io(String),
    /// An interactive terminal was required but not available.
    NoTty,
    /// The caller supplied malformed arguments.
    Usage(String),
    /// A command was refused because it would leak a secret.
    Denied(String),
}

impl Error {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            backtrace: Backtrace::capture(),
        }
    }

    /// Returns the category of this error.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Returns the backtrace captured when the error was created.
    pub fn backtrace(&self) -> &Backtrace {
        &self.backtrace
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ErrorKind::InvalidName(name) => write!(
                f,
                "invalid secret name `{name}`: use 1-64 characters of a-z, 0-9, '.', '_', '-', starting with a letter or digit"
            ),
            ErrorKind::InvalidUser(why) => write!(f, "invalid user: {why}"),
            ErrorKind::UnknownName(name) => write!(f, "no secret named `{name}`"),
            ErrorKind::NameExists(name) => {
                write!(
                    f,
                    "secret `{name}` already exists; pass overwrite to replace it"
                )
            }
            ErrorKind::InvalidValue(why) => write!(f, "secret value rejected: {why}"),
            ErrorKind::Keyring(why) => write!(f, "OS keyring unavailable: {why}"),
            ErrorKind::Clipboard(why) => write!(f, "clipboard unavailable: {why}"),
            ErrorKind::Index(why) => write!(f, "metadata index error: {why}"),
            ErrorKind::Random(why) => write!(f, "random source failed: {why}"),
            ErrorKind::Spawn(why) => write!(f, "could not run command: {why}"),
            ErrorKind::Io(why) => write!(f, "I/O error: {why}"),
            ErrorKind::NoTty => write!(f, "this command needs an interactive terminal"),
            ErrorKind::Usage(why) | ErrorKind::Denied(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for Error {}

impl Error {
    /// Creates an error of the given kind.
    #[must_use]
    pub fn from_kind(kind: ErrorKind) -> Self {
        Self::new(kind)
    }

    /// Wraps an I/O error that occurred during `context`.
    #[must_use]
    pub fn from_io(context: &str, err: &std::io::Error) -> Self {
        Self::new(ErrorKind::Io(format!("{context}: {err}")))
    }
}
