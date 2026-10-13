//! Let LLM agents capture, generate and use secrets they can never read.
//!
//! Secrets live in the OS keyring. Agents refer to them by name; values are
//! resolved only when a child process is spawned, and the child's output is
//! redacted before anyone sees it. No operation returns a secret value.

pub mod error;
pub mod name;

pub use error::{Error, ErrorKind, Result};
pub use name::SecretName;
