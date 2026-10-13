# llm-secret-vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `lsv`, a Rust CLI + MCP server + Claude Code hook that lets LLM agents capture, generate and use OS-keyring secrets without any operation ever returning a secret value.

**Architecture:** One crate (`llm-secret-vault`, lib + bin `lsv`). A `Vault` service combines a private `Backend` (OS keyring via `keyring`, or in-memory for tests) with a JSON metadata index. `inject` is the only module that resolves values; it spawns the child and pipes output through a streaming `Redactor`. `mcp`, `hook` and the CLI are thin front ends.

**Tech Stack:** Rust 2024 edition, keyring 3, arboard 3, clap 4, serde/serde_json, hmac 0.12 + sha2 0.10, base64 0.22, getrandom 0.3, regex, rpassword, zeroize, proptest, tempfile.

**Spec:** `docs/superpowers/specs/2026-10-13-llm-secret-vault-design.md`

## Global Constraints

- Crate name `llm-secret-vault`, binary `lsv`, edition 2024, MIT license.
- Cargo metadata: `authors = ["Enzo Lombardi <enzinol@gmail.com>"]`, repository `https://github.com/aovestdipaperino/llm-secret-vault`.
- Pin the dependency majors listed in Task 1 exactly. Newer majors exist (keyring 4, getrandom 0.4, hmac 0.13, sha2 0.11, base64 0.23) with different APIs; do not upgrade.
- **No read verb:** no public function, CLI subcommand or MCP tool returns a secret value. Only `inject` calls `Vault::resolve`; only `fingerprint` and `vault` call `Backend::resolve`.
- Error messages and `Debug` output never contain secret values.
- Secret names: `^[a-z0-9][a-z0-9._-]{0,63}$`. Keyring service `llm-secret-vault`, account = name. Reserved account `__lsv_hmac_key__`.
- Secret values: 4 to 16384 bytes (`MIN_VALUE_LEN`, `MAX_VALUE_LEN`).
- Redaction marker: `«redacted:<name>»`.
- MCP defaults: `secret_run` `timeout_s = 120`, `max_output_kb = 32`; capture `min_len = 8`; generate `length = 32`, `alphabet = alnum`.
- Rust guidelines (`~/rust-guidelines.txt`): every public item documented, first doc sentence under 15 words, `# Errors` on every public fn returning `Result`, `# Panics` where a public fn can panic, `//!` docs on every module, all public types `Debug`.
- `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` (with the pedantic lints from Cargo.toml) must pass at the end of every task.
- Tests must never touch the real OS keyring except tests marked `#[ignore]`.

## File Structure

```
Cargo.toml
LICENSE
README.md
.gitignore
.github/workflows/ci.yml
docs/DESIGN.md
src/lib.rs            crate docs, module list, re-exports
src/error.rs          Error struct + ErrorKind
src/name.rs           SecretName newtype
src/backend/mod.rs    Backend trait (pub(crate)), SERVICE const
src/backend/memory.rs MemoryBackend
src/backend/keyring_store.rs KeyringBackend
src/index.rs          metadata index (JSON file or in-memory)
src/fingerprint.rs    keyed HMAC fingerprints
src/vault.rs          Vault service, Meta, Source
src/redact.rs         streaming Redactor
src/inject.rs         RunRequest, RunOutput, run()
src/capture.rs        Clipboard trait, SystemClipboard, capture()
src/generate.rs       Alphabet, GenerateOptions, generate()
src/import.rs         interactive import()
src/mcp/mod.rs        Server, JSON-RPC handling, serve()
src/mcp/tools.rs      tool definitions and dispatch
src/hook.rs           PreToolUse guard
src/main.rs           clap CLI
tests/inject.rs       end-to-end injection tests (unix)
tests/no_leak.rs      property tests
tests/mcp.rs          MCP server tests
tests/hook.rs         hook rule table
tests/cli.rs          binary smoke tests
tests/invariants.rs   resolve call-site check
```

---

### Task 1: Scaffold, errors and secret names

**Files:**
- Create: `Cargo.toml`, `.gitignore`, `LICENSE`, `src/lib.rs`, `src/error.rs`, `src/name.rs`, `src/main.rs`

**Interfaces:**
- Produces: `llm_secret_vault::{Error, ErrorKind, Result, SecretName}`; `Error::new(ErrorKind) -> Error` (`pub(crate)`), `Error::kind(&self) -> &ErrorKind`; `SecretName::new(impl AsRef<str>) -> Result<SecretName>`, `SecretName::as_str(&self) -> &str`; `ErrorKind` variants `InvalidName(String)`, `UnknownName(String)`, `NameExists(String)`, `InvalidValue(String)`, `Keyring(String)`, `Clipboard(String)`, `Index(String)`, `Random(String)`, `Spawn(String)`, `NoTty`, `Usage(String)`.

- [ ] **Step 1: Create `Cargo.toml`**

```toml
[package]
name = "llm-secret-vault"
version = "0.1.0"
edition = "2024"
rust-version = "1.85"
authors = ["Enzo Lombardi <enzinol@gmail.com>"]
description = "Let LLM agents capture, generate and use OS-keyring secrets without ever reading them"
license = "MIT"
repository = "https://github.com/aovestdipaperino/llm-secret-vault"
homepage = "https://github.com/aovestdipaperino/llm-secret-vault"
readme = "README.md"
keywords = ["mcp", "secrets", "keyring", "llm", "claude"]
categories = ["command-line-utilities", "authentication"]

[[bin]]
name = "lsv"
path = "src/main.rs"

[dependencies]
arboard = "3"
base64 = "0.22"
clap = { version = "4", features = ["derive"] }
dirs = "6"
getrandom = "0.3"
hex = "0.4"
hmac = "0.12"
keyring = { version = "3", features = ["apple-native", "windows-native", "sync-secret-service", "crypto-rust"] }
regex = "1"
rpassword = "7"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
zeroize = "1"

[dev-dependencies]
proptest = "1"
tempfile = "3"

[lints.rust]
missing_debug_implementations = "warn"
unsafe_op_in_unsafe_fn = "warn"
unused_lifetimes = "warn"

[lints.clippy]
pedantic = { level = "warn", priority = -1 }
perf = { level = "warn", priority = -1 }
```

- [ ] **Step 2: Create `.gitignore` and `LICENSE`**

`.gitignore`:
```
/target
```

`LICENSE`: the standard MIT license text with the line `Copyright (c) 2026 Enzo Lombardi`.

- [ ] **Step 3: Write `src/error.rs`**

```rust
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
    /// An interactive terminal was required but not available.
    NoTty,
    /// The caller supplied malformed arguments.
    Usage(String),
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
    #[must_use]
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
            ErrorKind::UnknownName(name) => write!(f, "no secret named `{name}`"),
            ErrorKind::NameExists(name) => {
                write!(f, "secret `{name}` already exists; pass overwrite to replace it")
            }
            ErrorKind::InvalidValue(why) => write!(f, "secret value rejected: {why}"),
            ErrorKind::Keyring(why) => write!(f, "OS keyring unavailable: {why}"),
            ErrorKind::Clipboard(why) => write!(f, "clipboard unavailable: {why}"),
            ErrorKind::Index(why) => write!(f, "metadata index error: {why}"),
            ErrorKind::Random(why) => write!(f, "random source failed: {why}"),
            ErrorKind::Spawn(why) => write!(f, "could not run command: {why}"),
            ErrorKind::NoTty => write!(f, "this command needs an interactive terminal"),
            ErrorKind::Usage(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for Error {}
```

- [ ] **Step 4: Write the failing tests for `SecretName` at the bottom of `src/name.rs`**

Create `src/name.rs` containing only:

```rust
//! Validated secret names.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn accepts_valid_names() {
        for name in ["nas-root", "hf.token", "a", "0day", "aws_secret-2", &"x".repeat(64)] {
            assert_eq!(SecretName::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for name in ["", "Nas", "-lead", ".lead", "_lead", "has space", "ünï", &"x".repeat(65), "__lsv_hmac_key__"] {
            let err = SecretName::new(name).unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::InvalidName(_)), "{name}");
        }
    }

    #[test]
    fn round_trips_through_json() {
        let name = SecretName::new("nas-root").unwrap();
        let json = serde_json::to_string(&name).unwrap();
        assert_eq!(json, "\"nas-root\"");
        assert_eq!(serde_json::from_str::<SecretName>(&json).unwrap(), name);
        assert!(serde_json::from_str::<SecretName>("\"Bad\"").is_err());
    }

    #[test]
    fn parses_from_str() {
        let name: SecretName = "hf-token".parse().unwrap();
        assert_eq!(name.to_string(), "hf-token");
    }
}
```

Create `src/lib.rs`:

```rust
//! Let LLM agents capture, generate and use secrets they can never read.
//!
//! Secrets live in the OS keyring. Agents refer to them by name; values are
//! resolved only when a child process is spawned, and the child's output is
//! redacted before anyone sees it. No operation returns a secret value.

pub mod error;
pub mod name;

pub use error::{Error, ErrorKind, Result};
pub use name::SecretName;
```

Create `src/main.rs`:

```rust
//! `lsv`: command-line front end for llm-secret-vault.

fn main() {}
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `cargo test --lib name`
Expected: compile error, `cannot find type SecretName`.

- [ ] **Step 6: Implement `SecretName` above the tests in `src/name.rs`**

```rust
//! Validated secret names.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};

/// Maximum length of a secret name, in characters.
pub const MAX_NAME_LEN: usize = 64;

/// A validated secret name such as `nas-root` or `hf.token`.
///
/// Names are 1-64 characters of `a-z`, `0-9`, `.`, `_` and `-`, starting with
/// a letter or digit.
///
/// # Examples
///
/// ```
/// use llm_secret_vault::SecretName;
///
/// assert!(SecretName::new("nas-root").is_ok());
/// assert!(SecretName::new("Bad Name").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretName(String);

impl SecretName {
    /// Validates `name` and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidName`] when `name` breaks the naming rules.
    pub fn new(name: impl AsRef<str>) -> Result<Self> {
        let name = name.as_ref();
        let mut chars = name.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        let rest_ok = chars.all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
        });
        if first_ok && rest_ok && name.len() <= MAX_NAME_LEN {
            Ok(Self(name.to_owned()))
        } else {
            Err(Error::new(ErrorKind::InvalidName(name.to_owned())))
        }
    }

    /// Returns the name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretName {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<SecretName> for String {
    fn from(name: SecretName) -> Self {
        name.0
    }
}

impl FromStr for SecretName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SecretName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
```

(Keep the `#[cfg(test)] mod tests` block from Step 4 at the bottom.)

- [ ] **Step 7: Run tests and lints**

Run: `cargo test --lib name && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: 4 tests pass, no warnings. The doctest runs with `cargo test --doc` and passes.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: scaffold crate with Error and SecretName"
```

---

### Task 2: Storage backends

**Files:**
- Create: `src/backend/mod.rs`, `src/backend/memory.rs`, `src/backend/keyring_store.rs`
- Modify: `src/lib.rs` (add `mod backend;`)

**Interfaces:**
- Consumes: `Error::new`, `ErrorKind::Keyring`, `Result`.
- Produces (all `pub(crate)`): `trait Backend: Send + Sync + Debug { fn put(&self, account: &str, value: &str) -> Result<()>; fn resolve(&self, account: &str) -> Result<Option<Zeroizing<String>>>; fn delete(&self, account: &str) -> Result<bool>; }`, `MemoryBackend` (`Default`), `KeyringBackend` (`Default`), `const SERVICE: &str = "llm-secret-vault"`.

- [ ] **Step 1: Write `src/backend/mod.rs`**

```rust
//! Storage backends holding secret values.

mod keyring_store;
mod memory;

pub(crate) use keyring_store::KeyringBackend;
pub(crate) use memory::MemoryBackend;

use zeroize::Zeroizing;

use crate::error::Result;

/// Keyring service under which every entry is stored.
pub(crate) const SERVICE: &str = "llm-secret-vault";

/// Low-level secret storage keyed by account string.
///
/// Callers outside `vault` and `fingerprint` must not call [`Backend::resolve`].
pub(crate) trait Backend: Send + Sync + std::fmt::Debug {
    /// Stores `value` under `account`, replacing any existing value.
    fn put(&self, account: &str, value: &str) -> Result<()>;
    /// Returns the value under `account`, or `None` if absent.
    fn resolve(&self, account: &str) -> Result<Option<Zeroizing<String>>>;
    /// Deletes `account`; returns whether it existed.
    fn delete(&self, account: &str) -> Result<bool>;
}
```

- [ ] **Step 2: Write the failing memory backend test in `src/backend/memory.rs`**

```rust
//! In-memory backend used by tests and `Vault::in_memory`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;

    #[test]
    fn put_resolve_delete() {
        let backend = MemoryBackend::default();
        assert!(backend.resolve("a").unwrap().is_none());
        backend.put("a", "value-1").unwrap();
        assert_eq!(backend.resolve("a").unwrap().unwrap().as_str(), "value-1");
        backend.put("a", "value-2").unwrap();
        assert_eq!(backend.resolve("a").unwrap().unwrap().as_str(), "value-2");
        assert!(backend.delete("a").unwrap());
        assert!(!backend.delete("a").unwrap());
    }

    #[test]
    fn debug_does_not_print_values() {
        let backend = MemoryBackend::default();
        backend.put("a", "super-secret-value").unwrap();
        let debug = format!("{backend:?}");
        assert!(!debug.contains("super-secret-value"));
        assert!(debug.contains("entries: 1"));
    }
}
```

Add `mod backend;` to `src/lib.rs` below `pub mod name;`.

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test --lib backend`
Expected: compile error, `cannot find type MemoryBackend`, and `keyring_store` module file missing. Create an empty `src/backend/keyring_store.rs` with just `//! OS keyring backend.` and `pub(crate) struct KeyringBackend;` temporarily if needed to reach the MemoryBackend error.

- [ ] **Step 4: Implement `MemoryBackend` above the tests**

```rust
//! In-memory backend used by tests and `Vault::in_memory`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use zeroize::Zeroizing;

use super::Backend;
use crate::error::Result;

/// Backend that keeps values in process memory.
#[derive(Default)]
pub(crate) struct MemoryBackend {
    entries: Mutex<HashMap<String, Zeroizing<String>>>,
}

impl MemoryBackend {
    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Zeroizing<String>>> {
        self.entries.lock().expect("memory backend mutex poisoned")
    }
}

impl fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryBackend {{ entries: {} }}", self.entries().len())
    }
}

impl Backend for MemoryBackend {
    fn put(&self, account: &str, value: &str) -> Result<()> {
        self.entries()
            .insert(account.to_owned(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn resolve(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        Ok(self.entries().get(account).cloned())
    }

    fn delete(&self, account: &str) -> Result<bool> {
        Ok(self.entries().remove(account).is_some())
    }
}
```

- [ ] **Step 5: Implement `KeyringBackend` in `src/backend/keyring_store.rs`**

```rust
//! OS keyring backend (macOS Keychain, Secret Service, Windows Credential Manager).

use zeroize::Zeroizing;

use super::{Backend, SERVICE};
use crate::error::{Error, ErrorKind, Result};

/// Backend that stores values in the platform keyring.
#[derive(Debug, Default)]
pub(crate) struct KeyringBackend;

fn entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, account).map_err(map_err)
}

fn map_err(err: keyring::Error) -> Error {
    Error::new(ErrorKind::Keyring(err.to_string()))
}

impl Backend for KeyringBackend {
    fn put(&self, account: &str, value: &str) -> Result<()> {
        entry(account)?.set_password(value).map_err(map_err)
    }

    fn resolve(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        match entry(account)?.get_password() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(map_err(err)),
        }
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(map_err(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real OS keyring; run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "uses the real OS keyring"]
    fn round_trip_in_real_keyring() {
        let account = format!("__lsv_test_{}", std::process::id());
        let backend = KeyringBackend;
        backend.put(&account, "test-value-123").unwrap();
        assert_eq!(backend.resolve(&account).unwrap().unwrap().as_str(), "test-value-123");
        assert!(backend.delete(&account).unwrap());
        assert!(backend.resolve(&account).unwrap().is_none());
    }
}
```

- [ ] **Step 6: Run tests and lints**

Run: `cargo test --lib backend && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: 2 tests pass, 1 ignored. Clippy may flag `dead_code` for items unused until Task 3; add `#[allow(dead_code)]` on `mod backend;` in `lib.rs` with a comment `// used from Task 3 (vault)`, and remove it in Task 3.

Optionally verify the real keyring locally: `cargo test --lib backend -- --ignored` (macOS may show a Keychain prompt).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add keyring and in-memory storage backends"
```

---

### Task 3: Index, fingerprints and the Vault service

**Files:**
- Create: `src/index.rs`, `src/fingerprint.rs`, `src/vault.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Backend`, `MemoryBackend`, `KeyringBackend` (Task 2); `SecretName`, `Error`, `ErrorKind` (Task 1).
- Produces:
  - `pub struct Meta { pub name: SecretName, pub len: usize, pub fingerprint: String, pub source: Source, pub created: u64, pub rotated: Option<u64> }` (`Debug, Clone, PartialEq, Eq, Serialize, Deserialize`)
  - `pub enum Source { Clipboard, Generated, Imported }` (serde lowercase)
  - `pub struct Vault` (`Debug, Clone`) with `open() -> Result<Vault>`, `in_memory() -> Vault`, `list(&self, prefix: Option<&str>) -> Vec<Meta>`, `info(&self, &SecretName) -> Result<Meta>`, `exists(&self, &SecretName) -> bool`, `store(&self, &SecretName, value: &str, Source, overwrite: bool) -> Result<Meta>`, `delete(&self, &SecretName) -> Result<()>`, `pub(crate) resolve(&self, &SecretName) -> Result<Zeroizing<String>>`
  - `pub const MIN_VALUE_LEN: usize = 4; pub const MAX_VALUE_LEN: usize = 16 * 1024;`
  - `pub(crate) fn fingerprint(backend: &dyn Backend, value: &str) -> Result<String>` (8 lowercase hex chars)
  - `pub(crate) struct Index` with `in_memory()`, `load(impl AsRef<Path>) -> Result<Index>`, `default_path() -> Result<PathBuf>`, `get`, `list`, `upsert(Meta) -> Result<()>`, `remove(&SecretName) -> Result<bool>`

- [ ] **Step 1: Write `src/fingerprint.rs` with its test**

```rust
//! Keyed fingerprints that identify a value without revealing it.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::backend::Backend;
use crate::error::{Error, ErrorKind, Result};

/// Reserved keyring account holding the per-installation HMAC key.
pub(crate) const KEY_ACCOUNT: &str = "__lsv_hmac_key__";

/// Returns the first 8 hex characters of HMAC-SHA256(`value`) under the installation key.
///
/// Creates and stores a random key on first use.
pub(crate) fn fingerprint(backend: &dyn Backend, value: &str) -> Result<String> {
    let key = match backend.resolve(KEY_ACCOUNT)? {
        Some(key) => key,
        None => {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw)
                .map_err(|e| Error::new(ErrorKind::Random(e.to_string())))?;
            let key = Zeroizing::new(hex::encode(raw));
            backend.put(KEY_ACCOUNT, &key)?;
            key
        }
    };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(value.as_bytes());
    Ok(hex::encode(&mac.finalize().into_bytes()[..4]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MemoryBackend;

    #[test]
    fn stable_per_installation_and_distinct_across_values() {
        let backend = MemoryBackend::default();
        let a1 = fingerprint(&backend, "value-a").unwrap();
        let a2 = fingerprint(&backend, "value-a").unwrap();
        let b = fingerprint(&backend, "value-b").unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_eq!(a1.len(), 8);
        assert!(a1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_installations_give_different_fingerprints() {
        let one = MemoryBackend::default();
        let two = MemoryBackend::default();
        assert_ne!(fingerprint(&one, "same").unwrap(), fingerprint(&two, "same").unwrap());
    }
}
```

- [ ] **Step 2: Write `src/vault.rs` types and failing tests (no `impl Vault` yet)**

```rust
//! The vault service: store, describe and delete secrets by name.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::backend::Backend;
use crate::index::Index;
use crate::name::SecretName;

/// Minimum accepted length of a secret value, in characters.
pub const MIN_VALUE_LEN: usize = 4;
/// Maximum accepted length of a secret value, in bytes.
pub const MAX_VALUE_LEN: usize = 16 * 1024;

/// How a secret entered the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// Captured from the system clipboard.
    Clipboard,
    /// Generated randomly by the vault.
    Generated,
    /// Typed by a human at a terminal prompt.
    Imported,
}

/// Public metadata about a stored secret; never includes the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// The secret's name.
    pub name: SecretName,
    /// Length of the value in characters.
    pub len: usize,
    /// Keyed fingerprint of the value (8 hex characters).
    pub fingerprint: String,
    /// How the current value entered the vault.
    pub source: Source,
    /// Unix seconds when the secret was first stored.
    pub created: u64,
    /// Unix seconds of the last overwrite, if any.
    pub rotated: Option<u64>,
}

/// Handle to the secret store; cheap to clone.
#[derive(Debug, Clone)]
pub struct Vault {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    backend: Box<dyn Backend>,
    index: Index,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    fn name(s: &str) -> SecretName {
        SecretName::new(s).unwrap()
    }

    #[test]
    fn store_info_list_resolve() {
        let vault = Vault::in_memory();
        let meta = vault.store(&name("nas-root"), "hunter2-long", Source::Clipboard, false).unwrap();
        assert_eq!(meta.len, 12);
        assert_eq!(meta.source, Source::Clipboard);
        assert!(meta.rotated.is_none());
        assert_eq!(vault.info(&name("nas-root")).unwrap(), meta);
        assert_eq!(vault.list(None), vec![meta.clone()]);
        assert_eq!(vault.list(Some("nas")), vec![meta]);
        assert!(vault.list(Some("hf")).is_empty());
        assert_eq!(vault.resolve(&name("nas-root")).unwrap().as_str(), "hunter2-long");
    }

    #[test]
    fn refuses_overwrite_unless_asked() {
        let vault = Vault::in_memory();
        vault.store(&name("k"), "first-value", Source::Generated, false).unwrap();
        let err = vault.store(&name("k"), "second-value", Source::Generated, false).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::NameExists(_)));
        let first = vault.info(&name("k")).unwrap();
        let rotated = vault.store(&name("k"), "second-value", Source::Imported, true).unwrap();
        assert_eq!(rotated.created, first.created);
        assert!(rotated.rotated.is_some());
        assert_ne!(rotated.fingerprint, first.fingerprint);
        assert_eq!(vault.resolve(&name("k")).unwrap().as_str(), "second-value");
    }

    #[test]
    fn rejects_bad_lengths_without_echoing_value() {
        let vault = Vault::in_memory();
        let err = vault.store(&name("k"), "abc", Source::Imported, false).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidValue(_)));
        assert!(!err.to_string().contains("abc"));
        let big = "x".repeat(MAX_VALUE_LEN + 1);
        assert!(vault.store(&name("k"), &big, Source::Imported, false).is_err());
    }

    #[test]
    fn unknown_and_delete() {
        let vault = Vault::in_memory();
        assert!(matches!(vault.info(&name("nope")).unwrap_err().kind(), ErrorKind::UnknownName(_)));
        assert!(matches!(vault.resolve(&name("nope")).unwrap_err().kind(), ErrorKind::UnknownName(_)));
        vault.store(&name("gone"), "value-123", Source::Generated, false).unwrap();
        vault.delete(&name("gone")).unwrap();
        assert!(!vault.exists(&name("gone")));
        assert!(matches!(vault.delete(&name("gone")).unwrap_err().kind(), ErrorKind::UnknownName(_)));
    }

    #[test]
    fn hmac_key_is_not_listed() {
        let vault = Vault::in_memory();
        vault.store(&name("a"), "value-123", Source::Generated, false).unwrap();
        assert_eq!(vault.list(None).len(), 1);
    }
}
```

Add to `src/lib.rs` (remove the temporary `#[allow(dead_code)]` from Task 2):

```rust
pub mod vault;

mod backend;
mod fingerprint;
mod index;

pub use vault::{Meta, Source, Vault};
```

- [ ] **Step 3: Write `src/index.rs` with its test**

```rust
//! Index of secret names and metadata; never holds values.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::vault::Meta;

const INDEX_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct IndexFile {
    version: u32,
    secrets: BTreeMap<SecretName, Meta>,
}

impl IndexFile {
    fn empty() -> Self {
        Self {
            version: INDEX_VERSION,
            secrets: BTreeMap::new(),
        }
    }
}

/// Metadata index persisted as JSON, or kept in memory when `path` is `None`.
#[derive(Debug)]
pub(crate) struct Index {
    path: Option<PathBuf>,
    state: Mutex<IndexFile>,
}

fn index_err(why: String) -> Error {
    Error::new(ErrorKind::Index(why))
}

impl Index {
    pub(crate) fn in_memory() -> Self {
        Self {
            path: None,
            state: Mutex::new(IndexFile::empty()),
        }
    }

    pub(crate) fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| index_err(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => IndexFile::empty(),
            Err(e) => return Err(index_err(format!("{}: {e}", path.display()))),
        };
        Ok(Self {
            path: Some(path),
            state: Mutex::new(file),
        })
    }

    pub(crate) fn default_path() -> Result<PathBuf> {
        dirs::config_dir()
            .map(|dir| dir.join("llm-secret-vault").join("index.json"))
            .ok_or_else(|| index_err("this platform has no config directory".to_owned()))
    }

    fn state(&self) -> MutexGuard<'_, IndexFile> {
        self.state.lock().expect("index mutex poisoned")
    }

    pub(crate) fn get(&self, name: &SecretName) -> Option<Meta> {
        self.state().secrets.get(name).cloned()
    }

    pub(crate) fn list(&self, prefix: Option<&str>) -> Vec<Meta> {
        self.state()
            .secrets
            .values()
            .filter(|m| prefix.is_none_or(|p| m.name.as_str().starts_with(p)))
            .cloned()
            .collect()
    }

    pub(crate) fn upsert(&self, meta: Meta) -> Result<()> {
        let mut state = self.state();
        state.secrets.insert(meta.name.clone(), meta);
        self.persist(&state)
    }

    pub(crate) fn remove(&self, name: &SecretName) -> Result<bool> {
        let mut state = self.state();
        let existed = state.secrets.remove(name).is_some();
        self.persist(&state)?;
        Ok(existed)
    }

    fn persist(&self, file: &IndexFile) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let io = |e: std::io::Error| index_err(format!("{}: {e}", path.display()));
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io)?;
        }
        let bytes = serde_json::to_vec_pretty(file).map_err(|e| index_err(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, bytes).map_err(io)?;
        fs::rename(&tmp, path).map_err(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::Source;

    fn meta(name: &str) -> Meta {
        Meta {
            name: SecretName::new(name).unwrap(),
            len: 12,
            fingerprint: "deadbeef".to_owned(),
            source: Source::Generated,
            created: 1,
            rotated: None,
        }
    }

    #[test]
    fn persists_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("index.json");
        let index = Index::load(&path).unwrap();
        index.upsert(meta("a")).unwrap();
        index.upsert(meta("b")).unwrap();
        assert!(index.remove(&SecretName::new("b").unwrap()).unwrap());
        let reloaded = Index::load(&path).unwrap();
        assert_eq!(reloaded.list(None), vec![meta("a")]);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"version\": 1"));
    }

    #[test]
    fn corrupt_file_is_an_index_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        fs::write(&path, "not json").unwrap();
        assert!(matches!(Index::load(&path).unwrap_err().kind(), ErrorKind::Index(_)));
    }
}
```

- [ ] **Step 4: Run tests to verify the vault tests fail**

Run: `cargo test --lib`
Expected: compile errors in `vault::tests`, `no function or associated item named in_memory found for struct Vault`.

- [ ] **Step 5: Implement `Vault` in `src/vault.rs` (between the types and the tests)**

Add these imports at the top of `src/vault.rs`:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::backend::{KeyringBackend, MemoryBackend};
use crate::error::{Error, ErrorKind, Result};
use crate::fingerprint::fingerprint;
```

Then:

```rust
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn unknown(name: &SecretName) -> Error {
    Error::new(ErrorKind::UnknownName(name.to_string()))
}

impl Vault {
    /// Opens the vault backed by the OS keyring and the default index file.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Index`] if the index file exists but cannot be read
    /// or parsed, or if the platform has no config directory.
    pub fn open() -> Result<Self> {
        let index = Index::load(Index::default_path()?)?;
        Ok(Self::with_parts(Box::new(KeyringBackend), index))
    }

    /// Creates a vault that lives only in process memory.
    ///
    /// # Examples
    ///
    /// ```
    /// use llm_secret_vault::{SecretName, Source, Vault};
    ///
    /// let vault = Vault::in_memory();
    /// let name = SecretName::new("demo").unwrap();
    /// let meta = vault.store(&name, "example-value", Source::Generated, false).unwrap();
    /// assert_eq!(meta.len, 13);
    /// ```
    #[must_use]
    pub fn in_memory() -> Self {
        Self::with_parts(Box::new(MemoryBackend::default()), Index::in_memory())
    }

    fn with_parts(backend: Box<dyn Backend>, index: Index) -> Self {
        Self {
            inner: Arc::new(Inner { backend, index }),
        }
    }

    /// Lists metadata for every secret, optionally filtered by name prefix.
    #[must_use]
    pub fn list(&self, prefix: Option<&str>) -> Vec<Meta> {
        self.inner.index.list(prefix)
    }

    /// Returns metadata for one secret.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::UnknownName`] if no such secret exists.
    pub fn info(&self, name: &SecretName) -> Result<Meta> {
        self.inner.index.get(name).ok_or_else(|| unknown(name))
    }

    /// Returns whether a secret with this name exists.
    #[must_use]
    pub fn exists(&self, name: &SecretName) -> bool {
        self.inner.index.get(name).is_some()
    }

    /// Stores `value` under `name` and returns its metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidValue`] if the value length is out of range,
    /// [`ErrorKind::NameExists`] if the name exists and `overwrite` is false,
    /// [`ErrorKind::Keyring`] or [`ErrorKind::Index`] if storage fails.
    pub fn store(
        &self,
        name: &SecretName,
        value: &str,
        source: Source,
        overwrite: bool,
    ) -> Result<Meta> {
        let len = value.chars().count();
        if len < MIN_VALUE_LEN {
            return Err(Error::new(ErrorKind::InvalidValue(format!(
                "{len} characters, minimum is {MIN_VALUE_LEN}"
            ))));
        }
        if value.len() > MAX_VALUE_LEN {
            return Err(Error::new(ErrorKind::InvalidValue(format!(
                "{} bytes, maximum is {MAX_VALUE_LEN}",
                value.len()
            ))));
        }
        let existing = self.inner.index.get(name);
        if existing.is_some() && !overwrite {
            return Err(Error::new(ErrorKind::NameExists(name.to_string())));
        }
        self.inner.backend.put(name.as_str(), value)?;
        let now = now_secs();
        let meta = Meta {
            name: name.clone(),
            len,
            fingerprint: fingerprint(self.inner.backend.as_ref(), value)?,
            source,
            created: existing.as_ref().map_or(now, |m| m.created),
            rotated: existing.map(|_| now),
        };
        self.inner.index.upsert(meta.clone())?;
        Ok(meta)
    }

    /// Deletes a secret from the keyring and the index.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::UnknownName`] if the secret exists in neither,
    /// or [`ErrorKind::Keyring`] / [`ErrorKind::Index`] if deletion fails.
    pub fn delete(&self, name: &SecretName) -> Result<()> {
        let in_index = self.inner.index.remove(name)?;
        let in_store = self.inner.backend.delete(name.as_str())?;
        if in_index || in_store {
            Ok(())
        } else {
            Err(unknown(name))
        }
    }

    /// Returns a secret's value. Only `inject` may call this.
    pub(crate) fn resolve(&self, name: &SecretName) -> Result<Zeroizing<String>> {
        self.inner
            .backend
            .resolve(name.as_str())?
            .ok_or_else(|| unknown(name))
    }
}
```

- [ ] **Step 6: Run tests and lints**

Run: `cargo test --lib && cargo test --doc && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all vault, index, fingerprint, backend and name tests pass. `Vault::resolve` will trigger a `dead_code` warning until Task 5; add `#[allow(dead_code)] // used by inject (Task 5)` on it and remove it in Task 5.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add Vault service with metadata index and keyed fingerprints"
```

---

### Task 4: Streaming redactor

**Files:**
- Create: `src/redact.rs`
- Modify: `src/lib.rs` (add `pub mod redact;`)
- Test: `tests/no_leak.rs`

**Interfaces:**
- Produces: `pub struct Redactor` (`Clone`, manual `Debug`) with `Redactor::new<'a>(impl IntoIterator<Item = (&'a str, &'a str)>) -> Redactor` taking `(label, value)` pairs, `push(&mut self, &[u8]) -> Vec<u8>`, `finish(self) -> Vec<u8>`; `pub fn redact_all<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>, input: &[u8]) -> Vec<u8>`.

- [ ] **Step 1: Write failing unit tests in `src/redact.rs`**

```rust
//! Streaming redaction of secret values and their common encodings.

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(secrets: &[(&str, &str)], input: &str) -> String {
        String::from_utf8(redact_all(secrets.iter().copied(), input.as_bytes())).unwrap()
    }

    #[test]
    fn replaces_raw_value() {
        assert_eq!(
            redact(&[("nas", "hunter2-secret")], "pw=hunter2-secret ok"),
            "pw=«redacted:nas» ok"
        );
    }

    #[test]
    fn replaces_common_encodings() {
        let value = "p@ss w0rd!";
        let secrets = [("k", value)];
        for encoded in [
            "cEBzcyB3MHJkIQ==",           // base64 standard
            "cEBzcyB3MHJkIQ",             // base64 without padding
            "p%40ss%20w0rd%21",           // percent-encoded
            "7040737320773072642",        // prefix of hex lower, must NOT be redacted alone
        ] {
            let out = redact(&secrets, encoded);
            if encoded.starts_with("70407") {
                assert_eq!(out, encoded);
            } else {
                assert_eq!(out, "«redacted:k»", "{encoded}");
            }
        }
        assert_eq!(redact(&secrets, "70407373207730726421"), "«redacted:k»");
        assert_eq!(redact(&secrets, "70407373207730726421".to_uppercase().as_str()), "«redacted:k»");
    }

    #[test]
    fn handles_values_split_across_chunks() {
        let mut redactor = Redactor::new([("tok", "abcdefghij")]);
        let input = b"xx abcdefghij yy abcdefghij";
        let mut out = Vec::new();
        for byte in input {
            out.extend(redactor.push(std::slice::from_ref(byte)));
        }
        out.extend(redactor.finish());
        assert_eq!(String::from_utf8(out).unwrap(), "xx «redacted:tok» yy «redacted:tok»");
    }

    #[test]
    fn longest_match_wins_for_overlapping_secrets() {
        let secrets = [("short", "abcd1234"), ("long", "abcd1234efgh")];
        assert_eq!(redact(&secrets, "abcd1234efgh abcd1234"), "«redacted:long» «redacted:short»");
    }

    #[test]
    fn passes_through_without_secrets_and_on_empty_input() {
        assert_eq!(redact(&[], "nothing to hide"), "nothing to hide");
        assert_eq!(redact(&[("k", "value-123")], ""), "");
    }

    #[test]
    fn debug_hides_patterns() {
        let redactor = Redactor::new([("k", "super-secret-value")]);
        assert!(!format!("{redactor:?}").contains("super-secret-value"));
    }
}
```

Add `pub mod redact;` to `src/lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib redact`
Expected: compile error, `cannot find function redact_all`.

- [ ] **Step 3: Implement the redactor above the tests**

```rust
//! Streaming redaction of secret values and their common encodings.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

#[derive(Clone)]
struct Pattern {
    bytes: Vec<u8>,
    marker: Vec<u8>,
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Byte forms of `value` that must never appear in output.
fn variants(value: &str) -> Vec<Vec<u8>> {
    let raw = value.as_bytes();
    let mut all = vec![
        raw.to_vec(),
        STANDARD.encode(raw).into_bytes(),
        STANDARD_NO_PAD.encode(raw).into_bytes(),
        URL_SAFE.encode(raw).into_bytes(),
        URL_SAFE_NO_PAD.encode(raw).into_bytes(),
        percent_encode(value).into_bytes(),
        hex::encode(raw).into_bytes(),
        hex::encode_upper(raw).into_bytes(),
    ];
    all.retain(|v| !v.is_empty());
    all.sort();
    all.dedup();
    all
}

/// Redacts secrets from a byte stream, even when a value spans two chunks.
///
/// It holds back the last `longest pattern - 1` bytes of each chunk until
/// more input or [`Redactor::finish`] shows whether they start a match.
///
/// # Examples
///
/// ```
/// use llm_secret_vault::redact::Redactor;
///
/// let mut redactor = Redactor::new([("token", "abc123xyz")]);
/// let mut out = redactor.push(b"key=abc1");
/// out.extend(redactor.push(b"23xyz\n"));
/// out.extend(redactor.finish());
/// assert_eq!(out, "key=«redacted:token»\n".as_bytes());
/// ```
#[derive(Clone)]
pub struct Redactor {
    patterns: Vec<Pattern>,
    max_len: usize,
    pending: Vec<u8>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("patterns", &self.patterns.len())
            .field("pending_bytes", &self.pending.len())
            .finish()
    }
}

impl Redactor {
    /// Creates a redactor from `(label, value)` pairs.
    #[must_use]
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut patterns = Vec::new();
        for (label, value) in secrets {
            let marker = format!("«redacted:{label}»").into_bytes();
            for bytes in variants(value) {
                patterns.push(Pattern {
                    bytes,
                    marker: marker.clone(),
                });
            }
        }
        patterns.sort_by(|a, b| b.bytes.len().cmp(&a.bytes.len()));
        let max_len = patterns.first().map_or(0, |p| p.bytes.len());
        Self {
            patterns,
            max_len,
            pending: Vec::new(),
        }
    }

    /// Feeds a chunk and returns the bytes that are now safe to emit.
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        if self.max_len == 0 {
            return std::mem::take(&mut self.pending);
        }
        let hold = self.max_len - 1;
        if self.pending.len() <= hold {
            return Vec::new();
        }
        let limit = self.pending.len() - hold;
        let (out, consumed) = self.scan(limit);
        self.pending.drain(..consumed);
        out
    }

    /// Flushes everything still held back.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        let limit = self.pending.len();
        self.scan(limit).0
    }

    /// Emits output for pending positions `< limit`; returns it and the bytes consumed.
    fn scan(&self, limit: usize) -> (Vec<u8>, usize) {
        let pending = &self.pending;
        let mut out = Vec::with_capacity(limit);
        let mut i = 0;
        while i < limit {
            let rest = &pending[i..];
            if let Some(pattern) = self.patterns.iter().find(|p| rest.starts_with(&p.bytes)) {
                out.extend_from_slice(&pattern.marker);
                i += pattern.bytes.len();
            } else {
                out.push(pending[i]);
                i += 1;
            }
        }
        (out, i)
    }
}

/// Redacts a complete buffer in one call.
#[must_use]
pub fn redact_all<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a str)>, input: &[u8]) -> Vec<u8> {
    let mut redactor = Redactor::new(secrets);
    let mut out = redactor.push(input);
    out.extend(redactor.finish());
    out
}
```

- [ ] **Step 4: Run unit tests**

Run: `cargo test --lib redact && cargo test --doc`
Expected: 6 unit tests and the doctest pass.

- [ ] **Step 5: Write the property test `tests/no_leak.rs`**

```rust
//! Property tests: redacted output never contains a secret in any covered form.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use llm_secret_vault::redact::Redactor;
use proptest::prelude::*;

fn redact_chunked(value: &str, input: &[u8], chunk: usize) -> String {
    let mut redactor = Redactor::new([("s", value)]);
    let mut out = Vec::new();
    for piece in input.chunks(chunk.max(1)) {
        out.extend(redactor.push(piece));
    }
    out.extend(redactor.finish());
    String::from_utf8_lossy(&out).into_owned()
}

proptest! {
    // Uppercase-only values cannot occur inside the lowercase marker text.
    #[test]
    fn no_raw_or_encoded_value_survives(
        value in "[A-Z0-9!@#%^&*]{8,40}",
        before in "[ -~]{0,64}",
        between in "[ -~]{0,64}",
        after in "[ -~]{0,64}",
        chunk in 1usize..64,
    ) {
        let b64 = STANDARD.encode(value.as_bytes());
        let hex_lower = hex::encode(value.as_bytes());
        let input = format!("{before}{value}{between}{b64}{after}{hex_lower}");
        let out = redact_chunked(&value, input.as_bytes(), chunk);
        prop_assert!(!out.contains(&value));
        prop_assert!(!out.contains(&b64));
        prop_assert!(!out.contains(&hex_lower));
        prop_assert!(out.contains("«redacted:s»"));
    }
}
```

Note: this test depends on `hex` and `base64`, which are normal dependencies, so integration tests can use them.

- [ ] **Step 6: Run the property test and lints**

Run: `cargo test --test no_leak && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: PASS (256 cases).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add streaming redactor covering common encodings"
```

---

### Task 5: Injection runner

**Files:**
- Create: `src/inject.rs`, `tests/inject.rs`, `tests/invariants.rs`
- Modify: `src/lib.rs` (add `pub mod inject;`), `src/vault.rs` (remove `#[allow(dead_code)]` on `resolve`), `tests/no_leak.rs` (append end-to-end property)

**Interfaces:**
- Consumes: `Vault::resolve` (Task 3), `Redactor` (Task 4), `SecretName`.
- Produces: `pub struct RunRequest` with `new<I, S>(argv: I) where I: IntoIterator<Item = S>, S: Into<String>`, builder methods `env(self, var: impl Into<String>, secret: SecretName)`, `cwd(self, impl Into<PathBuf>)`, `timeout(self, Duration)`, `max_output_bytes(self, usize)`, accessor `argv(&self) -> &[String]`; `pub struct RunOutput { pub exit_code: Option<i32>, pub stdout: String, pub stderr: String, pub truncated: bool, pub timed_out: bool }` (`Serialize`); `pub fn run(vault: &Vault, request: &RunRequest) -> Result<RunOutput>`.

- [ ] **Step 1: Write the failing integration tests `tests/inject.rs`**

```rust
//! End-to-end tests for secret injection (Unix shells).
#![cfg(unix)]

use std::time::{Duration, Instant};

use llm_secret_vault::inject::{RunRequest, run};
use llm_secret_vault::{ErrorKind, SecretName, Source, Vault};

const VALUE: &str = "hunter2-very-secret";

fn vault() -> Vault {
    let vault = Vault::in_memory();
    vault
        .store(&SecretName::new("nas-root").unwrap(), VALUE, Source::Clipboard, false)
        .unwrap();
    vault
}

fn nas() -> SecretName {
    SecretName::new("nas-root").unwrap()
}

#[test]
fn env_injection_reaches_child_and_is_redacted() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "echo \"pw=$PW\""]).env("PW", nas());
    let out = run(&vault, &req).unwrap();
    assert_eq!(out.stdout, "pw=«redacted:nas-root»\n");
    assert_eq!(out.exit_code, Some(0));

    let check = RunRequest::new(["sh", "-c", &format!("test \"$PW\" = '{VALUE}' && echo ok")])
        .env("PW", nas());
    assert_eq!(run(&vault, &check).unwrap().stdout, "ok\n");
}

#[test]
fn placeholder_is_substituted_and_redacted() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "printf %s \"$0\"", "{{nas-root}}"]);
    assert_eq!(run(&vault, &req).unwrap().stdout, "«redacted:nas-root»");
    let literal = RunRequest::new(["printf", "%s", "{{ .Values.x }}"]);
    assert_eq!(run(&vault, &literal).unwrap().stdout, "{{ .Values.x }}");
}

#[test]
fn encoded_output_is_redacted() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "printf %s \"$PW\" | base64"]).env("PW", nas());
    let out = run(&vault, &req).unwrap();
    assert!(out.stdout.contains("«redacted:nas-root»"), "{}", out.stdout);
}

#[test]
fn stderr_is_redacted_too() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "echo \"$PW\" >&2"]).env("PW", nas());
    assert_eq!(run(&vault, &req).unwrap().stderr, "«redacted:nas-root»\n");
}

#[test]
fn unknown_secret_fails_before_spawning() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "touch should-not-exist"])
        .env("X", SecretName::new("missing").unwrap());
    let err = run(&vault, &req).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::UnknownName(_)));
    assert!(!std::path::Path::new("should-not-exist").exists());
}

#[test]
fn usage_errors() {
    let vault = vault();
    let empty: [&str; 0] = [];
    assert!(matches!(run(&vault, &RunRequest::new(empty)).unwrap_err().kind(), ErrorKind::Usage(_)));
    let bad = RunRequest::new(["true"]).env("1BAD", nas());
    assert!(matches!(run(&vault, &bad).unwrap_err().kind(), ErrorKind::Usage(_)));
}

#[test]
fn spawn_error_names_program_only() {
    let vault = vault();
    let err = run(&vault, &RunRequest::new(["/no/such/program", "{{nas-root}}"])).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Spawn(_)));
    assert!(err.to_string().contains("/no/such/program"));
    assert!(!err.to_string().contains(VALUE));
}

#[test]
fn exit_code_is_reported() {
    let out = run(&vault(), &RunRequest::new(["sh", "-c", "exit 3"])).unwrap();
    assert_eq!(out.exit_code, Some(3));
}

#[test]
fn timeout_kills_the_process_group() {
    let start = Instant::now();
    let req = RunRequest::new(["sh", "-c", "sleep 30 & sleep 30"]).timeout(Duration::from_millis(300));
    let out = run(&vault(), &req).unwrap();
    assert!(out.timed_out);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn output_is_capped() {
    let req = RunRequest::new(["sh", "-c", "yes | head -c 100000"]).max_output_bytes(1000);
    let out = run(&vault(), &req).unwrap();
    assert_eq!(out.stdout.len(), 1000);
    assert!(out.truncated);
}

#[test]
fn working_directory_is_honored() {
    let dir = tempfile::tempdir().unwrap();
    let req = RunRequest::new(["pwd"]).cwd(dir.path());
    let out = run(&vault(), &req).unwrap();
    let expected = dir.path().canonicalize().unwrap();
    assert_eq!(std::path::Path::new(out.stdout.trim()).canonicalize().unwrap(), expected);
}
```

Add `pub mod inject;` to `src/lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test inject`
Expected: compile error, `could not find inject in llm_secret_vault` (or unresolved items).

- [ ] **Step 3: Implement `src/inject.rs`**

```rust
//! Running commands with secrets injected and their output redacted.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::ops::Range;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::redact::Redactor;
use crate::vault::Vault;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const READ_CHUNK: usize = 8192;

/// A command to run with secrets injected.
///
/// Secrets reach the child as environment variables (via [`RunRequest::env`])
/// or through `{{name}}` placeholders in any argument after the program.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use llm_secret_vault::{inject::RunRequest, SecretName};
///
/// let request = RunRequest::new(["./deploy.sh"])
///     .env("API_TOKEN", SecretName::new("api-token").unwrap())
///     .timeout(Duration::from_secs(60));
/// assert_eq!(request.argv()[0], "./deploy.sh");
/// ```
#[derive(Debug, Clone)]
pub struct RunRequest {
    argv: Vec<String>,
    env: BTreeMap<String, SecretName>,
    cwd: Option<PathBuf>,
    timeout: Option<Duration>,
    max_output_bytes: Option<usize>,
}

impl RunRequest {
    /// Creates a request for `argv`, where `argv[0]` is the program.
    #[must_use]
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            env: BTreeMap::new(),
            cwd: None,
            timeout: None,
            max_output_bytes: None,
        }
    }

    /// Injects `secret` as environment variable `var`.
    #[must_use]
    pub fn env(mut self, var: impl Into<String>, secret: SecretName) -> Self {
        self.env.insert(var.into(), secret);
        self
    }

    /// Runs the child in `dir`.
    #[must_use]
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Kills the child (and its process group on Unix) after `limit`.
    #[must_use]
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// Keeps at most `bytes` of redacted output per stream.
    #[must_use]
    pub fn max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes = Some(bytes);
        self
    }

    /// Returns the command line as given, with placeholders unexpanded.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
}

/// Result of a [`run`]: exit status and redacted output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunOutput {
    /// Exit code, or `None` if the child was killed by a signal.
    pub exit_code: Option<i32>,
    /// Redacted standard output.
    pub stdout: String,
    /// Redacted standard error.
    pub stderr: String,
    /// Whether either stream hit the output cap.
    pub truncated: bool,
    /// Whether the child was killed for exceeding the timeout.
    pub timed_out: bool,
}

fn usage(why: impl Into<String>) -> Error {
    Error::new(ErrorKind::Usage(why.into()))
}

fn is_env_var_name(var: &str) -> bool {
    let mut chars = var.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Finds `{{name}}` placeholders whose inner text is a valid secret name.
fn placeholders(arg: &str) -> Vec<(Range<usize>, SecretName)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(open) = arg[from..].find("{{").map(|i| i + from) {
        let Some(close) = arg[open + 2..].find("}}").map(|i| i + open + 2) else {
            break;
        };
        if let Ok(name) = SecretName::new(arg[open + 2..close].trim()) {
            found.push((open..close + 2, name));
            from = close + 2;
        } else {
            from = open + 2;
        }
    }
    found
}

fn substitute(arg: &str, values: &BTreeMap<SecretName, Zeroizing<String>>) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(arg.len()));
    let mut last = 0;
    for (range, name) in placeholders(arg) {
        out.push_str(&arg[last..range.start]);
        out.push_str(values[&name].as_str());
        last = range.end;
    }
    out.push_str(&arg[last..]);
    out
}

fn append_capped(out: &mut Vec<u8>, bytes: &[u8], cap: Option<usize>) -> bool {
    match cap {
        Some(cap) if out.len() + bytes.len() > cap => {
            let room = cap - out.len();
            out.extend_from_slice(&bytes[..room]);
            true
        }
        _ => {
            out.extend_from_slice(bytes);
            false
        }
    }
}

/// Reads a stream to EOF through the redactor, keeping at most `cap` bytes.
fn pump(mut reader: impl Read, mut redactor: Redactor, cap: Option<usize>) -> (Vec<u8>, bool) {
    let mut collected = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; READ_CHUNK];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if !truncated {
            let clean = redactor.push(&buf[..n]);
            truncated = append_capped(&mut collected, &clean, cap);
        }
    }
    if !truncated {
        let clean = redactor.finish();
        truncated = append_capped(&mut collected, &clean, cap);
    }
    (collected, truncated)
}

fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

/// Runs `request` with its secrets injected and returns redacted output.
///
/// # Errors
///
/// Returns [`ErrorKind::Usage`] for an empty argv or an invalid environment
/// variable name, [`ErrorKind::UnknownName`] if a referenced secret does not
/// exist (nothing is spawned), [`ErrorKind::Keyring`] if the keyring fails,
/// and [`ErrorKind::Spawn`] if the program cannot be started or awaited.
///
/// # Panics
///
/// Panics only if an internal output-reader thread panics, which is a bug.
pub fn run(vault: &Vault, request: &RunRequest) -> Result<RunOutput> {
    let program = request
        .argv
        .first()
        .ok_or_else(|| usage("argv must contain at least the program to run"))?;
    if let Some(var) = request.env.keys().find(|v| !is_env_var_name(v)) {
        return Err(usage(format!("`{var}` is not a valid environment variable name")));
    }

    let mut names: BTreeSet<SecretName> = request.env.values().cloned().collect();
    for arg in &request.argv[1..] {
        names.extend(placeholders(arg).into_iter().map(|(_, name)| name));
    }
    let mut values = BTreeMap::new();
    for name in names {
        let value = vault.resolve(&name)?;
        values.insert(name, value);
    }

    let args: Vec<Zeroizing<String>> =
        request.argv[1..].iter().map(|a| substitute(a, &values)).collect();
    let mut command = Command::new(program);
    command
        .args(args.iter().map(|a| a.as_str()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (var, name) in &request.env {
        command.env(var, values[name].as_str());
    }
    if let Some(dir) = &request.cwd {
        command.current_dir(dir);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|e| Error::new(ErrorKind::Spawn(format!("{program}: {e}"))))?;

    let redactor = Redactor::new(values.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    let cap = request.max_output_bytes;
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let out_reader = {
        let redactor = redactor.clone();
        thread::spawn(move || pump(stdout, redactor, cap))
    };
    let err_reader = thread::spawn(move || pump(stderr, redactor, cap));

    let mut timed_out = false;
    let status = match request.timeout {
        None => child.wait(),
        Some(limit) => {
            let deadline = Instant::now() + limit;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if Instant::now() >= deadline => {
                        timed_out = true;
                        kill_tree(&mut child);
                        break child.wait();
                    }
                    Ok(None) => thread::sleep(POLL_INTERVAL),
                    Err(e) => break Err(e),
                }
            }
        }
    }
    .map_err(|e| Error::new(ErrorKind::Spawn(format!("waiting for {program}: {e}"))))?;

    let (stdout, out_truncated) = out_reader.join().expect("stdout reader panicked");
    let (stderr, err_truncated) = err_reader.join().expect("stderr reader panicked");
    Ok(RunOutput {
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: out_truncated || err_truncated,
        timed_out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_only_valid_placeholders() {
        let found: Vec<_> = placeholders("a {{nas-root}} b {{ hf.token }} c {{Bad}} {{x")
            .into_iter()
            .map(|(_, n)| n.to_string())
            .collect();
        assert_eq!(found, ["nas-root", "hf.token"]);
    }

    #[test]
    fn env_var_names() {
        assert!(is_env_var_name("HF_TOKEN"));
        assert!(is_env_var_name("_x1"));
        assert!(!is_env_var_name("1BAD"));
        assert!(!is_env_var_name("A-B"));
        assert!(!is_env_var_name(""));
    }
}
```

Remove the `#[allow(dead_code)]` on `Vault::resolve` in `src/vault.rs`.

- [ ] **Step 4: Run inject tests**

Run: `cargo test --test inject && cargo test --lib inject`
Expected: all pass. If `timeout_kills_the_process_group` hangs, the process-group kill is not working: confirm `process_group(0)` is applied before `spawn()`.

- [ ] **Step 5: Write the invariant test `tests/invariants.rs`**

```rust
//! Structural checks that keep the "no read verb" invariant honest.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn resolve_is_called_only_from_allowed_modules() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let allowed = ["backend", "vault.rs", "fingerprint.rs", "inject.rs"];
    for file in files {
        let rel = file.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/");
        let text = fs::read_to_string(&file).unwrap();
        if text.contains(".resolve(") {
            assert!(
                allowed.iter().any(|a| rel.starts_with(a)),
                "{rel} calls .resolve(); only {allowed:?} may"
            );
        }
    }
}
```

- [ ] **Step 6: Append the end-to-end no-leak property to `tests/no_leak.rs`**

```rust
#[cfg(unix)]
mod end_to_end {
    use llm_secret_vault::inject::{RunRequest, run};
    use llm_secret_vault::{SecretName, Source, Vault};
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn run_output_never_contains_the_value(value in "[A-Z0-9]{8,32}", noise in "[a-z ]{0,40}") {
            let vault = Vault::in_memory();
            let name = SecretName::new("prop").unwrap();
            vault.store(&name, &value, Source::Generated, false).unwrap();
            let script = format!("printf '%s' '{noise}'; printf '%s' \"$S\"; printf '%s' \"$S\" | base64; echo \"$S\" >&2");
            let out = run(&vault, &RunRequest::new(["sh", "-c", script.as_str()]).env("S", name)).unwrap();
            prop_assert!(!out.stdout.contains(&value));
            prop_assert!(!out.stderr.contains(&value));
        }
    }
}
```

- [ ] **Step 7: Run everything and lints**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all tests pass, keyring test ignored.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: run commands with injected secrets and redacted output"
```

---

### Task 6: Clipboard capture, generation and import

**Files:**
- Create: `src/capture.rs`, `src/generate.rs`, `src/import.rs`
- Modify: `src/lib.rs` (add `pub mod capture; pub mod generate; pub mod import;`)

**Interfaces:**
- Consumes: `Vault::{store, exists}`, `Source`, `Meta`, `SecretName`.
- Produces:
  - `pub trait Clipboard { fn text(&mut self) -> Result<Option<String>>; fn clear(&mut self) -> Result<()>; }`
  - `pub struct SystemClipboard` with `new() -> Result<SystemClipboard>`, implementing `Clipboard`
  - `pub struct CaptureOptions { pub overwrite: bool, pub expect_prefix: Option<String>, pub min_len: Option<usize>, pub allow_multiline: bool }` (`Default`)
  - `pub struct CaptureReport { pub meta: Meta, pub clipboard_cleared: bool }`
  - `pub fn capture(vault: &Vault, clipboard: &mut dyn Clipboard, name: &SecretName, options: &CaptureOptions) -> Result<CaptureReport>`
  - `pub const DEFAULT_MIN_LEN: usize = 8; pub const MAX_SINGLE_LINE_LEN: usize = 4096;`
  - `pub enum Alphabet { Alnum, Hex, Base64url, Printable }` (`Default = Alnum`, serde lowercase, `clap::ValueEnum`)
  - `pub struct GenerateOptions { pub length: usize, pub alphabet: Alphabet, pub overwrite: bool }` (`Default`: 32, Alnum, false)
  - `pub fn generate(vault: &Vault, name: &SecretName, options: &GenerateOptions) -> Result<Meta>`
  - `pub const MIN_GENERATED_LEN: usize = 8; pub const MAX_GENERATED_LEN: usize = 1024;`
  - `pub fn import(vault: &Vault, name: &SecretName, overwrite: bool) -> Result<Meta>`

- [ ] **Step 1: Write failing tests in `src/capture.rs`**

```rust
//! Moving a secret from the clipboard into the vault without anyone seeing it.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ErrorKind, Source};

    #[derive(Debug, Default)]
    struct FakeClipboard {
        text: Option<String>,
        swap_after_first_read: Option<String>,
        reads: usize,
        cleared: bool,
    }

    impl Clipboard for FakeClipboard {
        fn text(&mut self) -> Result<Option<String>> {
            self.reads += 1;
            let current = self.text.clone();
            if self.reads == 1 {
                if let Some(next) = self.swap_after_first_read.take() {
                    self.text = Some(next);
                }
            }
            Ok(current)
        }

        fn clear(&mut self) -> Result<()> {
            self.text = None;
            self.cleared = true;
            Ok(())
        }
    }

    fn clip(text: &str) -> FakeClipboard {
        FakeClipboard { text: Some(text.to_owned()), ..FakeClipboard::default() }
    }

    fn name(s: &str) -> SecretName {
        SecretName::new(s).unwrap()
    }

    #[test]
    fn stores_and_clears() {
        let vault = Vault::in_memory();
        let mut cb = clip("hf_abcdefghijklmnop\n");
        let report = capture(&vault, &mut cb, &name("hf-token"), &CaptureOptions::default()).unwrap();
        assert!(report.clipboard_cleared);
        assert!(cb.cleared);
        assert_eq!(report.meta.len, 19, "trailing newline is trimmed");
        assert_eq!(report.meta.source, Source::Clipboard);
        assert_eq!(vault.resolve(&name("hf-token")).unwrap().as_str(), "hf_abcdefghijklmnop");
    }

    #[test]
    fn leaves_clipboard_alone_if_it_changed() {
        let vault = Vault::in_memory();
        let mut cb = clip("first-secret-value");
        cb.swap_after_first_read = Some("something the user copied later".to_owned());
        let report = capture(&vault, &mut cb, &name("k"), &CaptureOptions::default()).unwrap();
        assert!(!report.clipboard_cleared);
        assert!(!cb.cleared);
    }

    #[test]
    fn empty_clipboard_is_an_error() {
        let vault = Vault::in_memory();
        let mut cb = FakeClipboard::default();
        let err = capture(&vault, &mut cb, &name("k"), &CaptureOptions::default()).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::Clipboard(_)));
    }

    #[test]
    fn validation_failures_never_echo_content() {
        let vault = Vault::in_memory();
        let cases = [
            ("sk_live_wrongprefix", CaptureOptions { expect_prefix: Some("hf_".into()), ..Default::default() }),
            ("short", CaptureOptions::default()),
            ("line-one-secret\nline-two-secret", CaptureOptions::default()),
        ];
        for (text, options) in cases {
            let mut cb = clip(text);
            let err = capture(&vault, &mut cb, &name("k"), &options).unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::InvalidValue(_)), "{text}");
            assert!(!err.to_string().contains(text.lines().next().unwrap()), "{err}");
            assert!(!cb.cleared);
            assert!(!vault.exists(&name("k")));
        }
    }

    #[test]
    fn multiline_allowed_on_request() {
        let vault = Vault::in_memory();
        let mut cb = clip("-----BEGIN KEY-----\nabcdefgh\n-----END KEY-----");
        let options = CaptureOptions { allow_multiline: true, ..Default::default() };
        assert!(capture(&vault, &mut cb, &name("ssh-key"), &options).is_ok());
    }

    #[test]
    fn overwrite_rules() {
        let vault = Vault::in_memory();
        capture(&vault, &mut clip("first-secret-value"), &name("k"), &CaptureOptions::default()).unwrap();
        let err = capture(&vault, &mut clip("second-secret-value"), &name("k"), &CaptureOptions::default())
            .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::NameExists(_)));
        let options = CaptureOptions { overwrite: true, ..Default::default() };
        let report = capture(&vault, &mut clip("second-secret-value"), &name("k"), &options).unwrap();
        assert!(report.meta.rotated.is_some());
    }
}
```

Add `pub mod capture;` to `src/lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib capture`
Expected: compile error, `cannot find trait Clipboard`.

- [ ] **Step 3: Implement capture above the tests**

```rust
//! Moving a secret from the clipboard into the vault without anyone seeing it.

use std::fmt;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::vault::{Meta, Source, Vault};

/// Default minimum length for captured values.
pub const DEFAULT_MIN_LEN: usize = 8;
/// Longest single-line value accepted without `allow_multiline`, in bytes.
pub const MAX_SINGLE_LINE_LEN: usize = 4096;

/// Minimal clipboard access needed for capture.
pub trait Clipboard {
    /// Returns the clipboard text, or `None` if it holds no text.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Clipboard`] if the clipboard cannot be read.
    fn text(&mut self) -> Result<Option<String>>;

    /// Empties the clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Clipboard`] if the clipboard cannot be written.
    fn clear(&mut self) -> Result<()>;
}

/// The operating system clipboard.
pub struct SystemClipboard {
    inner: arboard::Clipboard,
}

impl fmt::Debug for SystemClipboard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SystemClipboard")
    }
}

fn clipboard_err(err: &arboard::Error) -> Error {
    Error::new(ErrorKind::Clipboard(err.to_string()))
}

impl SystemClipboard {
    /// Connects to the system clipboard.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Clipboard`] when no clipboard is reachable, for
    /// example on a Linux machine without X11 or Wayland.
    pub fn new() -> Result<Self> {
        arboard::Clipboard::new()
            .map(|inner| Self { inner })
            .map_err(|e| {
                Error::new(ErrorKind::Clipboard(format!(
                    "{e}; on a headless machine use `lsv import` instead"
                )))
            })
    }
}

impl Clipboard for SystemClipboard {
    fn text(&mut self) -> Result<Option<String>> {
        match self.inner.get_text() {
            Ok(text) => Ok(Some(text)),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(clipboard_err(&e)),
        }
    }

    fn clear(&mut self) -> Result<()> {
        self.inner.clear().map_err(|e| clipboard_err(&e))
    }
}

/// Checks applied to clipboard text before it is stored.
#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    /// Replace an existing secret with the same name.
    pub overwrite: bool,
    /// Required prefix, such as `hf_` or `sk_live_`.
    pub expect_prefix: Option<String>,
    /// Minimum length in characters; defaults to [`DEFAULT_MIN_LEN`].
    pub min_len: Option<usize>,
    /// Accept values containing newlines or longer than [`MAX_SINGLE_LINE_LEN`].
    pub allow_multiline: bool,
}

/// Outcome of a successful [`capture`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureReport {
    /// Metadata of the stored secret.
    pub meta: Meta,
    /// Whether the clipboard was cleared (it is left alone if it changed meanwhile).
    pub clipboard_cleared: bool,
}

fn reject(why: String) -> Error {
    Error::new(ErrorKind::InvalidValue(why))
}

fn validate(value: &str, options: &CaptureOptions) -> Result<()> {
    let len = value.chars().count();
    if value.is_empty() {
        return Err(reject("clipboard text is empty".to_owned()));
    }
    if let Some(prefix) = &options.expect_prefix {
        if !value.starts_with(prefix.as_str()) {
            return Err(reject(format!(
                "clipboard text ({len} characters) does not start with the expected prefix `{prefix}`"
            )));
        }
    }
    let min = options.min_len.unwrap_or(DEFAULT_MIN_LEN);
    if len < min {
        return Err(reject(format!("clipboard text is {len} characters, minimum is {min}")));
    }
    if !options.allow_multiline {
        if value.contains('\n') {
            return Err(reject(format!(
                "clipboard text ({len} characters) spans several lines; pass allow_multiline if that is intended"
            )));
        }
        if value.len() > MAX_SINGLE_LINE_LEN {
            return Err(reject(format!(
                "clipboard text is {} bytes, more than {MAX_SINGLE_LINE_LEN}; pass allow_multiline if that is intended",
                value.len()
            )));
        }
    }
    Ok(())
}

/// Stores the clipboard text as secret `name`, then clears the clipboard.
///
/// Trailing newlines are trimmed. The clipboard is cleared only if it still
/// holds the captured text.
///
/// # Errors
///
/// Returns [`ErrorKind::Clipboard`] if the clipboard is unreadable or holds no
/// text, [`ErrorKind::InvalidValue`] if validation fails (nothing is stored),
/// [`ErrorKind::NameExists`] if the name exists without `overwrite`, and
/// storage errors from [`Vault::store`].
pub fn capture(
    vault: &Vault,
    clipboard: &mut dyn Clipboard,
    name: &SecretName,
    options: &CaptureOptions,
) -> Result<CaptureReport> {
    let original = Zeroizing::new(
        clipboard
            .text()?
            .ok_or_else(|| Error::new(ErrorKind::Clipboard("clipboard holds no text".to_owned())))?,
    );
    let value = Zeroizing::new(original.trim_end_matches(['\r', '\n']).to_owned());
    validate(&value, options)?;
    if vault.exists(name) && !options.overwrite {
        return Err(Error::new(ErrorKind::NameExists(name.to_string())));
    }
    let meta = vault.store(name, &value, Source::Clipboard, options.overwrite)?;
    let still_there = matches!(clipboard.text(), Ok(Some(now)) if Zeroizing::new(now) == original);
    if still_there {
        clipboard.clear()?;
    }
    Ok(CaptureReport {
        meta,
        clipboard_cleared: still_there,
    })
}
```

- [ ] **Step 4: Run capture tests**

Run: `cargo test --lib capture`
Expected: 6 tests pass.

- [ ] **Step 5: Write `src/generate.rs` with tests**

```rust
//! Generating random secrets that nobody ever sees.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::vault::{Meta, Source, Vault};

/// Shortest generated value.
pub const MIN_GENERATED_LEN: usize = 8;
/// Longest generated value.
pub const MAX_GENERATED_LEN: usize = 1024;

/// Character set for generated values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Alphabet {
    /// `A-Z`, `a-z`, `0-9`.
    #[default]
    Alnum,
    /// `0-9`, `a-f`.
    Hex,
    /// `A-Z`, `a-z`, `0-9`, `-`, `_`.
    Base64url,
    /// Every printable ASCII character except space.
    Printable,
}

impl Alphabet {
    fn chars(self) -> Vec<u8> {
        let alnum = || (b'A'..=b'Z').chain(b'a'..=b'z').chain(b'0'..=b'9');
        match self {
            Self::Alnum => alnum().collect(),
            Self::Hex => b"0123456789abcdef".to_vec(),
            Self::Base64url => alnum().chain([b'-', b'_']).collect(),
            Self::Printable => (33u8..=126).collect(),
        }
    }
}

/// Parameters for [`generate`].
#[derive(Debug, Clone, Copy)]
pub struct GenerateOptions {
    /// Number of characters.
    pub length: usize,
    /// Character set.
    pub alphabet: Alphabet,
    /// Replace an existing secret with the same name.
    pub overwrite: bool,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            length: 32,
            alphabet: Alphabet::Alnum,
            overwrite: false,
        }
    }
}

/// Uniformly random string over `alphabet` using rejection sampling.
fn random_string(length: usize, alphabet: &[u8]) -> Result<Zeroizing<String>> {
    let n = alphabet.len();
    let limit = 256 - (256 % n);
    let mut out = Zeroizing::new(String::with_capacity(length));
    let mut buf = [0u8; 64];
    while out.len() < length {
        getrandom::fill(&mut buf).map_err(|e| Error::new(ErrorKind::Random(e.to_string())))?;
        for &byte in &buf {
            if usize::from(byte) < limit && out.len() < length {
                out.push(char::from(alphabet[usize::from(byte) % n]));
            }
        }
    }
    Ok(out)
}

/// Generates a random value and stores it as `name` without revealing it.
///
/// # Errors
///
/// Returns [`ErrorKind::Usage`] if `length` is outside
/// [`MIN_GENERATED_LEN`]..=[`MAX_GENERATED_LEN`], [`ErrorKind::Random`] if
/// the OS random source fails, and storage errors from [`Vault::store`].
pub fn generate(vault: &Vault, name: &SecretName, options: &GenerateOptions) -> Result<Meta> {
    if !(MIN_GENERATED_LEN..=MAX_GENERATED_LEN).contains(&options.length) {
        return Err(Error::new(ErrorKind::Usage(format!(
            "length must be between {MIN_GENERATED_LEN} and {MAX_GENERATED_LEN}"
        ))));
    }
    let value = random_string(options.length, &options.alphabet.chars())?;
    vault.store(name, &value, Source::Generated, options.overwrite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_strings_respect_length_and_alphabet() {
        for alphabet in [Alphabet::Alnum, Alphabet::Hex, Alphabet::Base64url, Alphabet::Printable] {
            let chars = alphabet.chars();
            let value = random_string(200, &chars).unwrap();
            assert_eq!(value.len(), 200);
            assert!(value.bytes().all(|b| chars.contains(&b)), "{alphabet:?}");
        }
    }

    #[test]
    fn values_differ() {
        let chars = Alphabet::Alnum.chars();
        assert_ne!(*random_string(32, &chars).unwrap(), *random_string(32, &chars).unwrap());
    }

    #[test]
    fn generate_stores_blind() {
        let vault = Vault::in_memory();
        let name = SecretName::new("db-password").unwrap();
        let meta = generate(&vault, &name, &GenerateOptions::default()).unwrap();
        assert_eq!(meta.len, 32);
        assert_eq!(meta.source, Source::Generated);
        let rotated = generate(&vault, &name, &GenerateOptions { overwrite: true, ..Default::default() }).unwrap();
        assert_ne!(rotated.fingerprint, meta.fingerprint);
    }

    #[test]
    fn rejects_out_of_range_lengths() {
        let vault = Vault::in_memory();
        let name = SecretName::new("x").unwrap();
        for length in [0, 7, 1025] {
            let options = GenerateOptions { length, ..Default::default() };
            assert!(matches!(generate(&vault, &name, &options).unwrap_err().kind(), ErrorKind::Usage(_)));
        }
    }
}
```

Add `pub mod generate;` to `src/lib.rs`.

- [ ] **Step 6: Write `src/import.rs`**

```rust
//! Typing an existing secret into the vault at a hidden terminal prompt.

use std::io::IsTerminal;

use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::vault::{Meta, Source, Vault};

fn prompt(label: &str) -> Result<Zeroizing<String>> {
    rpassword::prompt_password(label)
        .map(Zeroizing::new)
        .map_err(|e| Error::new(ErrorKind::Usage(format!("could not read from terminal: {e}"))))
}

/// Prompts twice for a value (hidden) and stores it as `name`.
///
/// Refuses to run without a terminal, so a value can never arrive through a
/// pipe, a file or an agent.
///
/// # Errors
///
/// Returns [`ErrorKind::NoTty`] without a terminal, [`ErrorKind::NameExists`]
/// if the name exists without `overwrite`, [`ErrorKind::InvalidValue`] if the
/// two entries differ, and storage errors from [`Vault::store`].
pub fn import(vault: &Vault, name: &SecretName, overwrite: bool) -> Result<Meta> {
    if !std::io::stdin().is_terminal() {
        return Err(Error::new(ErrorKind::NoTty));
    }
    if vault.exists(name) && !overwrite {
        return Err(Error::new(ErrorKind::NameExists(name.to_string())));
    }
    let first = prompt(&format!("Value for `{name}`: "))?;
    let second = prompt("Repeat: ")?;
    if first != second {
        return Err(Error::new(ErrorKind::InvalidValue("the two entries differ".to_owned())));
    }
    vault.store(name, &first, Source::Imported, overwrite)
}
```

Add `pub mod import;` to `src/lib.rs`. `import` has no automated test because it needs a real terminal; Task 9 covers it manually.

- [ ] **Step 7: Run all tests and lints**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: add clipboard capture, blind generation and terminal import"
```

---

### Task 7: MCP server

**Files:**
- Create: `src/mcp/mod.rs`, `src/mcp/tools.rs`, `tests/mcp.rs`
- Modify: `src/lib.rs` (add `pub mod mcp;`)

**Interfaces:**
- Consumes: `Vault`, `capture::{capture, Clipboard, SystemClipboard, CaptureOptions}`, `generate::{generate, GenerateOptions, Alphabet}`, `inject::{run, RunRequest}`, `SecretName`.
- Produces: `pub type ClipboardFactory = Box<dyn Fn() -> Result<Box<dyn Clipboard>> + Send + Sync>`; `pub struct Server` with `new(Vault, ClipboardFactory) -> Server`, `with_system_clipboard(Vault) -> Server`, `handle(&self, &serde_json::Value) -> Option<serde_json::Value>`, `serve(&self, impl BufRead, impl Write) -> std::io::Result<()>`; `pub const PROTOCOL_VERSION: &str = "2025-06-18"`.

- [ ] **Step 1: Write the failing tests `tests/mcp.rs`**

```rust
//! MCP server tests: protocol handling and tools, with a no-leak check on every response.

use std::io::Cursor;

use llm_secret_vault::capture::Clipboard;
use llm_secret_vault::mcp::Server;
use llm_secret_vault::{Result, Vault};
use serde_json::{Value, json};

const SECRET: &str = "re_live_0123456789abcdef";

#[derive(Debug)]
struct FixedClipboard(Option<String>);

impl Clipboard for FixedClipboard {
    fn text(&mut self) -> Result<Option<String>> {
        Ok(self.0.clone())
    }
    fn clear(&mut self) -> Result<()> {
        self.0 = None;
        Ok(())
    }
}

fn server() -> Server {
    Server::new(
        Vault::in_memory(),
        Box::new(|| Ok(Box::new(FixedClipboard(Some(SECRET.to_owned()))) as Box<dyn Clipboard>)),
    )
}

fn call(server: &Server, id: u64, method: &str, params: Value) -> Value {
    let response = server
        .handle(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
        .expect("requests get responses");
    assert!(!response.to_string().contains(SECRET), "leak in {response}");
    response
}

fn tool(server: &Server, name: &str, arguments: Value) -> (String, bool) {
    let response = call(server, 1, "tools/call", json!({"name": name, "arguments": arguments}));
    let result = &response["result"];
    (
        result["content"][0]["text"].as_str().unwrap().to_owned(),
        result["isError"].as_bool().unwrap(),
    )
}

#[test]
fn initialize_echoes_protocol_version() {
    let response = call(&server(), 1, "initialize", json!({"protocolVersion": "2025-03-26", "capabilities": {}}));
    assert_eq!(response["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(response["result"]["serverInfo"]["name"], "llm-secret-vault");
    assert!(response["result"]["capabilities"]["tools"].is_object());
}

#[test]
fn notifications_get_no_response() {
    assert!(server().handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).is_none());
}

#[test]
fn lists_exactly_the_five_tools() {
    let response = call(&server(), 1, "tools/list", json!({}));
    let mut names: Vec<&str> = response["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["secret_capture", "secret_generate", "secret_info", "secret_list", "secret_run"]);
}

#[test]
fn capture_then_list_and_info() {
    let server = server();
    let (text, is_error) = tool(&server, "secret_capture", json!({"name": "resend", "expect_prefix": "re_"}));
    assert!(!is_error, "{text}");
    assert!(text.starts_with("stored resend: 24 chars, fp "), "{text}");
    assert!(text.ends_with("clipboard cleared"), "{text}");

    let (list, _) = tool(&server, "secret_list", json!({}));
    assert!(list.contains("\"resend\""));
    let (info, _) = tool(&server, "secret_info", json!({"name": "resend"}));
    assert!(info.contains("\"source\": \"clipboard\""), "{info}");
}

#[test]
fn generate_reports_metadata_only() {
    let (text, is_error) = tool(&server(), "secret_generate", json!({"name": "db", "length": 40, "alphabet": "hex"}));
    assert!(!is_error);
    assert!(text.starts_with("stored db: 40 chars, fp "), "{text}");
}

#[cfg(unix)]
#[test]
fn run_redacts_output() {
    let server = server();
    tool(&server, "secret_capture", json!({"name": "resend"}));
    let (text, is_error) = tool(
        &server,
        "secret_run",
        json!({"argv": ["sh", "-c", "echo token=$T"], "env": {"T": "resend"}}),
    );
    assert!(!is_error, "{text}");
    let out: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(out["stdout"], "token=«redacted:resend»\n");
    assert_eq!(out["exit_code"], 0);
}

#[test]
fn errors_are_tool_errors_without_values() {
    let server = server();
    let (text, is_error) = tool(&server, "secret_info", json!({"name": "missing"}));
    assert!(is_error);
    assert_eq!(text, "no secret named `missing`");
    let (_, is_error) = tool(&server, "secret_capture", json!({"name": "x", "expect_prefix": "hf_"}));
    assert!(is_error);
    let (text, is_error) = tool(&server, "secret_delete", json!({"name": "x"}));
    assert!(is_error);
    assert!(text.contains("unknown tool"));
    let (_, is_error) = tool(&server, "secret_list", json!({"bogus": 1}));
    assert!(is_error);
}

#[test]
fn unknown_method_is_a_protocol_error() {
    let response = call(&server(), 7, "resources/list", json!({}));
    assert_eq!(response["error"]["code"], -32601);
    assert_eq!(response["id"], 7);
}

#[test]
fn serve_handles_newline_delimited_stream() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#, "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, "\n",
        "\n",
        "not json\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#, "\n",
    );
    let mut output = Vec::new();
    server().serve(Cursor::new(input), &mut output).unwrap();
    let lines: Vec<Value> = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["id"], 1);
    assert_eq!(lines[1]["error"]["code"], -32700);
    assert_eq!(lines[2]["id"], 2);
}
```

Add `pub mod mcp;` to `src/lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test mcp`
Expected: compile error, `could not find mcp`.

- [ ] **Step 3: Implement `src/mcp/tools.rs`**

```rust
//! Tool definitions and dispatch for the MCP server.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::ClipboardFactory;
use crate::capture::{CaptureOptions, capture};
use crate::error::{Error, ErrorKind, Result};
use crate::generate::{Alphabet, GenerateOptions, generate};
use crate::inject::{RunRequest, run};
use crate::name::SecretName;
use crate::vault::Vault;

const DEFAULT_TIMEOUT_S: u64 = 120;
const DEFAULT_MAX_OUTPUT_KB: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameArgs {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureArgs {
    name: String,
    #[serde(default)]
    overwrite: bool,
    expect_prefix: Option<String>,
    min_len: Option<usize>,
    #[serde(default)]
    allow_multiline: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateArgs {
    name: String,
    length: Option<usize>,
    alphabet: Option<Alphabet>,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    argv: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    timeout_s: Option<u64>,
    max_output_kb: Option<usize>,
}

fn parse<T: DeserializeOwned>(args: &Value) -> Result<T> {
    serde_json::from_value(args.clone())
        .map_err(|e| Error::new(ErrorKind::Usage(format!("invalid arguments: {e}"))))
}

fn pretty(value: &impl serde::Serialize) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| Error::new(ErrorKind::Usage(e.to_string())))
}

/// JSON descriptions of every tool, for `tools/list`.
pub(super) fn definitions() -> Value {
    json!([
        {
            "name": "secret_list",
            "description": "List stored secrets: names, lengths, fingerprints, sources and dates. Never returns values.",
            "inputSchema": {
                "type": "object",
                "properties": {"prefix": {"type": "string", "description": "Only names starting with this prefix."}},
                "additionalProperties": false
            }
        },
        {
            "name": "secret_info",
            "description": "Metadata for one secret (length, fingerprint, source, dates). Never returns the value.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": "secret_capture",
            "description": "Store the text currently on the user's clipboard as a named secret, then clear the clipboard. Use this whenever the user says a key or password is in the clipboard; never ask them to paste it into chat.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Lowercase name, e.g. nas-root or hf-token."},
                    "overwrite": {"type": "boolean", "default": false},
                    "expect_prefix": {"type": "string", "description": "Reject the capture unless the text starts with this, e.g. hf_ or sk_live_."},
                    "min_len": {"type": "integer", "default": 8},
                    "allow_multiline": {"type": "boolean", "default": false}
                },
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": "secret_generate",
            "description": "Generate a random secret and store it without revealing it. With overwrite=true this rotates an existing secret.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "length": {"type": "integer", "default": 32, "minimum": 8, "maximum": 1024},
                    "alphabet": {"type": "string", "enum": ["alnum", "hex", "base64url", "printable"], "default": "alnum"},
                    "overwrite": {"type": "boolean", "default": false}
                },
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": "secret_run",
            "description": "Run a command with secrets injected. Map env var names to secret names in `env`, or write {{secret-name}} inside any argument after the program. stdout/stderr come back with secret values replaced by «redacted:name». Do not try to print secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Program and arguments; no shell unless you call one."},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "ENV_VAR -> secret name."},
                    "cwd": {"type": "string"},
                    "timeout_s": {"type": "integer", "default": DEFAULT_TIMEOUT_S},
                    "max_output_kb": {"type": "integer", "default": DEFAULT_MAX_OUTPUT_KB}
                },
                "required": ["argv"],
                "additionalProperties": false
            }
        }
    ])
}

/// Runs tool `tool` and returns the text for its result.
pub(super) fn call(
    vault: &Vault,
    clipboard: &ClipboardFactory,
    tool: &str,
    args: &Value,
) -> Result<String> {
    match tool {
        "secret_list" => {
            let args: ListArgs = parse(args)?;
            pretty(&vault.list(args.prefix.as_deref()))
        }
        "secret_info" => {
            let args: NameArgs = parse(args)?;
            pretty(&vault.info(&SecretName::new(&args.name)?)?)
        }
        "secret_capture" => {
            let args: CaptureArgs = parse(args)?;
            let name = SecretName::new(&args.name)?;
            let options = CaptureOptions {
                overwrite: args.overwrite,
                expect_prefix: args.expect_prefix,
                min_len: args.min_len,
                allow_multiline: args.allow_multiline,
            };
            let mut board = clipboard()?;
            let report = capture(vault, board.as_mut(), &name, &options)?;
            let clipboard_note = if report.clipboard_cleared {
                "clipboard cleared"
            } else {
                "clipboard changed since capture, left untouched"
            };
            Ok(format!(
                "stored {name}: {} chars, fp {}, {clipboard_note}",
                report.meta.len, report.meta.fingerprint
            ))
        }
        "secret_generate" => {
            let args: GenerateArgs = parse(args)?;
            let name = SecretName::new(&args.name)?;
            let defaults = GenerateOptions::default();
            let options = GenerateOptions {
                length: args.length.unwrap_or(defaults.length),
                alphabet: args.alphabet.unwrap_or(defaults.alphabet),
                overwrite: args.overwrite,
            };
            let meta = generate(vault, &name, &options)?;
            Ok(format!("stored {name}: {} chars, fp {}", meta.len, meta.fingerprint))
        }
        "secret_run" => {
            let args: RunArgs = parse(args)?;
            let mut request = RunRequest::new(args.argv)
                .timeout(Duration::from_secs(args.timeout_s.unwrap_or(DEFAULT_TIMEOUT_S)))
                .max_output_bytes(args.max_output_kb.unwrap_or(DEFAULT_MAX_OUTPUT_KB) * 1024);
            for (var, secret) in args.env {
                request = request.env(var, SecretName::new(secret)?);
            }
            if let Some(dir) = args.cwd {
                request = request.cwd(dir);
            }
            pretty(&run(vault, &request)?)
        }
        other => Err(Error::new(ErrorKind::Usage(format!("unknown tool `{other}`")))),
    }
}
```

- [ ] **Step 4: Implement `src/mcp/mod.rs`**

```rust
//! Minimal MCP server over stdio exposing the vault as tools.

mod tools;

use std::fmt;
use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::capture::{Clipboard, SystemClipboard};
use crate::error::Result;
use crate::vault::Vault;

/// Protocol version announced when the client does not request one.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "Secrets are referenced by name and never returned. \
When the user says a key or password is in the clipboard, call secret_capture. \
Use secret_run to pass secrets to commands through env vars or {{name}} placeholders. \
Never ask the user to paste a secret into the chat.";

/// Creates a clipboard handle on demand (so headless machines fail per call, not at startup).
pub type ClipboardFactory = Box<dyn Fn() -> Result<Box<dyn Clipboard>> + Send + Sync>;

/// MCP server that answers JSON-RPC messages using a [`Vault`].
pub struct Server {
    vault: Vault,
    clipboard: ClipboardFactory,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server").field("vault", &self.vault).finish_non_exhaustive()
    }
}

fn tool_result(text: String, is_error: bool) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

impl Server {
    /// Creates a server using `clipboard` to reach the clipboard.
    #[must_use]
    pub fn new(vault: Vault, clipboard: ClipboardFactory) -> Self {
        Self { vault, clipboard }
    }

    /// Creates a server that uses the system clipboard.
    #[must_use]
    pub fn with_system_clipboard(vault: Vault) -> Self {
        Self::new(
            vault,
            Box::new(|| Ok(Box::new(SystemClipboard::new()?) as Box<dyn Clipboard>)),
        )
    }

    /// Handles one JSON-RPC message; returns `None` for notifications.
    #[must_use]
    pub fn handle(&self, message: &Value) -> Option<Value> {
        let id = message.get("id")?.clone();
        let params = message.get("params");
        let result = match message.get("method").and_then(Value::as_str) {
            Some("initialize") => Ok(Self::initialize(params)),
            Some("ping") => Ok(json!({})),
            Some("tools/list") => Ok(json!({"tools": tools::definitions()})),
            Some("tools/call") => self.call(params),
            Some(other) => Err((-32601, format!("method not found: {other}"))),
            None => Err((-32600, "invalid request: missing method".to_owned())),
        };
        Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, message)) => {
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
            }
        })
    }

    fn initialize(params: Option<&Value>) -> Value {
        let version = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .unwrap_or(PROTOCOL_VERSION);
        json!({
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "llm-secret-vault", "version": env!("CARGO_PKG_VERSION")},
            "instructions": INSTRUCTIONS,
        })
    }

    fn call(&self, params: Option<&Value>) -> std::result::Result<Value, (i64, String)> {
        let params = params.ok_or((-32602, "missing params".to_owned()))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "missing tool name".to_owned()))?;
        let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
        Ok(match tools::call(&self.vault, &self.clipboard, name, &args) {
            Ok(text) => tool_result(text, false),
            Err(err) => tool_result(err.to_string(), true),
        })
    }

    /// Serves newline-delimited JSON-RPC from `input` to `output` until EOF.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if reading `input` or writing `output` fails.
    pub fn serve(&self, input: impl BufRead, mut output: impl Write) -> std::io::Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle(&message),
                Err(e) => Some(json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {"code": -32700, "message": format!("parse error: {e}")}
                })),
            };
            if let Some(response) = response {
                serde_json::to_writer(&mut output, &response)?;
                output.write_all(b"\n")?;
                output.flush()?;
            }
        }
        Ok(())
    }
}
```

- [ ] **Step 5: Run tests and lints**

Run: `cargo test --test mcp && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add stdio MCP server exposing vault tools"
```

---

### Task 8: Claude Code guard hook

**Files:**
- Create: `src/hook.rs`, `tests/hook.rs`
- Modify: `src/lib.rs` (add `pub mod hook;`)

**Interfaces:**
- Produces: `pub enum Decision { Allow, Deny(String) }`; `pub fn check_command(command: &str) -> Decision`; `pub fn evaluate(input: &str) -> Result<Decision>`; `pub fn render(decision: &Decision) -> Option<String>`.

- [ ] **Step 1: Write the failing rule table `tests/hook.rs`**

```rust
//! Guard hook rule table.

use llm_secret_vault::hook::{Decision, check_command, evaluate, render};

const DENY: &[&str] = &[
    "security find-generic-password -s foo -w",
    "security find-internet-password -gs github.com",
    "secret-tool lookup service nas",
    "powershell -c Get-StoredCredential -Target nas",
    "cmdkey /list:nas /pass",
    "cat /proc/1234/environ",
    "lsv run PW=nas-root -- sh -c 'echo $PW'",
    "lsv run PW=nas-root -- sh -c 'printf %s \"$PW\" | base64'",
    "lsv run T=tok -- sh -c 'echo ${T} | rev'",
    "lsv run T=tok -- sh -c 'printf %s $T | xxd'",
    "lsv run -- echo {{nas-root}}",
    "lsv run PW=nas-root -- printenv",
    "lsv run PW=nas-root -- printenv PW",
    "lsv run PW=nas-root -- env",
    "lsv run PW=nas-root -- sh -c 'set'",
    "lsv run PW=nas-root -- sh -c 'export -p'",
    "cd /tmp && lsv run PW=nas-root -- sh -c 'ls; echo $PW'",
];

const ALLOW: &[&str] = &[
    "ls -la",
    "echo hello",
    "cargo test 2>&1 | tail",
    "security find-generic-password -s foo",
    "lsv run HF_TOKEN=hf-token -- huggingface-cli upload repo file",
    "lsv run T=tok -- sh -c 'printf %s \"$T\" | docker login --password-stdin'",
    "lsv run T=tok -- sh -c 'curl -H \"Authorization: Bearer $T\" https://x > out.json'",
    "lsv run PW=nas-root -- sshpass -e ssh root@nas",
    "lsv run -- curl -H 'Bearer {{resend}}' https://api.resend.com",
    "lsv run PW=nas-root -- env FOO=1 ./deploy.sh",
    "lsv list",
    "echo $HOME",
];

#[test]
fn denies_leaky_commands() {
    for command in DENY {
        assert!(matches!(check_command(command), Decision::Deny(_)), "should deny: {command}");
    }
}

#[test]
fn allows_normal_commands() {
    for command in ALLOW {
        assert_eq!(check_command(command), Decision::Allow, "should allow: {command}");
    }
}

#[test]
fn evaluates_hook_json() {
    let deny = r#"{"tool_name":"Bash","tool_input":{"command":"lsv run X=a -- printenv"}}"#;
    assert!(matches!(evaluate(deny).unwrap(), Decision::Deny(_)));
    let other_tool = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#;
    assert_eq!(evaluate(other_tool).unwrap(), Decision::Allow);
    assert!(evaluate("not json").is_err());
    assert!(evaluate(r#"{"tool_name":"Bash","tool_input":{}}"#).is_err());
}

#[test]
fn renders_deny_for_claude_code() {
    assert!(render(&Decision::Allow).is_none());
    let json: serde_json::Value =
        serde_json::from_str(&render(&Decision::Deny("because".into())).unwrap()).unwrap();
    let out = &json["hookSpecificOutput"];
    assert_eq!(out["hookEventName"], "PreToolUse");
    assert_eq!(out["permissionDecision"], "deny");
    assert_eq!(out["permissionDecisionReason"], "llm-secret-vault: because");
}
```

Add `pub mod hook;` to `src/lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test hook`
Expected: compile error, `could not find hook`.

- [ ] **Step 3: Implement `src/hook.rs`**

```rust
//! Claude Code `PreToolUse` guard that blocks commands likely to print secrets.
//!
//! This is a heuristic safety net against accidents, not a sandbox.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::error::{Error, ErrorKind, Result};

/// Verdict for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let the command run.
    Allow,
    /// Block the command; the payload explains why.
    Deny(String),
}

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("hook patterns are valid")
}

static DIRECT_READS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            regex(r"\bsecurity\s+find-(generic|internet)-password\b[^|;&]*\s-[A-Za-z]*[wg][A-Za-z]*\b"),
            "reads a Keychain password directly; use `lsv run` instead",
        ),
        (
            regex(r"\bsecret-tool\s+lookup\b"),
            "reads a Secret Service password directly; use `lsv run` instead",
        ),
        (
            regex(r"(?i)\bGet-StoredCredential\b"),
            "reads a Windows credential directly; use `lsv run` instead",
        ),
        (
            regex(r"(?i)\bcmdkey\b[^|;&]*/pass"),
            "reads a Windows credential directly; use `lsv run` instead",
        ),
        (regex(r"/proc/[^\s/]+/environ"), "reads another process's environment"),
    ]
});

static LSV_RUN: LazyLock<Regex> = LazyLock::new(|| regex(r"\blsv\s+run\b"));
static DOUBLE_DASH: LazyLock<Regex> = LazyLock::new(|| regex(r"\s--(\s|$)"));
static BINDING: LazyLock<Regex> =
    LazyLock::new(|| regex(r"\b([A-Za-z_][A-Za-z0-9_]*)=[a-z0-9][a-z0-9._-]*"));
static SEPARATORS: LazyLock<Regex> = LazyLock::new(|| regex(r"&&|\|\||;|\n"));
static SHELL_PREFIX: LazyLock<Regex> = LazyLock::new(|| regex(r"^(?:sh|bash|zsh)\s+-c\s+"));

const ENCODERS: &[&str] = &["rev", "base64", "xxd", "od", "hexdump"];

fn first_word(segment: &str) -> &str {
    segment.split_whitespace().next().unwrap_or("")
}

fn dumps_env(segment: &str) -> bool {
    let mut words = segment.split_whitespace();
    match words.next() {
        Some("printenv") => true,
        Some("env" | "set") => words.next().is_none(),
        Some("export") => words.next() == Some("-p"),
        _ => false,
    }
}

/// Checks the child part of an `lsv run` command line.
fn check_child(child: &str, vars: &[&str]) -> Option<String> {
    let unquoted: String = child.chars().filter(|c| !matches!(c, '\'' | '"')).collect();
    let references = |s: &str| {
        s.contains("{{")
            || vars
                .iter()
                .any(|v| s.contains(&format!("${v}")) || s.contains(&format!("${{{v}}}")))
    };
    for command in SEPARATORS.split(&unquoted) {
        let command = SHELL_PREFIX.replace(command.trim(), "");
        let segments: Vec<&str> = command.split('|').map(str::trim).collect();
        if segments.iter().any(|s| dumps_env(s)) {
            return Some("the child command dumps its environment, which holds the injected secrets".to_owned());
        }
        if !segments.iter().any(|s| references(s)) {
            continue;
        }
        if let Some(encoder) = segments.iter().map(|s| first_word(s)).find(|w| ENCODERS.contains(w)) {
            return Some(format!("`{encoder}` would print an encoded copy of an injected secret"));
        }
        if let Some(last) = segments.last() {
            let word = first_word(last);
            if matches!(word, "echo" | "printf") && references(last) {
                return Some(format!("`{word}` would print an injected secret"));
            }
        }
    }
    None
}

/// Decides whether a shell command line may run.
#[must_use]
pub fn check_command(command: &str) -> Decision {
    for (pattern, reason) in DIRECT_READS.iter() {
        if pattern.is_match(command) {
            return Decision::Deny((*reason).to_owned());
        }
    }
    let Some(run) = LSV_RUN.find(command) else {
        return Decision::Allow;
    };
    let rest = &command[run.end()..];
    let Some(dash) = DOUBLE_DASH.find(rest) else {
        return Decision::Allow;
    };
    let vars: Vec<&str> = BINDING
        .captures_iter(&rest[..dash.start()])
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect();
    match check_child(&rest[dash.end()..], &vars) {
        Some(reason) => Decision::Deny(reason),
        None => Decision::Allow,
    }
}

/// Evaluates a Claude Code `PreToolUse` hook payload.
///
/// Tools other than `Bash` are always allowed.
///
/// # Errors
///
/// Returns [`ErrorKind::Usage`] if `input` is not valid hook JSON or a `Bash`
/// payload lacks `tool_input.command`. Callers should then allow the command
/// and warn, so a hook bug cannot wedge the session.
pub fn evaluate(input: &str) -> Result<Decision> {
    let usage = |why: String| Error::new(ErrorKind::Usage(why));
    let value: Value =
        serde_json::from_str(input).map_err(|e| usage(format!("could not parse hook input: {e}")))?;
    if value.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return Ok(Decision::Allow);
    }
    let command = value
        .pointer("/tool_input/command")
        .and_then(Value::as_str)
        .ok_or_else(|| usage("Bash hook input has no tool_input.command".to_owned()))?;
    Ok(check_command(command))
}

/// Renders a decision as Claude Code hook output; `None` means allow silently.
#[must_use]
pub fn render(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Deny(reason) => Some(
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": format!("llm-secret-vault: {reason}"),
                }
            })
            .to_string(),
        ),
    }
}
```

- [ ] **Step 4: Run tests and lints**

Run: `cargo test --test hook && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all 4 tests pass. If a table entry fails, fix the rule, not the table, unless the entry contradicts the spec's hook section.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add Claude Code guard hook"
```

---

### Task 9: CLI

**Files:**
- Modify: `src/main.rs` (replace)
- Create: `tests/cli.rs`

**Interfaces:**
- Consumes: everything public from Tasks 1-8.
- Produces: the `lsv` binary with subcommands `list`, `info`, `capture`, `generate`, `import`, `run`, `delete`, `mcp`, `hook`, `setup claude`.

- [ ] **Step 1: Write the failing smoke tests `tests/cli.rs`**

These never open the vault, so they cannot touch the real keyring.

```rust
//! Smoke tests for the `lsv` binary (no keyring access).

use std::io::Write;
use std::process::{Command, Stdio};

fn lsv() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsv"))
}

fn hook(input: &str) -> std::process::Output {
    let mut child = lsv()
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn help_lists_subcommands() {
    let out = lsv().arg("--help").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for sub in ["list", "info", "capture", "generate", "import", "run", "delete", "mcp", "hook", "setup"] {
        assert!(text.contains(sub), "missing {sub}");
    }
}

#[test]
fn hook_denies_and_allows() {
    let out = hook(r#"{"tool_name":"Bash","tool_input":{"command":"lsv run X=a -- printenv"}}"#);
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout).unwrap().contains("\"permissionDecision\":\"deny\""));

    let out = hook(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#);
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn hook_fails_open_on_garbage() {
    let out = hook("garbage");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8(out.stderr).unwrap().contains("warning"));
}

#[test]
fn setup_claude_prints_instructions() {
    let out = lsv().args(["setup", "claude"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("claude mcp add --scope user llm-secret-vault -- lsv mcp"));
    assert!(text.contains("\"command\": \"lsv hook\""));
}

#[test]
fn invalid_name_is_rejected_before_opening_vault() {
    let out = lsv().args(["info", "Bad Name"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8(out.stderr).unwrap().contains("invalid secret name"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test cli`
Expected: failures (the binary currently does nothing).

- [ ] **Step 3: Implement `src/main.rs`**

```rust
//! `lsv`: command-line front end for llm-secret-vault.

use std::io::{Read, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use llm_secret_vault::capture::{CaptureOptions, SystemClipboard, capture};
use llm_secret_vault::generate::{Alphabet, GenerateOptions, generate};
use llm_secret_vault::hook::{evaluate, render};
use llm_secret_vault::import::import;
use llm_secret_vault::inject::{RunRequest, run};
use llm_secret_vault::mcp::Server;
use llm_secret_vault::{Error, ErrorKind, Meta, Result, SecretName, Vault};

/// Let LLM agents use secrets they can never read.
#[derive(Debug, Parser)]
#[command(name = "lsv", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// List secret names and metadata (never values).
    List {
        /// Only names starting with this prefix.
        prefix: Option<String>,
    },
    /// Show metadata for one secret.
    Info { name: String },
    /// Store the clipboard text as a secret, then clear the clipboard.
    Capture {
        name: String,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        expect_prefix: Option<String>,
        #[arg(long)]
        min_len: Option<usize>,
        #[arg(long)]
        allow_multiline: bool,
    },
    /// Generate a random secret without showing it.
    Generate {
        name: String,
        #[arg(long, default_value_t = 32)]
        length: usize,
        #[arg(long, value_enum, default_value_t = Alphabet::Alnum)]
        alphabet: Alphabet,
        #[arg(long)]
        overwrite: bool,
    },
    /// Type a secret at a hidden prompt.
    Import {
        name: String,
        #[arg(long)]
        overwrite: bool,
    },
    /// Run a command with secrets injected: lsv run VAR=name ... -- program args.
    Run {
        /// VAR=secret-name bindings.
        bindings: Vec<String>,
        /// Program and arguments; {{name}} placeholders are expanded.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Delete a secret.
    Delete { name: String },
    /// Serve MCP over stdio (launched by Claude Code).
    Mcp,
    /// Claude Code `PreToolUse` guard; reads hook JSON on stdin.
    Hook,
    /// Print setup instructions.
    Setup {
        #[command(subcommand)]
        target: SetupTarget,
    },
}

#[derive(Debug, Subcommand)]
enum SetupTarget {
    /// Claude Code: MCP registration and guard hook.
    Claude,
}

const SETUP_CLAUDE: &str = r#"1. Register the MCP server:

   claude mcp add --scope user llm-secret-vault -- lsv mcp

2. Add the guard hook to ~/.claude/settings.json (merge with existing "hooks"):

   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash",
           "hooks": [{ "type": "command", "command": "lsv hook" }]
         }
       ]
     }
   }

3. Next time a secret is on your clipboard, tell Claude its name, e.g.
   "the NAS root password is in the clipboard, save it as nas-root".
"#;

fn main() -> ExitCode {
    match dispatch(Cli::parse().command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("lsv: {err}");
            ExitCode::from(2)
        }
    }
}

fn dispatch(command: Cmd) -> Result<ExitCode> {
    match command {
        Cmd::Hook => Ok(hook_main()),
        Cmd::Setup { target: SetupTarget::Claude } => {
            print!("{SETUP_CLAUDE}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::List { prefix } => {
            print_table(&Vault::open()?.list(prefix.as_deref()));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Info { name } => {
            let name = SecretName::new(name)?;
            print_info(&Vault::open()?.info(&name)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Capture { name, overwrite, expect_prefix, min_len, allow_multiline } => {
            let name = SecretName::new(name)?;
            let options = CaptureOptions { overwrite, expect_prefix, min_len, allow_multiline };
            let mut clipboard = SystemClipboard::new()?;
            let report = capture(&Vault::open()?, &mut clipboard, &name, &options)?;
            println!(
                "stored {name}: {} chars, fp {}{}",
                report.meta.len,
                report.meta.fingerprint,
                if report.clipboard_cleared { ", clipboard cleared" } else { "" }
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Generate { name, length, alphabet, overwrite } => {
            let name = SecretName::new(name)?;
            let meta = generate(&Vault::open()?, &name, &GenerateOptions { length, alphabet, overwrite })?;
            println!("stored {name}: {} chars, fp {}", meta.len, meta.fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Import { name, overwrite } => {
            let name = SecretName::new(name)?;
            let meta = import(&Vault::open()?, &name, overwrite)?;
            println!("stored {name}: {} chars, fp {}", meta.len, meta.fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Run { bindings, argv } => run_main(&bindings, argv),
        Cmd::Delete { name } => {
            let name = SecretName::new(name)?;
            Vault::open()?.delete(&name)?;
            println!("deleted {name}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Mcp => {
            let server = Server::with_system_clipboard(Vault::open()?);
            server
                .serve(std::io::stdin().lock(), std::io::stdout().lock())
                .map_err(|e| Error::from_io("MCP transport", &e))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_main(bindings: &[String], argv: Vec<String>) -> Result<ExitCode> {
    let mut request = RunRequest::new(argv);
    for binding in bindings {
        let (var, name) = binding.split_once('=').ok_or_else(|| {
            usage(format!("expected VAR=secret-name before `--`, got `{binding}`"))
        })?;
        request = request.env(var, SecretName::new(name)?);
    }
    let output = run(&Vault::open()?, &request)?;
    std::io::stdout().write_all(output.stdout.as_bytes()).ok();
    std::io::stderr().write_all(output.stderr.as_bytes()).ok();
    let code = output.exit_code.and_then(|c| u8::try_from(c).ok()).unwrap_or(1);
    Ok(ExitCode::from(code))
}

fn hook_main() -> ExitCode {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("lsv hook: warning: could not read stdin: {e}");
        return ExitCode::SUCCESS;
    }
    match evaluate(&input) {
        Ok(decision) => {
            if let Some(json) = render(&decision) {
                println!("{json}");
            }
        }
        Err(e) => eprintln!("lsv hook: warning: {e}; allowing the command"),
    }
    ExitCode::SUCCESS
}

fn usage(why: String) -> Error {
    Error::from_kind(ErrorKind::Usage(why))
}

fn print_table(secrets: &[Meta]) {
    if secrets.is_empty() {
        println!("no secrets stored");
        return;
    }
    println!("{:<32} {:>5}  {:<8}  {:<9}  UPDATED", "NAME", "LEN", "FP", "SOURCE");
    for meta in secrets {
        println!(
            "{:<32} {:>5}  {:<8}  {:<9}  {}",
            meta.name,
            meta.len,
            meta.fingerprint,
            source_label(meta),
            date(meta.rotated.unwrap_or(meta.created))
        );
    }
}

fn print_info(meta: &Meta) {
    println!("name:        {}", meta.name);
    println!("length:      {}", meta.len);
    println!("fingerprint: {}", meta.fingerprint);
    println!("source:      {}", source_label(meta));
    println!("created:     {}", date(meta.created));
    if let Some(rotated) = meta.rotated {
        println!("rotated:     {}", date(rotated));
    }
}

fn source_label(meta: &Meta) -> String {
    serde_json::to_value(meta.source)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Formats Unix seconds as a UTC `YYYY-MM-DD` date.
fn date(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Converts days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_791_849_600), "2026-10-13");
        assert_eq!(date(951_782_400), "2000-02-29");
    }
}
```

`main.rs` uses `Error::from_kind` and `Error::from_io`, which the library does not expose yet because `Error::new` is `pub(crate)`. Add both to `src/error.rs`:

```rust
impl Error {
    /// Creates an error of the given kind.
    #[must_use]
    pub fn from_kind(kind: ErrorKind) -> Self {
        Self::new(kind)
    }

    /// Wraps an I/O error that occurred during `context`.
    #[must_use]
    pub fn from_io(context: &str, err: &std::io::Error) -> Self {
        Self::new(ErrorKind::Spawn(format!("{context}: {err}")))
    }
}
```

- [ ] **Step 4: Run tests and lints**

Run: `cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check`
Expected: all pass, including `tests/cli.rs` and the date test.

- [ ] **Step 5: Manual check against the real keyring (macOS, local)**

Run, one at a time, and confirm the output shape (the user may need to approve Keychain prompts):

```bash
cargo install --path .
printf 'demo-secret-value-123' | pbcopy
lsv capture lsv-demo --expect-prefix demo-
# expected: stored lsv-demo: 21 chars, fp xxxxxxxx, clipboard cleared
pbpaste | wc -c                     # expected: 0
lsv list                            # expected: a row for lsv-demo, no value
lsv run V=lsv-demo -- sh -c 'echo "got $V"'
# expected: got «redacted:lsv-demo»
lsv run V=lsv-demo -- sh -c 'test "$V" = demo-secret-value-123 && echo match'
# expected: match
lsv delete lsv-demo                 # expected: deleted lsv-demo
```

If an agent is executing this plan, skip `import` (it needs a human at a TTY) and report the remaining results.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add lsv command-line interface"
```

---

### Task 10: Documentation, CI and publishing

**Files:**
- Create: `README.md`, `docs/DESIGN.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: the finished crate.

- [ ] **Step 1: Write `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - name: Install Linux keyring dependencies
        if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y libdbus-1-dev pkg-config gnome-keyring dbus-x11
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
      - name: Real keyring tests (Linux)
        if: runner.os == 'Linux'
        run: dbus-run-session -- sh -c 'printf ci | gnome-keyring-daemon --unlock --components=secrets && cargo test -- --ignored'
      - name: Real keyring tests (macOS, Windows)
        if: runner.os != 'Linux'
        run: cargo test -- --ignored
```

- [ ] **Step 2: Write `docs/DESIGN.md`**

Copy the spec and adjust the header:

```bash
cp docs/superpowers/specs/2026-10-13-llm-secret-vault-design.md docs/DESIGN.md
```

Then in `docs/DESIGN.md` replace the first three lines (`# llm-secret-vault: design`, the `Date:` line, the `Status:` line) with:

```markdown
# llm-secret-vault design

This document describes how `lsv` keeps secrets out of an agent's context.
It was written before implementation and is kept in sync with the code.
```

- [ ] **Step 3: Write `README.md`**

````markdown
# llm-secret-vault

**Let LLM agents capture, generate and use your secrets without ever reading them.**

[![CI](https://github.com/aovestdipaperino/llm-secret-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/aovestdipaperino/llm-secret-vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Coding agents need credentials all the time: a NAS password for `ssh`, a
Hugging Face token, an API key for `curl`. The usual workflow is "the key is
in the clipboard" or pasting it into the chat, and from then on the value
lives in transcripts and logs you don't control.

`lsv` stores secrets in your OS keyring (macOS Keychain, Linux Secret
Service, Windows Credential Manager) and gives the agent names instead of
values. The agent can capture a secret from your clipboard, generate a new
one, rotate it, and run commands with it. No operation returns a value, and
command output is redacted before the agent sees it.

```text
you    the NAS root password is in the clipboard, save it as nas-root and back up /data

agent  → secret_capture(name="nas-root")
       ⇐ stored nas-root: 18 chars, fp 3a9c01e2, clipboard cleared
agent  → secret_run(argv=["sshpass","-e","ssh","root@nas","tar czf - /data"], env={"SSHPASS":"nas-root"})
       ⇐ exit 0
```

## Install

```bash
cargo install llm-secret-vault      # installs the `lsv` binary
lsv setup claude                    # prints the MCP and hook setup for Claude Code
```

On Linux, building needs `libdbus-1-dev` and `pkg-config`.

## Use it yourself

```bash
lsv capture hf-token --expect-prefix hf_     # clipboard → keyring, clipboard cleared
lsv generate db-password --length 40         # random, never shown
lsv import nas-root                          # hidden prompt, typed twice
lsv list                                     # names, lengths, fingerprints, dates
lsv run HF_TOKEN=hf-token -- huggingface-cli upload me/model ./weights
lsv run -- curl -H "Authorization: Bearer {{resend}}" https://api.resend.com/emails
lsv generate db-password --overwrite         # rotate
lsv delete db-password
```

`lsv run` prints the command's output after it finishes, with every secret
value replaced by `«redacted:name»`, so pasting it into a chat is safe.

## MCP tools

| Tool | What it does |
|---|---|
| `secret_list` | Names and metadata, optional prefix filter |
| `secret_info` | Metadata for one secret |
| `secret_capture` | Clipboard → keyring, optional `expect_prefix` check, clears the clipboard |
| `secret_generate` | Random value, `overwrite: true` rotates |
| `secret_run` | Run an argv with `env` bindings and `{{name}}` placeholders; redacted output, 120 s timeout and 32 KB cap by default |

There is deliberately no delete tool: only you can delete, from the CLI.

## The guard hook

`lsv hook` is a Claude Code `PreToolUse` hook for Bash. It blocks commands
that would print a secret: `lsv run` children that echo or encode an injected
variable or dump the environment, and direct keyring reads such as
`security find-generic-password -w` or `secret-tool lookup`. If the hook
cannot parse its input it allows the command and prints a warning, so it can
never wedge your session.

## Threat model

`lsv` keeps secrets out of an agent's context **by accident**. It does not
stop an agent that is deliberately trying to exfiltrate them: a child process
receives the real value and can transform it in ways no redactor recognizes
(the hook catches the common ones). Other limits worth knowing:

- `{{name}}` placeholders put the value in the child's argv, visible in the
  process table while the child runs. Prefer env bindings when the tool
  accepts them.
- Redaction covers the raw value, base64 (standard and URL-safe, with and
  without padding), percent-encoding and hex. A value printed only in part,
  or base64-encoded at an offset inside a longer blob, is not caught.
- Storage, encryption and locking are the OS keyring's. On macOS over plain
  SSH the login keychain is locked, so `lsv` reports the keyring as
  unavailable.
- On Windows, a timeout kills the child but not its grandchildren.

See [docs/DESIGN.md](docs/DESIGN.md) for the full design.

## License

MIT
````

- [ ] **Step 4: Final verification**

Run: `cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo test --doc && cargo package --list | head -40`
Expected: everything passes. The package list includes `src/`, `README.md`, `LICENSE`, `Cargo.toml` and does not include `target/`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: add README, design doc and CI workflow"
```

- [ ] **Step 6: Create the public GitHub repository and push**

The user asked for a public repo. Run:

```bash
gh repo create aovestdipaperino/llm-secret-vault --public --source . --push \
  --description "Let LLM agents capture, generate and use OS-keyring secrets without ever reading them"
gh run watch --exit-status || gh run list --limit 1
```

Expected: the repo exists, `main` is pushed, and the CI run is green on all three OSes. If the Linux keyring step fails, report the log and leave it to the user; don't weaken the step without asking.

Do not run `cargo publish`. Publishing to crates.io was not requested.
