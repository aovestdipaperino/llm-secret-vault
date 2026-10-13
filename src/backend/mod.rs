//! Storage backends holding secret values.

mod keyring_store;
mod memory;

// used from Task 3 (vault)
#[allow(unused_imports)]
pub(crate) use keyring_store::KeyringBackend;
#[allow(unused_imports)]
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
