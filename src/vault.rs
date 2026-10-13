//! The vault service: store, describe and delete secrets by name.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backend::{Backend, KeyringBackend, MemoryBackend};
use crate::error::{Error, ErrorKind, Result};
use crate::fingerprint::fingerprint;
use crate::index::Index;
use crate::name::SecretName;

/// Minimum accepted length of a secret value, in bytes.
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
    /// Serializes `store` and `delete` within this process.
    write_lock: Mutex<()>,
}

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
            inner: Arc::new(Inner {
                backend,
                index,
                write_lock: Mutex::new(()),
            }),
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
    ///
    /// The fingerprint is computed before anything is stored. If the index
    /// update fails after the keyring write succeeded, the error is returned
    /// and the keyring keeps the new value (an overwritten old value is not
    /// restored).
    ///
    /// # Panics
    ///
    /// Panics if the internal write lock is poisoned.
    pub fn store(
        &self,
        name: &SecretName,
        value: &str,
        source: Source,
        overwrite: bool,
    ) -> Result<Meta> {
        if value.len() < MIN_VALUE_LEN {
            return Err(Error::new(ErrorKind::InvalidValue(format!(
                "{} bytes, minimum is {MIN_VALUE_LEN}",
                value.len()
            ))));
        }
        if value.len() > MAX_VALUE_LEN {
            return Err(Error::new(ErrorKind::InvalidValue(format!(
                "{} bytes, maximum is {MAX_VALUE_LEN}",
                value.len()
            ))));
        }
        let _guard = self.inner.write_lock.lock().expect("write lock poisoned");
        let existing = self.inner.index.get(name);
        if existing.is_some() && !overwrite {
            return Err(Error::new(ErrorKind::NameExists(name.to_string())));
        }
        let fingerprint = fingerprint(self.inner.backend.as_ref(), value)?;
        self.inner.backend.put(name.as_str(), value)?;
        let now = now_secs();
        let meta = Meta {
            name: name.clone(),
            len: value.chars().count(),
            fingerprint,
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
    /// The keyring entry is deleted first, so a keyring failure leaves the
    /// index entry in place.
    ///
    /// # Panics
    ///
    /// Panics if the internal write lock is poisoned.
    pub fn delete(&self, name: &SecretName) -> Result<()> {
        let _guard = self.inner.write_lock.lock().expect("write lock poisoned");
        let in_store = self.inner.backend.delete(name.as_str())?;
        let in_index = self.inner.index.remove(name)?;
        if in_index || in_store {
            Ok(())
        } else {
            Err(unknown(name))
        }
    }

    /// Returns a secret's value. Only `inject` may call this.
    #[allow(dead_code)] // used by inject (Task 5)
    pub(crate) fn resolve(&self, name: &SecretName) -> Result<Zeroizing<String>> {
        self.inner
            .backend
            .resolve(name.as_str())?
            .ok_or_else(|| unknown(name))
    }
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
        let meta = vault
            .store(&name("nas-root"), "hunter2-long", Source::Clipboard, false)
            .unwrap();
        assert_eq!(meta.len, 12);
        assert_eq!(meta.source, Source::Clipboard);
        assert!(meta.rotated.is_none());
        assert_eq!(vault.info(&name("nas-root")).unwrap(), meta);
        assert_eq!(vault.list(None), vec![meta.clone()]);
        assert_eq!(vault.list(Some("nas")), vec![meta]);
        assert!(vault.list(Some("hf")).is_empty());
        assert_eq!(
            vault.resolve(&name("nas-root")).unwrap().as_str(),
            "hunter2-long"
        );
    }

    #[test]
    fn refuses_overwrite_unless_asked() {
        let vault = Vault::in_memory();
        vault
            .store(&name("k"), "first-value", Source::Generated, false)
            .unwrap();
        let err = vault
            .store(&name("k"), "second-value", Source::Generated, false)
            .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::NameExists(_)));
        let first = vault.info(&name("k")).unwrap();
        let rotated = vault
            .store(&name("k"), "second-value", Source::Imported, true)
            .unwrap();
        assert_eq!(rotated.created, first.created);
        assert!(rotated.rotated.is_some());
        assert_ne!(rotated.fingerprint, first.fingerprint);
        assert_eq!(vault.resolve(&name("k")).unwrap().as_str(), "second-value");
    }

    #[test]
    fn rejects_bad_lengths_without_echoing_value() {
        let vault = Vault::in_memory();
        let marker = "zq9-DISTINCTIVE-marker-7731";
        let err = vault
            .store(&name("k"), &marker[..3], Source::Imported, false)
            .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidValue(_)));
        assert!(!err.to_string().contains(marker));
        let big = "x".repeat(MAX_VALUE_LEN + 1);
        assert!(
            vault
                .store(&name("k"), &big, Source::Imported, false)
                .is_err()
        );
    }

    #[test]
    fn unknown_and_delete() {
        let vault = Vault::in_memory();
        assert!(matches!(
            vault.info(&name("nope")).unwrap_err().kind(),
            ErrorKind::UnknownName(_)
        ));
        assert!(matches!(
            vault.resolve(&name("nope")).unwrap_err().kind(),
            ErrorKind::UnknownName(_)
        ));
        vault
            .store(&name("gone"), "value-123", Source::Generated, false)
            .unwrap();
        vault.delete(&name("gone")).unwrap();
        assert!(!vault.exists(&name("gone")));
        assert!(matches!(
            vault.delete(&name("gone")).unwrap_err().kind(),
            ErrorKind::UnknownName(_)
        ));
    }

    #[test]
    fn hmac_key_is_not_listed() {
        let vault = Vault::in_memory();
        vault
            .store(&name("a"), "value-123", Source::Generated, false)
            .unwrap();
        assert_eq!(vault.list(None).len(), 1);
        assert!(
            vault
                .inner
                .backend
                .resolve(crate::fingerprint::KEY_ACCOUNT)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn value_length_bounds_are_in_bytes() {
        let vault = Vault::in_memory();
        let store = |v: &str| vault.store(&name("k"), v, Source::Imported, true);
        assert!(store(&"x".repeat(MIN_VALUE_LEN)).is_ok());
        assert!(store(&"x".repeat(MIN_VALUE_LEN - 1)).is_err());
        // Two characters but exactly MIN_VALUE_LEN bytes.
        assert!(store("\u{e9}\u{e9}").is_ok());
        // One character but fewer than MIN_VALUE_LEN bytes.
        assert!(store("\u{e9}").is_err());
        assert!(store(&"x".repeat(MAX_VALUE_LEN)).is_ok());
        assert!(store(&"x".repeat(MAX_VALUE_LEN + 1)).is_err());
    }

    #[test]
    fn delete_of_unknown_name_does_not_create_index_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        let vault = Vault::with_parts(
            Box::new(MemoryBackend::default()),
            Index::load(&path).unwrap(),
        );
        assert!(vault.delete(&name("nope")).is_err());
        assert!(!path.exists());
    }
}
