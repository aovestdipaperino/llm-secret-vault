//! OS keyring backend (macOS Keychain, Secret Service, Windows Credential Manager).

use zeroize::Zeroizing;

use super::{Backend, SERVICE};
use crate::error::{Error, ErrorKind, Result};

/// Backend that stores values in the platform keyring.
#[derive(Debug, Default)]
pub(crate) struct KeyringBackend;

fn entry(account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(SERVICE, account).map_err(|err| map_err(&err))
}

fn map_err(err: &keyring::Error) -> Error {
    Error::new(ErrorKind::Keyring(err.to_string()))
}

impl Backend for KeyringBackend {
    fn put(&self, account: &str, value: &str) -> Result<()> {
        entry(account)?
            .set_password(value)
            .map_err(|err| map_err(&err))
    }

    fn resolve(&self, account: &str) -> Result<Option<Zeroizing<String>>> {
        match entry(account)?.get_password() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(map_err(&err)),
        }
    }

    fn delete(&self, account: &str) -> Result<bool> {
        match entry(account)?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(err) => Err(map_err(&err)),
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
        assert_eq!(
            backend.resolve(&account).unwrap().unwrap().as_str(),
            "test-value-123"
        );
        assert!(backend.delete(&account).unwrap());
        assert!(backend.resolve(&account).unwrap().is_none());
    }
}
