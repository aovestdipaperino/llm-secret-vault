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
    let key = if let Some(key) = backend.resolve(KEY_ACCOUNT)? {
        key
    } else {
        let mut raw = [0u8; 32];
        getrandom::fill(&mut raw).map_err(|e| Error::new(ErrorKind::Random(e.to_string())))?;
        let key = Zeroizing::new(hex::encode(raw));
        backend.put(KEY_ACCOUNT, &key)?;
        key
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
        assert_ne!(
            fingerprint(&one, "same").unwrap(),
            fingerprint(&two, "same").unwrap()
        );
    }
}
