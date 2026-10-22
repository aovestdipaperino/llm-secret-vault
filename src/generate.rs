//! Generating random secrets that nobody ever sees.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};
use crate::name::{SecretName, SecretUser};
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
            Self::Base64url => alnum().chain(*b"-_").collect(),
            Self::Printable => (33u8..=126).collect(),
        }
    }
}

/// Parameters for [`generate`].
#[derive(Debug, Clone)]
pub struct GenerateOptions {
    /// Number of characters.
    pub length: usize,
    /// Character set.
    pub alphabet: Alphabet,
    /// Replace an existing secret with the same name.
    pub overwrite: bool,
    /// Account the secret belongs to; on overwrite `None` keeps the current one.
    pub user: Option<SecretUser>,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            length: 32,
            alphabet: Alphabet::Alnum,
            overwrite: false,
            user: None,
        }
    }
}

/// Uniformly random string over `alphabet` using rejection sampling.
fn random_string(length: usize, alphabet: &[u8]) -> Result<Zeroizing<String>> {
    let n = alphabet.len();
    let limit = 256 - (256 % n);
    let mut out = Zeroizing::new(String::with_capacity(length));
    let mut buf = Zeroizing::new([0u8; 64]);
    while out.len() < length {
        getrandom::fill(&mut *buf).map_err(|e| Error::new(ErrorKind::Random(e.to_string())))?;
        for &byte in buf.iter() {
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
    vault.store(
        name,
        &value,
        Source::Generated,
        options.overwrite,
        options.user.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_strings_respect_length_and_alphabet() {
        for alphabet in [
            Alphabet::Alnum,
            Alphabet::Hex,
            Alphabet::Base64url,
            Alphabet::Printable,
        ] {
            let chars = alphabet.chars();
            let value = random_string(200, &chars).unwrap();
            assert_eq!(value.len(), 200);
            assert!(value.bytes().all(|b| chars.contains(&b)), "{alphabet:?}");
        }
    }

    #[test]
    fn values_differ() {
        let chars = Alphabet::Alnum.chars();
        assert_ne!(
            *random_string(32, &chars).unwrap(),
            *random_string(32, &chars).unwrap()
        );
    }

    #[test]
    fn generate_stores_blind() {
        let vault = Vault::in_memory();
        let name = SecretName::new("db-password").unwrap();
        let meta = generate(&vault, &name, &GenerateOptions::default()).unwrap();
        assert_eq!(meta.len, 32);
        assert_eq!(meta.source, Source::Generated);
        let rotated = generate(
            &vault,
            &name,
            &GenerateOptions {
                overwrite: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_ne!(rotated.fingerprint, meta.fingerprint);
    }

    #[test]
    fn rejects_out_of_range_lengths() {
        let vault = Vault::in_memory();
        let name = SecretName::new("x").unwrap();
        for length in [0, 7, 1025] {
            let options = GenerateOptions {
                length,
                ..Default::default()
            };
            assert!(matches!(
                generate(&vault, &name, &options).unwrap_err().kind(),
                ErrorKind::Usage(_)
            ));
        }
    }

    #[test]
    fn generate_stores_user() {
        let vault = Vault::in_memory();
        let name = SecretName::new("db-app").unwrap();
        let options = GenerateOptions {
            user: Some(SecretUser::new("app").unwrap()),
            ..Default::default()
        };
        let meta = generate(&vault, &name, &options).unwrap();
        assert_eq!(meta.user, Some(SecretUser::new("app").unwrap()));
    }
}
