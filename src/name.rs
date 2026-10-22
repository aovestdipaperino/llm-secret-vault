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
        let rest_ok = chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
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
        f.pad(&self.0)
    }
}

impl AsRef<str> for SecretName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Maximum length of a secret's user, in characters.
pub const MAX_USER_LEN: usize = 128;

/// The account a secret belongs to, such as `root` or `admin@corp.com`.
///
/// Users are 1-128 characters without whitespace or control characters and
/// never contain `{{` or `}}`. A user is not secret.
///
/// # Examples
///
/// ```
/// use llm_secret_vault::SecretUser;
///
/// assert!(SecretUser::new("root").is_ok());
/// assert!(SecretUser::new("two words").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretUser(String);

impl SecretUser {
    /// Validates `user` and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidUser`] naming the rule `user` breaks.
    pub fn new(user: impl AsRef<str>) -> Result<Self> {
        let user = user.as_ref();
        let broken = if user.is_empty() {
            Some("it is empty")
        } else if user.chars().count() > MAX_USER_LEN {
            Some("it is longer than 128 characters")
        } else if user.chars().any(char::is_whitespace) {
            Some("it contains whitespace")
        } else if user.chars().any(char::is_control) {
            Some("it contains control characters")
        } else if user.contains("{{") || user.contains("}}") {
            Some("it contains `{{` or `}}`")
        } else {
            None
        };
        match broken {
            None => Ok(Self(user.to_owned())),
            Some(rule) => Err(Error::new(ErrorKind::InvalidUser(rule.to_owned()))),
        }
    }

    /// Returns the user as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretUser {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<SecretUser> for String {
    fn from(user: SecretUser) -> Self {
        user.0
    }
}

impl fmt::Display for SecretUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn accepts_valid_names() {
        for name in [
            "nas-root",
            "hf.token",
            "a",
            "0day",
            "aws_secret-2",
            &"x".repeat(64),
        ] {
            assert_eq!(SecretName::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn rejects_invalid_names() {
        for name in [
            "",
            "Nas",
            "-lead",
            ".lead",
            "_lead",
            "has space",
            "ünï",
            &"x".repeat(65),
            "__lsv_hmac_key__",
        ] {
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
    fn display_honours_width_and_alignment() {
        let name = SecretName::new("ab").unwrap();
        assert_eq!(format!("[{name:<6}]"), "[ab    ]");
        assert_eq!(format!("[{name:>4}]"), "[  ab]");
    }

    #[test]
    fn parses_from_str() {
        let name: SecretName = "hf-token".parse().unwrap();
        assert_eq!(name.to_string(), "hf-token");
    }

    #[test]
    fn accepts_valid_users() {
        for user in [
            "root",
            "admin@corp.com",
            "CORP\\enzo",
            "ünï",
            "a{b}c",
            &"x".repeat(128),
        ] {
            assert_eq!(SecretUser::new(user).unwrap().as_str(), user);
        }
    }

    #[test]
    fn rejects_invalid_users() {
        for (user, rule) in [
            ("", "it is empty"),
            (&"x".repeat(129) as &str, "it is longer than 128 characters"),
            ("two words", "it contains whitespace"),
            ("tab\there", "it contains whitespace"),
            ("bell\u{7}", "it contains control characters"),
            ("{{root}}", "it contains `{{` or `}}`"),
            ("root}}", "it contains `{{` or `}}`"),
        ] {
            let err = SecretUser::new(user).unwrap_err();
            assert_eq!(
                err.kind(),
                &ErrorKind::InvalidUser(rule.to_owned()),
                "{user:?}"
            );
            assert_eq!(err.to_string(), format!("invalid user: {rule}"));
        }
    }

    #[test]
    fn user_round_trips_through_json() {
        let user = SecretUser::new("root").unwrap();
        let json = serde_json::to_string(&user).unwrap();
        assert_eq!(json, "\"root\"");
        assert_eq!(serde_json::from_str::<SecretUser>(&json).unwrap(), user);
        assert!(serde_json::from_str::<SecretUser>("\"two words\"").is_err());
    }
}
