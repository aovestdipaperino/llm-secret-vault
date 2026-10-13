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
        return Err(reject(format!(
            "clipboard text is {len} characters, minimum is {min}"
        )));
    }
    if !options.allow_multiline {
        if value.contains(['\n', '\r']) {
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
    let original =
        Zeroizing::new(clipboard.text()?.ok_or_else(|| {
            Error::new(ErrorKind::Clipboard("clipboard holds no text".to_owned()))
        })?);
    let value = Zeroizing::new(original.trim_end_matches(['\r', '\n']).to_owned());
    validate(&value, options)?;
    if vault.exists(name) && !options.overwrite {
        return Err(Error::new(ErrorKind::NameExists(name.to_string())));
    }
    let meta = vault.store(name, &value, Source::Clipboard, options.overwrite)?;
    let still_there = match clipboard.text() {
        Ok(Some(now)) => Zeroizing::new(now) == original,
        _ => false,
    };
    // The secret is already stored; a failed clear must not hide that.
    let cleared = still_there && clipboard.clear().is_ok();
    Ok(CaptureReport {
        meta,
        clipboard_cleared: cleared,
    })
}

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
        fail_clear: bool,
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
            if self.fail_clear {
                return Err(Error::new(ErrorKind::Clipboard("boom".to_owned())));
            }
            self.text = None;
            self.cleared = true;
            Ok(())
        }
    }

    fn clip(text: &str) -> FakeClipboard {
        FakeClipboard {
            text: Some(text.to_owned()),
            ..FakeClipboard::default()
        }
    }

    fn name(s: &str) -> SecretName {
        SecretName::new(s).unwrap()
    }

    #[test]
    fn stores_and_clears() {
        let vault = Vault::in_memory();
        let mut cb = clip("hf_abcdefghijklmnop\n");
        let report = capture(
            &vault,
            &mut cb,
            &name("hf-token"),
            &CaptureOptions::default(),
        )
        .unwrap();
        assert!(report.clipboard_cleared);
        assert!(cb.cleared);
        assert_eq!(report.meta.len, 19, "trailing newline is trimmed");
        assert_eq!(report.meta.source, Source::Clipboard);
        // Capture must not read values back, so compare keyed fingerprints
        // against the same trimmed value stored under another name.
        let expected = vault
            .store(
                &name("probe"),
                "hf_abcdefghijklmnop",
                Source::Imported,
                false,
            )
            .unwrap();
        assert_eq!(report.meta.fingerprint, expected.fingerprint);
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
            (
                "sk_live_wrongprefix",
                CaptureOptions {
                    expect_prefix: Some("hf_".into()),
                    ..Default::default()
                },
            ),
            ("short", CaptureOptions::default()),
            (
                "line-one-secret\nline-two-secret",
                CaptureOptions::default(),
            ),
        ];
        for (text, options) in cases {
            let mut cb = clip(text);
            let err = capture(&vault, &mut cb, &name("k"), &options).unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::InvalidValue(_)), "{text}");
            assert!(
                !err.to_string().contains(text.lines().next().unwrap()),
                "{err}"
            );
            assert!(!cb.cleared);
            assert!(!vault.exists(&name("k")));
        }
    }

    #[test]
    fn multiline_allowed_on_request() {
        let vault = Vault::in_memory();
        let mut cb = clip("-----BEGIN KEY-----\nabcdefgh\n-----END KEY-----");
        let options = CaptureOptions {
            allow_multiline: true,
            ..Default::default()
        };
        let report = capture(&vault, &mut cb, &name("ssh-key"), &options).unwrap();
        assert_eq!(report.meta.len, 46);
    }

    #[test]
    fn clear_failure_still_reports_stored_secret() {
        let vault = Vault::in_memory();
        let mut cb = clip("first-secret-value");
        cb.fail_clear = true;
        let report = capture(&vault, &mut cb, &name("k"), &CaptureOptions::default()).unwrap();
        assert!(!report.clipboard_cleared);
        assert!(vault.exists(&name("k")));
        assert!(vault.list(None).iter().any(|m| m.name == name("k")));
    }

    #[test]
    fn oversized_single_line_rejected() {
        let vault = Vault::in_memory();
        let mut cb = clip(&"x".repeat(MAX_SINGLE_LINE_LEN + 1));
        let err = capture(&vault, &mut cb, &name("k"), &CaptureOptions::default()).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidValue(_)));
        assert!(!vault.exists(&name("k")));
    }

    #[test]
    fn carriage_return_counts_as_multiline() {
        let vault = Vault::in_memory();
        let mut cb = clip("line-one-secret\rline-two-secret");
        let err = capture(&vault, &mut cb, &name("k"), &CaptureOptions::default()).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidValue(_)));
    }

    #[test]
    fn name_exists_leaves_clipboard_alone() {
        let vault = Vault::in_memory();
        capture(
            &vault,
            &mut clip("first-secret-value"),
            &name("k"),
            &CaptureOptions::default(),
        )
        .unwrap();
        let mut cb = clip("second-secret-value");
        assert!(capture(&vault, &mut cb, &name("k"), &CaptureOptions::default()).is_err());
        assert!(!cb.cleared);
    }

    #[test]
    fn overwrite_rules() {
        let vault = Vault::in_memory();
        capture(
            &vault,
            &mut clip("first-secret-value"),
            &name("k"),
            &CaptureOptions::default(),
        )
        .unwrap();
        let err = capture(
            &vault,
            &mut clip("second-secret-value"),
            &name("k"),
            &CaptureOptions::default(),
        )
        .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::NameExists(_)));
        let options = CaptureOptions {
            overwrite: true,
            ..Default::default()
        };
        let report = capture(
            &vault,
            &mut clip("second-secret-value"),
            &name("k"),
            &options,
        )
        .unwrap();
        assert!(report.meta.rotated.is_some());
    }
}
