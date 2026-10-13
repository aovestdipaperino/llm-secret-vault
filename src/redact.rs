//! Streaming redaction of secret values and their common encodings.

use std::fmt::{self, Write as _};

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
            let _ = write!(out, "%{byte:02X}");
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
            .finish_non_exhaustive()
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
        patterns.sort_by_key(|p| std::cmp::Reverse(p.bytes.len()));
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
pub fn redact_all<'a>(
    secrets: impl IntoIterator<Item = (&'a str, &'a str)>,
    input: &[u8],
) -> Vec<u8> {
    let mut redactor = Redactor::new(secrets);
    let mut out = redactor.push(input);
    out.extend(redactor.finish());
    out
}

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
            "cEBzcyB3MHJkIQ==",    // base64 standard
            "cEBzcyB3MHJkIQ",      // base64 without padding
            "p%40ss%20w0rd%21",    // percent-encoded
            "7040737320773072642", // prefix of hex lower, must NOT be redacted alone
        ] {
            let out = redact(&secrets, encoded);
            if encoded.starts_with("70407") {
                assert_eq!(out, encoded);
            } else {
                assert_eq!(out, "«redacted:k»", "{encoded}");
            }
        }
        assert_eq!(redact(&secrets, "70407373207730726421"), "«redacted:k»");
        assert_eq!(
            redact(&secrets, "70407373207730726421".to_uppercase().as_str()),
            "«redacted:k»"
        );
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
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "xx «redacted:tok» yy «redacted:tok»"
        );
    }

    #[test]
    fn longest_match_wins_for_overlapping_secrets() {
        let secrets = [("short", "abcd1234"), ("long", "abcd1234efgh")];
        assert_eq!(
            redact(&secrets, "abcd1234efgh abcd1234"),
            "«redacted:long» «redacted:short»"
        );
    }

    #[test]
    fn longest_match_wins_at_every_chunk_size() {
        let secrets = [("short", "abcd1234"), ("long", "abcd1234efgh")];
        let input = b"abcd1234efgh abcd1234 abcd1234efg";
        for size in 1..=input.len() {
            let mut redactor = Redactor::new(secrets);
            let mut out = Vec::new();
            for piece in input.chunks(size) {
                out.extend(redactor.push(piece));
            }
            out.extend(redactor.finish());
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "«redacted:long» «redacted:short» «redacted:short»efg",
                "chunk size {size}"
            );
        }
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
