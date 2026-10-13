//! Streaming redaction of secret values and their common encodings.
//!
//! Covered forms: the raw value, standard and URL-safe base64 (padded and
//! unpadded), percent-encoding, and lower/upper-case hex. When a secret is
//! followed by other bytes inside one base64 blob, the prefix made of complete
//! 3-byte groups is also covered. Base64 of a secret at a non-zero offset
//! inside a larger blob is not covered.
//!
//! Matches that overlap or touch are merged into one span, replaced by one
//! marker per distinct label in the order the secrets were found.

use std::fmt::{self, Write as _};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use zeroize::Zeroizing;

#[derive(Clone)]
struct Pattern {
    bytes: Zeroizing<Vec<u8>>,
    marker: Vec<u8>,
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            // Writing to a String cannot fail.
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
    // JSON string-escaped form, as it appears when echoed inside a document.
    if let Ok(quoted) = serde_json::to_string(value) {
        let escaped = &quoted[1..quoted.len() - 1];
        if escaped != value {
            all.push(escaped.as_bytes().to_vec());
        }
    }
    // Base64 of `secret + more`: only whole 3-byte groups are independent of
    // what follows, so cover that prefix (when it is long enough to be useful).
    if raw.len() % 3 != 0 {
        let prefix_len = raw.len() / 3 * 4;
        if prefix_len >= 4 {
            all.push(STANDARD.encode(raw).into_bytes()[..prefix_len].to_vec());
            all.push(URL_SAFE.encode(raw).into_bytes()[..prefix_len].to_vec());
        }
    }
    all.retain(|v| !v.is_empty());
    all.sort();
    all.dedup();
    all
}

/// Redacts secrets from a byte stream, even when a value spans two chunks.
///
/// It holds back the last `longest pattern - 1` bytes of each chunk until
/// more input or [`Redactor::finish`] shows whether they start a match. The
/// holdback is at most one byte less than the longest encoded form (up to
/// `3 * 16384 - 1` bytes for percent-encoding) and can grow while a chain of
/// overlapping matches is still open. Scanning costs O(bytes x patterns).
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
                    bytes: Zeroizing::new(bytes),
                    marker: marker.clone(),
                });
            }
        }
        Self::from_patterns(patterns)
    }

    /// Builds a redactor from ready-made patterns, longest first.
    fn from_patterns(mut patterns: Vec<Pattern>) -> Self {
        patterns.sort_by_key(|p| std::cmp::Reverse(p.bytes.len()));
        let max_len = patterns.first().map_or(0, |p| p.bytes.len());
        Self {
            patterns,
            max_len,
            pending: Vec::new(),
        }
    }

    /// Feeds a chunk and returns the bytes that are now safe to emit.
    #[must_use]
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
        // Every position up to the end is decidable once no more input follows.
        let limit = self.pending.len() + 1;
        self.scan(limit).0
    }

    /// Longest pattern matching at `pos`, if any.
    fn match_at(&self, pos: usize) -> Option<&Pattern> {
        let rest = &self.pending[pos..];
        self.patterns.iter().find(|p| rest.starts_with(&p.bytes))
    }

    /// Emits output for pending positions `< limit`; returns it and the bytes consumed.
    ///
    /// A span of overlapping or touching matches is only emitted once every
    /// position up to and including its end is `< limit`; otherwise the scan
    /// stops at the span start and leaves it pending.
    fn scan(&self, limit: usize) -> (Vec<u8>, usize) {
        let pending = &self.pending;
        let stop = limit.min(pending.len());
        let mut out = Vec::with_capacity(stop);
        let mut i = 0;
        while i < stop {
            let Some(first) = self.match_at(i) else {
                out.push(pending[i]);
                i += 1;
                continue;
            };
            let mut end = i + first.bytes.len();
            let mut markers: Vec<&[u8]> = vec![&first.marker];
            let mut j = i + 1;
            while j <= end {
                if j >= limit {
                    return (out, i);
                }
                if let Some(next) = self.match_at(j) {
                    end = end.max(j + next.bytes.len());
                    if !markers.contains(&next.marker.as_slice()) {
                        markers.push(&next.marker);
                    }
                }
                j += 1;
            }
            for marker in markers {
                out.extend_from_slice(marker);
            }
            i = end;
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

    fn chunked(secrets: &[(&str, &str)], input: &[u8], size: usize) -> String {
        let mut redactor = Redactor::new(secrets.iter().copied());
        let mut out = Vec::new();
        for piece in input.chunks(size) {
            out.extend(redactor.push(piece));
        }
        out.extend(redactor.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn offset_overlap_is_merged_at_every_chunk_size() {
        let secrets = [("a", "abcd1234"), ("b", "1234efgh")];
        let input = b"x abcd1234efgh y";
        for size in 1..=input.len() {
            assert_eq!(
                chunked(&secrets, input, size),
                "x «redacted:a»«redacted:b» y",
                "chunk size {size}"
            );
        }
    }

    #[test]
    fn three_chained_overlaps_are_merged() {
        let secrets = [("a", "abcd1234"), ("b", "1234efgh"), ("c", "efghWXYZ")];
        let input = b"[abcd1234efghWXYZ]";
        for size in 1..=input.len() {
            assert_eq!(
                chunked(&secrets, input, size),
                "[«redacted:a»«redacted:b»«redacted:c»]",
                "chunk size {size}"
            );
        }
    }

    #[test]
    fn touching_matches_are_merged() {
        let secrets = [("a", "abcd1234"), ("b", "efghWXYZ")];
        assert_eq!(
            chunked(&secrets, b"abcd1234efghWXYZ!", 3),
            "«redacted:a»«redacted:b»!"
        );
    }

    #[test]
    fn base64_prefix_is_covered_when_secret_is_followed_by_bytes() {
        let secret = "hunter2-secret";
        for suffix in ["X", ":more"] {
            let blob = STANDARD.encode(format!("{secret}{suffix}"));
            let out = redact(&[("k", secret)], &blob);
            assert!(out.starts_with("«redacted:k»"), "{suffix}: {out}");
            let head = &blob[..16];
            for window in head.as_bytes().windows(8) {
                assert!(!out.contains(std::str::from_utf8(window).unwrap()));
            }
        }
    }

    #[test]
    fn url_safe_base64_is_redacted() {
        let value = "a???>>>b";
        let std_form = STANDARD.encode(value);
        assert!(std_form.contains('/') || std_form.contains('+'));
        let url_form = std_form.replace('+', "-").replace('/', "_");
        assert_ne!(std_form, url_form);
        assert_eq!(redact(&[("k", value)], &url_form), "«redacted:k»");
        assert_eq!(redact(&[("k", value)], &std_form), "«redacted:k»");
    }

    #[test]
    fn json_escaped_value_is_redacted_at_every_chunk_size() {
        let value = r#"pa"ss\w/ord"#;
        let doc = serde_json::json!({"echo": value}).to_string();
        assert!(!doc.contains(value));
        for size in 1..=doc.len() {
            let out = chunked(&[("k", value)], doc.as_bytes(), size);
            assert_eq!(out, r#"{"echo":"«redacted:k»"}"#, "chunk size {size}");
        }
    }

    #[test]
    fn single_byte_input_passes_through() {
        assert_eq!(redact(&[("k", "abcd")], "x"), "x");
    }

    #[test]
    fn passes_through_without_secrets_and_on_empty_input() {
        assert_eq!(redact(&[], "nothing to hide"), "nothing to hide");
        assert_eq!(redact(&[("k", "value-123")], ""), "");
    }

    /// Every string over `{0, 1, 2}` with length in `min..=max`.
    fn strings(min: usize, max: usize) -> Vec<Vec<u8>> {
        let mut all = vec![Vec::new()];
        let mut layer = vec![Vec::new()];
        for _ in 0..max {
            layer = layer
                .iter()
                .flat_map(|s: &Vec<u8>| (0..3).map(move |b| [s.as_slice(), &[b]].concat()))
                .collect();
            all.extend(layer.iter().cloned());
        }
        all.retain(|s| s.len() >= min);
        all
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Bounded exhaustive check of the scanner: for every pair of secrets up to
    /// `max_pattern` bytes and every input up to `max_input` bytes over the
    /// alphabet `{0, 1, 2}`, no secret survives, clean input is unchanged, and
    /// every split into three chunks gives the one-shot output. Each label's
    /// marker is one byte outside the alphabet, so a secret found in the output
    /// can only be input that escaped. See `formal/README.md`.
    fn exhaustive(max_pattern: usize, max_input: usize) {
        let patterns = strings(1, max_pattern);
        let inputs = strings(0, max_input);
        let redactor = |a: &[u8], b: &[u8]| {
            Redactor::from_patterns(vec![
                Pattern {
                    bytes: Zeroizing::new(a.to_vec()),
                    marker: vec![0xF0],
                },
                Pattern {
                    bytes: Zeroizing::new(b.to_vec()),
                    marker: vec![0xF1],
                },
            ])
        };
        for a in &patterns {
            for b in &patterns {
                for input in &inputs {
                    let mut r = redactor(a, b);
                    let mut whole = r.push(input);
                    whole.extend(r.finish());
                    assert!(
                        !contains(&whole, a) && !contains(&whole, b),
                        "{a:?} {b:?} {input:?}"
                    );
                    if !contains(input, a) && !contains(input, b) {
                        assert_eq!(&whole, input);
                    }
                    for i in 0..=input.len() {
                        for j in i..=input.len() {
                            let mut r = redactor(a, b);
                            let mut out = r.push(&input[..i]);
                            out.extend(r.push(&input[i..j]));
                            out.extend(r.push(&input[j..]));
                            out.extend(r.finish());
                            assert_eq!(out, whole, "{a:?} {b:?} {input:?} split {i} {j}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_small() {
        exhaustive(3, 4);
    }

    #[test]
    #[ignore = "about 10 s in release; run with --release -- --ignored"]
    fn exhaustive_large() {
        exhaustive(3, 6);
    }

    #[test]
    fn debug_hides_patterns() {
        let redactor = Redactor::new([("k", "super-secret-value")]);
        assert!(!format!("{redactor:?}").contains("super-secret-value"));
    }
}
