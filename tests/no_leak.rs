//! Property tests: redacted output never contains a secret in any covered form.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use llm_secret_vault::redact::Redactor;
use proptest::prelude::*;
use std::fmt::Write as _;

fn redact_chunked(secrets: &[(&str, &str)], input: &[u8], chunk: usize) -> String {
    let mut redactor = Redactor::new(secrets.iter().copied());
    let mut out = Vec::new();
    for piece in input.chunks(chunk.max(1)) {
        out.extend(redactor.push(piece));
    }
    out.extend(redactor.finish());
    String::from_utf8_lossy(&out).into_owned()
}

fn forms(value: &str) -> Vec<String> {
    let mut pct = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() {
            pct.push(char::from(byte));
        } else {
            let _ = write!(pct, "%{byte:02X}");
        }
    }
    vec![
        value.to_owned(),
        STANDARD.encode(value.as_bytes()),
        pct,
        hex::encode(value.as_bytes()),
        hex::encode_upper(value.as_bytes()),
    ]
}

proptest! {
    // Uppercase-only values cannot occur inside the lowercase marker text.
    #[test]
    fn no_raw_or_encoded_value_survives(
        value in "[A-Z0-9!@#%^&*]{8,40}",
        other in "[A-Z0-9!@#%^&*]{8,40}",
        before in "[ -~]{0,64}",
        between in "[ -~]{0,64}",
        after in "[ -~]{0,64}",
        chunk in 1usize..64,
    ) {
        let mut input = before.clone();
        let mut all = forms(&value);
        all.extend(forms(&other));
        for form in &all {
            input.push_str(form);
            input.push_str(&between);
        }
        input.push_str(&after);
        let out = redact_chunked(&[("s", &value), ("t", &other)], input.as_bytes(), chunk);
        for form in &all {
            prop_assert!(!out.contains(form.as_str()), "{form} survived in {out}");
        }
        prop_assert!(out.contains("«redacted:s»"));
        prop_assert!(out.contains("«redacted:t»"));
    }
}
