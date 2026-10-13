//! Property tests: redacted output never contains a secret in any covered form.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use llm_secret_vault::redact::Redactor;
use proptest::prelude::*;

fn redact_chunked(value: &str, input: &[u8], chunk: usize) -> String {
    let mut redactor = Redactor::new([("s", value)]);
    let mut out = Vec::new();
    for piece in input.chunks(chunk.max(1)) {
        out.extend(redactor.push(piece));
    }
    out.extend(redactor.finish());
    String::from_utf8_lossy(&out).into_owned()
}

proptest! {
    // Uppercase-only values cannot occur inside the lowercase marker text.
    #[test]
    fn no_raw_or_encoded_value_survives(
        value in "[A-Z0-9!@#%^&*]{8,40}",
        before in "[ -~]{0,64}",
        between in "[ -~]{0,64}",
        after in "[ -~]{0,64}",
        chunk in 1usize..64,
    ) {
        let b64 = STANDARD.encode(value.as_bytes());
        let hex_lower = hex::encode(value.as_bytes());
        let input = format!("{before}{value}{between}{b64}{after}{hex_lower}");
        let out = redact_chunked(&value, input.as_bytes(), chunk);
        prop_assert!(!out.contains(&value));
        prop_assert!(!out.contains(&b64));
        prop_assert!(!out.contains(&hex_lower));
        prop_assert!(out.contains("«redacted:s»"));
    }
}
