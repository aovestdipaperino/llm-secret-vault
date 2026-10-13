//! Structural checks that keep the "no read verb" invariant honest.

use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Relative paths (with `/` separators) of source files whose text matches
/// `pred`, as `(relative path, components)`.
fn files_matching(pred: impl Fn(&str) -> bool) -> Vec<(String, Vec<String>)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files
        .into_iter()
        .filter(|f| pred(&fs::read_to_string(f).unwrap()))
        .map(|f| {
            let rel = f.strip_prefix(&src).unwrap();
            let parts: Vec<String> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            (parts.join("/"), parts)
        })
        .collect()
}

#[test]
fn injection_resolver_is_used_only_by_inject_and_vault() {
    let allowed = ["inject.rs", "vault.rs"];
    for (rel, _) in files_matching(|t| t.contains("resolve_for_injection")) {
        assert!(
            allowed.contains(&rel.as_str()),
            "{rel} mentions resolve_for_injection; only {allowed:?} may"
        );
    }
}

#[test]
fn backend_resolve_is_called_only_by_fingerprint_vault_and_backend_dir() {
    let allowed_files = ["fingerprint.rs", "vault.rs"];
    for (rel, parts) in files_matching(|t| t.contains(".resolve(") || t.contains("::resolve")) {
        let in_backend_dir = parts.len() > 1 && parts[0] == "backend";
        assert!(
            in_backend_dir || allowed_files.contains(&rel.as_str()),
            "{rel} calls resolve; only {allowed_files:?} and src/backend/ may"
        );
    }
}
