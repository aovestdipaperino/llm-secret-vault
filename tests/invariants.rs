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

#[test]
fn resolve_is_called_only_from_allowed_modules() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let allowed = ["backend", "vault.rs", "fingerprint.rs", "inject.rs"];
    for file in files {
        let rel = file
            .strip_prefix(&src)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&file).unwrap();
        if text.contains(".resolve(") {
            assert!(
                allowed.iter().any(|a| rel.starts_with(a)),
                "{rel} calls .resolve(); only {allowed:?} may"
            );
        }
    }
}
