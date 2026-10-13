//! End-to-end tests for secret injection (Unix shells).
#![cfg(unix)]

use std::time::{Duration, Instant};

use llm_secret_vault::inject::{RunRequest, run};
use llm_secret_vault::{ErrorKind, SecretName, Source, Vault};

const VALUE: &str = "hunter2-very-secret";

fn vault() -> Vault {
    let vault = Vault::in_memory();
    vault
        .store(
            &SecretName::new("nas-root").unwrap(),
            VALUE,
            Source::Clipboard,
            false,
        )
        .unwrap();
    vault
}

fn nas() -> SecretName {
    SecretName::new("nas-root").unwrap()
}

#[test]
fn env_injection_reaches_child_and_is_redacted() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "echo \"pw=$PW\""]).env("PW", nas());
    let out = run(&vault, &req).unwrap();
    assert_eq!(out.stdout, "pw=«redacted:nas-root»\n");
    assert_eq!(out.exit_code, Some(0));

    let check = RunRequest::new(["sh", "-c", &format!("test \"$PW\" = '{VALUE}' && echo ok")])
        .env("PW", nas());
    assert_eq!(run(&vault, &check).unwrap().stdout, "ok\n");
}

#[test]
fn placeholder_is_substituted_and_redacted() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "printf %s \"$0\"", "{{nas-root}}"]);
    assert_eq!(run(&vault, &req).unwrap().stdout, "«redacted:nas-root»");
    let literal = RunRequest::new(["printf", "%s", "{{ .Values.x }}"]);
    assert_eq!(run(&vault, &literal).unwrap().stdout, "{{ .Values.x }}");
}

#[test]
fn encoded_output_is_redacted() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "printf %s \"$PW\" | base64"]).env("PW", nas());
    let out = run(&vault, &req).unwrap();
    assert!(out.stdout.contains("«redacted:nas-root»"), "{}", out.stdout);
}

#[test]
fn stderr_is_redacted_too() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "echo \"$PW\" >&2"]).env("PW", nas());
    assert_eq!(run(&vault, &req).unwrap().stderr, "«redacted:nas-root»\n");
}

#[test]
fn unknown_secret_fails_before_spawning() {
    let vault = vault();
    let req = RunRequest::new(["sh", "-c", "touch should-not-exist"])
        .env("X", SecretName::new("missing").unwrap());
    let err = run(&vault, &req).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::UnknownName(_)));
    assert!(!std::path::Path::new("should-not-exist").exists());
}

#[test]
fn usage_errors() {
    let vault = vault();
    let empty: [&str; 0] = [];
    assert!(matches!(
        run(&vault, &RunRequest::new(empty)).unwrap_err().kind(),
        ErrorKind::Usage(_)
    ));
    let bad = RunRequest::new(["true"]).env("1BAD", nas());
    assert!(matches!(
        run(&vault, &bad).unwrap_err().kind(),
        ErrorKind::Usage(_)
    ));
}

#[test]
fn spawn_error_names_program_only() {
    let vault = vault();
    let err = run(
        &vault,
        &RunRequest::new(["/no/such/program", "{{nas-root}}"]),
    )
    .unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Spawn(_)));
    assert!(err.to_string().contains("/no/such/program"));
    assert!(!err.to_string().contains(VALUE));
}

#[test]
fn exit_code_is_reported() {
    let out = run(&vault(), &RunRequest::new(["sh", "-c", "exit 3"])).unwrap();
    assert_eq!(out.exit_code, Some(3));
}

#[test]
fn timeout_kills_the_process_group() {
    let start = Instant::now();
    let req =
        RunRequest::new(["sh", "-c", "sleep 30 & sleep 30"]).timeout(Duration::from_millis(300));
    let out = run(&vault(), &req).unwrap();
    assert!(out.timed_out);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn output_is_capped() {
    let req = RunRequest::new(["sh", "-c", "yes | head -c 100000"]).max_output_bytes(1000);
    let out = run(&vault(), &req).unwrap();
    assert_eq!(out.stdout.len(), 1000);
    assert!(out.truncated);
}

#[test]
fn working_directory_is_honored() {
    let dir = tempfile::tempdir().unwrap();
    let req = RunRequest::new(["pwd"]).cwd(dir.path());
    let out = run(&vault(), &req).unwrap();
    let expected = dir.path().canonicalize().unwrap();
    assert_eq!(
        std::path::Path::new(out.stdout.trim())
            .canonicalize()
            .unwrap(),
        expected
    );
}

#[test]
fn periodic_secret_flood_is_bounded_and_redacted() {
    let vault = Vault::in_memory();
    let name = SecretName::new("periodic").unwrap();
    vault
        .store(&name, "abab", Source::Clipboard, false)
        .unwrap();
    let start = Instant::now();
    let req = RunRequest::new(["sh", "-c", "yes abab | tr -d '\\n' | head -c 20000000"])
        .env("S", name)
        .max_output_bytes(100)
        .timeout(Duration::from_secs(60));
    let out = run(&vault, &req).unwrap();
    assert!(out.truncated);
    assert!(!out.timed_out);
    assert!(!out.stdout.contains("abab"));
    assert!(out.stdout.len() <= 100);
    assert!(!out.stdout.contains("abab"));
    assert!(start.elapsed() < Duration::from_secs(20));
}

#[test]
fn timeout_covers_background_process_holding_the_pipe() {
    let start = Instant::now();
    let req =
        RunRequest::new(["sh", "-c", "sleep 30 & echo hi"]).timeout(Duration::from_millis(500));
    let out = run(&vault(), &req).unwrap();
    assert!(out.timed_out);
    assert!(out.stdout.contains("hi"), "{:?}", out.stdout);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn placeholder_in_program_is_resolved() {
    let vault = Vault::in_memory();
    let tool = SecretName::new("tool").unwrap();
    vault
        .store(&tool, "/bin/echo", Source::Clipboard, false)
        .unwrap();
    let out = run(&vault, &RunRequest::new(["{{tool}}", "hi"])).unwrap();
    assert_eq!(out.stdout, "hi\n");
}

#[test]
fn unknown_placeholder_in_program_fails_before_spawning() {
    let err = run(&vault(), &RunRequest::new(["{{missing}}"])).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::UnknownName(_)));
}

#[test]
fn spawn_error_for_program_placeholder_hides_resolved_value() {
    let vault = Vault::in_memory();
    let tool = SecretName::new("tool").unwrap();
    vault
        .store(&tool, "/no/such/secret-path", Source::Clipboard, false)
        .unwrap();
    let err = run(&vault, &RunRequest::new(["{{tool}}"])).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::Spawn(_)));
    assert!(err.to_string().contains("{{tool}}"));
    assert!(!err.to_string().contains("secret-path"));
}

#[test]
fn truncation_cuts_on_a_char_boundary() {
    let req = RunRequest::new(["sh", "-c", "printf 'aé€'"]).max_output_bytes(2);
    let out = run(&vault(), &req).unwrap();
    assert_eq!(out.stdout, "a");
    assert!(out.truncated);
}
