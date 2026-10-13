//! Smoke tests for the `lsv` binary (no keyring access).

use std::io::Write;
use std::process::{Command, Stdio};

fn lsv() -> Command {
    Command::new(env!("CARGO_BIN_EXE_lsv"))
}

fn hook(input: &str) -> std::process::Output {
    let mut child = lsv()
        .arg("hook")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn help_lists_subcommands() {
    let out = lsv().arg("--help").output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    for sub in [
        "list", "info", "capture", "generate", "import", "run", "delete", "mcp", "hook", "setup",
    ] {
        assert!(text.contains(sub), "missing {sub}");
    }
}

#[test]
fn hook_denies_and_allows() {
    let out = hook(r#"{"tool_name":"Bash","tool_input":{"command":"lsv run X=a -- printenv"}}"#);
    assert!(out.status.success());
    assert!(
        String::from_utf8(out.stdout)
            .unwrap()
            .contains("\"permissionDecision\":\"deny\"")
    );

    let out = hook(r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#);
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
}

#[test]
fn hook_fails_open_on_garbage() {
    let out = hook("garbage");
    assert!(out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8(out.stderr).unwrap().contains("warning"));
}

#[test]
fn setup_claude_prints_instructions() {
    let out = lsv().args(["setup", "claude"]).output().unwrap();
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("claude mcp add --scope user llm-secret-vault -- lsv mcp"));
    assert!(text.contains("\"command\": \"lsv hook\""));
}

#[test]
fn invalid_name_is_rejected_before_opening_vault() {
    let out = lsv().args(["info", "Bad Name"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("invalid secret name")
    );
}

#[test]
fn malformed_binding_is_rejected_before_opening_vault() {
    let out = lsv()
        .args(["run", "NOEQUALS", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8(out.stderr)
            .unwrap()
            .contains("VAR=secret-name")
    );
}
