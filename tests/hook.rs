//! Guard hook rule table.

use llm_secret_vault::hook::{Decision, check_command, evaluate, render};

const DENY: &[&str] = &[
    "security find-generic-password -s foo -w",
    "security find-internet-password -gs github.com",
    "secret-tool lookup service nas",
    "powershell -c Get-StoredCredential -Target nas",
    "cmdkey /list:nas /pass",
    "cat /proc/1234/environ",
    "lsv run PW=nas-root -- sh -c 'echo $PW'",
    "lsv run PW=nas-root -- sh -c 'printf %s \"$PW\" | base64'",
    "lsv run T=tok -- sh -c 'echo ${T} | rev'",
    "lsv run T=tok -- sh -c 'printf %s $T | xxd'",
    "lsv run -- echo {{nas-root}}",
    "lsv run PW=nas-root -- printenv",
    "lsv run PW=nas-root -- printenv PW",
    "lsv run PW=nas-root -- env",
    "lsv run PW=nas-root -- sh -c 'set'",
    "lsv run PW=nas-root -- sh -c 'export -p'",
    "cd /tmp && lsv run PW=nas-root -- sh -c 'ls; echo $PW'",
    "lsv run A=a -- ls && lsv run PW=b -- printenv",
    "./target/release/lsv run PW=b -- printenv",
    "/usr/local/bin/lsv run PW=b -- sh -c 'echo $PW'",
    "lsv run PW=b -- /bin/sh -c 'echo $PW'",
    "lsv run PW=b -- bash -lc 'echo $PW'",
    "lsv run PW=b -- /usr/bin/env -0",
    "lsv run PW=b -- env -i",
    "lsv run PW=b -- /usr/bin/printenv",
    "lsv run PW=b -- sh -c 'export'",
    "security -q find-generic-password -s foo -w",
];

const ALLOW: &[&str] = &[
    "ls -la",
    "echo hello",
    "cargo test 2>&1 | tail",
    "security find-generic-password -s foo",
    "lsv run HF_TOKEN=hf-token -- huggingface-cli upload repo file",
    "lsv run T=tok -- sh -c 'printf %s \"$T\" | docker login --password-stdin'",
    "lsv run T=tok -- sh -c 'curl -H \"Authorization: Bearer $T\" https://x > out.json'",
    "lsv run PW=nas-root -- sshpass -e ssh root@nas",
    "lsv run -- curl -H 'Bearer {{resend}}' https://api.resend.com",
    "lsv run PW=nas-root -- env FOO=1 ./deploy.sh",
    "lsv list",
    "lsv run T=x -- sh -c 'echo $T > f'",
    "lsv run T=x -- sh -c 'printf %s \"$T\" >> f'",
    "lsv run T=tok -- sh -c 'echo $TERM'",
    "cmdkey /add:nas /user:u /pass:x",
    "echo $HOME",
];

#[test]
fn denies_leaky_commands() {
    for command in DENY {
        assert!(
            matches!(check_command(command), Decision::Deny(_)),
            "should deny: {command}"
        );
    }
}

#[test]
fn allows_normal_commands() {
    for command in ALLOW {
        assert_eq!(
            check_command(command),
            Decision::Allow,
            "should allow: {command}"
        );
    }
}

#[test]
fn evaluates_hook_json() {
    let deny = r#"{"tool_name":"Bash","tool_input":{"command":"lsv run X=a -- printenv"}}"#;
    assert!(matches!(evaluate(deny).unwrap(), Decision::Deny(_)));
    let other_tool = r#"{"tool_name":"Read","tool_input":{"file_path":"/etc/hosts"}}"#;
    assert_eq!(evaluate(other_tool).unwrap(), Decision::Allow);
    assert!(evaluate("not json").is_err());
    assert!(evaluate(r#"{"tool_name":"Bash","tool_input":{}}"#).is_err());
}

#[test]
fn renders_deny_for_claude_code() {
    assert!(render(&Decision::Allow).is_none());
    let json: serde_json::Value =
        serde_json::from_str(&render(&Decision::Deny("because".into())).unwrap()).unwrap();
    let out = &json["hookSpecificOutput"];
    assert_eq!(out["hookEventName"], "PreToolUse");
    assert_eq!(out["permissionDecision"], "deny");
    assert_eq!(out["permissionDecisionReason"], "llm-secret-vault: because");
}
