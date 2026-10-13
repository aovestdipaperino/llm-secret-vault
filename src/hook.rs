//! Claude Code `PreToolUse` guard that blocks commands likely to print secrets.
//!
//! This is a heuristic safety net against accidents, not a sandbox.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Value, json};

use crate::error::{Error, ErrorKind, Result};

/// Verdict for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Let the command run.
    Allow,
    /// Block the command; the payload explains why.
    Deny(String),
}

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).expect("hook patterns are valid")
}

static DIRECT_READS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            regex(
                r"\bsecurity\s+find-(generic|internet)-password\b[^|;&]*\s-[A-Za-z]*[wg][A-Za-z]*\b",
            ),
            "reads a Keychain password directly; use `lsv run` instead",
        ),
        (
            regex(r"\bsecret-tool\s+lookup\b"),
            "reads a Secret Service password directly; use `lsv run` instead",
        ),
        (
            regex(r"(?i)\bGet-StoredCredential\b"),
            "reads a Windows credential directly; use `lsv run` instead",
        ),
        (
            regex(r"(?i)\bcmdkey\b[^|;&]*/pass"),
            "reads a Windows credential directly; use `lsv run` instead",
        ),
        (
            regex(r"/proc/[^\s/]+/environ"),
            "reads another process's environment",
        ),
    ]
});

static LSV_RUN: LazyLock<Regex> = LazyLock::new(|| regex(r"\blsv\s+run\b"));
static DOUBLE_DASH: LazyLock<Regex> = LazyLock::new(|| regex(r"\s--(\s|$)"));
static BINDING: LazyLock<Regex> =
    LazyLock::new(|| regex(r"\b([A-Za-z_][A-Za-z0-9_]*)=[a-z0-9][a-z0-9._-]*"));
static SEPARATORS: LazyLock<Regex> = LazyLock::new(|| regex(r"&&|\|\||;|\n"));
static SHELL_PREFIX: LazyLock<Regex> = LazyLock::new(|| regex(r"^(?:sh|bash|zsh)\s+-c\s+"));

const ENCODERS: &[&str] = &["rev", "base64", "xxd", "od", "hexdump"];

fn first_word(segment: &str) -> &str {
    segment.split_whitespace().next().unwrap_or("")
}

fn dumps_env(segment: &str) -> bool {
    let mut words = segment.split_whitespace();
    match words.next() {
        Some("printenv") => true,
        Some("env" | "set") => words.next().is_none(),
        Some("export") => words.next() == Some("-p"),
        _ => false,
    }
}

/// Checks the child part of an `lsv run` command line.
fn check_child(child: &str, vars: &[&str]) -> Option<String> {
    let unquoted: String = child.chars().filter(|c| !matches!(c, '\'' | '"')).collect();
    let references = |s: &str| {
        s.contains("{{")
            || vars
                .iter()
                .any(|v| s.contains(&format!("${v}")) || s.contains(&format!("${{{v}}}")))
    };
    for command in SEPARATORS.split(&unquoted) {
        let command = SHELL_PREFIX.replace(command.trim(), "");
        let segments: Vec<&str> = command.split('|').map(str::trim).collect();
        if segments.iter().any(|s| dumps_env(s)) {
            return Some(
                "the child command dumps its environment, which holds the injected secrets"
                    .to_owned(),
            );
        }
        if !segments.iter().any(|s| references(s)) {
            continue;
        }
        if let Some(encoder) = segments
            .iter()
            .map(|s| first_word(s))
            .find(|w| ENCODERS.contains(w))
        {
            return Some(format!(
                "`{encoder}` would print an encoded copy of an injected secret"
            ));
        }
        if let Some(last) = segments.last() {
            let word = first_word(last);
            if matches!(word, "echo" | "printf") && references(last) {
                return Some(format!("`{word}` would print an injected secret"));
            }
        }
    }
    None
}

/// Decides whether a shell command line may run.
#[must_use]
pub fn check_command(command: &str) -> Decision {
    for (pattern, reason) in DIRECT_READS.iter() {
        if pattern.is_match(command) {
            return Decision::Deny((*reason).to_owned());
        }
    }
    let Some(run) = LSV_RUN.find(command) else {
        return Decision::Allow;
    };
    let rest = &command[run.end()..];
    let Some(dash) = DOUBLE_DASH.find(rest) else {
        return Decision::Allow;
    };
    let vars: Vec<&str> = BINDING
        .captures_iter(&rest[..dash.start()])
        .filter_map(|c| c.get(1).map(|m| m.as_str()))
        .collect();
    match check_child(&rest[dash.end()..], &vars) {
        Some(reason) => Decision::Deny(reason),
        None => Decision::Allow,
    }
}

/// Evaluates a Claude Code `PreToolUse` hook payload.
///
/// Tools other than `Bash` are always allowed.
///
/// # Errors
///
/// Returns [`ErrorKind::Usage`] if `input` is not valid hook JSON or a `Bash`
/// payload lacks `tool_input.command`. Callers should then allow the command
/// and warn, so a hook bug cannot wedge the session.
pub fn evaluate(input: &str) -> Result<Decision> {
    let usage = |why: String| Error::new(ErrorKind::Usage(why));
    let value: Value = serde_json::from_str(input)
        .map_err(|e| usage(format!("could not parse hook input: {e}")))?;
    if value.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return Ok(Decision::Allow);
    }
    let command = value
        .pointer("/tool_input/command")
        .and_then(Value::as_str)
        .ok_or_else(|| usage("Bash hook input has no tool_input.command".to_owned()))?;
    Ok(check_command(command))
}

/// Renders a decision as Claude Code hook output; `None` means allow silently.
#[must_use]
pub fn render(decision: &Decision) -> Option<String> {
    match decision {
        Decision::Allow => None,
        Decision::Deny(reason) => Some(
            json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": format!("llm-secret-vault: {reason}"),
                }
            })
            .to_string(),
        ),
    }
}
