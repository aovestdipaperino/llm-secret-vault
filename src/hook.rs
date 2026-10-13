//! `PreToolUse` guard (Claude Code, plank) that blocks commands likely to print secrets.
//!
//! This is a heuristic safety net against accidents, not a sandbox.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

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
                r"\bsecurity\s+(?:-\S+\s+)*find-(generic|internet)-password\b[^|;&]*\s-[A-Za-z]*[wg][A-Za-z]*\b",
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
            regex(r"(?i)\bcmdkey\b[^|;&]*/list[^|;&]*/pass"),
            "reads a Windows credential directly; use `lsv run` instead",
        ),
        (
            regex(r"/proc/[^\s/]+/environ"),
            "reads another process's environment",
        ),
    ]
});

static LSV_RUN: LazyLock<Regex> =
    LazyLock::new(|| regex(r#"(?:^|[\s;&|("'`])(?:[^\s;&|()]*/)?lsv\s+run\b"#));
/// Any invocation of `lsv` (bare or by path) as a command word.
static LSV_INVOKE: LazyLock<Regex> =
    LazyLock::new(|| regex(r#"(?:^|[\s;&|("'`])(?:[^\s;&|()]*/)?lsv(?:\s|$)"#));
/// The `--no-touch` flag of `lsv run`, as a word of its own.
static NO_TOUCH: LazyLock<Regex> = LazyLock::new(|| regex(r"(?:^|\s)--no-touch(?:[\s=]|$)"));
static DOUBLE_DASH: LazyLock<Regex> = LazyLock::new(|| regex(r"\s--(\s|$)"));
static BINDING: LazyLock<Regex> =
    LazyLock::new(|| regex(r"\b([A-Za-z_][A-Za-z0-9_]*)=[a-z0-9][a-z0-9._-]*"));
static SEPARATORS: LazyLock<Regex> = LazyLock::new(|| regex(r"&&|\|\||;|\n"));
static SHELL_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| regex(r"^(?:\S*/)?(?:sh|bash|zsh)\s+-[A-Za-z]*c\s+"));

const ENCODERS: &[&str] = &["rev", "base64", "xxd", "od", "hexdump"];

fn first_word(segment: &str) -> &str {
    segment.split_whitespace().next().unwrap_or("")
}

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

fn dumps_env(segment: &str) -> bool {
    let mut words = segment.split_whitespace();
    match words.next().map(basename) {
        Some("printenv") => true,
        Some("env") => words.all(|w| w.starts_with('-')),
        Some("set") => words.next().is_none(),
        Some("export") => matches!(words.next(), None | Some("-p")),
        _ => false,
    }
}

/// Whether `text` contains `$name` (not followed by an identifier character) or `${name}`.
fn mentions_var(text: &str, name: &str) -> bool {
    if text.contains(&format!("${{{name}}}")) {
        return true;
    }
    let needle = format!("${name}");
    text.match_indices(&needle).any(|(i, _)| {
        !text[i + needle.len()..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Returns the byte offset of the first unquoted `&&`, `||`, `;` or newline.
fn top_level_end(text: &str) -> usize {
    let bytes = text.as_bytes();
    let mut quote = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) => {}
            None => match b {
                b'\'' | b'"' => quote = Some(b),
                b';' | b'\n' => return i,
                b'&' | b'|' if bytes.get(i + 1) == Some(&b) => return i,
                _ => {}
            },
        }
        i += 1;
    }
    text.len()
}

/// Output redirect: optional fd, `>` or `>>`, then the target (`&2` or a word).
static REDIRECT: LazyLock<Regex> = LazyLock::new(|| regex(r"(\d*)>>?\s*(&\s*\d|[^\s;&|<>]+)"));

/// Whether a redirect target may still reach the agent.
///
/// File descriptors (`&2`), devices other than `/dev/null` (`/dev/stdout`,
/// `/dev/tty`, `/dev/pts/0`, ...), anything under `/proc/`, process
/// substitutions (`>(cat)`) and expansions (`$OUT`) all count as visible.
fn visible_target(target: &str) -> bool {
    target.starts_with('&')
        || (target.starts_with("/dev/") && target != "/dev/null")
        || target.starts_with("/proc/")
        || target.starts_with('(')
        || target.starts_with('$')
}

/// Whether a command's stdout still reaches the agent: true unless stdout is
/// redirected to a real file (see [`visible_target`]). A redirect of another
/// fd (`2>f`) leaves stdout alone.
fn reaches_agent(segment: &str) -> bool {
    !REDIRECT.captures_iter(segment).any(|c| {
        let fd = &c[1];
        let target: String = c[2].split_whitespace().collect();
        (fd.is_empty() || fd == "1") && !visible_target(&target)
    })
}

const TOUCH_ID_VAR: &str = "LSV_TOUCH_ID";
const TOUCH_ID_VAR_REASON: &str = "changing LSV_TOUCH_ID would bypass Touch ID approval";
const NO_TOUCH_REASON: &str = "--no-touch skips Touch ID and is for your own terminal only";
const NESTED_LSV_REASON: &str = "secret_run must not start lsv itself";

fn strip_quotes(text: &str) -> String {
    text.chars().filter(|c| !matches!(c, '\'' | '"')).collect()
}

/// Checks the child part of an `lsv run` command line.
fn check_child(child: &str, vars: &[&str]) -> Option<String> {
    // Quote stripping is heuristic: it lets `sh -c '...'` bodies be inspected
    // as plain command lines, at the cost of ignoring real quoting rules.
    let unquoted = strip_quotes(child);
    let references = |s: &str| s.contains("{{") || vars.iter().any(|v| mentions_var(s, v));
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
            .map(|s| basename(first_word(s)))
            .find(|w| ENCODERS.contains(w))
        {
            return Some(format!(
                "`{encoder}` would print an encoded copy of an injected secret"
            ));
        }
        if let Some(last) = segments.last() {
            let word = basename(first_word(last));
            if matches!(word, "echo" | "printf") && references(last) && reaches_agent(last) {
                return Some(format!("`{word}` would print an injected secret"));
            }
        }
    }
    None
}

/// Decides whether a shell command line may run.
#[must_use]
pub fn check_command(command: &str) -> Decision {
    if command.contains(TOUCH_ID_VAR) {
        return Decision::Deny(TOUCH_ID_VAR_REASON.to_owned());
    }
    // Any `--no-touch` word is refused, not only after a literal `lsv run`,
    // so aliases and variables cannot smuggle it past the guard.
    if NO_TOUCH.is_match(&strip_quotes(command)) {
        return Decision::Deny(NO_TOUCH_REASON.to_owned());
    }
    for (pattern, reason) in DIRECT_READS.iter() {
        if pattern.is_match(command) {
            return Decision::Deny((*reason).to_owned());
        }
    }
    for run in LSV_RUN.find_iter(command) {
        let rest = &command[run.end()..];
        let rest = &rest[..top_level_end(rest)];
        let Some(dash) = DOUBLE_DASH.find(rest) else {
            continue;
        };
        let vars: Vec<&str> = BINDING
            .captures_iter(&rest[..dash.start()])
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .collect();
        if let Some(reason) = check_child(&rest[dash.end()..], &vars) {
            return Decision::Deny(reason);
        }
    }
    Decision::Allow
}

/// Decides whether an MCP `secret_run` argv may run.
///
/// Applies the `lsv run` child rules to `argv` joined with spaces, with
/// `vars` as the injected environment variable names. Also refuses any argv
/// that starts `lsv` itself (which could use `--no-touch` or print what it
/// injects) or mentions `LSV_TOUCH_ID`.
#[must_use]
pub fn check_run(argv: &[String], vars: &[&str]) -> Decision {
    let command = argv.join(" ");
    if command.contains(TOUCH_ID_VAR) || vars.iter().any(|v| v.contains(TOUCH_ID_VAR)) {
        return Decision::Deny(TOUCH_ID_VAR_REASON.to_owned());
    }
    if argv.iter().any(|a| basename(first_word(a)) == "lsv")
        || LSV_INVOKE.is_match(&strip_quotes(&command))
    {
        return Decision::Deny(NESTED_LSV_REASON.to_owned());
    }
    for (pattern, reason) in DIRECT_READS.iter() {
        if pattern.is_match(&command) {
            return Decision::Deny((*reason).to_owned());
        }
    }
    match check_child(&command, vars) {
        Some(reason) => Decision::Deny(reason),
        None => Decision::Allow,
    }
}

/// Evaluates a `PreToolUse` hook payload.
///
/// The shell tool is matched case-insensitively (`Bash` in Claude Code,
/// `bash` in plank); other tools are always allowed.
///
/// # Errors
///
/// Returns [`ErrorKind::Usage`] if `input` is not valid hook JSON or a shell
/// payload lacks `tool_input.command`. Callers should then allow the command
/// and warn, so a hook bug cannot wedge the session.
pub fn evaluate(input: &str) -> Result<Decision> {
    let usage = |why: String| Error::new(ErrorKind::Usage(why));
    let value: Value = serde_json::from_str(input)
        .map_err(|e| usage(format!("could not parse hook input: {e}")))?;
    let is_shell = value
        .get("tool_name")
        .and_then(Value::as_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("bash"));
    if !is_shell {
        return Ok(Decision::Allow);
    }
    let command = value
        .pointer("/tool_input/command")
        .and_then(Value::as_str)
        .ok_or_else(|| usage("shell hook input has no tool_input.command".to_owned()))?;
    Ok(check_command(command))
}

/// Kani proof harnesses. Run with `cargo kani`; see `formal/README.md`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `check_command` slices at `top_level_end`, so it must return an
    /// in-bounds character boundary for any UTF-8 input.
    #[kani::proof]
    #[kani::unwind(7)]
    fn top_level_end_is_a_char_boundary() {
        let bytes: [u8; 5] = kani::any();
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return;
        };
        let end = top_level_end(text);
        assert!(end <= text.len() && text.is_char_boundary(end));
    }
}
