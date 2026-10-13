//! Running commands with secrets injected and their output redacted.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::ops::Range;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::{Error, ErrorKind, Result};
use crate::name::SecretName;
use crate::redact::Redactor;
use crate::vault::Vault;

const POLL_INTERVAL: Duration = Duration::from_millis(10);
const READ_CHUNK: usize = 8192;
const KILL_GRACE: Duration = Duration::from_secs(1);
const RAW_SLACK: usize = 64 * 1024;

/// A command to run with secrets injected.
///
/// Secrets reach the child as environment variables (via [`RunRequest::env`])
/// or through `{{name}}` placeholders in any element of the command line,
/// including the program itself. Any `{{word}}` whose inner text (trimmed) is
/// a valid secret name is treated as a reference; there is no escape syntax.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use llm_secret_vault::{inject::RunRequest, SecretName};
///
/// let request = RunRequest::new(["./deploy.sh"])
///     .env("API_TOKEN", SecretName::new("api-token").unwrap())
///     .timeout(Duration::from_secs(60));
/// assert_eq!(request.argv()[0], "./deploy.sh");
/// ```
#[derive(Debug, Clone)]
pub struct RunRequest {
    argv: Vec<String>,
    env: BTreeMap<String, SecretName>,
    cwd: Option<PathBuf>,
    timeout: Option<Duration>,
    max_output_bytes: Option<usize>,
}

impl RunRequest {
    /// Creates a request for `argv`, where `argv[0]` is the program.
    #[must_use]
    pub fn new<I, S>(argv: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            env: BTreeMap::new(),
            cwd: None,
            timeout: None,
            max_output_bytes: None,
        }
    }

    /// Injects `secret` as environment variable `var`.
    #[must_use]
    pub fn env(mut self, var: impl Into<String>, secret: SecretName) -> Self {
        self.env.insert(var.into(), secret);
        self
    }

    /// Runs the child in `dir`.
    #[must_use]
    pub fn cwd(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cwd = Some(dir.into());
        self
    }

    /// Kills the child and its whole process group (Unix) after `limit`.
    ///
    /// Background processes the command leaves in its process group are killed
    /// at the timeout, and [`run`] waits for them (and for the output pipes to
    /// close). In total [`run`] waits up to `limit` plus a 1 s grace period.
    #[must_use]
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// Keeps at most `bytes` of redacted output per stream.
    ///
    /// Excess output is discarded, not blocked on. Without a
    /// [`timeout`](Self::timeout), a command that never exits still never
    /// returns.
    #[must_use]
    pub fn max_output_bytes(mut self, bytes: usize) -> Self {
        self.max_output_bytes = Some(bytes);
        self
    }

    /// Returns the command line as given, with placeholders unexpanded.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    /// Checks the request shape without touching the vault.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::Usage`] for an empty argv or an invalid
    /// environment variable name.
    pub fn validate(&self) -> Result<()> {
        if self.argv.is_empty() {
            return Err(usage("argv must contain at least the program to run"));
        }
        if let Some(var) = self.env.keys().find(|v| !is_env_var_name(v)) {
            return Err(usage(format!(
                "`{var}` is not a valid environment variable name"
            )));
        }
        Ok(())
    }

    /// Returns every secret this request would inject, by name.
    #[must_use]
    pub fn secret_names(&self) -> BTreeSet<SecretName> {
        let mut names: BTreeSet<SecretName> = self.env.values().cloned().collect();
        for arg in &self.argv {
            names.extend(placeholders(arg).into_iter().map(|(_, name)| name));
        }
        names
    }
}

/// Result of a [`run`]: exit status and redacted output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunOutput {
    /// Exit code, or `None` if the child was killed by a signal.
    pub exit_code: Option<i32>,
    /// Redacted standard output.
    pub stdout: String,
    /// Redacted standard error.
    pub stderr: String,
    /// Whether either stream hit the output cap.
    pub truncated: bool,
    /// Whether the child was killed for exceeding the timeout.
    pub timed_out: bool,
}

fn usage(why: impl Into<String>) -> Error {
    Error::new(ErrorKind::Usage(why.into()))
}

fn is_env_var_name(var: &str) -> bool {
    let mut chars = var.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Finds `{{name}}` placeholders whose inner text is a valid secret name.
fn placeholders(arg: &str) -> Vec<(Range<usize>, SecretName)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(open) = arg[from..].find("{{").map(|i| i + from) {
        let Some(close) = arg[open + 2..].find("}}").map(|i| i + open + 2) else {
            break;
        };
        if let Ok(name) = SecretName::new(arg[open + 2..close].trim()) {
            found.push((open..close + 2, name));
            from = close + 2;
        } else {
            from = open + 2;
        }
    }
    found
}

fn substitute(arg: &str, values: &BTreeMap<SecretName, Zeroizing<String>>) -> Zeroizing<String> {
    let found = placeholders(arg);
    // Sized up front so the buffer never reallocates (a realloc would leave an
    // unzeroed copy of the value behind).
    let capacity = arg.len() + found.iter().map(|(_, n)| values[n].len()).sum::<usize>();
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    let mut last = 0;
    for (range, name) in found {
        out.push_str(&arg[last..range.start]);
        out.push_str(values[&name].as_str());
        last = range.end;
    }
    out.push_str(&arg[last..]);
    out
}

fn append_capped(out: &mut Vec<u8>, bytes: &[u8], cap: Option<usize>) -> bool {
    match cap {
        Some(cap) if out.len() + bytes.len() > cap => {
            let room = cap - out.len();
            out.extend_from_slice(&bytes[..room]);
            true
        }
        _ => {
            out.extend_from_slice(bytes);
            false
        }
    }
}

/// Raw bytes a stream may feed the redactor, given an output cap.
///
/// The redactor can hold back unbounded input for periodic secrets, so the
/// raw input is bounded separately: `max(cap * 4, cap + 64 KiB)`.
fn raw_limit(cap: usize) -> usize {
    cap.saturating_mul(4).max(cap.saturating_add(RAW_SLACK))
}

/// Reads a stream to EOF through the redactor, keeping at most `cap` bytes.
///
/// After the output cap or the raw-input bound is hit the stream is still
/// drained (so the child never blocks) but no longer fed to the redactor.
fn pump(mut reader: impl Read, mut redactor: Redactor, cap: Option<usize>) -> (Vec<u8>, bool) {
    let raw_max = cap.map(raw_limit);
    let mut collected = Vec::new();
    let mut raw_fed = 0usize;
    let mut truncated = false;
    let mut buf = [0u8; READ_CHUNK];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                truncated = true;
                break;
            }
        };
        if truncated {
            continue;
        }
        if raw_max.is_some_and(|max| raw_fed.saturating_add(n) > max) {
            truncated = true;
            continue;
        }
        raw_fed += n;
        let clean = redactor.push(&buf[..n]);
        truncated = append_capped(&mut collected, &clean, cap);
    }
    if !truncated {
        let clean = redactor.finish();
        truncated = append_capped(&mut collected, &clean, cap);
    }
    if truncated {
        // Cut on a character boundary, not in the middle of a UTF-8 sequence.
        if let Err(e) = std::str::from_utf8(&collected) {
            if e.error_len().is_none() {
                collected.truncate(e.valid_up_to());
            }
        }
    }
    (collected, truncated)
}

fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

struct Waited {
    status: Option<ExitStatus>,
    out: Option<(Vec<u8>, bool)>,
    err: Option<(Vec<u8>, bool)>,
    timed_out: bool,
}

type Chunk = (Stream, (Vec<u8>, bool));

/// Waits for the leader and both readers, enforcing the timeout over all three.
fn supervise(
    child: &mut Child,
    rx: &mpsc::Receiver<Chunk>,
    timeout: Option<Duration>,
    template: &str,
) -> Result<Waited> {
    // The deadline covers the leader and both output pipes, so background
    // processes holding a pipe open cannot stall us past the timeout.
    let deadline = timeout.and_then(|limit| Instant::now().checked_add(limit));
    let mut timed_out = false;
    let mut status = None;
    let mut out: Option<(Vec<u8>, bool)> = None;
    let mut err: Option<(Vec<u8>, bool)> = None;
    let mut give_up_at: Option<Instant> = None;
    loop {
        while let Ok((stream, result)) = rx.try_recv() {
            match stream {
                Stream::Out => out = Some(result),
                Stream::Err => err = Some(result),
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(s) => status = s,
                Err(e) => {
                    kill_tree(child);
                    return Err(Error::new(ErrorKind::Spawn(format!(
                        "waiting for {template}: {e}"
                    ))));
                }
            }
        }
        if status.is_some() && out.is_some() && err.is_some() {
            break;
        }
        let now = Instant::now();
        if let Some(give_up) = give_up_at {
            if now >= give_up {
                break;
            }
        } else if deadline.is_some_and(|d| now >= d) {
            timed_out = true;
            kill_tree(child);
            give_up_at = Some(now + KILL_GRACE);
        }
        thread::sleep(POLL_INTERVAL);
    }
    if status.is_none() {
        // Killed but not yet reaped within the grace period.
        status = child.try_wait().ok().flatten();
    }
    Ok(Waited {
        status,
        out,
        err,
        timed_out,
    })
}

/// Runs `request` with its secrets injected and returns redacted output.
///
/// # Errors
///
/// Returns [`ErrorKind::Usage`] for an empty argv or an invalid environment
/// variable name, [`ErrorKind::UnknownName`] if a referenced secret does not
/// exist (nothing is spawned), [`ErrorKind::Keyring`] if the keyring fails,
/// and [`ErrorKind::Spawn`] if the program cannot be started or awaited. Spawn
/// errors name the program as given, before placeholder substitution.
///
/// # Panics
///
/// Panics only if the child's piped streams are missing, which is a bug.
pub fn run(vault: &Vault, request: &RunRequest) -> Result<RunOutput> {
    request.validate()?;
    let template = request
        .argv
        .first()
        .ok_or_else(|| usage("argv must contain at least the program to run"))?;

    let mut values = BTreeMap::new();
    for name in request.secret_names() {
        let value = vault.resolve_for_injection(&name)?;
        values.insert(name, value);
    }

    let argv: Vec<Zeroizing<String>> = request
        .argv
        .iter()
        .map(|a| substitute(a, &values))
        .collect();
    let mut command = Command::new(argv[0].as_str());
    command
        .args(argv[1..].iter().map(|a| a.as_str()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (var, name) in &request.env {
        command.env(var, values[name].as_str());
    }
    if let Some(dir) = &request.cwd {
        command.current_dir(dir);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    // Errors name the unsubstituted template, never the resolved value.
    let mut child = command
        .spawn()
        .map_err(|e| Error::new(ErrorKind::Spawn(format!("{template}: {e}"))))?;

    let redactor = Redactor::new(values.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    let cap = request.max_output_bytes;
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let (tx, rx) = mpsc::channel();
    {
        let (tx, redactor) = (tx.clone(), redactor.clone());
        thread::spawn(move || {
            let _ = tx.send((Stream::Out, pump(stdout, redactor, cap)));
        });
    }
    thread::spawn(move || {
        let _ = tx.send((Stream::Err, pump(stderr, redactor, cap)));
    });

    let Waited {
        status,
        out,
        err,
        timed_out,
    } = supervise(&mut child, &rx, request.timeout, template)?;

    // A stream whose reader did not return is reported as truncated and empty.
    let (stdout, out_truncated) = out.unwrap_or((Vec::new(), true));
    let (stderr, err_truncated) = err.unwrap_or((Vec::new(), true));
    Ok(RunOutput {
        exit_code: status.and_then(|s| s.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: out_truncated || err_truncated,
        timed_out,
    })
}

#[derive(Clone, Copy)]
enum Stream {
    Out,
    Err,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_only_valid_placeholders() {
        let found: Vec<_> = placeholders("a {{nas-root}} b {{ hf.token }} c {{Bad}} {{x")
            .into_iter()
            .map(|(_, n)| n.to_string())
            .collect();
        assert_eq!(found, ["nas-root", "hf.token"]);
    }

    /// Every argument up to `max` characters over the characters that matter
    /// to placeholder parsing, plus one multi-byte character.
    fn arguments(max: usize) -> Vec<String> {
        let mut all = vec![String::new()];
        let mut layer = vec![String::new()];
        for _ in 0..max {
            layer = layer
                .iter()
                .flat_map(|s| ['{', '}', 'a', ' ', 'é'].map(|c| format!("{s}{c}")))
                .collect();
            all.extend(layer.iter().cloned());
        }
        all
    }

    /// Bounded exhaustive check (see `formal/README.md`): placeholder ranges
    /// are in bounds, on character boundaries, ordered, disjoint and shaped
    /// `{{ name }}`, and `substitute` fills exactly the buffer it reserves, so
    /// it never reallocates and leaves no unzeroed copy of a value behind.
    #[test]
    fn placeholders_and_substitute_exhaustive() {
        for arg in arguments(7) {
            let found = placeholders(&arg);
            let mut last_end = 0;
            for (range, name) in &found {
                assert!(
                    last_end <= range.start && range.start < range.end,
                    "{arg:?}"
                );
                assert!(arg.is_char_boundary(range.start) && arg.is_char_boundary(range.end));
                let text = &arg[range.clone()];
                assert!(text.starts_with("{{") && text.ends_with("}}"), "{arg:?}");
                assert_eq!(text[2..text.len() - 2].trim(), name.as_str());
                last_end = range.end;
            }
            for len in 0..=3 {
                let values: BTreeMap<SecretName, Zeroizing<String>> = found
                    .iter()
                    .map(|(_, n)| (n.clone(), Zeroizing::new("v".repeat(len))))
                    .collect();
                let reserved =
                    arg.len() + found.iter().map(|(_, n)| values[n].len()).sum::<usize>();
                let out = substitute(&arg, &values);
                assert!(out.len() <= reserved);
                assert_eq!(out.capacity(), reserved, "{arg:?}");
            }
        }
    }

    #[test]
    fn env_var_names() {
        assert!(is_env_var_name("HF_TOKEN"));
        assert!(is_env_var_name("_x1"));
        assert!(!is_env_var_name("1BAD"));
        assert!(!is_env_var_name("A-B"));
        assert!(!is_env_var_name(""));
    }
}

/// Kani proof harnesses. Run with `cargo kani`; see `formal/README.md`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// With the invariant `pump` keeps (output never above the cap), appending
    /// keeps it, never panics, and reports truncation exactly when it cuts.
    #[kani::proof]
    #[kani::unwind(6)]
    fn append_capped_respects_cap() {
        let cap: Option<usize> = kani::any();
        let have: usize = kani::any();
        let add: usize = kani::any();
        kani::assume(have <= 3 && add <= 3);
        kani::assume(cap.is_none_or(|c| have <= c));
        let mut out = vec![0u8; have];
        let truncated = append_capped(&mut out, &[1u8; 3][..add], cap);
        if let Some(c) = cap {
            assert!(out.len() <= c);
        }
        assert_eq!(truncated, out.len() < have + add);
    }

    /// The raw-input bound never overflows and never undercuts the output cap.
    #[kani::proof]
    fn raw_limit_is_at_least_cap() {
        let cap: usize = kani::any();
        assert!(raw_limit(cap) >= cap);
    }
}
