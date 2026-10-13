//! Running commands with secrets injected and their output redacted.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::ops::Range;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
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
const RAW_SLACK: usize = 64 * 1024;

/// A command to run with secrets injected.
///
/// Secrets reach the child as environment variables (via [`RunRequest::env`])
/// or through `{{name}}` placeholders in any argument after the program.
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

    /// Kills the child (and its process group on Unix) after `limit`.
    #[must_use]
    pub fn timeout(mut self, limit: Duration) -> Self {
        self.timeout = Some(limit);
        self
    }

    /// Keeps at most `bytes` of redacted output per stream.
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
    let mut out = Zeroizing::new(String::with_capacity(arg.len()));
    let mut last = 0;
    for (range, name) in placeholders(arg) {
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
            Err(_) => break,
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

/// Runs `request` with its secrets injected and returns redacted output.
///
/// # Errors
///
/// Returns [`ErrorKind::Usage`] for an empty argv or an invalid environment
/// variable name, [`ErrorKind::UnknownName`] if a referenced secret does not
/// exist (nothing is spawned), [`ErrorKind::Keyring`] if the keyring fails,
/// and [`ErrorKind::Spawn`] if the program cannot be started or awaited.
///
/// # Panics
///
/// Panics only if an internal output-reader thread panics, which is a bug.
pub fn run(vault: &Vault, request: &RunRequest) -> Result<RunOutput> {
    let program = request
        .argv
        .first()
        .ok_or_else(|| usage("argv must contain at least the program to run"))?;
    if let Some(var) = request.env.keys().find(|v| !is_env_var_name(v)) {
        return Err(usage(format!(
            "`{var}` is not a valid environment variable name"
        )));
    }

    let mut names: BTreeSet<SecretName> = request.env.values().cloned().collect();
    for arg in &request.argv[1..] {
        names.extend(placeholders(arg).into_iter().map(|(_, name)| name));
    }
    let mut values = BTreeMap::new();
    for name in names {
        let value = vault.resolve(&name)?;
        values.insert(name, value);
    }

    let args: Vec<Zeroizing<String>> = request.argv[1..]
        .iter()
        .map(|a| substitute(a, &values))
        .collect();
    let mut command = Command::new(program);
    command
        .args(args.iter().map(|a| a.as_str()))
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
    let mut child = command
        .spawn()
        .map_err(|e| Error::new(ErrorKind::Spawn(format!("{program}: {e}"))))?;

    let redactor = Redactor::new(values.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    let cap = request.max_output_bytes;
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");
    let out_reader = {
        let redactor = redactor.clone();
        thread::spawn(move || pump(stdout, redactor, cap))
    };
    let err_reader = thread::spawn(move || pump(stderr, redactor, cap));

    let mut timed_out = false;
    let status = match request.timeout {
        None => child.wait(),
        Some(limit) => {
            let deadline = Instant::now() + limit;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if Instant::now() >= deadline => {
                        timed_out = true;
                        kill_tree(&mut child);
                        break child.wait();
                    }
                    Ok(None) => thread::sleep(POLL_INTERVAL),
                    Err(e) => break Err(e),
                }
            }
        }
    }
    .map_err(|e| Error::new(ErrorKind::Spawn(format!("waiting for {program}: {e}"))))?;

    let (stdout, out_truncated) = out_reader.join().expect("stdout reader panicked");
    let (stderr, err_truncated) = err_reader.join().expect("stderr reader panicked");
    Ok(RunOutput {
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: out_truncated || err_truncated,
        timed_out,
    })
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

    #[test]
    fn env_var_names() {
        assert!(is_env_var_name("HF_TOKEN"));
        assert!(is_env_var_name("_x1"));
        assert!(!is_env_var_name("1BAD"));
        assert!(!is_env_var_name("A-B"));
        assert!(!is_env_var_name(""));
    }
}
