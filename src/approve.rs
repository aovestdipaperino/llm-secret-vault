//! Approval step that runs before secrets are injected into a command.
//!
//! Approvers never see secret values; the reason shown to the user names the
//! command and the secrets by name only.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{Error, ErrorKind, Result};
use crate::inject::RunRequest;
use crate::name::SecretName;

const DEFAULT_TTL_S: u64 = 300;
const MAX_TTL_S: u64 = 3600;
const REASON_CMD_CHARS: usize = 80;

/// Asks the user to approve injecting secrets into a command.
pub trait Approver: Send + Sync + fmt::Debug {
    /// Asks for approval to inject `secrets`; `reason` is shown to the user.
    ///
    /// # Errors
    ///
    /// Returns an error if approval is denied, cancelled or unavailable.
    fn approve(&self, reason: &str, secrets: &BTreeSet<SecretName>) -> Result<()>;
}

/// An approver that approves everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct AllowAll;

impl Approver for AllowAll {
    fn approve(&self, _reason: &str, _secrets: &BTreeSet<SecretName>) -> Result<()> {
        Ok(())
    }
}

/// Remembers successful approvals per secret name for a while, so prompts
/// are not repeated for secrets the user already approved.
#[derive(Debug)]
pub struct Cached<A> {
    inner: A,
    ttl: Duration,
    approved_at: Mutex<BTreeMap<SecretName, Instant>>,
}

impl<A> Cached<A> {
    /// Wraps `inner`, skipping it when every requested secret was approved
    /// within the last `ttl`.
    #[must_use]
    pub fn new(inner: A, ttl: Duration) -> Self {
        Self {
            inner,
            ttl,
            approved_at: Mutex::new(BTreeMap::new()),
        }
    }
}

impl<A: Approver> Approver for Cached<A> {
    fn approve(&self, reason: &str, secrets: &BTreeSet<SecretName>) -> Result<()> {
        let mut approved = self
            .approved_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fresh =
            |name: &SecretName| approved.get(name).is_some_and(|at| at.elapsed() < self.ttl);
        if secrets.iter().all(fresh) {
            return Ok(());
        }
        self.inner.approve(reason, secrets)?;
        let now = Instant::now();
        for name in secrets {
            approved.insert(name.clone(), now);
        }
        Ok(())
    }
}

/// Which entry points require approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Never ask.
    Off,
    /// Ask for MCP calls only.
    Mcp,
    /// Ask for MCP calls and the command line.
    All,
}

/// The entry point asking for approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    /// The MCP server.
    Mcp,
    /// The `lsv run` command.
    Cli,
}

fn usage(message: String) -> Error {
    Error::from_kind(ErrorKind::Usage(message))
}

impl Mode {
    /// Parses the `LSV_TOUCH_ID` value; unset means [`Mode::All`].
    ///
    /// # Errors
    ///
    /// Returns a usage error for values other than `off`, `mcp` or `all`.
    pub fn parse(value: Option<&str>) -> Result<Self> {
        let Some(value) = value else {
            return Ok(Self::All);
        };
        match value.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "mcp" => Ok(Self::Mcp),
            "all" => Ok(Self::All),
            _ => Err(usage(format!(
                "LSV_TOUCH_ID must be off, mcp or all, got `{value}`"
            ))),
        }
    }

    /// Returns whether approval is required in `context`.
    #[must_use]
    pub fn covers(self, context: Context) -> bool {
        matches!((self, context), (Self::All, _) | (Self::Mcp, Context::Mcp))
    }
}

/// Parses the `LSV_TOUCH_ID_TTL` value in seconds; unset means 300.
///
/// # Errors
///
/// Returns a usage error unless the value is an integer in `0..=3600`.
pub fn parse_ttl(value: Option<&str>) -> Result<Duration> {
    let Some(value) = value else {
        return Ok(Duration::from_secs(DEFAULT_TTL_S));
    };
    match value.trim().parse::<u64>() {
        Ok(secs) if secs <= MAX_TTL_S => Ok(Duration::from_secs(secs)),
        _ => Err(usage(
            "LSV_TOUCH_ID_TTL must be 0..=3600 seconds".to_owned(),
        )),
    }
}

/// Builds the approver configured by `LSV_TOUCH_ID` and `LSV_TOUCH_ID_TTL`.
///
/// # Errors
///
/// Returns a usage error if either variable is malformed.
pub fn from_env(context: Context) -> Result<Box<dyn Approver>> {
    let mode = Mode::parse(std::env::var("LSV_TOUCH_ID").ok().as_deref())?;
    let ttl = parse_ttl(std::env::var("LSV_TOUCH_ID_TTL").ok().as_deref())?;
    if mode.covers(context) {
        Ok(platform_approver(ttl))
    } else {
        Ok(Box::new(AllowAll))
    }
}

#[cfg(target_os = "macos")]
fn platform_approver(ttl: Duration) -> Box<dyn Approver> {
    Box::new(Cached::new(TouchId, ttl))
}

#[cfg(not(target_os = "macos"))]
fn platform_approver(_ttl: Duration) -> Box<dyn Approver> {
    eprintln!("lsv: Touch ID approval is only available on macOS; continuing without it");
    Box::new(AllowAll)
}

/// How long a Touch ID prompt may stay unanswered before it counts as a refusal.
#[cfg(target_os = "macos")]
const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Asks for Touch ID, or the login password, through `LocalAuthentication`.
#[cfg(target_os = "macos")]
#[derive(Debug, Default, Clone, Copy)]
pub struct TouchId;

#[cfg(target_os = "macos")]
impl Approver for TouchId {
    fn approve(&self, reason: &str, _secrets: &BTreeSet<SecretName>) -> Result<()> {
        if evaluate_device_owner(reason) {
            Ok(())
        } else {
            Err(Error::from_kind(ErrorKind::Denied(
                "Touch ID approval was denied or cancelled".to_owned(),
            )))
        }
    }
}

/// Runs `LAPolicy::DeviceOwnerAuthentication` and waits for the reply.
///
/// Returns `false` if the user fails or cancels, if the reply block is
/// released without being called, or if nobody answers within
/// [`PROMPT_TIMEOUT`] (the dialog is then dismissed).
#[cfg(target_os = "macos")]
fn evaluate_device_owner(reason: &str) -> bool {
    use std::sync::mpsc;

    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    let (tx, rx) = mpsc::channel::<bool>();
    let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
        // The receiver may be gone only if this thread stopped waiting.
        let _ = tx.send(success.as_bool());
    });
    let reason = NSString::from_str(reason);
    // SAFETY: `+[LAContext new]` has no preconditions and returns an owned,
    // initialised context.
    let context = unsafe { LAContext::new() };
    // SAFETY: `context`, `reason` and `reply` are valid for the call; the
    // policy is a defined `LAPolicy` constant; the block only touches an
    // owned `Sender`, which is safe to use from LocalAuthentication's private
    // queue, and ignores the error pointer. `context` outlives the reply
    // because we block on `rx` before dropping it.
    unsafe {
        context.evaluatePolicy_localizedReason_reply(
            LAPolicy::DeviceOwnerAuthentication,
            &reason,
            &reply,
        );
    }
    let approved = match rx.recv_timeout(PROMPT_TIMEOUT) {
        Ok(approved) => approved,
        Err(mpsc::RecvTimeoutError::Disconnected) => false,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // SAFETY: `context` is a valid, live context; invalidating it
            // dismisses the dialog and makes the pending reply fire with a
            // cancel error.
            unsafe { context.invalidate() };
            // Wait briefly for that reply so the block is not left pending.
            let _ = rx.recv_timeout(Duration::from_secs(1));
            false
        }
    };
    drop(context);
    approved
}

/// Describes `request` for an approval prompt, naming secrets but never values.
#[must_use]
pub fn run_reason(request: &RunRequest) -> String {
    // Collapse whitespace runs so padding cannot push the tail out of view.
    let joined = request
        .argv()
        .iter()
        .flat_map(|arg| arg.split_whitespace())
        .collect::<Vec<_>>()
        .join(" ");
    let command = if joined.chars().count() > REASON_CMD_CHARS {
        let end = joined
            .char_indices()
            .nth(REASON_CMD_CHARS)
            .map_or(joined.len(), |(i, _)| i);
        format!("{}…", &joined[..end])
    } else {
        joined
    };
    let names: Vec<String> = request
        .secret_names()
        .iter()
        .map(ToString::to_string)
        .collect();
    format!("run \"{command}\" with secrets {}", names.join(", "))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug, Default)]
    struct Counting {
        asked: AtomicUsize,
        fail: bool,
    }

    impl Approver for &Counting {
        fn approve(&self, _reason: &str, _secrets: &BTreeSet<SecretName>) -> Result<()> {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(Error::from_kind(ErrorKind::Denied("no".to_owned())))
            } else {
                Ok(())
            }
        }
    }

    fn names(list: &[&str]) -> BTreeSet<SecretName> {
        list.iter().map(|n| SecretName::new(*n).unwrap()).collect()
    }

    fn asks(counting: &Counting, ttl: Duration) -> (usize, usize) {
        let cached = Cached::new(counting, ttl);
        let oks = (0..3)
            .filter(|_| cached.approve("r", &names(&["a"])).is_ok())
            .count();
        (oks, counting.asked.load(Ordering::SeqCst))
    }

    #[test]
    fn cache_is_keyed_by_secret_names() {
        let counting = Counting::default();
        let cached = Cached::new(&counting, Duration::from_secs(60));
        cached.approve("r", &names(&["a"])).unwrap();
        assert_eq!(counting.asked.load(Ordering::SeqCst), 1);
        cached.approve("r", &names(&["a", "b"])).unwrap();
        assert_eq!(counting.asked.load(Ordering::SeqCst), 2);
        cached.approve("r", &names(&["a"])).unwrap();
        cached.approve("r", &names(&["b"])).unwrap();
        cached.approve("r", &names(&["a", "b"])).unwrap();
        assert_eq!(counting.asked.load(Ordering::SeqCst), 2);
        cached.approve("r", &names(&["c"])).unwrap();
        assert_eq!(counting.asked.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn zero_ttl_always_asks() {
        assert_eq!(asks(&Counting::default(), Duration::ZERO), (3, 3));
    }

    #[test]
    fn positive_ttl_asks_once() {
        assert_eq!(asks(&Counting::default(), Duration::from_secs(60)), (3, 1));
    }

    #[test]
    fn failures_are_not_cached() {
        let failing = Counting {
            fail: true,
            ..Counting::default()
        };
        assert_eq!(asks(&failing, Duration::from_secs(60)), (0, 3));
    }

    #[test]
    fn parses_mode() {
        assert_eq!(Mode::parse(None).unwrap(), Mode::All);
        assert_eq!(Mode::parse(Some("OFF")).unwrap(), Mode::Off);
        assert_eq!(Mode::parse(Some("mcp")).unwrap(), Mode::Mcp);
        assert_eq!(Mode::parse(Some("All")).unwrap(), Mode::All);
        let err = Mode::parse(Some("yes")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "LSV_TOUCH_ID must be off, mcp or all, got `yes`"
        );
    }

    #[test]
    fn parses_ttl() {
        assert_eq!(parse_ttl(None).unwrap(), Duration::from_secs(300));
        assert_eq!(parse_ttl(Some("0")).unwrap(), Duration::ZERO);
        assert_eq!(parse_ttl(Some("3600")).unwrap(), Duration::from_secs(3600));
        assert!(parse_ttl(Some("3601")).is_err());
        assert!(parse_ttl(Some("abc")).is_err());
    }

    #[test]
    fn covers_matrix() {
        assert!(!Mode::Off.covers(Context::Mcp));
        assert!(!Mode::Off.covers(Context::Cli));
        assert!(Mode::Mcp.covers(Context::Mcp));
        assert!(!Mode::Mcp.covers(Context::Cli));
        assert!(Mode::All.covers(Context::Mcp));
        assert!(Mode::All.covers(Context::Cli));
    }

    #[test]
    fn reason_names_command_and_secrets() {
        let request = RunRequest::new(["sh", "-c", "echo hi {{api}}"])
            .env("T", SecretName::new("tok").unwrap());
        assert_eq!(
            run_reason(&request),
            "run \"sh -c echo hi {{api}}\" with secrets api, tok"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "shows a real Touch ID prompt; run by hand"]
    fn touch_id_prompt() {
        TouchId
            .approve("test llm-secret-vault Touch ID", &BTreeSet::new())
            .unwrap();
    }

    #[test]
    fn reason_collapses_whitespace_before_truncating() {
        let padded = format!("x{}y", " ".repeat(200));
        let request = RunRequest::new(["sh".to_owned(), "-c".to_owned(), padded])
            .env("T", SecretName::new("tok").unwrap());
        assert_eq!(run_reason(&request), "run \"sh -c x y\" with secrets tok");
    }

    #[test]
    fn reason_truncates_long_commands() {
        let long = "é".repeat(200);
        let request =
            RunRequest::new(["echo".to_owned(), long]).env("T", SecretName::new("tok").unwrap());
        let expected = format!("run \"echo {}…\" with secrets tok", "é".repeat(75));
        assert_eq!(run_reason(&request), expected);
    }
}
