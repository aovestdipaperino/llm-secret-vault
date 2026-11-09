//! Approval step that runs before secrets are injected into a command.
//!
//! Approvers never see secret values; the reason shown to the user names the
//! command and the secrets by name only.

use std::collections::BTreeSet;
use std::fmt;
#[cfg(target_os = "macos")]
use std::time::Duration;

use crate::error::{Error, ErrorKind, Result};
use crate::inject::RunRequest;
use crate::name::SecretName;

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

/// Whether command-line secret use requires approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Never ask.
    Off,
    /// Ask before every command-line secret use.
    All,
}

fn usage(message: String) -> Error {
    Error::from_kind(ErrorKind::Usage(message))
}

impl Mode {
    /// Parses the `LSV_TOUCH_ID` value; unset means [`Mode::All`].
    ///
    /// # Errors
    ///
    /// Returns a usage error for values other than `off` or `all`.
    pub fn parse(value: Option<&str>) -> Result<Self> {
        let Some(value) = value else {
            return Ok(Self::All);
        };
        match value.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "all" => Ok(Self::All),
            _ => Err(usage(format!(
                "LSV_TOUCH_ID must be off or all, got `{value}`"
            ))),
        }
    }
}

/// Builds the approver configured by `LSV_TOUCH_ID`.
///
/// # Errors
///
/// Returns a usage error if the variable is malformed.
pub fn from_env() -> Result<Box<dyn Approver>> {
    let mode = Mode::parse(std::env::var("LSV_TOUCH_ID").ok().as_deref())?;
    match mode {
        Mode::All => Ok(platform_approver()),
        Mode::Off => Ok(Box::new(AllowAll)),
    }
}

#[cfg(target_os = "macos")]
fn platform_approver() -> Box<dyn Approver> {
    Box::new(TouchId)
}

#[cfg(not(target_os = "macos"))]
fn platform_approver() -> Box<dyn Approver> {
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
    use super::*;

    #[test]
    fn parses_mode() {
        assert_eq!(Mode::parse(None).unwrap(), Mode::All);
        assert_eq!(Mode::parse(Some("OFF")).unwrap(), Mode::Off);
        assert_eq!(Mode::parse(Some("All")).unwrap(), Mode::All);
        for value in ["mcp", "yes"] {
            let err = Mode::parse(Some(value)).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("LSV_TOUCH_ID must be off or all, got `{value}`")
            );
        }
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
