//! Tool definitions and dispatch for the MCP server.

use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::ClipboardFactory;
use crate::approve::{self, Approver};
use crate::capture::{CaptureOptions, capture};
use crate::error::{Error, ErrorKind, Result};
use crate::generate::{Alphabet, GenerateOptions, generate};
use crate::hook::{Decision, check_run};
use crate::inject::{RunRequest, run};
use crate::name::SecretName;
use crate::vault::Vault;

const DEFAULT_TIMEOUT_S: u64 = 120;
const DEFAULT_MAX_OUTPUT_KB: usize = 32;
const TIMEOUT_RANGE_S: RangeInclusive<u64> = 1..=3600;
const OUTPUT_RANGE_KB: RangeInclusive<usize> = 1..=1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    prefix: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameArgs {
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureArgs {
    name: String,
    #[serde(default)]
    overwrite: bool,
    expect_prefix: Option<String>,
    min_len: Option<usize>,
    #[serde(default)]
    allow_multiline: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateArgs {
    name: String,
    length: Option<usize>,
    alphabet: Option<Alphabet>,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunArgs {
    argv: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    cwd: Option<PathBuf>,
    timeout_s: Option<u64>,
    max_output_kb: Option<usize>,
}

fn parse<T: DeserializeOwned>(args: &Value) -> Result<T> {
    T::deserialize(args)
        .map_err(|e| Error::new(ErrorKind::Usage(format!("invalid arguments: {e}"))))
}

fn bounded<T>(field: &str, value: Option<T>, default: T, range: &RangeInclusive<T>) -> Result<T>
where
    T: PartialOrd + Copy + std::fmt::Display,
{
    let value = value.unwrap_or(default);
    if range.contains(&value) {
        Ok(value)
    } else {
        Err(Error::new(ErrorKind::Usage(format!(
            "{field} must be between {} and {}",
            range.start(),
            range.end()
        ))))
    }
}

fn pretty(value: &impl serde::Serialize) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| Error::new(ErrorKind::Usage(e.to_string())))
}

/// JSON descriptions of every tool, for `tools/list`.
pub(super) fn definitions() -> Value {
    json!([
        {
            "name": "secret_list",
            "description": "List stored secrets: names, lengths, fingerprints, sources and dates. Never returns values.",
            "inputSchema": {
                "type": "object",
                "properties": {"prefix": {"type": "string", "description": "Only names starting with this prefix."}},
                "additionalProperties": false
            }
        },
        {
            "name": "secret_info",
            "description": "Metadata for one secret (length, fingerprint, source, dates). Never returns the value.",
            "inputSchema": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": "secret_capture",
            "description": "Store the text currently on the user's clipboard as a named secret, then clear the clipboard. Use this whenever the user says a key or password is in the clipboard; never ask them to paste it into chat.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Lowercase name, e.g. nas-root or hf-token."},
                    "overwrite": {"type": "boolean", "default": false},
                    "expect_prefix": {"type": "string", "description": "Reject the capture unless the text starts with this, e.g. hf_ or sk_live_."},
                    "min_len": {"type": "integer", "default": 8},
                    "allow_multiline": {"type": "boolean", "default": false}
                },
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": "secret_generate",
            "description": "Generate a random secret and store it without revealing it. With overwrite=true this rotates an existing secret.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "length": {"type": "integer", "default": 32, "minimum": 8, "maximum": 1024},
                    "alphabet": {"type": "string", "enum": ["alnum", "hex", "base64url", "printable"], "default": "alnum"},
                    "overwrite": {"type": "boolean", "default": false}
                },
                "required": ["name"],
                "additionalProperties": false
            }
        },
        {
            "name": "secret_run",
            "description": "Run a command with secrets injected. Map env var names to secret names in `env`, or write {{secret-name}} inside any argv element, including the program. stdout/stderr come back with secret values replaced by «redacted:name». Do not try to print secrets. If a run is refused or approval is denied, do not retry; ask the user.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1, "description": "Program and arguments; no shell unless you call one."},
                    "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "ENV_VAR -> secret name."},
                    "cwd": {"type": "string"},
                    "timeout_s": {"type": "integer", "default": DEFAULT_TIMEOUT_S, "minimum": 1, "maximum": 3600},
                    "max_output_kb": {"type": "integer", "default": DEFAULT_MAX_OUTPUT_KB, "minimum": 1, "maximum": 1024}
                },
                "required": ["argv"],
                "additionalProperties": false
            }
        }
    ])
}

/// Runs tool `tool` and returns the text for its result.
pub(super) fn call(
    vault: &Vault,
    clipboard: &ClipboardFactory,
    approver: &dyn Approver,
    tool: &str,
    args: &Value,
) -> Result<String> {
    match tool {
        "secret_list" => {
            let args: ListArgs = parse(args)?;
            pretty(&vault.list(args.prefix.as_deref()))
        }
        "secret_info" => {
            let args: NameArgs = parse(args)?;
            pretty(&vault.info(&SecretName::new(&args.name)?)?)
        }
        "secret_capture" => {
            let args: CaptureArgs = parse(args)?;
            let name = SecretName::new(&args.name)?;
            let options = CaptureOptions {
                overwrite: args.overwrite,
                expect_prefix: args.expect_prefix,
                min_len: args.min_len,
                allow_multiline: args.allow_multiline,
            };
            let mut board = clipboard()?;
            let report = capture(vault, board.as_mut(), &name, &options)?;
            let clipboard_note = if report.clipboard_cleared {
                "clipboard cleared"
            } else {
                "clipboard NOT cleared"
            };
            Ok(format!(
                "stored {name}: {} chars, fp {}, {clipboard_note}",
                report.meta.len, report.meta.fingerprint
            ))
        }
        "secret_generate" => {
            let args: GenerateArgs = parse(args)?;
            let name = SecretName::new(&args.name)?;
            let defaults = GenerateOptions::default();
            let options = GenerateOptions {
                length: args.length.unwrap_or(defaults.length),
                alphabet: args.alphabet.unwrap_or(defaults.alphabet),
                overwrite: args.overwrite,
            };
            let meta = generate(vault, &name, &options)?;
            Ok(format!(
                "stored {name}: {} chars, fp {}",
                meta.len, meta.fingerprint
            ))
        }
        "secret_run" => {
            let args: RunArgs = parse(args)?;
            let timeout_s = bounded(
                "timeout_s",
                args.timeout_s,
                DEFAULT_TIMEOUT_S,
                &TIMEOUT_RANGE_S,
            )?;
            let output_kb = bounded(
                "max_output_kb",
                args.max_output_kb,
                DEFAULT_MAX_OUTPUT_KB,
                &OUTPUT_RANGE_KB,
            )?;
            let vars: Vec<&str> = args.env.keys().map(String::as_str).collect();
            if let Decision::Deny(reason) = check_run(&args.argv, &vars) {
                return Err(Error::new(ErrorKind::Denied(format!(
                    "refused by llm-secret-vault: {reason}"
                ))));
            }
            let mut request = RunRequest::new(args.argv)
                .timeout(Duration::from_secs(timeout_s))
                .max_output_bytes(output_kb.saturating_mul(1024));
            for (var, secret) in args.env {
                request = request.env(var, SecretName::new(secret)?);
            }
            if let Some(dir) = args.cwd {
                request = request.cwd(dir);
            }
            request.validate()?;
            let names = request.secret_names();
            if !names.is_empty() {
                // Fail on unknown names before showing a prompt.
                for name in &names {
                    vault.info(name)?;
                }
                approver.approve(&approve::run_reason(&request), &names)?;
            }
            pretty(&run(vault, &request)?)
        }
        other => Err(Error::new(ErrorKind::Usage(format!(
            "unknown tool `{other}`"
        )))),
    }
}
