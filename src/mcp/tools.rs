//! Tool definitions and dispatch for the MCP server.

use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::ClipboardFactory;
use crate::capture::{CaptureOptions, capture};
use crate::error::{Error, ErrorKind, Result};
use crate::generate::{Alphabet, GenerateOptions, generate};
use crate::name::{SecretHost, SecretName, SecretUser};
use crate::vault::{Labels, Vault};

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
    user: Option<String>,
    host: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerateArgs {
    name: String,
    length: Option<usize>,
    alphabet: Option<Alphabet>,
    #[serde(default)]
    overwrite: bool,
    user: Option<String>,
    host: Option<String>,
}

fn parse<T: DeserializeOwned>(args: &Value) -> Result<T> {
    T::deserialize(args)
        .map_err(|e| Error::new(ErrorKind::Usage(format!("invalid arguments: {e}"))))
}

fn pretty(value: &impl serde::Serialize) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|e| Error::new(ErrorKind::Usage(e.to_string())))
}

/// JSON descriptions of every tool, for `tools/list`.
pub(super) fn definitions() -> Value {
    json!([
        {
            "name": "secret_list",
            "description": "List stored secrets: names, users, hosts, lengths, fingerprints, sources and dates. Never returns values. One host can have several secrets for different accounts (e.g. nas-root with user root and nas-enzo with user enzo): pick the secret whose user is the login you need, then write its user as the login and its host as the address to connect to.",
            "inputSchema": {
                "type": "object",
                "properties": {"prefix": {"type": "string", "description": "Only names starting with this prefix."}},
                "additionalProperties": false
            }
        },
        {
            "name": "secret_info",
            "description": "Metadata for one secret (user, host, length, fingerprint, source, dates). Never returns the value.",
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
                    "allow_multiline": {"type": "boolean", "default": false},
                    "user": {"type": "string", "description": "Account this secret belongs to, e.g. root for the NAS root password. Not secret; shown in secret_list. On overwrite, omitting it keeps the current user."},
                    "host": {"type": "string", "description": "Where this secret is used: hostname, IP or URL, e.g. 192.168.1.8 for the NAS. Not secret; shown in secret_list. On overwrite, omitting it keeps the current host."}
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
                    "overwrite": {"type": "boolean", "default": false},
                    "user": {"type": "string", "description": "Account this secret belongs to, e.g. root for the NAS root password. Not secret; shown in secret_list. On overwrite, omitting it keeps the current user."},
                    "host": {"type": "string", "description": "Where this secret is used: hostname, IP or URL, e.g. 192.168.1.8 for the NAS. Not secret; shown in secret_list. On overwrite, omitting it keeps the current host."}
                },
                "required": ["name"],
                "additionalProperties": false
            }
        }
    ])
}

/// Validates the optional user and host arguments of a storing tool.
fn labels(user: Option<String>, host: Option<String>) -> Result<Labels> {
    Ok(Labels {
        user: user.map(SecretUser::new).transpose()?,
        host: host.map(SecretHost::new).transpose()?,
    })
}

/// Runs tool `tool` and returns the text for its result.
pub(super) fn call(
    vault: &Vault,
    clipboard: &ClipboardFactory,
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
                labels: labels(args.user, args.host)?,
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
                labels: labels(args.user, args.host)?,
            };
            let meta = generate(vault, &name, &options)?;
            Ok(format!(
                "stored {name}: {} chars, fp {}",
                meta.len, meta.fingerprint
            ))
        }

        other => Err(Error::new(ErrorKind::Usage(format!(
            "unknown tool `{other}`"
        )))),
    }
}
