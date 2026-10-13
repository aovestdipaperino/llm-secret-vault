//! `lsv`: command-line front end for llm-secret-vault.

use std::io::{Read, Write};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use llm_secret_vault::approve::{self, Context};
use llm_secret_vault::capture::{CaptureOptions, SystemClipboard, capture};
use llm_secret_vault::generate::{Alphabet, GenerateOptions, generate};
use llm_secret_vault::hook::{Decision, evaluate};
use llm_secret_vault::import::import;
use llm_secret_vault::inject::{RunRequest, run};
use llm_secret_vault::mcp::Server;
use llm_secret_vault::{Error, ErrorKind, Meta, Result, SecretName, Vault};

/// Let LLM agents use secrets they can never read.
#[derive(Debug, Parser)]
#[command(name = "lsv", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// List secret names and metadata (never values).
    List {
        /// Only names starting with this prefix.
        prefix: Option<String>,
    },
    /// Show metadata for one secret.
    Info { name: String },
    /// Store the clipboard text as a secret, then clear the clipboard.
    Capture {
        name: String,
        #[arg(long)]
        overwrite: bool,
        #[arg(long)]
        expect_prefix: Option<String>,
        #[arg(long)]
        min_len: Option<usize>,
        #[arg(long)]
        allow_multiline: bool,
    },
    /// Generate a random secret without showing it.
    Generate {
        name: String,
        #[arg(long, default_value_t = 32)]
        length: usize,
        #[arg(long, value_enum, default_value_t = Alphabet::Alnum)]
        alphabet: Alphabet,
        #[arg(long)]
        overwrite: bool,
    },
    /// Type a secret at a hidden prompt.
    Import {
        name: String,
        #[arg(long)]
        overwrite: bool,
    },
    /// Run a command with secrets injected: lsv run VAR=name ... -- program args.
    Run {
        /// VAR=secret-name bindings.
        bindings: Vec<String>,
        /// Program and arguments; {{name}} placeholders are expanded.
        #[arg(last = true, required = true)]
        argv: Vec<String>,
    },
    /// Delete a secret.
    Delete { name: String },
    /// Serve MCP over stdio (launched by Claude Code).
    Mcp,
    /// `PreToolUse` guard for Claude Code and plank; reads hook JSON on stdin.
    Hook,
    /// Print setup instructions.
    Setup {
        #[command(subcommand)]
        target: SetupTarget,
    },
}

#[derive(Debug, Subcommand)]
enum SetupTarget {
    /// Claude Code: MCP registration and guard hook.
    Claude,
    /// plank: MCP registration and guard hook.
    Plank,
}

const SETUP_CLAUDE: &str = r#"1. Register the MCP server:

   claude mcp add --scope user llm-secret-vault -- lsv mcp

2. Add the guard hook to ~/.claude/settings.json (merge with existing "hooks"):

   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "Bash",
           "hooks": [{ "type": "command", "command": "lsv hook" }]
         }
       ]
     }
   }

3. Next time a secret is on your clipboard, tell Claude its name, e.g.
   "the NAS root password is in the clipboard, save it as nas-root".
"#;

const SETUP_PLANK: &str = r#"1. Register the MCP server in ~/.plank/.mcp.json (merge with existing "mcpServers"):

   {
     "mcpServers": {
       "llm-secret-vault": { "command": "lsv", "args": ["mcp"] }
     }
   }

2. Add the guard hook to ~/.plank/hooks.json (merge with existing events):

   {
     "PreToolUse": [
       {
         "matcher": "bash",
         "hooks": [{ "type": "command", "command": "lsv hook" }]
       }
     ]
   }

3. Restart plank; /hooks should list the guard.
"#;

fn main() -> ExitCode {
    match dispatch(Cli::parse().command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("lsv: {err}");
            ExitCode::from(2)
        }
    }
}

fn dispatch(command: Cmd) -> Result<ExitCode> {
    match command {
        Cmd::Hook => Ok(hook_main()),
        Cmd::Setup { target } => {
            print!(
                "{}",
                match target {
                    SetupTarget::Claude => SETUP_CLAUDE,
                    SetupTarget::Plank => SETUP_PLANK,
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::List { prefix } => {
            print_table(&Vault::open()?.list(prefix.as_deref()));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Info { name } => {
            let name = SecretName::new(name)?;
            print_info(&Vault::open()?.info(&name)?);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Capture {
            name,
            overwrite,
            expect_prefix,
            min_len,
            allow_multiline,
        } => {
            let name = SecretName::new(name)?;
            let options = CaptureOptions {
                overwrite,
                expect_prefix,
                min_len,
                allow_multiline,
            };
            let mut clipboard = SystemClipboard::new()?;
            let report = capture(&Vault::open()?, &mut clipboard, &name, &options)?;
            println!(
                "stored {name}: {} chars, fp {}{}",
                report.meta.len,
                report.meta.fingerprint,
                if report.clipboard_cleared {
                    ", clipboard cleared"
                } else {
                    ", clipboard NOT cleared (clear it manually)"
                }
            );
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Generate {
            name,
            length,
            alphabet,
            overwrite,
        } => {
            let name = SecretName::new(name)?;
            let meta = generate(
                &Vault::open()?,
                &name,
                &GenerateOptions {
                    length,
                    alphabet,
                    overwrite,
                },
            )?;
            println!("stored {name}: {} chars, fp {}", meta.len, meta.fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Import { name, overwrite } => {
            let name = SecretName::new(name)?;
            let meta = import(&Vault::open()?, &name, overwrite)?;
            println!("stored {name}: {} chars, fp {}", meta.len, meta.fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Run { bindings, argv } => run_main(&bindings, argv),
        Cmd::Delete { name } => {
            let name = SecretName::new(name)?;
            Vault::open()?.delete(&name)?;
            println!("deleted {name}");
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Mcp => {
            let server = Server::with_system_clipboard(Vault::open()?)
                .with_approver(approve::from_env(Context::Mcp)?);
            server
                .serve(std::io::stdin().lock(), std::io::stdout().lock())
                .map_err(|e| Error::from_io("MCP transport", &e))?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn run_main(bindings: &[String], argv: Vec<String>) -> Result<ExitCode> {
    let mut request = RunRequest::new(argv);
    for binding in bindings {
        let (var, name) = binding.split_once('=').ok_or_else(|| {
            usage(format!(
                "expected VAR=secret-name before `--`, got `{binding}`"
            ))
        })?;
        request = request.env(var, SecretName::new(name)?);
    }
    let approver = approve::from_env(Context::Cli)?;
    if !request.secret_names().is_empty() {
        approver.approve(&approve::run_reason(&request))?;
    }
    let output = run(&Vault::open()?, &request)?;
    std::io::stdout().write_all(output.stdout.as_bytes()).ok();
    std::io::stderr().write_all(output.stderr.as_bytes()).ok();
    if output.timed_out {
        eprintln!("lsv: command timed out and was killed");
    }
    if output.truncated {
        eprintln!("lsv: output truncated");
    }
    let code = output
        .exit_code
        .and_then(|c| u8::try_from(c).ok())
        .unwrap_or(1);
    Ok(ExitCode::from(code))
}

fn hook_main() -> ExitCode {
    let mut input = String::new();
    if let Err(e) = std::io::stdin().read_to_string(&mut input) {
        eprintln!("lsv hook: warning: could not read stdin: {e}");
        return ExitCode::SUCCESS;
    }
    // Exit 2 with the reason on stderr is the blocking protocol shared by
    // Claude Code and plank; both show the reason to the model.
    match evaluate(&input) {
        Ok(Decision::Allow) => ExitCode::SUCCESS,
        Ok(Decision::Deny(reason)) => {
            eprintln!("llm-secret-vault: {reason}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("lsv hook: warning: {e}; allowing the command");
            ExitCode::SUCCESS
        }
    }
}

fn usage(why: String) -> Error {
    Error::from_kind(ErrorKind::Usage(why))
}

fn print_table(secrets: &[Meta]) {
    if secrets.is_empty() {
        println!("no secrets stored");
        return;
    }
    println!(
        "{:<32} {:>5}  {:<8}  {:<9}  UPDATED",
        "NAME", "LEN", "FP", "SOURCE"
    );
    for meta in secrets {
        println!(
            "{:<32} {:>5}  {:<8}  {:<9}  {}",
            meta.name,
            meta.len,
            meta.fingerprint,
            source_label(meta),
            date(meta.rotated.unwrap_or(meta.created))
        );
    }
}

fn print_info(meta: &Meta) {
    println!("name:        {}", meta.name);
    println!("length:      {}", meta.len);
    println!("fingerprint: {}", meta.fingerprint);
    println!("source:      {}", source_label(meta));
    println!("created:     {}", date(meta.created));
    if let Some(rotated) = meta.rotated {
        println!("rotated:     {}", date(rotated));
    }
}

fn source_label(meta: &Meta) -> String {
    serde_json::to_value(meta.source)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Formats Unix seconds as a UTC `YYYY-MM-DD` date.
fn date(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Converts days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_791_849_600), "2026-10-13");
        assert_eq!(date(951_782_400), "2000-02-29");
    }
}
