# llm-secret-vault design

This document describes how `lsv` keeps secrets out of an agent's context.
It is kept in sync with the code.

## Problem

LLM coding agents routinely need credentials: a NAS root password for `ssh`, a
Hugging Face token for uploads, a Resend or Lemon Squeezy API key for `curl`,
AWS keys. Today the user copies the value to the clipboard and tells the agent
"the key is in the clipboard", or pastes it straight into chat. Either way the
value enters the agent's context and lives on in transcripts
(`~/.claude/projects/*.jsonl`), logs and telemetry the user does not control.

`llm-secret-vault` lets an agent capture, generate, rotate and *use* secrets
held in the OS keyring without any operation ever returning a secret value to
the agent.

## Goals

- Agent-facing MCP server, human-facing CLI and a Claude Code guard hook, all
  sharing one core.
- Clipboard capture as the primary way to get an existing secret into the
  vault, matching the user's current habit.
- Secrets injected into child processes via environment variables and, when a
  tool needs them inline, `{{name}}` argv placeholders.
- Output of child processes redacted before it reaches the agent.
- macOS, Linux and Windows.

## Non-goals

- Defending against a deliberately hostile agent. A child process can always
  transform a value beyond recognition; the tool prevents accidents and makes
  leaks require intent. The README states this.
- Team or shared vaults (Bitwarden, 1Password). The `Backend` trait leaves room.
- A daemon or per-session approval prompts (possible v2).
- Editing the user's Claude Code settings automatically.

## Approach

A single binary `lsv` (crate `llm-secret-vault`) with three roles:

- `lsv <subcommand>`: CLI for the human.
- `lsv mcp`: stdio MCP server launched by Claude Code.
- `lsv hook`: `PreToolUse` hook for the shell tool (Claude Code `Bash`, plank `bash`).

No daemon, no own storage format for values: storage, encryption and locking
belong to the OS keyring. Alternatives considered: a daemon with thin clients
(rejected for v1: socket protocol and service lifecycle on three platforms),
and an MCP-only server (rejected: no shared references for the human's shell,
nothing for the hook to enforce).

## Invariants

1. **No read verb.** No CLI subcommand and no MCP tool returns secret material.
   The only way to view a value is the OS keyring's own UI.
2. **Resolve only at injection.** Secret values are resolved only by the
   `inject` module (through `Vault::resolve_for_injection`, which is `pub(crate)`); the only
   other caller of `Backend::resolve` is `fingerprint`, for its reserved HMAC
   key. `tests/invariants.rs` greps the crate for other call sites. The value goes straight into the
   child and its output is redacted before it is returned.
3. **No values in `lsv`'s own argv, files or logs.** The deliberate exception is
   `{{name}}` placeholders, which put the value in the *child's* argv; this is
   visible in the process table while the child runs and is documented.
4. **Metadata only.** `list` and `info` expose name, length, fingerprint,
   source and timestamps. The fingerprint is the first 8 hex chars of
   HMAC-SHA256(value) keyed with a per-installation key, so it cannot be used
   to brute-force short values offline without the key.

## Modules

| Module | Responsibility | Depends on |
|---|---|---|
| `backend` | `pub(crate) trait Backend { put, resolve, delete }`; `KeyringBackend` over the `keyring` crate; `MemoryBackend` for tests. The trait and `resolve` are `pub(crate)`. | keyring |
| `index` | Names and metadata in `index.json` under the platform config dir (`dirs`). Never values. Needed because `keyring` cannot enumerate entries on every platform. | serde, dirs |
| `fingerprint` | HMAC key stored as reserved keyring entry `__lsv_hmac_key__`, created on first use. | hmac, sha2, backend |
| `capture` | Clipboard to backend, then conditional clear. | arboard, backend, index |
| `generate` | Random value via `getrandom`, chosen length and alphabet, stored blind. | getrandom, backend, index |
| `import` | Hidden interactive prompt, entered twice; refuses without a TTY. CLI only. | rpassword, backend, index |
| `inject` | Parse references, resolve, spawn child, collect output through `redact`, enforce timeout and output cap. | backend, redact |
| `redact` | Streaming replacement of each value with `«redacted:name»`. Covers raw, base64 (standard and URL-safe, padded and unpadded, plus the base64 prefix of complete 3-byte groups so a secret followed by other bytes in a blob is still caught), percent-encoding (uppercase `%XX`), the JSON string-escaped form of the value, and hex (lower and upper). Correct across read-chunk boundaries; overlapping or touching matches merge into one span. Not covered: base64 of a secret at a non-zero offset inside a larger blob, and deliberate transformations. | none |
| `mcp` | Hand-written JSON-RPC 2.0 over stdio (initialize, tools/list, tools/call) with serde. | all core modules |
| `approve` | `Approver` trait consulted before secrets are injected. `LSV_TOUCH_ID` selects the mode: `off`, `mcp` (default, MCP `secret_run` only) or `all` (also `lsv run`). On macOS `TouchId` evaluates `LAPolicy::DeviceOwnerAuthentication` through LocalAuthentication (Touch ID, falling back to the login password) with the reason `run "<cmd>" with secrets <a, b>`: argv joined and cut to 80 characters, placeholders unexpanded, names sorted, never a value. It blocks on the reply block through a channel; denial or cancel fails with `Touch ID approval was denied or cancelled`. `Cached` skips the prompt for `LSV_TOUCH_ID_TTL` seconds after a success (default 300, max 3600, 0 asks every time; failures are not cached). Other platforms print a notice and allow. Asked only when secrets are referenced, after their names are known to exist. It cannot replace the Keychain password dialog: biometric access control needs the data-protection keychain, a Developer ID signature and entitlements, which a `cargo install` build lacks, and "Always Allow" is tied to the exact binary so it asks again after each rebuild. | block2, objc2, objc2-foundation, objc2-local-authentication (macOS only) |
| `hook` | Parse `PreToolUse` JSON, apply deny rules; the CLI blocks with exit 2 and the reason on stderr. `check_run` applies the same rules to an MCP `secret_run` argv. | none |
| `cli` | clap subcommands. | all core modules |

Keyring entries use service `llm-secret-vault` and the secret name as account.
Names match `^[a-z0-9][a-z0-9._-]{0,63}$`; names starting with `__lsv_` are
reserved.

## MCP tools

| Tool | Input | Output |
|---|---|---|
| `secret_list` | `prefix?` | array of metadata records |
| `secret_info` | `name` | one metadata record |
| `secret_capture` | `name`, `overwrite?=false`, `expect_prefix?`, `min_len?=8`, `allow_multiline?=false` | `stored <name>: <len> chars, fp <fp>, clipboard cleared` |
| `secret_generate` | `name`, `length?=32`, `alphabet?=alnum` (`alnum`, `hex`, `base64url`, `printable`), `overwrite?=false` | `stored <name>: <len> chars, fp <fp>` |
| `secret_run` | `argv[]`, `env?{VAR: name}`, `cwd?`, `timeout_s?=120` (1..=3600), `max_output_kb?=32` (1..=1024) | `exit_code`, `stdout`, `stderr` (redacted), `truncated`, `timed_out` |

Rotation is `secret_generate` or `secret_capture` with `overwrite: true`.
`delete` is CLI-only so the agent cannot destroy secrets. `secret_run` takes an
argv array rather than a shell string; `{{name}}` placeholders may appear in
any argv element. Unknown names fail before anything is spawned. Placeholders are substituted in
every argv element including the program; any `{{word}}` whose inner text is a
valid name is a reference (there is no escape syntax). At the timeout the whole
process group is killed, including background processes the command left
behind, and `run` waits up to the timeout plus one second. On Windows the
process-group kill does not exist, so a timeout kills the child but not its
grandchildren. The output cap also bounds the raw bytes fed into the redactor;
when output is truncated, pending bytes are dropped rather than flushed
unredacted.

The index re-reads `index.json` on every read and before each write, so a
running MCP server sees secrets added by the CLI. There is no file locking, so
concurrent writers in different processes can still race in a small window.
The MCP server negotiates protocol versions 2025-06-18, 2025-03-26 and
2024-11-05, and rejects JSON-RPC batches with -32600.

## CLI

```
lsv list [prefix]            lsv info <name>
lsv capture <name> [--overwrite] [--expect-prefix P] [--min-len N] [--allow-multiline]
lsv generate <name> [--length N] [--alphabet A] [--overwrite]
lsv import <name> [--overwrite]
lsv run [VAR=name ...] -- <argv...>
lsv delete <name>
lsv mcp                      lsv hook
lsv setup claude             # prints `claude mcp add` command and hook JSON
lsv setup plank              # prints ~/.plank/.mcp.json and hooks.json entries
```

`lsv run` from the human's shell redacts output too, so pasting terminal
output into a chat stays safe.

## Clipboard capture flow

1. Read clipboard text via `arboard`. Empty or non-text: error.
2. Validate: `expect_prefix`, `min_len`, no newline (`\r` counts like `\n`) and at most 4 KB unless
   `allow_multiline`. On failure store nothing; the error mentions only the
   observed length and which check failed, never content.
3. Existing name without `overwrite`: error.
4. Store in backend, update index (source `clipboard`, timestamps).
5. Re-read the clipboard; clear it only if it still equals the captured value.
   If the clipboard changed or clearing failed, the result says
   "clipboard NOT cleared".
6. Return length and fingerprint.

No display on Linux (no X11/Wayland): error suggesting `lsv import`.

## Guard hook

`lsv hook` reads the `PreToolUse` JSON from stdin, inspects
`tool_input.command` when `tool_name` is `bash` in any case, and blocks by
exiting 2 with a human-readable reason naming the rule on stderr when it
matches:

- `lsv run` whose child dumps the environment: `printenv`, `env` with no
  command (options only), bare `set`, `export`, `export -p`. Every `lsv run` in
  a command line is analysed, including `lsv` invoked by path.
- `lsv run` whose child pipeline references an injected variable (`$VAR`,
  `${VAR}`) or a `{{name}}` placeholder and either contains an encoder (`rev`,
  `base64`, `xxd`, `od`, `hexdump`) or ends in `echo`/`printf` writing to
  stdout. `printf %s "$T" | docker login --password-stdin` stays allowed.
  Echo or printf with redirection is allowed. Redirection and `tee` are not flagged: they usually save a command's output,
  not the secret, and flagging them caused too many false positives.
- Direct keyring reads bypassing `lsv`: `security find-generic-password` or
  `find-internet-password` with `-w`/`-g`, `secret-tool lookup`, `cmdkey /list`
  with `/pass`, PowerShell `Get-StoredCredential`.
- Reading `/proc/*/environ`.

MCP `secret_run` arguments never pass through the hook, so the server applies
the same rules itself through `hook::check_run(argv, vars)`, with the argv
joined by spaces as the shell text and the `env` keys as the injected
variables. It runs before anything is resolved; a match fails the call with
`ErrorKind::Denied` and the message `refused by llm-secret-vault: <reason>`,
and nothing is spawned. `lsv run` from the CLI is not checked this way; the
Bash hook covers agents that use it through the shell.

After the guard and the check that every referenced name exists, the
`approve` step runs: with `LSV_TOUCH_ID` at `mcp` (default) or `all` on macOS
it shows a Touch ID prompt naming the command and the secrets, never their
values, and a denial or cancel refuses the run with
`Touch ID approval was denied or cancelled`. A success is remembered for
`LSV_TOUCH_ID_TTL` seconds (default 300). For the MCP server set the variables
where it is registered, for example
`claude mcp add --scope user -e LSV_TOUCH_ID=all llm-secret-vault -- lsv mcp`
for Claude Code, or an `env` key on the server entry in plank's `.mcp.json`.

The hook is heuristic: quote stripping is approximate and it is a safety net,
not a parser.

Anything else is allowed (exit 0, no output). The hook never blocks on its own
errors: malformed input yields allow plus a stderr warning, so a bug in `lsv`
cannot wedge the user's session.

## Error handling

One `Error` struct carries a `Backtrace` and a `#[non_exhaustive]` `ErrorKind`
(invalid name, unknown name, name exists, invalid value, keyring, clipboard,
index, random, spawn, I/O, no TTY, usage). A timeout is not an error: `run`
returns normally with `timed_out: true` in its output. MCP maps errors to tool
results with `isError: true` and a message; messages never include values.
Keyring failures other than a missing entry get the hint "is the OS keyring
locked or unavailable (e.g. over SSH)?" appended to the OS message, which
covers the macOS-over-SSH case without inspecting platform error codes.

## Testing

- `redact`: chunk-boundary splits, every encoding, overlapping and prefix
  secrets, empty and one-byte inputs.
- Property test (proptest): with random values in `MemoryBackend` and a child
  that prints arbitrary mixes of values and noise, no `secret_run` response
  contains any stored value in any covered encoding.
- MCP: JSON-RPC request/response tests for every method and tool, including
  errors, each asserting no stored value appears in any response.
- Hook: table of allowed and denied commands.
- `inject`: env and placeholder substitution, unknown name fails pre-spawn,
  timeout, output cap.
- Invariant test: `resolve` has a single call site.
- CI: GitHub Actions on macOS, Ubuntu (headless gnome-keyring via
  dbus-run-session) and Windows; `cargo fmt --check`, `clippy -D warnings`,
  tests.

## Repository

Public GitHub repo `aovestdipaperino/llm-secret-vault`, MIT license, README
with quickstart and an honest threat model, this document, and a CI workflow
(including an MSRV job). The published package excludes `docs/superpowers/`,
`.github/` and `.superpowers/`. Cargo metadata: author Enzo Lombardi
<enzinol@gmail.com>, repository under `aovestdipaperino`.
