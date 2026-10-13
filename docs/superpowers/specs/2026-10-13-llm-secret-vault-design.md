# llm-secret-vault: design

Date: 2026-10-13
Status: approved for planning

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
- `lsv hook`: Claude Code `PreToolUse` hook for the `Bash` tool.

No daemon, no own storage format for values: storage, encryption and locking
belong to the OS keyring. Alternatives considered: a daemon with thin clients
(rejected for v1: socket protocol and service lifecycle on three platforms),
and an MCP-only server (rejected: no shared references for the human's shell,
nothing for the hook to enforce).

## Invariants

1. **No read verb.** No CLI subcommand and no MCP tool returns secret material.
   The only way to view a value is the OS keyring's own UI.
2. **Resolve only at injection.** Only the `inject` module calls
   `Backend::resolve` (enforced with `pub(crate)` visibility and a test that
   greps the crate for other call sites). The value goes straight into the
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
| `backend` | `trait Backend { put, delete, exists, resolve }`; `KeyringBackend` over the `keyring` crate; `MemoryBackend` for tests. `resolve` is `pub(crate)`. | keyring |
| `index` | Names and metadata in `index.json` under the platform config dir (`dirs`). Never values. Needed because `keyring` cannot enumerate entries on every platform. | serde, dirs |
| `fingerprint` | HMAC key stored as reserved keyring entry `__lsv_hmac_key__`, created on first use. | hmac, sha2, backend |
| `capture` | Clipboard to backend, then conditional clear. | arboard, backend, index |
| `generate` | Random value via `getrandom`, chosen length and alphabet, stored blind. | getrandom, backend, index |
| `import` | Hidden interactive prompt, entered twice; refuses without a TTY. CLI only. | rpassword, backend, index |
| `inject` | Parse references, resolve, spawn child, collect output through `redact`, enforce timeout and output cap. | backend, redact |
| `redact` | Streaming replacement of each value and its base64 (std and url-safe), percent-encoded and hex forms with `«redacted:name»`, correct across read-chunk boundaries and for overlapping secrets. | none |
| `mcp` | Hand-written JSON-RPC 2.0 over stdio (initialize, tools/list, tools/call) with serde. | all core modules |
| `hook` | Parse Claude Code `PreToolUse` JSON, apply deny rules, emit decision JSON. | none |
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
| `secret_run` | `argv[]`, `env?{VAR: name}`, `cwd?`, `timeout_s?=120`, `max_output_kb?=32` | `exit_code`, `stdout`, `stderr` (redacted), `truncated`, `timed_out` |

Rotation is `secret_generate` or `secret_capture` with `overwrite: true`.
`delete` is CLI-only so the agent cannot destroy secrets. `secret_run` takes an
argv array rather than a shell string; `{{name}}` placeholders may appear in
any argv element. Unknown names fail before anything is spawned.

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
```

`lsv run` from the human's shell redacts output too, so pasting terminal
output into a chat stays safe.

## Clipboard capture flow

1. Read clipboard text via `arboard`. Empty or non-text: error.
2. Validate: `expect_prefix`, `min_len`, no newline and at most 4 KB unless
   `allow_multiline`. On failure store nothing; the error mentions only the
   observed length and which check failed, never content.
3. Existing name without `overwrite`: error.
4. Store in backend, update index (source `clipboard`, timestamps).
5. Re-read the clipboard; clear it only if it still equals the captured value.
6. Return length and fingerprint.

No display on Linux (no X11/Wayland): error suggesting `lsv import`.

## Guard hook

`lsv hook` reads the `PreToolUse` JSON from stdin, inspects
`tool_input.command` for `Bash`, and returns a deny decision with a
human-readable reason naming the rule when it matches:

- `lsv run` whose child references an injected variable through an output or
  encoding command: `echo`, `printf`, `printenv`, `env`, `set`, `export -p`,
  `rev`, `base64`, `xxd`, `od`, `hexdump`, redirection `>`/`>>`, `tee`.
- Direct keyring reads bypassing `lsv`: `security find-generic-password` or
  `find-internet-password` with `-w`/`-g`, `secret-tool lookup`, `cmdkey /list`
  with `/pass`, PowerShell `Get-StoredCredential`.
- Reading `/proc/*/environ`.

Anything else is allowed (exit 0, no output). The hook never blocks on its own
errors: malformed input yields allow plus a stderr warning, so a bug in `lsv`
cannot wedge the user's session.

## Error handling

One `Error` enum (`thiserror`) with variants for keyring unavailable or
locked, unknown name, name exists, invalid name, clipboard unavailable,
validation failed, spawn failed, timeout. MCP maps them to tool results with
`isError: true` and a message; messages never include values. Keyring locked
(e.g. macOS over SSH) is reported as such with a hint.

## Testing

- `redact`: chunk-boundary splits, every encoding, overlapping and prefix
  secrets, empty and one-byte inputs.
- Property test (proptest): with random values in `MemoryBackend` and a child
  that prints arbitrary mixes of values and noise, no `secret_run` response
  contains any stored value in any covered encoding.
- MCP: golden JSON-RPC transcripts for every tool, including errors.
- Hook: table of allowed and denied commands.
- `inject`: env and placeholder substitution, unknown name fails pre-spawn,
  timeout, output cap.
- Invariant test: `resolve` has a single call site.
- CI: GitHub Actions on macOS, Ubuntu (headless gnome-keyring via
  dbus-run-session) and Windows; `cargo fmt --check`, `clippy -D warnings`,
  tests.

## Repository

Public GitHub repo `aovestdipaperino/llm-secret-vault`, MIT license, README
with quickstart and an honest threat model, `docs/DESIGN.md` derived from this
spec, CI workflow. Cargo metadata: author Enzo Lombardi
<enzinol@gmail.com>, repository under `aovestdipaperino`.
