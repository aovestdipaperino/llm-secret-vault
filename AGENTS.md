# AGENTS.md

This file provides guidance to coding agents working with code in this repository.

## What this is

`llm-secret-vault` (binary `lsv`) lets LLM agents capture, generate and use OS-keyring secrets by name without any operation ever returning a value. One binary plays three roles: a human CLI (`lsv <subcommand>`), a stdio MCP server (`lsv mcp`), and a `PreToolUse` guard hook for the shell tool (`lsv hook`). The threat model is "prevent accidents", not "sandbox a hostile agent".

## Commands

CI runs these on Linux, macOS and Windows, plus `cargo check --all-targets` on MSRV 1.85 (edition 2024):

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings      # clippy::pedantic is on as warn, so CI fails on pedantic lints
cargo test
cargo test --test hook                          # one integration test file (cli, hook, inject, invariants, mcp, no_leak)
cargo test redact::tests::exhaustive_small      # one test by path
```

Ignored tests, run deliberately:

```bash
cargo test -- --ignored --skip touch_id_prompt              # real OS keyring (Linux needs an unlocked gnome-keyring under dbus-run-session)
cargo test --release -- --ignored exhaustive_large           # ~46M redactor runs, ~10 s in release
cargo test -- --ignored touch_id_prompt                      # shows a real Touch ID prompt; by hand only
cargo kani                                                   # Kani proofs in #[cfg(kani)] mod proofs blocks
java -cp tla2tools.jar tlc2.TLC -config Approval.cfg Approval.tla   # from formal/; Approval-gap.cfg fails by design
```

Linux builds need `libdbus-1-dev` and `pkg-config`.

## Architecture

`src/main.rs` is the clap CLI; everything else is the library in `src/lib.rs`. The flow for a run is: `mcp` or CLI builds a `RunRequest` → `hook::check_run` guard (MCP only) → `RunRequest::validate` and name-existence check → `approve` (Touch ID per `LSV_TOUCH_ID` / `LSV_TOUCH_ID_TTL`) → `inject` resolves values and spawns the child → output streams through `redact` → redacted text returned.

- `backend`: `pub(crate) trait Backend { put, resolve, delete }`, with `KeyringBackend` (service `llm-secret-vault`, account = secret name) and `MemoryBackend` for tests.
- `index`: `index.json` under `dirs::config_dir()/llm-secret-vault/` holding names and metadata only, re-read on every read and before every write (no file locking). Exists because the keyring cannot enumerate entries on every platform.
- `vault`: ties backend + index + `fingerprint` (HMAC-SHA256 keyed by the reserved keyring entry `__lsv_hmac_key__`). `Vault::in_memory()` is the test constructor used throughout `tests/`. `Meta::user` is an optional non-secret `SecretUser`; `store` keeps it on overwrite when given `None`, and `set_user` (CLI `lsv user` only) changes it alone.
- `capture`, `generate`, `import`: the three ways a value enters the vault (clipboard, random, hidden TTY prompt; `import` is CLI-only).
- `inject` + `redact`: spawning with env bindings and `{{name}}` argv placeholders, timeout with process-group kill, output cap that also bounds raw bytes fed to the redactor; streaming redaction across chunk boundaries covering raw, base64, percent, JSON-escaped and hex forms.
- `hook`: shell-text heuristics shared by `lsv hook` (exit 2 + reason on stderr) and MCP `secret_run` (`check_run`), since MCP argv never passes through the host's hook.
- `mcp`: hand-written JSON-RPC 2.0 over stdio, tools in `mcp/tools.rs`. `Server::new(vault, clipboard_factory)` is how tests drive it in-process. There is deliberately no delete tool.

## Invariants that tests enforce

- **No read verb**: no CLI subcommand or MCP tool may return a secret value. `tests/mcp.rs` and `tests/no_leak.rs` assert the secret never appears in responses.
- **Resolve only at injection**: `Vault::resolve_for_injection` may be mentioned only in `inject.rs` and `vault.rs`; `Backend::resolve` may be called only from `fingerprint.rs`, `vault.rs` and `src/backend/`. `tests/invariants.rs` greps the source for `resolve_for_injection`, `.resolve(` and `::resolve`, so don't introduce those strings elsewhere, even in comments.
- Error messages from validation mention lengths and which check failed, never content.
- Secret names match `^[a-z0-9][a-z0-9._-]{0,63}$`; the `__lsv_` prefix is reserved.

## Docs kept in sync with code

`docs/DESIGN.md` states it is kept in sync with the code, and `README.md` documents exact user-facing behavior (hook refusal messages, defaults and ranges like `timeout_s` 1..=3600, redaction coverage, known hook gaps). `formal/README.md` lists each Kani harness and exhaustive test by path. When changing behavior, error strings, defaults or test names, update the matching text in these files. `docs/superpowers/` holds historical specs and plans, not living docs.
