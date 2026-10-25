# Per-secret host: design

Date: 2026-10-25
Status: approved ("go")

## Problem

A secret's user tells an agent which login it belongs to, but not where that
login works. For the NAS password the agent still has to guess or ask that the
NAS is at `192.168.1.8`. Each secret should be able to carry the host it is
used against, so the agent can write both the login and the address into the
command.

## Decisions

- The host is plain, non-secret metadata, like the user. Names stay the
  unique key.
- Free-form address: `192.168.1.8`, `nas.local`, `[fe80::1]:22` and
  `https://192.168.1.8:5001` are all valid. It is not parsed as a URL or host.
- Display only. No `{{name.host}}` placeholder; `inject`, `redact`, `hook`
  and `approve` do not change.
- Only the human changes the host of an existing secret, from the CLI.

## Data model

- `pub struct SecretHost(String)` in `src/name.rs`, re-exported from `lib.rs`.
  Rules, checked in this order and shared with `SecretUser` through a private
  helper: empty; longer than `MAX_HOST_LEN` = 255 characters; whitespace;
  control characters; invisible or bidirectional formatting characters; `{{`
  or `}}`. A failure is `ErrorKind::InvalidHost(rule)`, displayed as
  `invalid host: <rule>`, never echoing the value.
- `Meta` gains `host: Option<SecretHost>` after `user`, with
  `#[serde(default, skip_serializing_if = "Option::is_none")]`.
  `INDEX_VERSION` stays 1.

## Vault API

- New `pub struct Labels { pub user: Option<SecretUser>, pub host: Option<SecretHost> }`
  (`Default`, `Clone`, `Debug`, `PartialEq`, `Eq`) in `vault.rs`, re-exported.
- `Vault::store` replaces its `user: Option<&SecretUser>` parameter with
  `labels: &Labels`. On a new secret each field is set as given; on an
  overwrite each `None` field keeps the existing value and each `Some`
  replaces it. A user or host equal to the value is refused
  (`InvalidUser`/`InvalidHost("it equals the secret value")`) before anything
  is stored.
- New `Vault::set_host(&self, name, host: Option<&SecretHost>) -> Result<Meta>`,
  same contract as `set_user`.
- `CaptureOptions` and `GenerateOptions` replace `user` with `labels: Labels`;
  `import` takes `&Labels` instead of `Option<&SecretUser>`.

## CLI

- `--host <host>` on `capture`, `generate`, `import`.
- `lsv host <name> <host>` / `lsv host <name> --clear`, exactly one required.
- `lsv list` adds a HOST column after USER; `lsv info` adds `host:`. `-` when
  unset.

## MCP

- Optional `host` on `secret_capture` and `secret_generate`, validated before
  the clipboard is touched.
- `secret_list`/`secret_info` records include `"host"` when set.
- `secret_list` description: use `host` as the address to connect to and
  `user` as the login.
- No tool to change the host of an existing secret.

## Testing

Mirror the user tests: host validation (255 accepted, 256 refused, each
rule), JSON round trip; store with host, overwrite keeps/replaces, host equal
to value refused; `set_host` sets/clears without touching the rest, unknown
name fails; legacy index without `host` loads and saves without it; MCP
capture with host shows in `secret_list`, invalid host stores nothing and
leaves the clipboard; CLI `lsv host` argument parsing.

## Documentation

README (usage, MCP table), `docs/DESIGN.md` (metadata list, tool table, CLI
synopsis), `AGENTS.md` (vault line). Release 0.3.0.
