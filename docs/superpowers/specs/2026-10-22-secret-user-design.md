# Per-secret user: design

Date: 2026-10-22
Status: approved ("sure")

## Problem

One host often has several accounts, each with its own password: a NAS with
`root` and `enzo`, a database with `admin` and `app`. Today the only hint an
agent gets is the secret's name, so it has to guess which of `nas-root` and
`nas-enzo` belongs to which login, and it has nowhere to read the login name
itself. The user wants each secret to carry the account it belongs to, so an
agent can pick the right secret and write the right username into the
command.

## Decisions

- The user is plain, non-secret metadata on a secret. Names stay the unique
  key: `nas-root` and `nas-enzo` are two secrets that happen to share a host.
  A compound `(entry, user)` key was considered and rejected because it
  changes keyring accounts, the index format, placeholders and the hook.
- Display only. The agent reads the user from `secret_list`/`secret_info` and
  types it into the argv. There is no `{{name.user}}` placeholder or env
  binding for it, so `inject`, `redact`, `hook` and `approve` do not change.
- Only the human can change the user of an existing secret, from the CLI, so
  the labels an agent picks by are labels the human set.

## Data model

- New `pub struct SecretUser(String)` in `src/name.rs`, next to `SecretName`,
  re-exported from `lib.rs`. Validation: 1 to 128 characters, no whitespace,
  no control characters, and neither `{{` nor `}}` (so it can never look like
  a placeholder if an agent pastes it into an argv). `root`,
  `admin@corp.com` and `CORP\enzo` are valid. Serde goes through `String`
  with `try_from`, like `SecretName`. A failure is a new
  `ErrorKind::InvalidUser(String)` whose message states which rule failed;
  the value is shown, since it is not secret.
- `Meta` gains `pub user: Option<SecretUser>` with
  `#[serde(default, skip_serializing_if = "Option::is_none")]`. An existing
  `index.json` without the field loads unchanged and `INDEX_VERSION` stays 1.
- The user lives only in the index, never in the keyring.

## Vault API

- `Vault::store` gains a `user: Option<&SecretUser>` parameter. On a new
  secret it sets `Meta::user` to that value. On an overwrite, `None` keeps
  the existing user and `Some` replaces it. All callers are updated; tests
  pass `None` where the user is irrelevant.
- New `Vault::set_user(&self, name, user: Option<&SecretUser>) -> Result<Meta>`
  sets or clears the user under the write lock, leaves the value, length,
  fingerprint and timestamps alone, and fails with `UnknownName` for a
  missing secret.
- `CaptureOptions`, `GenerateOptions` and `import` carry an optional user and
  pass it to `store`.

## CLI

- `lsv capture`, `lsv generate` and `lsv import` take `--user <user>`.
- New `lsv user <name> <user>` sets the user; `lsv user <name> --clear`
  removes it. Exactly one of the two is required.
- `lsv list` and `lsv info` show the user (`-` when unset).

## MCP

- `secret_capture` and `secret_generate` accept an optional `user` string,
  validated like the CLI.
- `secret_list` and `secret_info` include `"user"` in each record when set
  (omitted otherwise, through the serde attribute).
- The `secret_list` description says that several secrets can belong to one
  host with different users, and that the agent should pick by the `user`
  field and use it as the login in the command.
- No tool to change the user of an existing secret.

## Error handling

An invalid user fails the whole operation before anything is stored, so a
capture with a bad `--user` leaves the clipboard and the vault untouched.
`set_user` on an unknown name fails with the existing unknown-name error.

## Testing

- `name.rs`: valid and invalid users, including whitespace, control
  characters, `{{`, `}}`, empty and 129 characters.
- `vault.rs`: store with a user; overwrite with `None` keeps it; overwrite
  with `Some` replaces it; `set_user` sets and clears without changing the
  fingerprint; `set_user` on an unknown name fails.
- `index.rs`: an index file written without `user` loads, and saving it does
  not add a `user` key.
- `tests/mcp.rs`: `secret_capture` with `user` appears in `secret_list`; an
  invalid `user` is refused and nothing is stored.
- `tests/cli.rs`: argument parsing for `lsv user` (`--clear` and a value are
  mutually exclusive, one is required).

## Documentation

Update `README.md` (usage examples and the MCP tool table), `docs/DESIGN.md`
(invariant 4's metadata list, the MCP tool table, the CLI synopsis) and
`AGENTS.md` if the vault API description changes.
