# Touch ID approval and `secret_run` guard: design

Date: 2026-10-13
Status: approved ("go")

## Problem

1. A manual test showed that MCP `secret_run` will happily run
   `sh -c 'printf %s $T | base64'`. Unquoted `$T` drops the value's spaces,
   so the base64 is of a near-copy the redactor cannot recognise, and the
   result reached the agent. The guard hook would have blocked the same
   child under `lsv run`, but it never sees MCP tool arguments.
2. The user wants a fingerprint check: an agent should not be able to use a
   secret without the human's finger on Touch ID.

Letting Touch ID replace the Keychain password dialog itself needs the
data-protection keychain and a biometric access control, which requires a
binary signed with a Developer ID and entitlements. A `cargo install` build
cannot have that, so it is out of scope and documented as such.

## Part A: guard `secret_run`

- New `pub fn hook::check_run(argv: &[String], vars: &[&str]) -> Decision`.
  It applies the same rules as an `lsv run` child: the `DIRECT_READS`
  patterns, environment dumps, encoders on a referenced variable or
  `{{name}}`, and `echo`/`printf` of one to stdout. It inspects the argv
  joined with spaces, so `["sh", "-c", "echo $T"]` is checked like the shell
  text `sh -c echo $T`.
- MCP `secret_run` calls it with the `env` keys as `vars` before resolving
  anything. On `Deny(reason)` the tool fails with a new
  `ErrorKind::Denied(String)` whose message is
  `refused by llm-secret-vault: <reason>`; nothing is spawned.
- `lsv run` from the CLI is not checked (the human runs it; the Bash hook
  covers agents that use it through the shell).

## Part B: Touch ID approval

- New module `approve`:
  - `pub trait Approver: Send + Sync + fmt::Debug { fn approve(&self, reason: &str) -> Result<()>; }`
  - `AllowAll`: always `Ok`.
  - `Cached<A>`: wraps an approver and skips it for `ttl` after a success.
    `ttl` zero means ask every time.
  - `TouchId` (macOS only): `LAContext` with policy
    `DeviceOwnerAuthentication` (Touch ID, falling back to the login
    password), localized reason = `reason`. Waits on the reply block
    through a channel. Failure or cancel gives `ErrorKind::Denied`.
  - `Mode { Off, Mcp, All }` parsed from `LSV_TOUCH_ID` (case-insensitive
    `off`, `mcp`, `all`; unset means `Mcp`; anything else is a usage error
    reported at startup).
  - `pub fn from_env(context: Context) -> Result<Box<dyn Approver>>` where
    `Context { Mcp, Cli }`. It returns `Cached<TouchId>` when the mode
    covers the context on macOS, otherwise `AllowAll`. TTL comes from
    `LSV_TOUCH_ID_TTL` in seconds, default 300, maximum 3600. On other
    platforms a covered context logs one stderr warning
    (`Touch ID approval is only available on macOS; continuing without it`)
    and returns `AllowAll`.
- `RunRequest::secret_names(&self) -> BTreeSet<SecretName>`: env names plus
  argv placeholders. `inject::run` uses it internally.
- Callers ask for approval only when `secret_names()` is non-empty, after
  validation and the guard, before `run`:
  - MCP `secret_run`: reason `run "<cmd>" with secrets <a, b>` (built by
    `pub fn approve::run_reason(request: &RunRequest) -> String`), where
    `<cmd>` is the argv joined
    with spaces and cut to 80 characters plus `…`. Placeholders appear
    unexpanded, so no value is ever in the prompt.
  - `lsv run`: same reason, only in mode `All`.
- `Server::with_approver(self, approver: Box<dyn Approver>) -> Self`; the
  default is `AllowAll` so existing tests are unchanged. `lsv mcp` installs
  `approve::from_env(Context::Mcp)?`.

## Testing

- Hook table tests for `check_run` (deny and allow).
- MCP tests: a guarded argv is refused with `isError` and nothing runs; a
  recording fake approver sees one reason naming the command and the
  secret names, and none of the values; a denying approver stops the run;
  a run with no secrets does not ask.
- `Cached` unit tests with a counting inner approver (ttl zero asks every
  time; a positive ttl asks once; a failure is not cached).
- `Mode` parsing tests.
- `TouchId` gets one `#[ignore]` test run by hand on a Mac.

## Docs

README gains a "Touch ID" section (modes, TTL, what the prompt shows, why
it cannot replace the Keychain password) and mentions the `secret_run`
guard in the hook section. DESIGN.md gets the same facts.
