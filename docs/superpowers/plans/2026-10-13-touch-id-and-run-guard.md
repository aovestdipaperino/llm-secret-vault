# Touch ID approval and `secret_run` guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refuse leaky MCP `secret_run` commands and require Touch ID before secrets are injected.

**Architecture:** `hook::check_run` reuses the `lsv run` child rules for MCP argv. A new `approve` module defines an `Approver` trait with `AllowAll`, `Cached` and a macOS `TouchId` implementation over LocalAuthentication; the MCP server and `lsv run` ask it before calling `inject::run`.

**Tech Stack:** Rust 2024, MSRV 1.85, `objc2-local-authentication` 0.3 / `objc2-foundation` 0.3 / `block2` 0.6 (macOS only).

Spec: `docs/superpowers/specs/2026-10-13-touch-id-and-run-guard-design.md`.

## Global Constraints

- Edition 2024, `rust-version = "1.85"`; must build with Rust 1.85.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (pedantic is on) and `cargo test` pass on macOS; non-macOS code paths must compile (`cfg(target_os = "macos")` gating, no macOS deps on other targets).
- No secret value may appear in any error, prompt reason, log or MCP response.
- `resolve_for_injection` stays referenced only from `src/inject.rs` and `src/vault.rs` (tests/invariants.rs).
- Public items get doc comments; first sentence under 15 words; `# Errors` sections on fallible pub fns.
- Error messages for the new variant: `refused by llm-secret-vault: <reason>` for the guard, `Touch ID approval was denied or cancelled` for approval failures (both via `ErrorKind::Denied(String)`, Display prints the payload).
- `LSV_TOUCH_ID`: `off` | `mcp` | `all`, case-insensitive, unset = `mcp`. `LSV_TOUCH_ID_TTL`: seconds, default 300, valid 0..=3600.
- Prompt reason format: `run "<cmd>" with secrets <a, b>`; `<cmd>` = argv joined by single spaces, cut to 80 chars then `…` appended when longer; names sorted, joined by `, `.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

---

### Task 1: Guard MCP `secret_run` with the hook rules

**Files:**
- Modify: `src/error.rs` (add `ErrorKind::Denied(String)`)
- Modify: `src/hook.rs` (add `check_run`)
- Modify: `src/mcp/tools.rs` (call it in `secret_run`)
- Test: `tests/hook.rs`, `tests/mcp.rs`

**Interfaces:**
- Produces: `pub fn check_run(argv: &[String], vars: &[&str]) -> Decision` in `hook`; `ErrorKind::Denied(String)`.

- [ ] **Step 1: Failing tests.** In `tests/hook.rs` add a `check_run` table:
  - deny: `["sh","-c","printf %s $T | base64"]` vars `["T"]`; `["sh","-c","echo $T"]` vars `["T"]`; `["printenv"]` vars `["T"]`; `["env"]` vars `["T"]`; `["echo","{{tok}}"]` vars `[]`; `["security","find-generic-password","-s","x","-w"]` vars `[]`; `["sh","-c","echo ${T} | xxd"]` vars `["T"]`.
  - allow: `["curl","-H","Authorization: Bearer {{tok}}","https://x"]`; `["sh","-c","printf %s \"$T\" | docker login --password-stdin"]` vars `["T"]`; `["sshpass","-e","ssh","root@nas"]` vars `["PW"]`; `["sh","-c","echo $T > f"]` vars `["T"]`; `["ls"]` vars `[]`.
  In `tests/mcp.rs` add a test that calls `secret_run` with `argv ["sh","-c","printf %s $T | base64"]`, `env {"T": <stored name>}` and asserts `isError: true`, the text starts with `refused by llm-secret-vault: `, and no stored value appears in the response (follow the file's existing helpers for storing secrets and calling tools).
- [ ] **Step 2: Run, see them fail** (`cargo test --test hook --test mcp`).
- [ ] **Step 3: Implement.**
  - `ErrorKind::Denied(String)` with `#[error("{0}")]` (match the existing style in `error.rs`).
  - In `hook.rs`:
    ```rust
    /// Decides whether an MCP `secret_run` argv may run.
    ///
    /// Applies the `lsv run` child rules to `argv` joined with spaces, with
    /// `vars` as the injected environment variable names.
    #[must_use]
    pub fn check_run(argv: &[String], vars: &[&str]) -> Decision {
        let command = argv.join(" ");
        for (pattern, reason) in DIRECT_READS.iter() {
            if pattern.is_match(&command) {
                return Decision::Deny((*reason).to_owned());
            }
        }
        match check_child(&command, vars) {
            Some(reason) => Decision::Deny(reason),
            None => Decision::Allow,
        }
    }
    ```
  - In `tools.rs` `secret_run`, after parsing args and before building/running the request:
    ```rust
    let vars: Vec<&str> = args.env.keys().map(String::as_str).collect();
    if let Decision::Deny(reason) = check_run(&args.argv, &vars) {
        return Err(Error::new(ErrorKind::Denied(format!(
            "refused by llm-secret-vault: {reason}"
        ))));
    }
    ```
    (Borrow before `args.argv` is moved into `RunRequest::new`.)
- [ ] **Step 4: Tests pass; fmt and clippy clean.**
- [ ] **Step 5: Commit** `feat: refuse leaky secret_run commands with the hook rules`.

### Task 2: Approval plumbing (`approve` module, no FFI)

**Files:**
- Create: `src/approve.rs`
- Modify: `src/lib.rs` (`pub mod approve;`), `src/inject.rs` (`secret_names`), `src/mcp/mod.rs` and `src/mcp/tools.rs` (approver field and call), `src/main.rs` (`lsv mcp` and `lsv run` wiring)
- Test: unit tests in `src/approve.rs`, `tests/mcp.rs`

**Interfaces:**
- Consumes: `ErrorKind::Denied(String)` (Task 1).
- Produces:
  - `pub trait Approver: Send + Sync + fmt::Debug { fn approve(&self, reason: &str) -> Result<()>; }`
  - `pub struct AllowAll;` (Debug, Default, Clone, Copy)
  - `pub struct Cached<A> { .. }` with `pub fn new(inner: A, ttl: Duration) -> Self`, implementing `Approver` for `A: Approver`. Uses `Mutex<Option<Instant>>`; a success at time t lets calls before t+ttl skip `inner`; `ttl` zero always calls `inner`; failures are never cached.
  - `pub enum Mode { Off, Mcp, All }` with `pub fn parse(value: Option<&str>) -> Result<Mode>` (None → `Mcp`; unknown → `ErrorKind::Usage("LSV_TOUCH_ID must be off, mcp or all, got `<v>`")`).
  - `pub fn parse_ttl(value: Option<&str>) -> Result<Duration>` (None → 300 s; 0..=3600; else usage error `LSV_TOUCH_ID_TTL must be 0..=3600 seconds`).
  - `pub enum Context { Mcp, Cli }` and `impl Mode { pub fn covers(self, context: Context) -> bool }` (`Off` none, `Mcp` only Mcp, `All` both).
  - `pub fn from_env(context: Context) -> Result<Box<dyn Approver>>`: reads both env vars; if `covers` → `platform_approver(ttl)`; else `AllowAll`. In this task `platform_approver` is a private fn that, on every platform, prints once to stderr `lsv: Touch ID approval is only available on macOS; continuing without it` and returns `AllowAll` (Task 3 replaces the macOS branch).
  - `pub fn run_reason(request: &RunRequest) -> String` per the Global Constraints format.
  - `RunRequest::secret_names(&self) -> BTreeSet<SecretName>` (pub, `#[must_use]`); refactor `inject::run` to use it.
  - `Server::with_approver(self, approver: Box<dyn Approver>) -> Self` (`#[must_use]`); default field value `Box::new(AllowAll)`. `tools::call` gains an `approver: &dyn Approver` parameter.
- [ ] **Step 1: Failing tests.**
  - `approve.rs` unit tests: a `Counting` test approver (AtomicUsize, optional failure) wrapped in `Cached`: ttl 0 → 3 calls ask 3 times; ttl 60 s → 3 calls ask once; a failing inner returns `Err` each call and is asked each time. `Mode::parse` for None, `"OFF"`, `"mcp"`, `"All"`, `"yes"` (error). `parse_ttl` for None (300 s), `"0"`, `"3600"`, `"3601"` (error), `"abc"` (error). `covers` matrix. `run_reason` for `["sh","-c","echo hi"]` with env T→`tok` and a placeholder `{{api}}` in argv → `run "sh -c echo hi {{api}}" with secrets api, tok`; and a 200-char argv is cut to 80 chars plus `…`.
  - `tests/mcp.rs`: a `Recording` approver (Arc<Mutex<Vec<String>>>, configurable allow/deny) installed with `with_approver`:
    - `secret_run` with a stored secret in `env` records exactly one reason containing the command and the secret name and not the value; the run succeeds.
    - with deny, the tool result is `isError: true` with text `Touch ID approval was denied or cancelled` and the child did not run (use a command that would create a marker file in a tempdir and assert it is absent).
    - `secret_run` with no env and no placeholders records nothing.
- [ ] **Step 2: Run, see them fail.**
- [ ] **Step 3: Implement** as specified above. In `tools.rs` `secret_run`, order is: parse → bounds → guard (Task 1) → build request → `if !request.secret_names().is_empty() { approver.approve(&approve::run_reason(&request))?; }` → `run`. `main.rs`: `lsv mcp` uses `Server::with_system_clipboard(Vault::open()?).with_approver(approve::from_env(approve::Context::Mcp)?)`; `run_main` builds `approve::from_env(Context::Cli)?` and applies the same non-empty check before `run`.
- [ ] **Step 4: Tests pass; fmt and clippy clean; `cargo test --test invariants` passes.**
- [ ] **Step 5: Commit** `feat: approval hook before secrets are injected`.

### Task 3: macOS Touch ID approver and docs

**Files:**
- Modify: `Cargo.toml` (macOS-only deps), `src/approve.rs` (`TouchId`, macOS branch of `platform_approver`), `README.md`, `docs/DESIGN.md`
- Test: `#[ignore]` manual test in `src/approve.rs`

**Interfaces:**
- Consumes: `Approver`, `Cached`, `platform_approver` from Task 2.
- Produces: `#[cfg(target_os = "macos")] pub struct TouchId;` implementing `Approver`.

- [ ] **Step 1: Dependencies.**
  ```toml
  [target.'cfg(target_os = "macos")'.dependencies]
  block2 = "0.6"
  objc2 = "0.6"
  objc2-foundation = { version = "0.3", default-features = false, features = ["std", "NSString", "NSError"] }
  objc2-local-authentication = { version = "0.3", default-features = false, features = ["std", "block2", "LAContext", "LAError"] }
  ```
  Adjust feature names if the compiler says they differ; keep the set minimal.
- [ ] **Step 2: Implement `TouchId::approve(reason)`.**
  - Create `LAContext::new()`.
  - Policy `LAPolicy::DeviceOwnerAuthentication` (Touch ID or the login password).
  - Call `evaluatePolicy_localizedReason_reply` with `NSString::from_str(reason)` and a `block2::RcBlock` reply `move |success: Bool, _error: *mut NSError|` that sends `success.as_bool()` on a `std::sync::mpsc::Sender` (wrap the sender in a `Mutex` or clone per call if the block must be `Fn`).
  - Block on `recv()`; `true` → `Ok(())`; `false` or a disconnected channel → `Err(ErrorKind::Denied("Touch ID approval was denied or cancelled"))`.
  - Each `unsafe` block gets a `// SAFETY:` comment. Keep the FFI in one private function.
  - `platform_approver(ttl)` on macOS returns `Box::new(Cached::new(TouchId, ttl))`; other platforms keep the warning + `AllowAll`.
- [ ] **Step 3: Manual test.**
  ```rust
  #[cfg(target_os = "macos")]
  #[test]
  #[ignore = "shows a real Touch ID prompt; run by hand"]
  fn touch_id_prompt() {
      TouchId.approve("test llm-secret-vault Touch ID").unwrap();
  }
  ```
  The implementer only checks it compiles (`cargo test --no-run`); the controller runs it by hand.
- [ ] **Step 4: Docs.**
  - README: new `## Touch ID` section after the guard hook section. Cover:
    - the modes and their default;
    - the TTL;
    - the prompt text;
    - that cancelling refuses the run;
    - that it is macOS only;
    - why it cannot replace the Keychain password dialog: that needs a Developer ID–signed binary with entitlements, and "Always Allow" in Keychain is tied to the exact binary, so it asks again after each rebuild.

    Also mention in the guard hook section that MCP `secret_run` argv is now checked by the same rules. Remove the sentence saying it is not.
  - DESIGN.md: the same facts in the module table (`approve`) and the guard section.
  - Also show how to set `LSV_TOUCH_ID` for the MCP server:
    - Claude: `claude mcp add --scope user -e LSV_TOUCH_ID=all llm-secret-vault -- lsv mcp`
    - plank: an `env` key in `.mcp.json`.
- [ ] **Step 5: fmt, clippy, tests pass; commit** `feat: Touch ID approval on macOS`.
