# Per-secret user Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let each secret carry an optional, non-secret user (login) so an agent can pick the right secret among several for one host.

**Architecture:** A validated `SecretUser` newtype lives next to `SecretName`. `Meta` gains `user: Option<SecretUser>`, stored only in the index. `Vault::store` takes the user (overwrite with `None` keeps the old one) and `Vault::set_user` changes it alone. Capture, generate and import options carry it; the CLI adds `--user` and `lsv user`; MCP capture and generate accept `user` and list/info show it.

**Tech Stack:** Rust 2024, MSRV 1.85, serde, clap derive.

Spec: `docs/superpowers/specs/2026-10-22-secret-user-design.md`.

## Global Constraints

- Edition 2024, `rust-version = "1.85"`; must build with Rust 1.85.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` (pedantic is on) and `cargo test` pass.
- User validation: 1 to 128 characters, no whitespace, no control characters, neither `{{` nor `}}`.
- Error message for a bad user: `invalid user: <rule>`; the value is never echoed.
- `index.json` without a `user` key must still load; a secret without a user serializes without a `user` key; `INDEX_VERSION` stays 1.
- Overwrite with no user keeps the existing user; overwrite with a user replaces it.
- No MCP tool changes the user of an existing secret. No `{{name.user}}` placeholder; `inject`, `redact`, `hook` and `approve` are not touched.
- An invalid user fails before anything is stored and before the clipboard is opened.
- `resolve_for_injection` stays referenced only from `src/inject.rs` and `src/vault.rs`; do not write `.resolve(` or `::resolve` in new code or comments outside the allowed files (`tests/invariants.rs` greps for them).
- Public items get doc comments; fallible pub fns get `# Errors`; lock-taking ones get `# Panics`.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

---

### Task 1: `SecretUser` type and `InvalidUser` error

**Files:**
- Modify: `src/error.rs`
- Modify: `src/name.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `pub struct SecretUser` with `SecretUser::new(impl AsRef<str>) -> Result<SecretUser>`, `as_str(&self) -> &str`, `Display`, serde via `String`; `pub const MAX_USER_LEN: usize = 128`; `ErrorKind::InvalidUser(String)`; re-export `llm_secret_vault::SecretUser`.

- [ ] **Step 1: Write the failing tests** at the end of `mod tests` in `src/name.rs`:

```rust
    #[test]
    fn accepts_valid_users() {
        for user in [
            "root",
            "admin@corp.com",
            "CORP\\enzo",
            "ünï",
            "a{b}c",
            &"x".repeat(128),
        ] {
            assert_eq!(SecretUser::new(user).unwrap().as_str(), user);
        }
    }

    #[test]
    fn rejects_invalid_users() {
        for (user, rule) in [
            ("", "it is empty"),
            (&"x".repeat(129) as &str, "it is longer than 128 characters"),
            ("two words", "it contains whitespace"),
            ("tab\there", "it contains whitespace"),
            ("bell\u{7}", "it contains control characters"),
            ("{{root}}", "it contains `{{` or `}}`"),
            ("root}}", "it contains `{{` or `}}`"),
        ] {
            let err = SecretUser::new(user).unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::InvalidUser(rule.to_owned()), "{user:?}");
            assert_eq!(err.to_string(), format!("invalid user: {rule}"));
        }
    }

    #[test]
    fn user_round_trips_through_json() {
        let user = SecretUser::new("root").unwrap();
        let json = serde_json::to_string(&user).unwrap();
        assert_eq!(json, "\"root\"");
        assert_eq!(serde_json::from_str::<SecretUser>(&json).unwrap(), user);
        assert!(serde_json::from_str::<SecretUser>("\"two words\"").is_err());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --lib name::tests`
Expected: compile error, `cannot find type SecretUser`.

- [ ] **Step 3: Add the error variant.** In `src/error.rs`, add after `InvalidName(String)` in `ErrorKind`:

```rust
    /// A secret's user does not match the allowed pattern; the payload names the rule.
    InvalidUser(String),
```

and in `Display`, after the `InvalidName` arm:

```rust
            ErrorKind::InvalidUser(why) => write!(f, "invalid user: {why}"),
```

- [ ] **Step 4: Add the type.** In `src/name.rs`, after the `impl AsRef<str> for SecretName` block (before `#[cfg(test)]`):

```rust
/// Maximum length of a secret's user, in characters.
pub const MAX_USER_LEN: usize = 128;

/// The account a secret belongs to, such as `root` or `admin@corp.com`.
///
/// Users are 1-128 characters without whitespace or control characters and
/// never contain `{{` or `}}`. A user is not secret.
///
/// # Examples
///
/// ```
/// use llm_secret_vault::SecretUser;
///
/// assert!(SecretUser::new("root").is_ok());
/// assert!(SecretUser::new("two words").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretUser(String);

impl SecretUser {
    /// Validates `user` and wraps it.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidUser`] naming the rule `user` breaks.
    pub fn new(user: impl AsRef<str>) -> Result<Self> {
        let user = user.as_ref();
        let broken = if user.is_empty() {
            Some("it is empty")
        } else if user.chars().count() > MAX_USER_LEN {
            Some("it is longer than 128 characters")
        } else if user.chars().any(char::is_whitespace) {
            Some("it contains whitespace")
        } else if user.chars().any(char::is_control) {
            Some("it contains control characters")
        } else if user.contains("{{") || user.contains("}}") {
            Some("it contains `{{` or `}}`")
        } else {
            None
        };
        match broken {
            None => Ok(Self(user.to_owned())),
            Some(rule) => Err(Error::new(ErrorKind::InvalidUser(rule.to_owned()))),
        }
    }

    /// Returns the user as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SecretUser {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<SecretUser> for String {
    fn from(user: SecretUser) -> Self {
        user.0
    }
}

impl fmt::Display for SecretUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0)
    }
}
```

Note: `\t` and `\n` are whitespace, so they hit the whitespace rule first; `\u{7}` is the control-character case.

- [ ] **Step 5: Re-export.** In `src/lib.rs` change `pub use name::SecretName;` to:

```rust
pub use name::{SecretName, SecretUser};
```

- [ ] **Step 6: Run tests**

Run: `cargo test --lib name::tests && cargo test --doc SecretUser`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/error.rs src/name.rs src/lib.rs
git commit -m "feat: add SecretUser, a validated non-secret account name

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `Meta::user`, `Vault::store` user parameter, `Vault::set_user`

**Files:**
- Modify: `src/vault.rs`
- Modify: `src/index.rs` (test helper and a new test)
- Modify (mechanical, add `None`): `src/capture.rs`, `src/generate.rs`, `src/import.rs`, `tests/inject.rs`, `tests/no_leak.rs`

**Interfaces:**
- Consumes: `SecretUser` from Task 1.
- Produces: `Meta { name, user: Option<SecretUser>, len, fingerprint, source, created, rotated }`; `Vault::store(&self, name: &SecretName, value: &str, source: Source, overwrite: bool, user: Option<&SecretUser>) -> Result<Meta>`; `Vault::set_user(&self, name: &SecretName, user: Option<&SecretUser>) -> Result<Meta>`.

- [ ] **Step 1: Write the failing vault tests** in `src/vault.rs` `mod tests`, after the `name` helper add:

```rust
    fn user(s: &str) -> SecretUser {
        SecretUser::new(s).unwrap()
    }
```

and at the end of the module:

```rust
    #[test]
    fn overwrite_keeps_or_replaces_user() {
        let vault = Vault::in_memory();
        let k = name("nas-root");
        let stored = vault
            .store(&k, "first-value", Source::Imported, false, Some(&user("root")))
            .unwrap();
        assert_eq!(stored.user, Some(user("root")));
        let kept = vault
            .store(&k, "second-value", Source::Generated, true, None)
            .unwrap();
        assert_eq!(kept.user, Some(user("root")));
        let replaced = vault
            .store(&k, "third-value", Source::Generated, true, Some(&user("admin")))
            .unwrap();
        assert_eq!(replaced.user, Some(user("admin")));
        assert_eq!(vault.info(&k).unwrap().user, Some(user("admin")));
    }

    #[test]
    fn set_user_changes_only_the_user() {
        let vault = Vault::in_memory();
        let k = name("nas-enzo");
        let before = vault
            .store(&k, "value-123", Source::Imported, false, None)
            .unwrap();
        assert_eq!(before.user, None);
        let after = vault.set_user(&k, Some(&user("enzo"))).unwrap();
        assert_eq!(
            after,
            Meta {
                user: Some(user("enzo")),
                ..before.clone()
            }
        );
        assert_eq!(vault.info(&k).unwrap(), after);
        assert_eq!(vault.set_user(&k, None).unwrap(), before);
        assert_eq!(
            vault.resolve_for_injection(&k).unwrap().as_str(),
            "value-123"
        );
    }

    #[test]
    fn set_user_of_unknown_name_fails() {
        let vault = Vault::in_memory();
        let err = vault.set_user(&name("nope"), Some(&user("root"))).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::UnknownName(_)));
    }
```

- [ ] **Step 2: Write the failing index test** in `src/index.rs` `mod tests`. First add `user: None,` after `name: SecretName::new(name).unwrap(),` in the `meta` helper. Then add:

```rust
    #[test]
    fn loads_entries_written_without_user_and_keeps_users() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.json");
        fs::write(
            &path,
            r#"{"version":1,"secrets":{"a":{"name":"a","len":12,"fingerprint":"deadbeef","source":"generated","created":1,"rotated":null}}}"#,
        )
        .unwrap();
        let index = Index::load(&path).unwrap();
        assert_eq!(index.list(None), vec![meta("a")]);
        index.upsert(meta("b")).unwrap();
        assert!(!fs::read_to_string(&path).unwrap().contains("\"user\""));

        let with_user = Meta {
            user: Some(crate::name::SecretUser::new("root").unwrap()),
            ..meta("c")
        };
        index.upsert(with_user.clone()).unwrap();
        let reloaded = Index::load(&path).unwrap();
        assert_eq!(
            reloaded.get(&SecretName::new("c").unwrap()),
            Some(with_user)
        );
    }
```

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test --lib vault::tests index::tests`
Expected: compile errors (`no field user on Meta`, `store` takes 4 arguments, `no method set_user`).

- [ ] **Step 4: Add the field.** In `src/vault.rs`, change `use crate::name::SecretName;` to `use crate::name::{SecretName, SecretUser};` and add to `Meta` right after `pub name: SecretName,`:

```rust
    /// Account the secret belongs to, such as `root`; not secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<SecretUser>,
```

- [ ] **Step 5: Thread the user through `store`.** Change the signature and doc of `Vault::store`:

```rust
    /// Stores `value` under `name` and returns its metadata.
    ///
    /// On an overwrite, `user` replaces the existing user when given and keeps
    /// it when `None`. The fingerprint is computed before anything is stored.
    /// If the index update fails after the keyring write succeeded, the error
    /// is returned and the keyring keeps the new value (an overwritten old
    /// value is not restored).
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::InvalidValue`] if the value length is out of range,
    /// [`ErrorKind::NameExists`] if the name exists and `overwrite` is false,
    /// [`ErrorKind::Keyring`] or [`ErrorKind::Index`] if storage fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal write lock is poisoned.
    pub fn store(
        &self,
        name: &SecretName,
        value: &str,
        source: Source,
        overwrite: bool,
        user: Option<&SecretUser>,
    ) -> Result<Meta> {
```

and replace the `let meta = Meta { ... };` block with:

```rust
        let user = user
            .cloned()
            .or_else(|| existing.as_ref().and_then(|m| m.user.clone()));
        let meta = Meta {
            name: name.clone(),
            user,
            len: value.chars().count(),
            fingerprint: fp,
            source,
            created: existing.as_ref().map_or(now, |m| m.created),
            rotated: existing.map(|_| now),
        };
```

- [ ] **Step 6: Add `set_user`** after `store` in `impl Vault`:

```rust
    /// Sets or clears the user of an existing secret, leaving its value alone.
    ///
    /// Length, fingerprint, source and timestamps are unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::UnknownName`] if no such secret exists, or
    /// [`ErrorKind::Index`] if the index cannot be written.
    ///
    /// # Panics
    ///
    /// Panics if the internal write lock is poisoned.
    pub fn set_user(&self, name: &SecretName, user: Option<&SecretUser>) -> Result<Meta> {
        let _guard = self.inner.write_lock.lock().expect("write lock poisoned");
        let mut meta = self.inner.index.get(name).ok_or_else(|| unknown(name))?;
        meta.user = user.cloned();
        self.inner.index.upsert(meta.clone())?;
        Ok(meta)
    }
```

- [ ] **Step 7: Update every other `store` call** by adding `None` as the new last argument. The compiler lists each one (`error[E0061]: this method takes 5 arguments but 4 arguments were supplied`). They are:
  - `src/capture.rs`: in `capture`, `vault.store(name, &value, Source::Clipboard, options.overwrite, None)?`, and the `probe` store in test `stores_and_clears` (add `None,` after `false,`).
  - `src/generate.rs`: `vault.store(name, &value, Source::Generated, options.overwrite, None)`.
  - `src/import.rs`: `vault.store(name, &first, Source::Imported, overwrite, None)`.
  - `src/vault.rs` existing tests: every `.store(..., false)` / `.store(..., true)` gets `, None`, including the closure in `value_length_bounds_are_in_bytes`: `|v: &str| vault.store(&name("k"), v, Source::Imported, true, None)`.
  - `tests/inject.rs`: the four calls at the `vault()` helper (add `None,` after `false,`), `periodic`, and both `tool` stores.
  - `tests/no_leak.rs`: `vault.store(&name, &value, Source::Generated, false, None).unwrap();`

Task 3 replaces the `None` in `capture`, `generate` and `import` with the real user.

- [ ] **Step 8: Run the whole suite**

Run: `cargo fmt && cargo test && cargo clippy --all-targets -- -D warnings`
Expected: all pass, no warnings.

- [ ] **Step 9: Commit**

```bash
git add src/vault.rs src/index.rs src/capture.rs src/generate.rs src/import.rs tests/inject.rs tests/no_leak.rs
git commit -m "feat: store an optional user per secret, set_user to change it

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: User in capture, generate, import and the CLI

**Files:**
- Modify: `src/capture.rs`, `src/generate.rs`, `src/import.rs`
- Modify: `src/main.rs`
- Test: `tests/cli.rs`

**Interfaces:**
- Consumes: `SecretUser`, `Vault::store(..., user)`, `Vault::set_user` from Tasks 1-2.
- Produces: `CaptureOptions::user: Option<SecretUser>`; `GenerateOptions::user: Option<SecretUser>` (the struct is no longer `Copy`); `import(vault: &Vault, name: &SecretName, overwrite: bool, user: Option<&SecretUser>) -> Result<Meta>`; CLI `--user` on capture/generate/import and `lsv user <name> (<user> | --clear)`.

- [ ] **Step 1: Write the failing unit tests.** In `src/capture.rs` `mod tests` add:

```rust
    #[test]
    fn stores_user() {
        let vault = Vault::in_memory();
        let mut cb = clip("hunter2-long-enough");
        let options = CaptureOptions {
            user: Some(SecretUser::new("root").unwrap()),
            ..Default::default()
        };
        let report = capture(&vault, &mut cb, &name("nas-root"), &options).unwrap();
        assert_eq!(report.meta.user, Some(SecretUser::new("root").unwrap()));
    }
```

In `src/generate.rs` `mod tests` add:

```rust
    #[test]
    fn generate_stores_user() {
        let vault = Vault::in_memory();
        let name = SecretName::new("db-app").unwrap();
        let options = GenerateOptions {
            user: Some(SecretUser::new("app").unwrap()),
            ..Default::default()
        };
        let meta = generate(&vault, &name, &options).unwrap();
        assert_eq!(meta.user, Some(SecretUser::new("app").unwrap()));
    }
```

- [ ] **Step 2: Write the failing CLI tests** at the end of `tests/cli.rs`:

```rust
#[test]
fn user_needs_exactly_one_of_value_and_clear() {
    for args in [
        &["user", "nas-root"][..],
        &["user", "nas-root", "root", "--clear"][..],
    ] {
        let out = lsv().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("Usage:"), "{err}");
    }
}

#[test]
fn invalid_user_is_rejected_before_opening_vault() {
    for args in [
        &["user", "nas-root", "two words"][..],
        &["capture", "nas-root", "--user", "two words"][..],
        &["generate", "nas-root", "--user", "two words"][..],
    ] {
        let out = lsv().args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(err.contains("invalid user: it contains whitespace"), "{err}");
    }
}
```

Also add `"user"` to the list in `help_lists_subcommands`.

- [ ] **Step 3: Run to verify they fail**

Run: `cargo test --lib stores_user; cargo test --test cli`
Expected: compile error on `user` fields; CLI tests fail (`unrecognized subcommand 'user'`).

- [ ] **Step 4: Options carry the user.**

In `src/capture.rs` change `use crate::name::SecretName;` to `use crate::name::{SecretName, SecretUser};`, add to `CaptureOptions` after `allow_multiline`:

```rust
    /// Account the secret belongs to; on overwrite `None` keeps the current one.
    pub user: Option<SecretUser>,
```

and in `capture` use `vault.store(name, &value, Source::Clipboard, options.overwrite, options.user.as_ref())?`.

In `src/generate.rs` change the import the same way, change `#[derive(Debug, Clone, Copy)]` on `GenerateOptions` to `#[derive(Debug, Clone)]`, add the field after `overwrite`:

```rust
    /// Account the secret belongs to; on overwrite `None` keeps the current one.
    pub user: Option<SecretUser>,
```

add `user: None,` to `impl Default for GenerateOptions`, and use `vault.store(name, &value, Source::Generated, options.overwrite, options.user.as_ref())`.

In `src/import.rs` change the import the same way and the function to:

```rust
/// Prompts twice for a value (hidden) and stores it as `name`.
///
/// Refuses to run without a terminal, so a value can never arrive through a
/// pipe, a file or an agent. `user` is recorded as the account the secret
/// belongs to; on overwrite `None` keeps the current one.
///
/// # Errors
///
/// Returns [`ErrorKind::NoTty`] without a terminal, [`ErrorKind::NameExists`]
/// if the name exists without `overwrite`, [`ErrorKind::InvalidValue`] if the
/// two entries differ, and storage errors from [`Vault::store`].
pub fn import(
    vault: &Vault,
    name: &SecretName,
    overwrite: bool,
    user: Option<&SecretUser>,
) -> Result<Meta> {
```

with the last line `vault.store(name, &first, Source::Imported, overwrite, user)`.

- [ ] **Step 5: CLI flags.** In `src/main.rs`:

Change the crate import to `use llm_secret_vault::{Error, ErrorKind, Meta, Result, SecretName, SecretUser, Vault};`.

Add to each of `Capture`, `Generate` and `Import` in `Cmd`, as the last field:

```rust
        /// Account this secret belongs to, e.g. root.
        #[arg(long)]
        user: Option<String>,
```

Add a variant after `Import`:

```rust
    /// Set or clear the user (account) a secret belongs to.
    User {
        name: String,
        /// The user, e.g. root.
        #[arg(required_unless_present = "clear", conflicts_with = "clear")]
        user: Option<String>,
        /// Remove the user.
        #[arg(long)]
        clear: bool,
    },
```

Add a helper next to `usage`:

```rust
fn parse_user(user: Option<String>) -> Result<Option<SecretUser>> {
    user.map(SecretUser::new).transpose()
}
```

In `dispatch`, update the three arms so the user is validated right after the name, before the clipboard or vault is opened:

```rust
        Cmd::Capture {
            name,
            overwrite,
            expect_prefix,
            min_len,
            allow_multiline,
            user,
        } => {
            let name = SecretName::new(name)?;
            let options = CaptureOptions {
                overwrite,
                expect_prefix,
                min_len,
                allow_multiline,
                user: parse_user(user)?,
            };
            // unchanged from here: SystemClipboard::new()?, capture, println
```

```rust
        Cmd::Generate {
            name,
            length,
            alphabet,
            overwrite,
            user,
        } => {
            let name = SecretName::new(name)?;
            let options = GenerateOptions {
                length,
                alphabet,
                overwrite,
                user: parse_user(user)?,
            };
            let meta = generate(&Vault::open()?, &name, &options)?;
            println!("stored {name}: {} chars, fp {}", meta.len, meta.fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Import {
            name,
            overwrite,
            user,
        } => {
            let name = SecretName::new(name)?;
            let user = parse_user(user)?;
            let meta = import(&Vault::open()?, &name, overwrite, user.as_ref())?;
            println!("stored {name}: {} chars, fp {}", meta.len, meta.fingerprint);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::User { name, user, .. } => {
            let name = SecretName::new(name)?;
            let user = parse_user(user)?;
            let meta = Vault::open()?.set_user(&name, user.as_ref())?;
            match &meta.user {
                Some(user) => println!("{name}: user {user}"),
                None => println!("{name}: user cleared"),
            }
            Ok(ExitCode::SUCCESS)
        }
```

(clap guarantees `user` is `None` exactly when `--clear` was given.)

- [ ] **Step 6: Show the user in `list` and `info`.** Add next to `source_label`:

```rust
fn user_label(meta: &Meta) -> &str {
    meta.user.as_ref().map_or("-", SecretUser::as_str)
}
```

In `print_table`, change the header and row formats to:

```rust
    println!(
        "{:<32} {:<16} {:>5}  {:<8}  {:<9}  UPDATED",
        "NAME", "USER", "LEN", "FP", "SOURCE"
    );
    for meta in secrets {
        println!(
            "{:<32} {:<16} {:>5}  {:<8}  {:<9}  {}",
            meta.name,
            user_label(meta),
            meta.len,
            meta.fingerprint,
            source_label(meta),
            date(meta.rotated.unwrap_or(meta.created))
        );
    }
```

In `print_info`, after the `name:` line:

```rust
    println!("user:        {}", user_label(meta));
```

- [ ] **Step 7: Run the whole suite**

Run: `cargo fmt && cargo test && cargo clippy --all-targets -- -D warnings`
Expected: all pass. Fix the `GenerateOptions` literal in `src/mcp/tools.rs` if the compiler flags it (add `user: None,`; Task 4 replaces it) and add `user: None,` to the `CaptureOptions` literal there too.

- [ ] **Step 8: Commit**

```bash
git add src/capture.rs src/generate.rs src/import.rs src/main.rs src/mcp/tools.rs tests/cli.rs
git commit -m "feat: --user on capture, generate and import; lsv user; show users

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: User in the MCP tools

**Files:**
- Modify: `src/mcp/tools.rs`
- Test: `tests/mcp.rs`

**Interfaces:**
- Consumes: `CaptureOptions::user`, `GenerateOptions::user`, `SecretUser::new` from Tasks 1-3.
- Produces: optional `user` argument on `secret_capture` and `secret_generate`; `user` key in `secret_list`/`secret_info` records when set.

- [ ] **Step 1: Write the failing tests** at the end of `tests/mcp.rs`:

```rust
#[test]
fn capture_with_user_shows_in_list_and_info() {
    let server = server();
    let (text, is_error) = tool(
        &server,
        "secret_capture",
        &json!({"name": "nas-root", "user": "root"}),
    );
    assert!(!is_error, "{text}");
    let (list, _) = tool(&server, "secret_list", &json!({"prefix": "nas"}));
    let list: Value = serde_json::from_str(&list).unwrap();
    assert_eq!(list[0]["user"], "root");
    let (info, _) = tool(&server, "secret_info", &json!({"name": "nas-root"}));
    assert!(info.contains("\"user\": \"root\""), "{info}");
}

#[test]
fn generate_with_user_and_without() {
    let server = server();
    tool(&server, "secret_generate", &json!({"name": "db-app", "user": "app"}));
    tool(&server, "secret_generate", &json!({"name": "db-plain"}));
    let (info, _) = tool(&server, "secret_info", &json!({"name": "db-app"}));
    assert!(info.contains("\"user\": \"app\""), "{info}");
    let (info, _) = tool(&server, "secret_info", &json!({"name": "db-plain"}));
    assert!(!info.contains("\"user\""), "{info}");
}

#[test]
fn invalid_user_stores_nothing() {
    let server = server();
    for name in ["secret_capture", "secret_generate"] {
        let (text, is_error) = tool(
            &server,
            name,
            &json!({"name": "nas-root", "user": "two words"}),
        );
        assert!(is_error, "{name}");
        assert!(text.contains("invalid user: it contains whitespace"), "{text}");
    }
    let (list, _) = tool(&server, "secret_list", &json!({}));
    assert_eq!(list.trim(), "[]");
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --test mcp user`
Expected: FAIL, `invalid arguments: unknown field \`user\``.

- [ ] **Step 3: Accept and validate `user`.** In `src/mcp/tools.rs`, change `use crate::name::SecretName;` to `use crate::name::{SecretName, SecretUser};`. Add `user: Option<String>,` as the last field of both `CaptureArgs` and `GenerateArgs`. In the `secret_capture` arm set `user: args.user.map(SecretUser::new).transpose()?,` in the `CaptureOptions` literal (it is built before `clipboard()?`, so a bad user never touches the clipboard). In the `secret_generate` arm set the same expression in the `GenerateOptions` literal.

- [ ] **Step 4: Schemas and descriptions.** In `definitions()`:
  - `secret_list` description: `"List stored secrets: names, users, lengths, fingerprints, sources and dates. Never returns values. One host can have several secrets for different accounts (e.g. nas-root with user root and nas-enzo with user enzo): pick the secret whose user is the login you need and write that user into the command."`
  - `secret_info` description: `"Metadata for one secret (user, length, fingerprint, source, dates). Never returns the value."`
  - Add to the `properties` of `secret_capture` and `secret_generate`:
    `"user": {"type": "string", "description": "Account this secret belongs to, e.g. root for the NAS root password. Not secret; shown in secret_list. On overwrite, omitting it keeps the current user."}`

- [ ] **Step 5: Run the whole suite**

Run: `cargo fmt && cargo test && cargo clippy --all-targets -- -D warnings`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/mcp/tools.rs tests/mcp.rs
git commit -m "feat: user argument on MCP capture and generate, shown in list/info

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`, `docs/DESIGN.md`, `AGENTS.md` (untracked; edit but do not commit unless the user asks)

- [ ] **Step 1: README.** In "Use it yourself", after the `lsv capture hf-token ...` line add:

```bash
lsv capture nas-root --user root             # record which account the password is for
lsv user nas-enzo enzo                       # set (or --clear) the user of an existing secret
```

In the MCP tools table: `secret_list` → `Names and metadata (including each secret's user), optional prefix filter`; `secret_capture` → `Clipboard to keyring, optional \`user\` and \`expect_prefix\` check, clears the clipboard`; `secret_generate` → `Random value, optional \`user\`, \`overwrite: true\` rotates`. After the table add one paragraph:

> A secret can record the user it belongs to, so a host with several accounts can hold `nas-root` (user `root`) and `nas-enzo` (user `enzo`) and the agent picks by user. The user is not secret: it is stored in the index, shown by `list` and `info`, and typed into commands by the agent. Overwriting a secret without a user keeps the old one. Only `lsv user` changes the user of an existing secret; there is no MCP tool for it.

In "Threat model", change "The metadata index holds names, lengths, keyed fingerprints, source and timestamps" to "The metadata index holds names, users, lengths, keyed fingerprints, source and timestamps".

- [ ] **Step 2: DESIGN.md.** Invariant 4: "`list` and `info` expose name, user, length, fingerprint, source and timestamps." Index module row: "Names and metadata (including the optional user)". MCP tool table: add `user?` to the `secret_capture` and `secret_generate` inputs. CLI block: add ` [--user U]` to `capture`, `generate` and `import`, and the line `lsv user <name> (<user> | --clear)`. Add after the MCP tools paragraph: "A secret's user is optional, non-secret metadata validated by `SecretUser` (1-128 characters, no whitespace or control characters, no `{{` or `}}`). Overwrite without a user keeps the existing one. Only `lsv user` changes it without storing a value."

- [ ] **Step 3: AGENTS.md.** In the `vault` bullet, append: "`Meta::user` is an optional non-secret `SecretUser`; `store` keeps it on overwrite when given `None`, and `set_user` (CLI `lsv user` only) changes it alone."

- [ ] **Step 4: Verify and commit**

Run: `cargo test --doc && cargo fmt --check`
Expected: pass.

```bash
git add README.md docs/DESIGN.md
git commit -m "docs: per-secret user

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
