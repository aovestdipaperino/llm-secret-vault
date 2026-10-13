# llm-secret-vault

**Let LLM agents capture, generate and use your secrets without ever reading them.**

[![CI](https://github.com/aovestdipaperino/llm-secret-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/aovestdipaperino/llm-secret-vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Coding agents need credentials all the time: a NAS password for `ssh`, a
Hugging Face token, an API key for `curl`. The usual workflow is "the key is
in the clipboard" or pasting it into the chat, and from then on the value
lives in transcripts and logs you don't control.

`lsv` stores secrets in your OS keyring (macOS Keychain, Linux Secret
Service, Windows Credential Manager) and gives the agent names instead of
values. The agent can capture a secret from your clipboard, generate a new
one, rotate it, and run commands with it. No operation returns a value, and
command output is redacted before the agent sees it.

```text
you    the NAS root password is in the clipboard, save it as nas-root and back up /data

agent  -> secret_capture(name="nas-root")
       <- stored nas-root: 18 chars, fp 3a9c01e2, clipboard cleared
agent  -> secret_run(argv=["sshpass","-e","ssh","root@nas","tar czf /backup/data.tgz /data"], env={"SSHPASS":"nas-root"})
       <- exit 0
```

`lsv run` and `secret_run` return text. Binary stdout is decoded lossily, so
write binary output to a file (as above) instead of streaming it through the
tool.

## Install

```bash
cargo install --git https://github.com/aovestdipaperino/llm-secret-vault   # installs the `lsv` binary
lsv setup claude                    # prints the MCP and hook setup for Claude Code
lsv setup plank                     # same for plank
```

The crate is not published on crates.io yet, hence the git install. On Linux,
building needs `libdbus-1-dev` and `pkg-config`, and running needs a Secret
Service provider (such as gnome-keyring) that is running and unlocked.

## Use it yourself

```bash
lsv capture hf-token --expect-prefix hf_     # clipboard -> keyring, clipboard cleared
lsv generate db-password --length 40         # random, never shown
lsv import nas-root                          # hidden prompt, typed twice
lsv list                                     # names, lengths, fingerprints, dates
lsv run HF_TOKEN=hf-token -- huggingface-cli upload me/model ./weights
lsv run -- curl -H "Authorization: Bearer {{resend}}" https://api.resend.com/emails
lsv generate db-password --overwrite         # rotate
lsv delete db-password
```

`lsv run` prints the command's output after it finishes, with every secret
value replaced by `«redacted:name»`, so pasting it into a chat is safe.
Capture refuses values that fail validation (prefix, minimum length, no
newlines unless allowed) and tells you plainly if the clipboard could not be
cleared, for instance because you copied something else in the meantime.

## MCP tools

| Tool | What it does |
|---|---|
| `secret_list` | Names and metadata, optional prefix filter |
| `secret_info` | Metadata for one secret |
| `secret_capture` | Clipboard to keyring, optional `expect_prefix` check, clears the clipboard |
| `secret_generate` | Random value, `overwrite: true` rotates |
| `secret_run` | Run an argv with `env` bindings and `{{name}}` placeholders; redacted output |

`secret_run` takes `timeout_s` from 1 to 3600 (default 120) and
`max_output_kb` from 1 to 1024 (default 32). When the timeout expires the
whole process group is killed, including background processes the command
left behind. The output cap also limits the raw bytes fed to the redactor, and
when output is truncated whatever is still pending is dropped rather than
flushed unredacted. Placeholders are substituted in every argv element,
including the program name, and any `{{word}}` whose inner text is a valid
secret name counts as a reference; there is no escape syntax.

There is deliberately no delete tool: only you can delete, from the CLI. The
server speaks MCP protocol versions 2025-06-18, 2025-03-26 and 2024-11-05 and
rejects JSON-RPC batches. It re-reads the secret index on every request, so a
secret you add from the CLI is visible to an already running server.

## Exit codes

`lsv`'s own errors (bad arguments, unknown secret, keyring failure) exit with
code 2. Otherwise `lsv run` exits with the child's exit code, or 1 if the
child was killed by a signal or timed out. This is ambiguous: a child that
exits 2 on its own looks the same as an `lsv` error, so check the message on
stderr when it matters.

## The guard hook

`lsv hook` is a `PreToolUse` hook for the shell tool only (`Bash` in Claude
Code, `bash` in plank). It blocks by exiting 2 with the reason on stderr,
which both hosts show to the model. The argv of an MCP `secret_run` call,
which the hook never sees, is checked by the same rules inside the server
before anything is resolved; a match fails the call with
`refused by llm-secret-vault: <reason>` and nothing is spawned. The hook
analyses every
`lsv run` in a command line (including `lsv` invoked by path) and blocks
children that echo or encode an injected variable or dump the environment
(`printenv`, `env` with only options, bare `set`, `export`, `export -p`). It
also blocks direct keyring reads such as `security find-generic-password -w`
or `secret-tool lookup`. Echo or printf with redirection is allowed. The hook
is a heuristic over shell text, and its quote stripping is approximate. If it
cannot parse its input it allows the command and prints a warning, so it can
never wedge your session.

## Touch ID

On macOS `lsv` can ask for your fingerprint before it injects secrets into a
command. The `LSV_TOUCH_ID` variable picks when: `off` never asks, `mcp` (the
default) asks for MCP `secret_run` calls, and `all` also asks for `lsv run`
from the command line. Nothing is asked for commands that use no secrets, and
an unknown secret name fails before any prompt appears.

The prompt's reason reads `run "<command>" with secrets <names>`, where the
command is the argv joined with spaces, cut to 80 characters plus `…` when
longer, and the names are listed in alphabetical order. Placeholders appear
as `{{name}}`, never expanded, so no secret value is ever shown. You can use
your login password instead of a finger at any time. Cancelling or failing
the prompt refuses the run with `Touch ID approval was denied or cancelled`,
and the command is not started. A prompt left unanswered for two minutes is
dismissed and counts as a refusal.

After a successful approval the server does not ask again for
`LSV_TOUCH_ID_TTL` seconds (default 300, maximum 3600; `0` asks every time).
The approval is remembered by the running process only, so each `lsv run`
from the shell asks on its own.

The MCP server reads these variables from its own environment, so set them
where the server is registered. For Claude Code:

```bash
claude mcp add --scope user llm-secret-vault -e LSV_TOUCH_ID=all -- lsv mcp
```

For plank, add an `env` key to the entry in `.mcp.json`:

```json
"llm-secret-vault": {
  "command": "lsv",
  "args": ["mcp"],
  "env": { "LSV_TOUCH_ID": "mcp", "LSV_TOUCH_ID_TTL": "300" }
}
```

On other platforms there is no fingerprint check: `lsv` prints a notice and
continues without it.

Touch ID is a separate check and does not replace the Keychain password
dialog. Gating the Keychain item itself on biometrics needs the
data-protection keychain and an access control, which only a binary signed
with a Developer ID and the right entitlements can use, and a `cargo install`
build has neither. For the same reason "Always Allow" in the Keychain dialog
is tied to the exact binary, so macOS asks again after every rebuild or
upgrade of `lsv`.

## Threat model

`lsv` prevents accidents. It keeps secrets out of an agent's context when the
agent is behaving normally, and it makes a leak require deliberate effort. It
is not a defense against a hostile agent: a child process receives the real
value and can transform it in ways no redactor recognizes, and the hook only
catches the common tricks. Treat it as a seatbelt, not a sandbox.

Within that scope, some specifics are worth knowing. Redaction covers the raw
value, base64 (standard and URL-safe, padded and unpadded, including the
prefix of a base64 blob when the secret is followed by other bytes),
percent-encoding (uppercase `%XX` only), the JSON string-escaped form (for
values containing quotes, backslashes or control characters that get echoed inside a JSON
document), and hex in both cases; overlapping matches are merged into
one marker. It does not cover a secret that is base64-encoded at a non-zero
offset inside a larger blob, a value printed only in part, or any deliberate
transformation.

`{{name}}` placeholders put the value in the child's argv, which is visible in
the process table while the child runs, so prefer env bindings when the tool
accepts them. Fingerprints shown by `list` and `info` are HMAC-SHA256 values
keyed with a per-installation key that lives in the keyring under the reserved
account `__lsv_hmac_key__`, so they cannot be used to brute-force short values
offline. Storage, encryption and locking are the OS keyring's; on macOS over
plain SSH the login keychain is locked and `lsv` reports the keyring as
unavailable.

The metadata index holds names, lengths, keyed fingerprints, source and
timestamps, never values. It lives at `dirs::config_dir()/llm-secret-vault/index.json`
(for example `~/Library/Application Support/llm-secret-vault/index.json` on
macOS, `~/.config/llm-secret-vault/index.json` on Linux) and is written with
mode 0600 on Unix. It is not protected by file locking. It is re-read before every write, but two
processes writing at the same instant can still race in a small window. On
Windows there is no process-group kill, so a timeout kills the child but not
its grandchildren.

See [docs/DESIGN.md](docs/DESIGN.md) for the full design.

## License

MIT
