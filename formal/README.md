# Formal checks

Three kinds of machine-checked evidence back the claims in `docs/DESIGN.md`:
Kani proofs for small arithmetic and slicing invariants, bounded exhaustive
checks for the redaction scanner and placeholder substitution, and a TLA+
model of the capture, approve and run flow.

All of them are bounded: they prove a property for every input up to a size
limit, not for all sizes. The limits are chosen so the interesting cases
(overlapping and touching secrets, a secret split across three chunks, a
multi-byte character next to a delimiter) fit inside them.

## Kani proofs

Install once with `cargo install --locked kani-verifier && cargo kani setup`.
The harnesses live in `#[cfg(kani)] mod proofs` blocks next to the code they
check, so normal builds never see them. `cargo kani` runs all three in about
five seconds.

| Harness | Property |
|---|---|
| `inject::proofs::append_capped_respects_cap` | Given the invariant `pump` keeps (output never above the cap), appending keeps it, cannot underflow, and reports truncation exactly when bytes are cut. |
| `inject::proofs::raw_limit_is_at_least_cap` | The raw-input bound never overflows and is never below the output cap, for every `usize`. |
| `hook::proofs::top_level_end_is_a_char_boundary` | The guard hook's command splitter returns an in-bounds character boundary for any 5-byte UTF-8 input, so slicing at it cannot panic. |

## Bounded exhaustive checks

Kani could not handle the rest in reasonable time with version 0.68: the
redaction scanner did not finish within ten minutes even for a 3-byte input
(symbolic `memcmp` inside the pattern search explodes), percent-encoding goes
through `core::fmt` and ran for over thirty minutes on 2 bytes, and
`str::find` in the placeholder parser crashes the Kani compiler. These
properties are instead checked by enumerating every input up to the bound,
which is a proof for that bound, just not a symbolic one.

| Test | Property |
|---|---|
| `redact::tests::exhaustive_small` | For every pair of secrets of 1-3 bytes and every input up to 4 bytes over `{0, 1, 2}`: no secret survives, clean input is unchanged, and every split into three chunks gives the one-shot output. Runs with `cargo test`. |
| `redact::tests::exhaustive_large` | The same up to 6-byte inputs (about 46 million redactor runs). Run with `cargo test --release -- --ignored exhaustive_large`, about 10 s. |
| `inject::tests::placeholders_and_substitute_exhaustive` | For every argument up to 7 characters over `{`, `}`, `a`, space and `é`: placeholder ranges are in bounds, on character boundaries, ordered, disjoint and shaped `{{ name }}`, and `substitute` fills exactly the buffer it reserves, so it never reallocates and leaves no unzeroed copy of a value behind. |

The redaction checks give each label a one-byte marker outside the alphabet.
That isolates the scanning logic: a secret found in the output can only be
input that escaped, not marker text. The encodings produced by `variants`
(base64, hex, percent and JSON escaping) are covered by the unit tests.

## TLA+ model of approval

`Approval.tla` models who can start a run (the agent through MCP or its shell
tool, the human at a terminal), the approval mode, the MCP server's approval
cache and its TTL, overwriting a secret, and the hook's refusal of
`--no-touch` and of changes to the mode variable. Check it with TLC from
[tla2tools.jar](https://github.com/tlaplus/tlaplus/releases):

```sh
java -cp tla2tools.jar tlc2.TLC -config Approval.cfg Approval.tla
```

`Approval.cfg` checks that every secret injected into a run the agent started,
in a context the mode covers, was approved by the user in that run or within
the TTL, that in mode `all` no agent run injects a secret without a user
approval, and that no action hands a value to the agent. TLC explores about
37,000 distinct states in a second.

`Approval-gap.cfg` checks the stronger claim that the agent never injects a
secret without a prompt unless the mode is `off`. It fails by design: in mode
`mcp` the agent can run `lsv run` through its shell tool and no prompt is
shown, which is the documented meaning of that mode. The counterexample is a
one-step trace and is kept as a reminder of the trade-off.

## Markers and secrets that spell marker text

The exhaustive check isolates the scanner from marker text. With the real
`«redacted:<label>»` markers, a secret that contains `«`, `»` or a slice of a
marker used to reappear in the output: `redact_all([("k", "k»Q")], "k»QQ")`
returned `«redacted:k»Q`, and a secret `acted:a` stored as `api` appeared
inside its own marker.

`Redactor::new` now detects that case and replaces every marker with one
character no secret contains (`█` first). Every pattern is valid UTF-8, so an
occurrence that touches a marker has to contain the whole marker character,
which no pattern does. That restores the setting of the exhaustive check:
markers that no secret can overlap. The regression test is
`redact::tests::secret_that_spells_marker_text_falls_back_to_plain_marker`.
