---------------------------- MODULE Approval ----------------------------
(***************************************************************************)
(* The capture -> approve -> run flow of llm-secret-vault.                 *)
(*                                                                         *)
(* A run is started by the agent (MCP secret_run, or `lsv run` through its *)
(* shell tool, which the PreToolUse hook guards) or by the human at their  *)
(* own terminal. The hook refuses `--no-touch` and any command that names  *)
(* the approval mode variable, so only the human can use either.          *)
(*                                                                         *)
(* The MCP server keeps one approval cache (approve::Cached) for its whole *)
(* life; each `lsv run` is a new process and always asks.                 *)
(*                                                                         *)
(* Values never reach the agent through any other action: list, info,     *)
(* capture and generate return metadata only, and run output is redacted  *)
(* (proved separately by the Kani harnesses in src/redact.rs). The model  *)
(* tracks what the agent has seen in `agentSeen` to make that explicit.   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Names,     \* secret names
          TTL,       \* cache lifetime in ticks (0 = always ask)
          MaxClock   \* bound on time, for model checking

Modes    == {"off", "mcp", "all"}
Actors   == {"agent", "human"}
Never    == MaxClock + TTL + 1   \* sentinel: not approved yet
NoRun    == [actor |-> "none"]

Covers(m, ctx) == m = "all" \/ (m = "mcp" /\ ctx = "mcp")

VARIABLES
    mode,          \* approval mode, chosen by the human, fixed for the run
    clock,
    version,       \* value version per name (capture/generate --overwrite)
    cache,         \* MCP server cache: name -> time of last approval
    userApproved,  \* ghost: name -> time the user last approved it
    lastRun,       \* the most recent run that injected secrets (or NoRun)
    agentSeen      \* secret values shown to the agent (must stay empty)

vars == <<mode, clock, version, cache, userApproved, lastRun, agentSeen>>

Init ==
    /\ mode \in Modes
    /\ clock = 0
    /\ version = [n \in Names |-> 0]
    /\ cache = [n \in Names |-> Never]
    /\ userApproved = [n \in Names |-> Never]
    /\ lastRun = NoRun
    /\ agentSeen = {}

Fresh(n) == cache[n] # Never /\ clock - cache[n] < TTL

Approve(s) == [n \in Names |-> IF n \in s THEN clock ELSE userApproved[n]]

\* Record a run together with the user's approval times as of that run. Only
\* the latest run is kept: every run is checked by the invariants in the
\* state where it is latest, which keeps the state space finite and small.
Inject(actor, ctx, s, prompted, ua) ==
    lastRun' = [actor |-> actor, ctx |-> ctx, secrets |-> s, at |-> clock,
                prompted |-> prompted, approvedAt |-> ua]

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<mode, version, cache, userApproved, lastRun, agentSeen>>

\* Capture or generate with --overwrite: the value changes, metadata goes back.
Overwrite(n) ==
    /\ version[n] < 1
    /\ version' = [version EXCEPT ![n] = @ + 1]
    /\ UNCHANGED <<mode, clock, cache, userApproved, lastRun, agentSeen>>

\* MCP secret_run: always the agent, always through the server cache.
McpRun(s) ==
    /\ s # {}
    /\ IF ~Covers(mode, "mcp") \/ \A n \in s : Fresh(n)
       THEN /\ Inject("agent", "mcp", s, FALSE, userApproved)
            /\ UNCHANGED <<cache, userApproved>>
       ELSE \E yes \in BOOLEAN :            \* the user answers the prompt
            IF yes
            THEN /\ userApproved' = Approve(s)
                 /\ cache' = [n \in Names |-> IF n \in s THEN clock ELSE cache[n]]
                 /\ Inject("agent", "mcp", s, TRUE, Approve(s))
            ELSE UNCHANGED <<cache, userApproved, lastRun>>
    /\ UNCHANGED <<mode, clock, version, agentSeen>>

\* `lsv run`: a fresh process with no cache. Only the human can pass --no-touch.
CliRun(actor, s, noTouch) ==
    /\ s # {}
    /\ actor = "agent" => ~noTouch          \* enforced by the hook
    /\ IF ~Covers(mode, "cli") \/ noTouch
       THEN Inject(actor, "cli", s, FALSE, userApproved) /\ UNCHANGED userApproved
       ELSE \E yes \in BOOLEAN :
            IF yes
            THEN /\ userApproved' = Approve(s)
                 /\ Inject(actor, "cli", s, TRUE, Approve(s))
            ELSE UNCHANGED <<userApproved, lastRun>>
    /\ UNCHANGED <<mode, clock, version, cache, agentSeen>>

Next ==
    \/ Tick
    \/ \E n \in Names : Overwrite(n)
    \/ \E s \in SUBSET Names : McpRun(s)
    \/ \E a \in Actors, s \in SUBSET Names, nt \in BOOLEAN : CliRun(a, s, nt)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ mode \in Modes
    /\ clock \in 0..MaxClock
    /\ agentSeen = {}

\* Every run the agent started in a context the mode covers injected only
\* secrets the user approved in that run or within the last TTL ticks.
AgentRunsApproved ==
    LET r == lastRun IN
        (r.actor = "agent" /\ Covers(mode, r.ctx)) =>
            \A n \in r.secrets :
                /\ r.approvedAt[n] # Never
                /\ \/ r.approvedAt[n] = r.at
                   \/ r.at - r.approvedAt[n] < TTL

\* In mode "all" no agent run injects a secret without a live user approval.
NoSilentAgentRunInAllMode ==
    mode = "all" =>
        LET r == lastRun IN
            r.actor = "agent" =>
                \A n \in r.secrets : r.approvedAt[n] # Never

\* Documents a known trade-off: in mode "mcp" the agent's own `lsv run` is
\* not covered. Checking this (see Approval-gap.cfg) yields a counterexample.
AgentNeverRunsUnprompted ==
    mode # "off" =>
        LET r == lastRun IN
            r.actor = "agent" =>
                \A n \in r.secrets : r.approvedAt[n] # Never
=============================================================================
