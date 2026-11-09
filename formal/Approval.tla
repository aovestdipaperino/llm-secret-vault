---------------------------- MODULE Approval ----------------------------
(***************************************************************************)
(* The capture -> approve -> run flow of llm-secret-vault.                 *)
(*                                                                         *)
(* A run is started by the agent through `lsv run` in its shell tool,     *)
(* guarded by PreToolUse, or by the human at their own terminal. The hook *)
(* refuses `--no-touch` and any command that names the approval mode      *)
(* variable, so only the human can use either. The MCP server has no      *)
(* execution tool and therefore no approval cache.                       *)
(*                                                                         *)
(* Values never reach the agent through any other action: list, info,     *)
(* capture and generate return metadata only, and run output is redacted  *)
(* (proved separately by the Kani harnesses in src/redact.rs). The model  *)
(* tracks what the agent has seen in `agentSeen` to make that explicit.   *)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Names,     \* secret names
          MaxClock   \* bound on time, for model checking

Modes    == {"off", "all"}
Actors   == {"agent", "human"}
Never    == MaxClock + 1          \* sentinel: not approved yet
NoRun    == [actor |-> "none"]

VARIABLES
    mode,          \* approval mode, chosen by the human, fixed for the run
    clock,
    version,       \* value version per name (capture/generate --overwrite)
    userApproved,  \* ghost: name -> time the user last approved it
    lastRun,       \* the most recent run that injected secrets (or NoRun)
    agentSeen      \* secret values shown to the agent (must stay empty)

vars == <<mode, clock, version, userApproved, lastRun, agentSeen>>

Init ==
    /\ mode \in Modes
    /\ clock = 0
    /\ version = [n \in Names |-> 0]
    /\ userApproved = [n \in Names |-> Never]
    /\ lastRun = NoRun
    /\ agentSeen = {}

Approve(s) == [n \in Names |-> IF n \in s THEN clock ELSE userApproved[n]]

\* Record a run together with the user's approval times as of that run. Only
\* the latest run is kept: every run is checked by the invariants in the
\* state where it is latest, which keeps the state space finite and small.
Inject(actor, s, prompted, ua) ==
    lastRun' = [actor |-> actor, secrets |-> s, at |-> clock,
                prompted |-> prompted, approvedAt |-> ua]

Tick ==
    /\ clock < MaxClock
    /\ clock' = clock + 1
    /\ UNCHANGED <<mode, version, userApproved, lastRun, agentSeen>>

\* Capture or generate with --overwrite: the value changes, metadata goes back.
Overwrite(n) ==
    /\ version[n] < 1
    /\ version' = [version EXCEPT ![n] = @ + 1]
    /\ UNCHANGED <<mode, clock, userApproved, lastRun, agentSeen>>

\* `lsv run`: a fresh process with no cache. Only the human can pass --no-touch.
CliRun(actor, s, noTouch) ==
    /\ s # {}
    /\ actor = "agent" => ~noTouch          \* enforced by the hook
    /\ IF mode = "off" \/ noTouch
       THEN Inject(actor, s, FALSE, userApproved) /\ UNCHANGED userApproved
       ELSE \E yes \in BOOLEAN :            \* the user answers the prompt
            IF yes
            THEN /\ userApproved' = Approve(s)
                 /\ Inject(actor, s, TRUE, Approve(s))
            ELSE UNCHANGED <<userApproved, lastRun>>
    /\ UNCHANGED <<mode, clock, version, agentSeen>>

Next ==
    \/ Tick
    \/ \E n \in Names : Overwrite(n)
    \/ \E a \in Actors, s \in SUBSET Names, nt \in BOOLEAN : CliRun(a, s, nt)

Spec == Init /\ [][Next]_vars

TypeOK ==
    /\ mode \in Modes
    /\ clock \in 0..MaxClock
    /\ agentSeen = {}

\* Every secret in an agent run in mode "all" was approved for that exact run.
AgentRunsApproved ==
    LET r == lastRun IN
        (r.actor = "agent" /\ mode = "all") =>
            \A n \in r.secrets : r.approvedAt[n] = r.at

\* In mode "all" no agent run injects a secret without a live user approval.
NoSilentAgentRunInAllMode ==
    mode = "all" =>
        LET r == lastRun IN
            r.actor = "agent" =>
                \A n \in r.secrets : r.approvedAt[n] # Never
=============================================================================
