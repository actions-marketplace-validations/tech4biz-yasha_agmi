# The memory agent: storage-side and composite search

The scorecard measures a fixed tool against a fixed list of edits. The agent
does the opposite: point it at one target the operator controls, let it search
for a way to get a false memory served as trusted, and have it prove each
landing with a script that reproduces it. This note is the design the agent is
built to, so the code and the claims stay in step.

## What exists today (front-door only)

`agmi/agent/hunter.py` runs five front-door hunts against a
`SemanticMemoryAdapter`: memory injection, cross-session bleed, retrieval
hijack, hidden instruction in retrieved text, update poisoning, metadata
poisoning. Each hunt tries the attack on three channels (plain external write;
a write with a forged `user` label; a forged label carrying a valid signature)
and, when the base payload misses, mutates it with `agmi/mutations.py`
(paraphrase, split, pad, look-alike characters, dilute) until one lands or the
budget is spent. A landing means the store returned the attacker's content as
trusted context for an innocent query. Nothing here touches the store's bytes;
that is what the scorecard's at-rest edits do, and the agent does not yet reach
them.

## What this design adds

Two capabilities, built in order, each behind the existing authorisation gate.

### 1. At-rest edits join the hunt (B2)

The nine storage-level edits (T1 content, T2 truncation, T3 middle deletion,
T4 reorder, T5 forged insert, T6 cross-context replay, T7 rollback replay,
T8 metadata, T9 whole-store rollback) become hunt steps the agent can take
against any adapter that already carries them for the scorecard. A single run
covers both families:

    python -m agmi.agent --target langgraph-sqlite --families at-rest,front-door

An at-rest landing is the tool's own verdict after the edit and a reload:
served as genuine is a landing, refused on read or reported on audit is not.
Every edit is checked to have landed as intended (control C3) before it counts,
the same guard the scorecard uses.

### 2. Composite search (B3)

The real differentiator. A single edit is one move; an attacker with store
access makes several in sequence, with a genuine write or a restart in
between. The agent searches sequences of up to two steps drawn from:

  - a storage edit (any of the nine),
  - a genuine write through the tool's own API,
  - a restart of the store (close and reopen),
  - a read.

It starts at length two (for example: one storage edit, then a genuine write,
then a read) and only goes to three once a length-two finding exists, so the
first result is cheap to produce and cheap to reproduce. The search reports
only sequences that land where no single step in them lands on its own. That is the set no fixed scorecard column and no front-door
tool can describe: a guard removed by one edit so a later genuine write is
trusted, or a rollback that only becomes harmful once a newer record is
written on top of it.

This is the gap no current tool fills. The crowded front-door red-teaming
tools compose prompt turns: several messages that nudge the agent until it
misbehaves. The 2026 research that calls itself multi-step or compositional
(salami-style chaining, skill-chain attacks, sequential tool calls) also
composes on the prompt side. agmi composes storage operations instead, which
nothing on the market does, and it is the one place the suite can keep ahead
of a funded team that ships front-door poisoning first.

## The threat model

The attacker has write access to the backing store, directly (a shared
Postgres, a mounted volume, a backup/restore path, an insider) and not through
the agent's own API. They cannot run code inside the agent process and cannot
read the agent's live memory; they work on the store at rest, between the
agent's sessions. This is the same boundary the scorecard measures, extended
from one edit to a sequence. It is deliberately narrower than the front-door
model (which assumes no store access at all); the two together cover both
sides of the API.

## What keeps it a security tool

  - **Authorisation gate, fail closed.** `agmi/agent/authz.py` runs before any
    target is touched. A library target the caller already holds is allowed; a
    network host only on proven control (a host-named token or an operator
    consent file); anything else raises before the hunt starts. Composition and
    at-rest edits change what the agent does to a target, never which targets it
    may touch, so the gate is unchanged.
  - **Deterministic and offline.** The search is seeded and makes no network
    calls of its own beyond the target adapter's. The same target yields the
    same findings, so a report can be re-run.
  - **Proof, not assertion.** Every finding carries a reproduction script and
    the landed-control evidence. A sequence with no script is not reported.
  - **Owns only what it proves.** A proven composite becomes a candidate
    fixture for the scorecard and, where it is a real defect in a named tool, a
    private disclosure first (SECURITY.md), never a public row before the
    maintainer is told.

## What is explicitly out of scope here

Live HTTP targets, an obedience oracle (a canary action the model takes only if
it believed the poison), and a model in the loop proposing new payloads are the
next tier and are not part of B2/B3. They are listed in the roadmap, not built
against this note.

## Known overlap (6 October 2026)

The engine checks a bare `edit:X` through the store's live handle and treats `edit:X -> restart`
as a two-move sequence. The scorecard's single attack already includes the restart, so on a
store that serves an edit only after a reopen (inspeximus with the attacker holding the config
home: tail truncation) the engine reports `edit:truncate -> restart` as composite-only while the
hunt reports the same truncation as a single finding. That is one result shown twice, not a new
one. A later revision should fold the restart into the single-move baseline for edits so the
composite list only carries sequences the hunt cannot reach.

Running the engine on inspeximus also caught a false positive in agmi's own adapter: its genuine
write derived its key from the on-disk record count, so under a live handle after a truncation it
superseded a seeded record and the engine read that as served tampering. The key is now a counter.
