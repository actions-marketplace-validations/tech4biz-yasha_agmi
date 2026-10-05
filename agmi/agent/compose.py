# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The composition engine: chain storage moves and report sequences that land
where no single move in them lands alone.

A single at-rest edit is one move. An attacker with store access makes several,
with a genuine write or a restart in between. This searches short sequences of
moves against one target and keeps only the ones whose harm is in the
sequence, not in any one move: for every reported sequence, each move run on
its own (same seed, same target) does NOT land, and the sequence does.

Moves:
  edit:<name>   apply one of the at-rest edits to the storage, bypassing the
                tool (the edit's own tamper step).
  write         add one genuine record through the tool's own API.
  restart       close and reopen the store (the agent restarting).

A "read" is implicit: after the sequence the tool's own verify() is the oracle,
exactly as the scorecard uses it. A sequence LANDS when the tool serves the
altered store as genuine (verify() returns True with the store changed) and the
landed controls for its edit moves all held.

The search is deterministic and offline. Default max length is 2; raise it
only once a length-2 finding exists, because the space grows fast.

Authorisation (agmi.agent.authz) runs before any target is touched; the
targets here are in-process library stores the caller already holds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from itertools import product

from agmi.adapters.base import MemoryAdapter
from agmi.agent.authz import Authorisation, authorise_library
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS

_EDITS = {cls.name: cls for cls in ALL_AT_REST_ATTACKS}


@dataclass
class CompositeFinding:
    """One sequence that lands where none of its single moves does."""
    sequence: list           # e.g. ["edit:truncate", "write"]
    detail: str
    singles_checked: list = field(default_factory=list)  # moves proven inert alone
    repro: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"sequence": self.sequence, "detail": self.detail,
                "singles_checked": self.singles_checked, "repro": self.repro}


class MoveInapplicable(Exception):
    """The move cannot be set up on this target at all (a missing hook or an
    unknown move). The sequence is skipped, never scored. A tool refusing a
    move through its own API is NOT this — that is the store defending itself
    and is recorded as a non-landing."""


def _apply_move(adapter: MemoryAdapter, move: str) -> None:
    """Run one move against an already-seeded adapter.

    Raises MoveInapplicable if the move cannot be set up here. Any other
    exception is the tool's own API refusing the move (the store defending
    itself) and propagates so the caller records a non-landing."""
    if move == "write":
        adapter.append_genuine()
    elif move == "restart":
        adapter.reload()
    elif move == "rollback":
        # whole-store rollback: restore an older complete copy after one more
        # genuine record was written through the tool's own API.
        if not getattr(adapter, "supports_snapshot", False):
            raise MoveInapplicable("target has no snapshot hooks")
        token = adapter.snapshot_store()
        adapter.append_genuine()
        adapter.restore_store(token)
    elif move.startswith("edit:"):
        name = move.split(":", 1)[1]
        _EDITS[name]().tamper(adapter)
    else:
        raise MoveInapplicable(f"unknown move {move!r}")


def _genuine_payloads(adapter) -> list:
    return [adapter.payload_of(r) for r in adapter.read_all_raw()]


def _lands(adapter_factory, moves: list) -> tuple[bool, str]:
    """Seed a fresh target, record the genuine memory, run the moves in order,
    then ask the tool. Returns (landed, detail). A sequence LANDS when the tool
    still serves the store without refusing (verify True) AND the memory it now
    serves differs from the genuine seed. A move that tampers nothing (a bare
    restart or genuine write) never lands; a tamper the tool serves silently
    does. ``genuine`` writes are expected to change the memory, so a sequence
    whose only change is its own genuine writes is not a landing either: the
    comparison ignores records added by ``write`` moves by length."""
    adapter = adapter_factory()
    try:
        adapter.setup()
        adapter.seed(5)
        if not adapter.verify():
            return False, "clean store did not verify"
        genuine = _genuine_payloads(adapter)
        writes = sum(1 for m in moves if m == "write")
        for move in moves:
            try:
                _apply_move(adapter, move)
            except MoveInapplicable:
                raise
            except Exception as exc:  # noqa: BLE001
                # the tool's own API refused this move: the store caught the
                # tampering before the move completed. Not a landing.
                return False, f"tool refused the move: {str(exc)[:120]}"
        if not adapter.verify():
            return False, "refused or reported"
        after = _genuine_payloads(adapter)
        base = after[:len(after) - writes] if writes else after
        prefix_changed = base != genuine[:len(base)] or len(base) < len(genuine)
        # A rollback move removes the newest genuine record: the served memory
        # is shorter than it should be, with no record of the loss. That is a
        # landing even though the surviving records are themselves genuine.
        rolled_back = "rollback" in moves and len(after) <= len(genuine)
        if not (prefix_changed or rolled_back):
            return False, "served, but the genuine memory is intact"
        return True, adapter.verify_detail or "altered memory served as genuine"
    finally:
        try:
            adapter.teardown()
        except Exception:  # noqa: BLE001
            pass


def _repro(target: str, moves: list) -> list:
    steps = [f"# target={target}, sequence={' -> '.join(moves)}"]
    steps.append("seed the store through the tool's own API (5 records)")
    for move in moves:
        if move == "write":
            steps.append("add one genuine record through the tool's own API")
        elif move == "restart":
            steps.append("close and reopen the store (agent restart)")
        elif move == "rollback":
            steps.append("restore an older full copy of the store after one "
                         "genuine record was written (whole-store rollback)")
        else:
            steps.append(f"apply the {move.split(':', 1)[1]} edit to the "
                         f"storage directly, bypassing the tool")
    steps.append("read back through the tool: it serves the altered store as "
                 "genuine")
    return steps


def _candidate_moves() -> list:
    return ["write", "restart", "rollback"] + [f"edit:{name}" for name in _EDITS]


def compose(adapter_factory, *, target: str = "library",
            max_len: int = 2, authorisation: Authorisation | None = None):
    """Search sequences up to ``max_len`` against the target. Return
    (authz_line, findings). A finding is a sequence that lands while every one
    of its moves, run alone on the same target, does not."""
    authz = authorisation or authorise_library()
    moves = _candidate_moves()

    # Which single moves land on their own? A sequence is only interesting if
    # none of its moves is already a single-move landing.
    single_lands: dict = {}
    for m in moves:
        try:
            landed, _ = _lands(adapter_factory, [m])
        except MoveInapplicable:
            landed = None  # move not applicable alone; treat as non-landing
        single_lands[m] = bool(landed)

    findings: list[CompositeFinding] = []
    seen: set = set()
    for length in range(2, max_len + 1):
        for combo in product(moves, repeat=length):
            # skip a sequence if any move already lands by itself: its harm is
            # not in the composition.
            if any(single_lands.get(m) for m in combo):
                continue
            # skip trivially inert sequences (only restarts/writes, nothing
            # that alters the store): nothing can land. A storage edit or a
            # rollback is a tampering move; a sequence needs at least one.
            if not any(m.startswith("edit:") or m == "rollback" for m in combo):
                continue
            key = tuple(combo)
            if key in seen:
                continue
            seen.add(key)
            try:
                landed, detail = _lands(adapter_factory, list(combo))
            except MoveInapplicable:
                continue  # sequence not applicable on this target
            if landed:
                findings.append(CompositeFinding(
                    sequence=list(combo), detail=detail,
                    singles_checked=[m for m in combo],
                    repro=_repro(target, list(combo))))
    return f"{authz.kind}: {authz.detail}", findings
