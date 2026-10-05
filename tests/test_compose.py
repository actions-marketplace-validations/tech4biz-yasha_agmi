# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The composition engine finds a two-move sequence that lands where neither
move lands alone, and reports nothing against a store with no such hole.

A composite-only finding is the engine's whole reason to exist, so one test
builds a reference store that is deliberately vulnerable to exactly one
sequence (restart, then edit) while catching every single edit, and asserts
the engine finds it with a reproduction. The other tests assert the engine
stays quiet on a fully defended store and on a fully undefended one (where
single edits already land, so nothing is composite-only)."""
from agmi.agent.compose import compose
from agmi.adapters.reference_atrest import ReferenceAtRestAdapter
from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter


class _RestartForgetsWitness(ReferenceAtRestAdapter):
    """A reference store with one flaw: on restart it re-derives its witness
    from the file instead of keeping it in the process. So a single edit is
    caught (the in-process witness still names the real head), but the
    sequence 'restart, then edit' is not: the restart drops the witness, and
    the chain-only check after the edit cannot tell the rollback happened.
    This is a composite-only hole and nothing else."""
    name = "reference-restart-forgets-witness"

    def reload(self) -> None:
        # The flaw: forget the off-process witness on restart.
        self._witness = None


def test_engine_finds_the_composite_only_sequence():
    authz, findings = compose(lambda: _RestartForgetsWitness(),
                              target="reference-restart-forgets-witness",
                              max_len=2)
    assert authz.startswith("library:")
    assert findings, "engine missed the composite-only sequence"
    seqs = [tuple(f.sequence) for f in findings]
    # the fixture's hole is a whole-store rollback followed by a restart: the
    # restart drops the off-process witness, so the older self-consistent copy
    # is served. Neither move lands alone.
    assert ("rollback", "restart") in seqs, seqs
    for f in findings:
        assert f.repro, "a finding must carry a reproduction"
        # the engine only reports composite-only sequences
        assert len(f.sequence) >= 2


def test_defended_reference_store_yields_no_composite():
    # The reference store catches every single edit, and since its witness
    # advances only forward (truncate-then-write can no longer launder a
    # deletion — a gap the composition engine first surfaced and that is now
    # fixed), it has no two-move hole either.
    _authz, findings = compose(lambda: ReferenceAtRestAdapter(),
                               target="reference", max_len=2)
    assert findings == []


def test_undefended_store_has_no_composite_only_finding():
    # langgraph-sqlite serves every single edit on its own, so every record
    # edit is a single-move landing and is filtered out; nothing is
    # composite-only. (A rollback there is also a single-move landing.)
    _authz, findings = compose(lambda: LangGraphSqliteAdapter(),
                               target="langgraph-sqlite", max_len=2)
    assert findings == []
