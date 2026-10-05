# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""T9, snapshot rollback: restore an older complete copy of the store
after one more genuine record was written through the tool's own API.

Self-validation: the reference store catches it only because it holds a
witness of the last head off the store; the OpenFang model, which keeps
its tip inside the same file, serves the older copy. An adapter without
the snapshot hooks reads not evaluable, never a pass."""

import pytest

from agmi.adapters.openfang import OpenFangAdapter
from agmi.adapters.reference_atrest import ReferenceAtRestAdapter
from agmi.attacks.at_rest import (
    ALL_AT_REST_ATTACKS, AT_REST_ATTACKS_WITH_SNAPSHOT, SnapshotRollbackAttack,
)


def test_the_nine_are_the_eight_plus_t9():
    assert AT_REST_ATTACKS_WITH_SNAPSHOT[:-1] == ALL_AT_REST_ATTACKS
    assert AT_REST_ATTACKS_WITH_SNAPSHOT[-1] is SnapshotRollbackAttack


def test_reference_store_rejects_with_a_witnessed_head():
    a = ReferenceAtRestAdapter()
    r = SnapshotRollbackAttack().run(a)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected
    assert "witnessed head" in (a.verify_detail or "")


def test_reference_store_still_rejects_the_eight():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(ReferenceAtRestAdapter())
        assert r.detected and r.guard is None and r.error is None, (r.attack, r.guard, r.error)


def test_openfang_model_serves_the_older_copy():
    """The persisted tip rolls back with the file it lives in."""
    r = SnapshotRollbackAttack().run(OpenFangAdapter(strict_tip=True))
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected


def test_adapter_without_hooks_is_not_evaluable():
    class Bare(ReferenceAtRestAdapter):
        supports_snapshot = False
    r = SnapshotRollbackAttack().run(Bare())
    assert r.error is not None and "snapshot" in r.error
    assert r.status == "n/a"


@pytest.mark.parametrize("modname, attr, expect", [
    ("agmi.adapters.agent_memory", "AgentMemoryAdapter", False),
    ("agmi.adapters.langgraph_sqlite", "LangGraphSqliteAdapter", False),
    ("agmi.adapters.openai_agents_session", "OpenAIAgentsSessionAdapter", False),
    ("agmi.adapters.langgraph_postgres", "LangGraphPostgresAdapter", False),
    ("agmi.adapters.langgraph_redis", "LangGraphRedisAdapter", False),
])
def test_measured_rows(modname, attr, expect):
    mod = pytest.importorskip(modname)
    cls = getattr(mod, attr)
    try:
        a = cls()
        r = SnapshotRollbackAttack().run(a)
    except ImportError:
        pytest.skip(f"{modname} dependency not installed")
    if r.error and ("No module" in r.error or "import" in r.error.lower()
                    or "is not set" in r.error):
        pytest.skip(r.error)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected is expect, a.verify_detail
