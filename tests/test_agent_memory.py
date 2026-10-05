# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the Agent Memory reference
runtime, plus two measurements the eight edits do not make.

Install the measured revision (not on PyPI):
    pip install "git+https://github.com/MythologIQ-Labs-LLC/agent-memory@f2aef57293b516e065cad5d0afea26ac7e3c28a9"
"""

import importlib.metadata as md
import shutil
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("agentmem_ref")

from agmi.adapters.agent_memory import (  # noqa: E402
    DB_NAME, SEED_TOKEN, TENANT, AgentMemoryAdapter,
)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "agent-memory-reference 0.2.0 at f2aef57"


def test_version_is_the_measured_one():
    assert md.version("agent-memory-reference") == "0.2.0", (
        "agent-memory-reference moved; re-measure and re-pin")


def test_every_edit_is_refused_on_open():
    for cls in ALL_AT_REST_ATTACKS:
        a = AgentMemoryAdapter()
        r = cls().run(a)
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected, f"{r.attack}: served as genuine on {MEASURED_ON}"
        assert "RuntimeRecoveryError" in (a.verify_detail or ""), a.verify_detail


def test_detection_is_on_the_read_path():
    assert AgentMemoryAdapter.detection_point == "read"


def test_clean_store_opens_and_recalls():
    """Controls C1 and C2: the untouched store verifies, and a no-op
    reload still verifies."""
    a = AgentMemoryAdapter()
    a.setup()
    try:
        a.seed(5)
        assert a.verify() is True
        a.reload()
        assert a.verify() is True
        assert a.verify_detail is None
    finally:
        a.teardown()


def _state_dir(a: AgentMemoryAdapter) -> Path:
    return a._db(TENANT).parent


def test_rollback_of_database_alone_is_refused():
    """Restoring an older copy of the SQLite file, with the sidecar left
    at the newer generation, is caught by the generation binding."""
    a = AgentMemoryAdapter()
    a.setup()
    try:
        a.seed(2)
        snap = a._db(TENANT).read_bytes()
        a._seed_into(TENANT, SEED_TOKEN + "late-", 1)
        a._db(TENANT).write_bytes(snap)
        assert a.verify() is False
        assert "generation" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_rollback_of_whole_state_dir_is_served():
    """The limit the eight edits do not reach: database and sidecar rolled
    back together. The generation anchor lives beside the store, so the
    older state opens as current and the newest memory is gone without an
    error. The stale-snapshot case in the Agent Memory maintainers' own
    durability issue (#571); the shape of the planned ninth edit."""
    a = AgentMemoryAdapter()
    a.setup()
    try:
        a.seed(2)
        d = _state_dir(a)
        snap = d.parent / "snap"
        shutil.copytree(d, snap)
        a._seed_into(TENANT, SEED_TOKEN + "late-", 1)
        shutil.rmtree(d)
        shutil.copytree(snap, d)
        assert a.verify() is True, a.verify_detail
        conn = sqlite3.connect(d / DB_NAME)
        texts = [r[0] for r in conn.execute("SELECT fact_text FROM facts")]
        conn.close()
        assert f"{SEED_TOKEN}late-0" not in texts
    finally:
        a.teardown()


def test_digests_are_unkeyed():
    """The row digests are SHA-256 over the row with no key, so an
    attacker who recomputes them after an edit defeats the digest check.
    Recorded as a limit; recomputing the store's digests is not one of the
    eight edits."""
    import inspect
    from agentmem_ref.state import sqlite_substrate
    src = inspect.getsource(sqlite_substrate)
    assert "hmac" not in src.lower()
    assert "sha256" in src
