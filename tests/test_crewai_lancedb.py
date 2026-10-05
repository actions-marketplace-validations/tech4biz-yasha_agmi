# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pinned scorecard row for CrewAI long-term memory on its LanceDB store.

Measured on crewai 1.15.23 (CrewAI 1.15 moved memory off a SQLite table to a
LanceDB dataset). Every storage edit is served as genuine on the read path:
the store has no integrity check, and LanceDB's own versioning only delays an
edit until the next reopen, which is the at-rest model anyway.
"""
import pytest

crewai = pytest.importorskip("crewai")
pytest.importorskip("lancedb")

from agmi.adapters.crewai_lancedb import CrewAILanceDBAdapter  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS, SnapshotRollbackAttack  # noqa: E402


def test_version_is_the_measured_one():
    assert crewai.__version__ == "1.15.23"


@pytest.mark.parametrize("attack_cls", ALL_AT_REST_ATTACKS)
def test_every_record_edit_is_served(attack_cls):
    r = attack_cls().run(CrewAILanceDBAdapter())
    assert r.error is None and r.guard is None, (r.attack, r.error, r.guard)
    assert not r.detected, f"{r.attack} was unexpectedly detected"


def test_t9_whole_store_rollback_is_served():
    r = SnapshotRollbackAttack().run(CrewAILanceDBAdapter())
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected


def test_detection_point_is_read():
    assert CrewAILanceDBAdapter().detection_point == "read"
