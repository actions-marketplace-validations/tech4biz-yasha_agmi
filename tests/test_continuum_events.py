# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the two CONTINUUM rows."""

import importlib.metadata as md

import pytest

pytest.importorskip("continuum")
pytest.importorskip("cryptography")

from agmi.adapters.continuum_events import (  # noqa: E402
    ContinuumEventsAdapter, ContinuumEventsAttestedAdapter,
)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "continuum-agent 0.1.0"

CHAIN_ONLY = {
    "tamper": True, "truncate": False, "delete_middle": True, "reorder": True,
    "forge": True, "cross_replay": True, "rollback_replay": True, "metadata_tamper": True,
}


def test_version_is_the_measured_one():
    assert md.version("continuum-agent") == "0.1.0", (
        "continuum-agent moved; re-measure and re-pin")


def test_chain_alone_misses_only_tail_truncation():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(ContinuumEventsAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected == CHAIN_ONLY[r.attack], (
            f"{r.attack}: measured {'reported' if r.detected else 'accepted'} on {MEASURED_ON}")


def test_signed_head_reports_all_eight():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(ContinuumEventsAttestedAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected, f"{r.attack}: served as genuine on {MEASURED_ON}"


def test_truncation_is_named_by_the_attestation_not_the_chain():
    a = ContinuumEventsAttestedAdapter()
    a.setup()
    try:
        a.seed(5)
        a.delete_raw(4)
        a.delete_raw(3)
        a.reload()
        assert a.verify() is False
        assert "ALTERED" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_t9_rollback_is_served_by_the_chain_and_reported_by_the_signed_head():
    """T9: agent.db restored from an older copy after one genuine event. The chain
    verifies on its own; the signed head held outside the store names the newer
    sequence and attest-verify reports ALTERED."""
    from agmi.attacks.at_rest import SnapshotRollbackAttack
    r = SnapshotRollbackAttack().run(ContinuumEventsAdapter())
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected
    a = ContinuumEventsAttestedAdapter()
    r = SnapshotRollbackAttack().run(a)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected and "ALTERED" in (a.verify_detail or "")
