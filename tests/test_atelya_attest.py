# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the two Atelya Attest rows."""

import importlib.metadata as md

import pytest

pytest.importorskip("amem_attest")

from agmi.adapters.atelya_attest import (  # noqa: E402
    AtelyaAttestAnchoredAdapter, AtelyaAttestChainAdapter,
)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "atelya-attest 0.1.1"

CHAIN_ONLY = {
    "tamper": True, "truncate": False, "delete_middle": True, "reorder": True,
    "forge": True, "cross_replay": True, "rollback_replay": True, "metadata_tamper": True,
}


def test_version_is_the_measured_one():
    assert md.version("atelya-attest") == "0.1.1", (
        "atelya-attest moved; re-measure and re-pin")


def test_chain_alone_misses_only_tail_truncation():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(AtelyaAttestChainAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected == CHAIN_ONLY[r.attack], (
            f"{r.attack}: measured {'reported' if r.detected else 'accepted'} on {MEASURED_ON}")


def test_anchored_head_reports_all_eight():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(AtelyaAttestAnchoredAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected, f"{r.attack}: served as genuine on {MEASURED_ON}"


def test_truncation_is_named_by_the_anchor_not_the_chain():
    a = AtelyaAttestAnchoredAdapter()
    a.setup()
    try:
        a.seed(5)
        a.delete_raw(4)
        a.delete_raw(3)
        assert a.verify() is False
        assert "truncated" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_t9_rollback_is_served_by_the_chain_and_reported_by_the_anchor():
    """T9: the chain files restored from an older copy after one genuine add. A
    self-consistent older chain verifies; the anchor ledger outside the store still
    names the newer head and reports the rollback."""
    from agmi.attacks.at_rest import SnapshotRollbackAttack
    r = SnapshotRollbackAttack().run(AtelyaAttestChainAdapter())
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected
    a = AtelyaAttestAnchoredAdapter()
    r = SnapshotRollbackAttack().run(a)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected and "anchor" in (a.verify_detail or "")
