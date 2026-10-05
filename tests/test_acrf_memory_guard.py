# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for acrf-memory-guard.

The package signs each entry's bytes with HMAC-SHA256 and checks them on
read. The measurement is of the package as documented, not a model of it;
the version is recorded so a release that binds the key or links entries
shows up here as a failure, which is the signal we want.
"""

import importlib.metadata as md

import pytest

pytest.importorskip("acrf_memory_guard")

from agmi.adapters.acrf_memory_guard import AcrfMemoryGuardAdapter  # noqa: E402
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "acrf-memory-guard 0.1.0"

# True = refused on the read path, False = served as genuine.
EXPECTED = {
    "tamper": True,
    "truncate": False,
    "delete_middle": False,
    "reorder": False,
    "forge": True,
    "cross_replay": False,
    "rollback_replay": False,
    "metadata_tamper": True,
}


def test_version_is_the_measured_one():
    assert md.version("acrf-memory-guard") == "0.1.0", (
        "acrf-memory-guard moved; re-measure and re-pin")


def test_the_scorecard_row_is_as_measured():
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(AcrfMemoryGuardAdapter())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected == EXPECTED[r.attack], (
            f"{r.attack}: measured {'rejected' if r.detected else 'accepted'}, "
            f"pinned {'rejected' if EXPECTED[r.attack] else 'accepted'} on {MEASURED_ON}")


def test_detection_is_on_the_read_path():
    a = AcrfMemoryGuardAdapter()
    assert a.detection_point == "read"


def test_a_signed_entry_from_the_other_user_is_served_under_this_users_key():
    """The T6 mechanism, spelled out: the signed content names ctx-B, the
    key says ctx-A, read_safe does not compare the two."""
    from acrf_memory_guard import read_safe
    from agmi.adapters.acrf_memory_guard import SECRET
    a = AcrfMemoryGuardAdapter()
    a.setup()
    try:
        a.seed(3)
        a.seed_other(3)
        donor = a.read_other_raw()[-1]
        a.replay_onto(2, donor)
        served = read_safe(a.read_all_raw()[2].fields["entry"], SECRET)
        assert served["owner"] == "ctx-B"
        assert a.verify() is True
    finally:
        a.teardown()


def test_t9_rollback_is_served():
    """T9: the JSON store restored from an older copy after one genuine signed
    entry. Every remaining entry carries a valid HMAC, so read_safe serves the
    older copy as current."""
    from agmi.attacks.at_rest import SnapshotRollbackAttack
    r = SnapshotRollbackAttack().run(AcrfMemoryGuardAdapter())
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected
