# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Pins the measured at-rest scorecard for the real inspeximus store.

Three rows. Receipts off (the default) with the read path as verify(): every attack accepted.
Receipts on with the attacker holding the store's directory (the SQLite file and the receipts
sidecar): `verify_writes()` reports all five, the tail truncation because the store keeps the chain's
head outside its directory. Receipts on with the attacker also holding the config home where that head
lives: four reported, the tail truncation accepted. The version is recorded so a change in inspeximus
that opens or closes a cell shows up here.
"""

import json
import os

import pytest

pytest.importorskip("inspeximus")

import inspeximus  # noqa: E402

from agmi.adapters.inspeximus_rows import (  # noqa: E402
    InspeximusDefaultAdapter, InspeximusRowsSidecarAdapter, InspeximusRowsSidecarHeadAdapter)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = ("inspeximus 2.38.0, submitted by the inspeximus maintainer; reproduced independently "
               "by agmi on inspeximus 3.0.0 (macOS, Python 3.12)")
EXPECTED = {
    InspeximusDefaultAdapter: {"tamper": False, "truncate": False, "delete_middle": False,
                               "reorder": False, "forge": False,
                               # receipts off: the read path checks nothing.
                               # cross_replay (issue #5): the victim pool is the first
                               # context's own rows, so the edit lands and is accepted.
                               "cross_replay": False, "rollback_replay": False,
                               "metadata_tamper": False},
    InspeximusRowsSidecarAdapter: {"tamper": True, "truncate": True, "delete_middle": True,
                                   "reorder": True, "forge": True,
                                   # cross_replay: see the default row (issue #5). The edit
                                   # lands on the victim's own row and the receipts report it.
                                   "cross_replay": True, "rollback_replay": True,
                                   "metadata_tamper": True},
    InspeximusRowsSidecarHeadAdapter: {"tamper": True, "truncate": False, "delete_middle": True,
                                       "reorder": True, "forge": True,
                                       "cross_replay": True, "rollback_replay": True,
                                       "metadata_tamper": True},
}


def _run_all(adapter_cls):
    return {cls().name: cls().run(adapter_cls()) for cls in ALL_AT_REST_ATTACKS}


@pytest.mark.parametrize("adapter_cls", list(EXPECTED))
def test_the_scorecard_row_is_as_measured(adapter_cls):
    expected = EXPECTED[adapter_cls]
    results = _run_all(adapter_cls)
    assert set(results) == set(expected)
    for name, r in results.items():
        if expected[name] == "ERROR":
            assert r.status == "ERROR", (
                f"{adapter_cls.name}/{name}: expected the landed guard to fire, "
                f"got {r.status}; if the edit now lands, pin the real verdict")
            continue
        assert r.error is None, f"{adapter_cls.name}/{name} errored: {r.error}"
        assert r.guard is None, f"{adapter_cls.name}/{name} did not land: {r.guard}"
        assert r.detected == expected[name], (
            f"{adapter_cls.name}/{name}: expected detected={expected[name]}, got {r.detected}; "
            f"re-measure and update the scorecard (last measured on {MEASURED_ON}, "
            f"now inspeximus {inspeximus.__version__})")


def test_a_clean_store_verifies_so_detection_is_not_a_fail_closed_verifier():
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        a.reload()
        assert a.verify() is True
    finally:
        a.teardown()


def test_a_tampered_row_is_named_by_verify_writes_and_still_served_by_recall():
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        a.write_raw(a.mutate_payload(recs[2]))
        a.reload()
        ok, problems = a._store.verify_writes(expected_pubkey=a._pk)
        assert ok is False
        assert any(recs[2].fields["id"] in str(p) for p in problems), problems
        texts = [h.get("text", "") for h in a._store.recall("limit", k=10)]
        assert any("agmi-TAMP-" in t for t in texts), (
            "detection is the audit call; recall still serves the row")
    finally:
        a.teardown()


def test_the_sidecar_attacker_removes_exactly_one_receipt_per_deletion():
    """Control for the instrument: if the sidecar format changes, delete_raw raises instead of
    silently dropping nothing, which would flip the directory row for the wrong reason."""
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        before = json.loads(a.receipts_path().read_text(encoding="utf-8"))
        assert len(before) == 5
        victim = a.read_all_raw()[4].fields["id"]
        a.delete_raw(4)
        after = json.loads(a.receipts_path().read_text(encoding="utf-8"))
        assert len(after) == 4
        assert victim not in {r["memory_id"] for r in after}
    finally:
        a.teardown()


def test_the_head_outside_the_directory_is_what_reports_the_truncation():
    """Control: the directory row reports truncate because of the head, not for another reason. The
    head lives outside the store's directory, and removing it is the only difference between the
    two receipts rows."""
    a = InspeximusRowsSidecarAdapter()
    a.setup()
    try:
        a.seed(5)
        hp = a._store.head_path()
        assert hp and os.path.exists(hp)
        assert not os.path.abspath(hp).startswith(os.path.abspath(a._dir.name)), \
            "the head must live outside the attacked directory"
        a.delete_raw(4)
        a.delete_raw(3)
        a.reload()
        assert a.verify() is False, "with the head in place the shorter chain is reported"
        os.remove(hp)
        a.reload()
        assert a.verify() is True, "with the head gone the shorter chain is internally consistent"
    finally:
        a.teardown()


def test_an_anchor_off_the_machine_detects_the_truncation_the_head_row_accepts():
    a = InspeximusRowsSidecarHeadAdapter()
    a.setup()
    try:
        a.seed(5)
        anchor = a._store.anchor()          # what a witness would hold
        a.delete_raw(4)
        a.delete_raw(3)
        a.reload()
        assert a.verify() is True, "the accepted cell: a tail cut with its receipts and its head verifies"
        ok, problems = a._store.verify_consistency(anchor)
        assert ok is False
        assert any("shrank" in p for p in problems), problems
    finally:
        a.teardown()


def test_t9_rollback_depends_on_who_holds_the_chain_head():
    """T9: restore the store directory from an older copy after one genuine
    remember(). The default (receipts off) keeps no head, so the older copy is
    served. With receipts on, the signed head lives in the user's config home:
    an attacker holding only the store directory leaves a chain shorter than
    that head, which verify_writes reports; an attacker holding the config home
    too rolls the head back with the store, so the older copy is served."""
    from agmi.attacks.at_rest import SnapshotRollbackAttack
    from agmi.adapters.inspeximus_rows import (
        InspeximusDefaultAdapter, InspeximusRowsSidecarAdapter,
        InspeximusRowsSidecarHeadAdapter)

    r = SnapshotRollbackAttack().run(InspeximusDefaultAdapter())
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected

    a = InspeximusRowsSidecarAdapter()
    r = SnapshotRollbackAttack().run(a)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected and "head kept outside the store" in (a.verify_detail or "")

    r = SnapshotRollbackAttack().run(InspeximusRowsSidecarHeadAdapter())
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected
