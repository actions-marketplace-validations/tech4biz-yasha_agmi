# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the AtMem 2.3.8 at-rest measurement.

These expectations were submitted by the AtMem maintainer in PR #7 and
reproduced independently by AGMI from the published PyPI wheel on Linux
and macOS before the scorecard was updated.
"""

import importlib.metadata as md
import sqlite3

import pytest

pytest.importorskip("atmem")

from agmi.adapters.atmem import (  # noqa: E402
    SUBJECT, AtMemAnchoredAdapter, AtMemChainAdapter,
)
from agmi.attacks.at_rest import (  # noqa: E402
    ALL_AT_REST_ATTACKS, SnapshotRollbackAttack,
)

MEASURED_ON = "atmem 2.3.8"


def test_version_is_the_measured_one():
    assert md.version("atmem") == "2.3.8", "atmem moved; re-measure and re-pin"


@pytest.mark.parametrize("cls", [AtMemChainAdapter, AtMemAnchoredAdapter])
def test_every_record_edit_is_reported_on_both_rows(cls):
    for attack in ALL_AT_REST_ATTACKS:
        if isinstance(attack(), SnapshotRollbackAttack):
            continue
        r = attack().run(cls())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert r.detected, f"{r.attack}: accepted on {MEASURED_ON}, re-pin"


def test_t9_rollback_is_served_by_the_chain_and_reported_by_the_checkpoint():
    r = SnapshotRollbackAttack().run(AtMemChainAdapter())
    assert r.error is None and r.guard is None
    assert not r.detected, "chain alone reported T9; re-pin"

    a = AtMemAnchoredAdapter()
    r = SnapshotRollbackAttack().run(a)
    assert r.error is None and r.guard is None
    assert r.detected, "checkpoint did not report T9; re-pin"
    assert "missing" in (a.verify_detail or "")


def test_record_commitment_tamper_is_reported():
    a = AtMemChainAdapter()
    a.setup()
    try:
        a.seed(3)
        con = sqlite3.connect(a._db)
        con.execute(
            "UPDATE records SET content = content || ' [TAMPERED]' "
            "WHERE subject_id = ? AND id = ("
            "SELECT id FROM records WHERE subject_id = ? ORDER BY created_at LIMIT 1)",
            (SUBJECT, SUBJECT),
        )
        con.commit()
        con.close()
        assert a.verify() is False
        assert "record" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_editing_the_chain_itself_is_reported():
    a = AtMemChainAdapter()
    a.setup()
    try:
        a.seed(2)
        con = sqlite3.connect(a._db)
        con.execute(
            "UPDATE audit_log SET payload = replace(payload, 'content_sha256', 'x') "
            "WHERE subject_id = ? AND event_type = 'memory.record_created'",
            (SUBJECT,),
        )
        con.commit()
        con.close()
        assert a.verify() is False
        assert "verify" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_owner_move_is_reported_and_leaves_the_first_context():
    a = AtMemChainAdapter()
    a.setup()
    try:
        a.seed(3)
        a.write_meta(1, {"subject_id": "agmi-user-B"})
        assert len(a.read_all_raw()) == 2
        assert [r.fields["content"] for r in a.read_other_raw()] == [
            "Agmi-seed-1 kappa 41."
        ]
        assert a.verify() is False
        assert "record" in (a.verify_detail or "")
    finally:
        a.teardown()
