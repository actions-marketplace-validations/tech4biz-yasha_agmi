# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the two AtMem rows."""

import hashlib
import importlib.metadata as md
import json
import sqlite3

import pytest

pytest.importorskip("atmem")

from agmi.adapters.atmem import (  # noqa: E402
    SUBJECT, AtMemAnchoredAdapter, AtMemChainAdapter,
)
from agmi.attacks.at_rest import (  # noqa: E402
    ALL_AT_REST_ATTACKS, SnapshotRollbackAttack,
)

MEASURED_ON = "atmem 2.3.7"


def test_version_is_the_measured_one():
    assert md.version("atmem") == "2.3.7", "atmem moved; re-measure and re-pin"


@pytest.mark.parametrize("cls", [AtMemChainAdapter, AtMemAnchoredAdapter])
def test_every_record_edit_is_served_on_both_rows(cls):
    # T1 to T8 edit the records table; the chain covers the audit log, so
    # verify() stays valid and list() serves the edited records.
    for attack in ALL_AT_REST_ATTACKS:
        r = attack().run(cls())
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert not r.detected, f"{r.attack}: reported on {MEASURED_ON}, re-pin"


def test_t9_rollback_is_served_by_the_chain_and_reported_by_the_checkpoint():
    r = SnapshotRollbackAttack().run(AtMemChainAdapter())
    assert r.error is None and r.guard is None
    assert not r.detected, "chain alone reported T9; re-pin"
    a = AtMemAnchoredAdapter()
    r = SnapshotRollbackAttack().run(a)
    assert r.error is None and r.guard is None
    assert r.detected, "checkpoint did not report T9; re-pin"
    assert "missing" in (a.verify_detail or "")


def test_record_digests_are_in_the_chain_and_never_compared():
    # Every memory.record_created event carries the record's content_sha256.
    # It matches at seed time, stops matching after a content edit, and
    # verify() does not look: the gap is one comparison away from closed.
    a = AtMemChainAdapter()
    a.setup()
    try:
        a.seed(3)
        con = sqlite3.connect(a._db)
        con.row_factory = sqlite3.Row
        events = con.execute(
            "SELECT record_id, payload FROM audit_log WHERE subject_id = ? "
            "AND event_type = 'memory.record_created' ORDER BY sequence", (SUBJECT,)).fetchall()
        content = {r["id"]: r["content"] for r in con.execute(
            "SELECT id, content FROM records WHERE subject_id = ?", (SUBJECT,))}
        assert len(events) == 3
        for e in events:
            assert json.loads(e["payload"])["content_sha256"] == \
                hashlib.sha256(content[e["record_id"]].encode()).hexdigest()
        rid = events[0]["record_id"]
        con.execute("UPDATE records SET content = content || ' [TAMPERED]' WHERE id = ?", (rid,))
        con.commit()
        con.close()
        assert a.verify() is True
        assert "[TAMPERED]" in a.read_all_raw()[0].fields["content"]
    finally:
        a.teardown()


def test_editing_the_chain_itself_is_reported():
    a = AtMemChainAdapter()
    a.setup()
    try:
        a.seed(2)
        con = sqlite3.connect(a._db)
        con.execute("UPDATE audit_log SET payload = replace(payload, 'content_sha256', 'x') "
                    "WHERE subject_id = ? AND event_type = 'memory.record_created'", (SUBJECT,))
        con.commit()
        con.close()
        assert a.verify() is False
        assert "verify" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_owner_move_leaves_the_first_context_and_is_not_reported():
    # Moving a record's subject_id to another user: the record leaves the
    # first context's view, the second context now serves it, verify() is
    # still valid.
    a = AtMemChainAdapter()
    a.setup()
    try:
        a.seed(3)
        a.write_meta(1, {"subject_id": "agmi-user-B"})
        assert len(a.read_all_raw()) == 2
        assert [r.fields["content"] for r in a.read_other_raw()] == ["Agmi-seed-1 kappa 41."]
        assert a.verify() is True
    finally:
        a.teardown()
