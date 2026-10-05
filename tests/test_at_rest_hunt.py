# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""The storage-side hunt reports exactly the edits a target serves, with a
reproduction for each, and nothing for a store that refuses them."""
from agmi.agent.at_rest_hunt import hunt_at_rest
from agmi.adapters.reference_atrest import ReferenceAtRestAdapter
from agmi.adapters.langgraph_sqlite import LangGraphSqliteAdapter


def test_reference_store_yields_no_findings():
    _authz, findings = hunt_at_rest(ReferenceAtRestAdapter())
    assert findings == []


def test_langgraph_sqlite_serves_every_edit_as_a_finding():
    authz, findings = hunt_at_rest(LangGraphSqliteAdapter())
    assert authz.startswith("library:")
    names = [f.edit for f in findings]
    # all eight record edits plus T9 come back as findings
    for edit in ("tamper", "truncate", "delete_middle", "reorder", "forge",
                 "cross_replay", "rollback_replay", "metadata_tamper",
                 "snapshot_rollback"):
        assert edit in names, edit
    # each finding carries a non-empty reproduction and a detection point
    for f in findings:
        assert f.repro and f.detection_point in ("read", "audit")
        assert f.outcome in ("served", "lost")


def test_authorisation_runs_and_is_reported():
    authz, _findings = hunt_at_rest(LangGraphSqliteAdapter())
    assert "caller" in authz or "library" in authz
