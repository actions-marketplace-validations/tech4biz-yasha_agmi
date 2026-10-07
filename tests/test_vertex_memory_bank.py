# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for Vertex AI Agent Engine Memory Bank.

Runs only when AGMI_GCP_PROJECT is set and Google application default
credentials are available. The row uses its own scope per run and deletes
its memories afterwards; the Agent Engine it creates is deleted at exit
unless AGMI_VERTEX_KEEP_ENGINE=1 (or AGMI_VERTEX_ENGINE names one to reuse)."""

import importlib.metadata as md
import os

import pytest

pytest.importorskip("vertexai")
if not os.environ.get("AGMI_GCP_PROJECT"):
    pytest.skip("AGMI_GCP_PROJECT not set", allow_module_level=True)

from agmi.adapters.vertex_memory_bank import VertexMemoryBankAdapter  # noqa: E402
from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_SNAPSHOT  # noqa: E402

MEASURED_ON = "google-cloud-aiplatform 2.4.0"
SERVED = {"tamper", "truncate", "delete_middle", "forge", "cross_replay",
          "rollback_replay", "metadata_tamper"}
NOT_APPLICABLE = {"reorder", "snapshot_rollback"}


def test_version_is_the_measured_one():
    assert md.version("google-cloud-aiplatform") == "2.4.0", (
        "google-cloud-aiplatform moved; re-measure and re-pin")


def test_applicable_edits_are_served_and_the_rest_are_not_applicable():
    seen = set()
    for cls in AT_REST_ATTACKS_WITH_SNAPSHOT:
        r = cls().run(VertexMemoryBankAdapter())
        seen.add(r.attack)
        if r.attack in NOT_APPLICABLE:
            assert r.error is not None, f"{r.attack} should be n/a on a managed store, got {r.status}"
            continue
        assert r.error is None, f"{r.attack} errored: {r.error}"
        assert r.guard is None, f"{r.attack} did not land: {r.guard}"
        assert not r.detected, f"{r.attack}: now refused or reported on {MEASURED_ON}; re-pin"
    assert SERVED | NOT_APPLICABLE <= seen


def test_patched_fact_is_what_retrieve_serves():
    """The agent's read path returns the patched fact, with no refusal."""
    a = VertexMemoryBankAdapter()
    a.setup()
    try:
        a.seed(3)
        recs = a.read_all_raw()
        victim = recs[1]
        a.write_raw(a.mutate_payload(victim))
        a.reload()
        assert a.verify() is True, a.verify_detail
        facts = {r.fields["fact"] for r in a.read_all_raw()}
        assert any("[agmi-tampered]" in f for f in facts)
    finally:
        a.teardown()
