# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Pins the measured at-rest scorecard for the two memory-blackbox rows:
the memory.md watcher with the agent process alive across the edit, and
with the agent restarted between the edit and the scan."""

import importlib.metadata as md
from pathlib import Path

import pytest

pytest.importorskip("memory_blackbox")

from agmi.adapters.memory_blackbox import (  # noqa: E402
    CTX_FILE, MemoryBlackboxMdAdapter, MemoryBlackboxMdRestartAdapter,
)
from agmi.attacks.at_rest import ALL_AT_REST_ATTACKS  # noqa: E402

MEASURED_ON = "memory-blackbox 0.1.1"


def test_version_is_the_measured_one():
    assert md.version("memory-blackbox") == "0.1.1", (
        "memory-blackbox moved; re-measure and re-pin")


@pytest.mark.parametrize("adapter_cls", [MemoryBlackboxMdAdapter, MemoryBlackboxMdRestartAdapter])
def test_every_edit_is_reported_on_scan(adapter_cls):
    for cls in ALL_AT_REST_ATTACKS:
        r = cls().run(adapter_cls())
        assert r.error is None, f"{adapter_cls.name} {r.attack} errored: {r.error}"
        assert r.guard is None, f"{adapter_cls.name} {r.attack} did not land: {r.guard}"
        assert r.detected, f"{adapter_cls.name} {r.attack}: served as genuine on {MEASURED_ON}"


def test_detection_is_on_the_audit_not_the_read_path():
    a = MemoryBlackboxMdAdapter()
    assert a.detection_point == "audit"
    a.setup()
    try:
        a.seed(5)
        recs = a.read_all_raw()
        a.write_raw(a.mutate_payload(recs[2]))
        # the file serves the edit as-is
        assert "[TAMPERED]" in a.read_all_raw()[2].fields["line"]
        assert a.verify() is False
        assert "out-of-band write" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_restart_baselines_from_the_ledger_not_the_file():
    """The 0.1.0 gap, as reported: seed, scan, close, edit the file, open a
    new engine, baseline, scan. On 0.1.1 the new process takes the ledger's
    last write as the baseline and the scan reports the edit."""
    a = MemoryBlackboxMdRestartAdapter()
    a.setup()
    try:
        a.seed(5)
        assert a.verify() is True  # clean, the agent's own write is trusted
        p = Path(a._dir) / CTX_FILE
        p.write_text(p.read_text(encoding="utf-8").replace("limit is 42", "limit is 999"),
                     encoding="utf-8")
        a.reload()  # close the engine, reopen, baseline() in a fresh process
        assert a.verify() is False
        assert "out-of-band write" in (a.verify_detail or "")
    finally:
        a.teardown()


def test_t9_rollback_is_reported_while_the_watcher_is_up_and_served_after_a_restart():
    """T9: the directory (memory.md, ledger, key) restored from an older copy after
    one genuine append. The live watcher still holds the newer digest, so its next
    scan reports the file change; a restarted watcher baselines from the rolled-back
    ledger and serves the older copy as current."""
    from agmi.attacks.at_rest import SnapshotRollbackAttack
    a = MemoryBlackboxMdAdapter()
    r = SnapshotRollbackAttack().run(a)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert r.detected and "out-of-band write" in (a.verify_detail or "")
    b = MemoryBlackboxMdRestartAdapter()
    r = SnapshotRollbackAttack().run(b)
    assert r.error is None and r.guard is None, (r.error, r.guard)
    assert not r.detected
