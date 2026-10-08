# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""agmi's independent verifier for the anchored-record-chain corpus
(probityai/agent-evidence-vectors at 74b8b98) must reach every expected
decision and reason. The corpus is vendored under tests/vectors with its
licence; its MANIFEST digests pin the fixtures."""

import hashlib
import json
from pathlib import Path

import pytest

from agmi.anchored_chain import verify_case

ROOT = Path(__file__).parent / "vectors" / "anchored-chain-74b8b98"
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text())
CASES = {v["id"]: v for v in MANIFEST["vectors"]}


def test_fixtures_match_manifest_digests():
    for v in MANIFEST["vectors"]:
        for name, digest in v["files"].items():
            assert hashlib.sha256((ROOT / v["path"] / name).read_bytes()).hexdigest() == digest, f"{v['id']}/{name}"


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_decision_and_reason_match_the_corpus(case_id):
    v = CASES[case_id]
    got = verify_case(ROOT / v["path"] / "case.json")
    assert got == v["expected"], f"{case_id}: expected {v['expected']}, got {got}"


def test_every_draft_edit_has_a_case():
    ids = set(CASES)
    for t in range(1, 10):
        assert any(i.startswith(f"t{t}-") for i in ids), f"no case for T{t}"
