# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
import json

import pytest

from agmi.merge_rows import MergeError, main, merge

V = {"tamper": 1}


def run(rows, versions=V, date="2026-10-08"):
    return {"date": date, "platform": "p", "attack_versions": versions, "attackers": {},
            "rows": [{"label": lb, "cells": {"tamper": {"verdict": v}}, "measured_on": None}
                     for lb, v in rows]}


def test_replaces_in_place_and_keeps_order_and_header():
    base = run([("a", "accepted"), ("x", "accepted"), ("b", "accepted")])
    extra = run([("x", "reported"), ("y", "reported")], date="2026-10-10")
    out = merge(base, extra, ["x"], "elsewhere")
    assert [r["label"] for r in out["rows"]] == ["a", "x", "b"]
    assert out["rows"][1]["cells"]["tamper"]["verdict"] == "reported"
    assert out["rows"][1]["measured_on"] == "elsewhere"
    assert out["date"] == "2026-10-08"
    assert base["rows"][1]["cells"]["tamper"]["verdict"] == "accepted"


def test_appends_a_new_label():
    out = merge(run([("a", "accepted")]), run([("z", "reported")]), ["z"])
    assert [r["label"] for r in out["rows"]] == ["a", "z"]


def test_refuses_different_attack_versions():
    with pytest.raises(MergeError):
        merge(run([("a", "accepted")]), run([("a", "reported")], versions={"tamper": 2}), ["a"])


def test_refuses_a_missing_label():
    with pytest.raises(MergeError):
        merge(run([("a", "accepted")]), run([("b", "reported")]), ["a"])


def test_cli_writes_the_file_in_the_runner_format(tmp_path):
    b, e = tmp_path / "b.json", tmp_path / "e.json"
    b.write_text(json.dumps(run([("a", "accepted")]), indent=2) + "\n")
    e.write_text(json.dumps(run([("a", "reported")]), indent=2) + "\n")
    assert main([str(b), str(e), "--labels", "a"]) == 0
    out = json.loads(b.read_text())
    assert out["rows"][0]["cells"]["tamper"]["verdict"] == "reported"
    assert b.read_text() == json.dumps(out, indent=2) + "\n"
    e.write_text(json.dumps(run([("q", "reported")]), indent=2) + "\n")
    assert main([str(b), str(e), "--labels", "a"]) == 1
