# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Carry rows measured in another environment into the results file.

Some stores cannot share one Python environment: AtMem 2.3.8 requires
cryptography below 49 and the Agent Memory reference runtime requires 50.
Run the full runner in each environment with --json, then merge the named
rows into the main results file:

    python -m agmi.merge_rows results/scorecard.json /tmp/atmem.json \\
        --labels atmem-chain atmem-chain+checkpoint

Each named row replaces the row with the same label in place, or is appended
if the label is new. The base file's date, platform and attack versions are
kept, so --measured-on records where and when the merged rows were measured.
The merge refuses if the two runs used different attack versions, or if a
named row is missing from the other run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


class MergeError(Exception):
    pass


def merge(base: dict, extra: dict, labels: list[str], measured_on: str | None = None) -> dict:
    if base.get("attack_versions") != extra.get("attack_versions"):
        raise MergeError("the two runs used different attack versions; re-run both")
    by_label = {r["label"]: r for r in extra.get("rows", [])}
    missing = [lb for lb in labels if lb not in by_label]
    if missing:
        raise MergeError(f"not in the other run: {', '.join(missing)}")
    rows = list(base.get("rows", []))
    index = {r["label"]: i for i, r in enumerate(rows)}
    for lb in labels:
        row = json.loads(json.dumps(by_label[lb]))
        if measured_on is not None:
            row["measured_on"] = measured_on
        if lb in index:
            rows[index[lb]] = row
        else:
            rows.append(row)
    out = dict(base)
    out["rows"] = rows
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agmi.merge_rows")
    ap.add_argument("base", type=Path, help="results file to update in place")
    ap.add_argument("extra", type=Path, help="--json output of the other environment's run")
    ap.add_argument("--labels", nargs="+", required=True, help="row labels to carry over")
    ap.add_argument("--measured-on", default=None, help="where and when those rows were measured")
    a = ap.parse_args(argv)
    try:
        out = merge(json.loads(a.base.read_text()), json.loads(a.extra.read_text()),
                    a.labels, a.measured_on)
    except MergeError as e:
        print(f"merge refused: {e}", file=sys.stderr)
        return 1
    a.base.write_text(json.dumps(out, indent=2) + "\n")
    print(f"merged {', '.join(a.labels)} into {a.base}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
