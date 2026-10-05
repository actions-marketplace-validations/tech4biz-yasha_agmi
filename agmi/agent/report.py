# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Turn a hunt report into text a person reads and a fixture the benchmark
can adopt. Only proven findings appear; a target with no findings says so."""

from __future__ import annotations

import json

from agmi.agent.hunter import HuntReport
from agmi.agent.at_rest_hunt import AtRestFinding  # noqa: F401


def to_text(report: HuntReport) -> str:
    lines = [
        f"agmi hunt report: {report.target}",
        f"authorisation: {report.authorisation}",
        f"platform: {report.platform}",
        f"attempts: {report.attempts if hasattr(report, 'attempts') else report.tried}",
        "",
    ]
    if not report.findings:
        lines.append("No landing found. Every attack, channel and mutation "
                     "in the default search was kept out of trusted retrieval.")
        return "\n".join(lines) + "\n"
    lines.append(f"{len(report.findings)} finding(s), each proven and "
                 f"reproducible:")
    for n, f in enumerate(report.findings, 1):
        lines += ["", f"[{n}] {f.attack}  ({f.detail})",
                  f"    channel: {f.channel}   mutation: {f.mutation}   "
                  f"fixture: {f.fixture}",
                  f"    proof: the memory served for {f.query!r} contained "
                  f"{f.key!r}", "    reproduce:"]
        lines += [f"      {step}" for step in f.repro]
    return "\n".join(lines) + "\n"


def to_json(report: HuntReport) -> str:
    return json.dumps(report.as_dict(), indent=2) + "\n"


def at_rest_to_text(target: str, authz_line: str, findings: list) -> str:
    lines = [f"agmi storage-side hunt: {target}",
             f"authorisation: {authz_line}", ""]
    if not findings:
        lines.append("No finding. Every storage edit was refused on read or "
                     "reported on audit.")
        return "\n".join(lines) + "\n"
    lines.append(f"{len(findings)} finding(s), each a storage edit the tool "
                 f"served without flagging:")
    for n, f in enumerate(findings, 1):
        lines += ["", f"[{n}] {f.edit}  ({f.outcome}; detection point "
                  f"{f.detection_point})",
                  f"    {f.detail}", "    reproduce:"]
        lines += [f"      {step}" for step in f.repro]
    return "\n".join(lines) + "\n"


def at_rest_to_json(target: str, authz_line: str, findings: list) -> str:
    return json.dumps({"target": target, "authorisation": authz_line,
                       "family": "at-rest",
                       "findings": [f.as_dict() for f in findings]},
                      indent=2) + "\n"


def compose_to_text(target: str, authz_line: str, findings: list) -> str:
    lines = [f"agmi composition engine: {target}",
             f"authorisation: {authz_line}", ""]
    if not findings:
        lines.append("No composite finding. No short sequence of storage "
                     "moves landed where its single moves did not.")
        return "\n".join(lines) + "\n"
    lines.append(f"{len(findings)} composite finding(s): each lands where no "
                 f"single move in it lands alone.")
    for n, f in enumerate(findings, 1):
        lines += ["", f"[{n}] {' -> '.join(f.sequence)}",
                  f"    {f.detail}", "    reproduce:"]
        lines += [f"      {step}" for step in f.repro]
    return "\n".join(lines) + "\n"


def compose_to_json(target: str, authz_line: str, findings: list) -> str:
    return json.dumps({"target": target, "authorisation": authz_line,
                       "family": "composite",
                       "findings": [f.as_dict() for f in findings]},
                      indent=2) + "\n"
