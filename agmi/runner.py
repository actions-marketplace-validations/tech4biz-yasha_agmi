# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Run every attack against every adapter and print a scorecard.

This is the asset: a table where rows are tools, columns are attacks, and
each cell says whether the tool detected that tampering. "VULNERABLE" means
the tool silently accepted a tampered store.
"""

from __future__ import annotations

from agmi.adapters.base import MemoryAdapter
from agmi.attacks.base import Attack, AttackResult


def run_matrix(adapters: list[MemoryAdapter],
               attacks: list[Attack]) -> list[AttackResult]:
    results: list[AttackResult] = []
    for adapter in adapters:
        for attack in attacks:
            results.append(attack.run(adapter))
    return results


def format_scorecard(results: list[AttackResult],
                     attacks: list[Attack]) -> str:
    tools = []
    for r in results:
        if r.tool not in tools:
            tools.append(r.tool)
    attack_names = [a.name for a in attacks]

    index = {(r.tool, r.attack): r for r in results}

    col_w = max([len(n) for n in attack_names] + [10])
    tool_w = max([len(t) for t in tools] + [8])

    def cell(text: str) -> str:
        return text.center(col_w)

    header = " " * tool_w + " | " + " | ".join(cell(n) for n in attack_names)
    rule = "-" * len(header)
    lines = [header, rule]
    for tool in tools:
        row = [tool.ljust(tool_w)]
        for name in attack_names:
            r = index.get((tool, name))
            mark = r.status if r else "?"
            row.append(cell(mark))
        lines.append(" | ".join(row))
    return "\n".join(lines)


def main() -> None:
    from agmi.adapters.openfang import OpenFangAdapter
    from agmi.attacks.at_rest import AT_REST_ATTACKS_WITH_SNAPSHOT as ALL_AT_REST_ATTACKS

    attacks = [cls() for cls in ALL_AT_REST_ATTACKS]
    adapters = [
        OpenFangAdapter(strict_tip=False),  # pre-fix
        OpenFangAdapter(strict_tip=True),   # post-fix
    ]
    # Distinguish the two OpenFang variants in the scorecard.
    adapters[0].name = "openfang(pre-fix)"
    adapters[1].name = "openfang(fixed)"

    results = run_matrix(adapters, attacks)
    print(format_scorecard(results, attacks))
    print()
    for r in results:
        if r.error:
            print(f"  note: {r.tool}/{r.attack} errored: {r.error}")


if __name__ == "__main__":
    main()
