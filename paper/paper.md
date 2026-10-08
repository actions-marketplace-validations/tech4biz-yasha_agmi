---
title: 'agmi: a conformance test suite for the integrity of AI agent memory at rest'
tags:
  - Python
  - AI agents
  - agent memory
  - security
  - benchmarking
  - tamper evidence
authors:
  - name: Yasha Khandelwal
    orcid: 0009-0005-2166-4951
    affiliation: 1
affiliations:
  - name: Tech4Biz Solutions, Bengaluru, India
    index: 1
date: 8 October 2026
bibliography: paper.bib
---

# Summary

AI agents built on frameworks such as LangGraph, Letta, Mem0 and the OpenAI Agents SDK persist state between sessions: long-term memory records, execution checkpoints and their metadata. On the next turn the agent reads that state back and acts on it as if it were its own prior experience. `agmi` (Agent Memory Integrity) measures whether a memory or checkpoint store notices when that persisted state has been altered at the storage layer, by a party who holds the file, database or volume but no key and no API access.

The method is fixed and small. A store is seeded through its own API. One of nine storage-level edits is applied behind its back: content change, tail removal, deletion of a middle record, reordering, forged insertion, cross-context replay of a genuine record from another tenant, rollback of one record to an older genuine copy, metadata change, and rollback of the whole store to an older snapshot. The store is reopened the way its users would reopen it and asked to read again through its own read path. Each cell records one of three verdicts: the store refused the edited record on read, the store reported it on a later audit the operator has to run, or the store served the edit as genuine. Three controls run before any verdict counts: the edit must land on disk as intended, a clean reopen must verify, and a no-op must not score. A second family of six attacks reaches the store through its front door, the agent's own write and retrieval API, and asks whether planted content reaches the agent or crosses a user boundary.

`agmi` ships adapters for the eighteen stores on the board and the reference models, a public results file that every published table is generated from, a GitHub Action that fails a build when a store serves an edited record as genuine, a storage-side hunt that composes edits to find sequences no single edit lands, and an independent verifier for the anchored-record-chain test-vector corpus of the OWASP agentic security initiative's Pillar 3 work. As of this writing the public scorecard holds 31 measured rows across 18 stores, including Google's Vertex AI Memory Bank, the first managed cloud memory service on the board.

# Statement of need

Agent memory is treated as a record: in finance, healthcare and anything with a regulator it is the audit trail of what the agent knew when it acted, and an agent's past decisions are replayed to justify its next one. Yet the security literature on agent memory concentrates almost entirely on the input path, prompt injection and poisoning through the agent's own write interface [@zhou2026memsecbench; @owasp2026asi]. No independent yardstick existed for the storage path: whether a store that someone else can write to, a shared Postgres, a mounted volume, a restored backup, a cloud data-plane role, lets the agent notice that its memory was changed.

The gap is measurable rather than theoretical. Of the nine stores on the board that make no integrity claim, all nine served every applicable edit as genuine. Of the nine that do claim tamper evidence, most report edits only when an audit is run after the agent has already acted; the detection point matters as much as detection, and the board names it for every row. Two findings generalise across stores: a genuine record copied from another tenant keeps every byte and every signature valid and is served as the victim's own unless the integrity binding covers tenant, position and predecessor, and a rollback of the whole store to an older snapshot is caught only by a head or key held outside the store.

Four tool maintainers have reproduced their own rows; one correction to the harness, found by one of them, changed four cells and is recorded with credit in the changelog. AWS's Well-Architected Agentic AI Lens now prescribes cryptographic integrity verification on memory reads [@aws2026lens]; `agmi` is the first place that practice can be checked against what stores actually do.

# State of the field

Front-door benchmarks measure whether an attacker can get content into memory through the agent: MemSecBench [@zhou2026memsecbench], the memory-integrity benchmark used in the AtMem paper [@atmem2026beyond], and the OWASP Agent Memory Guard reference implementation [@owasp2026amg] all work on the write path. Tamper-evident stores and audit layers such as inspeximus, AtMem, Atelya Attest, CONTINUUM and memory-blackbox each publish their own claim; `agmi` measures those claims with one yardstick and names the detection point. The `agent-evidence-vectors` corpus [@gilda2026vectors] fixes expected verdicts for an anchored record chain under the same nine edits; `agmi`'s verifier reaches the expected decision and reason on all fourteen of its cases. To the author's knowledge no other tool applies a fixed set of storage-level edits across stores, through each store's own read path, with the landed, clean-reopen and no-op controls, and publishes the matrix whichever way it falls.

# Software design

Each store is wrapped by a small adapter that exposes `setup`, `seed`, `read_all_raw`, the edit primitives the attacker needs, and `close`; adding a store means writing one adapter and nothing else. Attacks are versioned classes, so a cell records the attack version, the store version, the platform and the exact words the tool returned, and a later change to an attack cannot silently change an older cell. The results file is the single source: the Markdown scorecard, the README table, the badge endpoints and the public site are generated from it, and continuous integration fails if any published table drifts from the file. The pass rule is deliberately narrow: a store is credited with detection only when it raises, refuses or reports the problem itself; a changed answer is never inferred as detection. The GitHub Action wraps the same runner so a store's own CI can fail when a row regresses.

# Research impact statement

The suite is the test method proposed for the "Protection of Memory Data Integrity" metric in the IETF Benchmarking Methodology Working Group [@khandelwal2026draft], the memory-integrity evidence in the OWASP agentic security maturity model's traceability pillar, and the measurement the author of the IETF HDP agentic delegation draft requested against his reference implementation. Two maintainers run the GitHub Action in their own CI, four have reproduced their rows, one vendor fix was made in response to a measurement, and the verifier agrees with an independently authored test-vector corpus [@gilda2026vectors] on all fourteen cases. These are the uses a measurement tool exists for: a shared yardstick that standards text, vendor claims and outside corpora can all point at.

# AI usage disclosure

The author used Claude (Anthropic) as an assistant while writing code, documentation and this paper. Every adapter, attack and verdict rule was designed, run and checked by the author on the stores named; every published cell comes from a run on the author's machine or in continuous integration, and outside maintainers reproduced the rows that concern them. No measurement in the results file was produced or edited by an AI tool.

# Acknowledgements

Rastislav (DanceNitra) found and fixed the cross-context replay no-op on two adapters. Javad (AtMem), Lav Kumar Vishwakarma (memory-blackbox), Kevin (MythologIQ) and Sankalp Gilda (agent-evidence-vectors) reproduced rows or corpus results and shaped the wording of their configurations.

# References
