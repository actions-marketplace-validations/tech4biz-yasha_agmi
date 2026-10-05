# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Adapter for CrewAI's unified long-term memory on its LanceDB store (the real library).

As of CrewAI 1.15 the memory system no longer uses a SQLite table; long-term
memory is a `LanceDBStorage` backend, a LanceDB dataset (`memories.lance`: a
columnar data directory plus a transaction log and versioned manifests). Every
result here is a measurement of `crewai` at the pinned version, seeded through
`LanceDBStorage.save()` and read back through `LanceDBStorage.search()`.

Store layout (as created by the library):
    memories.lance table, columns:
      id, content, scope, categories_str, metadata_str, importance,
      created_at, last_accessed, source, private, vector

Ordering: the adapter keeps seed order by `id` (m0, m1, ...), so `seq` is the
ordinal position of a row in id order.

What "verify" means here: the library has no integrity check on its store.
LanceDB keeps versions and the vector index points at the data file it was
built on, so a raw edit only reaches the read path once the dataset is
reopened. The adapter therefore reopens the store (the agent restarting and
reading again, the at-rest model) before verifying. verify() returns True when
`search()` returns the seeded rows without raising, and False only when the
library itself raises.

T8 metadata: besides `content` the row carries `scope` (the owner),
`metadata_str`, `importance`, `created_at`, `source` and `private`. The generic
T8 edit adds a key no column holds, so write_meta() applies it as a rewritten
`created_at`: that is what the T8 cell measures. A changed `scope` (move to
another agent) is measured separately in the pinned tests.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime, timezone

from agmi.adapters.base import MemoryAdapter, Record

SCOPE = "agent:agmi-A"
OTHER_SCOPE = "agent:agmi-B"
SEED = "agmi-seed-"
OTHER = "agmi-other-"
VDIM = 8


def _emb(i: int, ctx: str) -> list[float]:
    # deterministic, distinct per context; close within a context so search
    # returns every seeded row of that context.
    base = 0.9 if ctx == SCOPE else 0.1
    v = [base] * VDIM
    v[0] = base + i * 1e-4
    return v


class CrewAILanceDBAdapter(MemoryAdapter):
    name = "crewai-ltm-lancedb"
    detection_point = "read"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True

    def __init__(self):
        self._dir: str | None = None
        self._store = None
        self._ids: list[str] = []
        self._other_ids: list[str] = []

    # --- lifecycle --------------------------------------------------------

    def _open(self):
        from crewai.memory.storage.lancedb_storage import LanceDBStorage
        self._store = LanceDBStorage(path=self._dir, vector_dim=VDIM, compact_every=0)

    def setup(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="agmi-crewai-")
        self._open()
        self._ids = []
        self._other_ids = []

    def teardown(self) -> None:
        self._store = None
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None

    def _record(self, rid: str, content: str, scope: str, i: int):
        from crewai.memory.storage.backend import MemoryRecord
        ts = datetime.fromtimestamp(1_700_000_000 + i, tz=timezone.utc)
        return MemoryRecord(
            id=rid, content=content, scope=scope, categories=["agmi"],
            metadata={"seq": i}, importance=0.5, created_at=ts, last_accessed=ts,
            embedding=_emb(i, scope), source="user", private=False)

    # --- the tool's own write path ----------------------------------------

    def _seed(self, scope: str, token: str, n: int, store_ids: list[str]) -> None:
        recs = []
        for i in range(n):
            rid = f"{'m' if scope == SCOPE else 'o'}{i}"
            recs.append(self._record(rid, f"{token}{i}: the limit is {40 + i}", scope, i))
            store_ids.append(rid)
        self._store.save(recs)

    def seed(self, n: int) -> None:
        self._seed(SCOPE, SEED, n, self._ids)

    def seed_other(self, n: int) -> None:
        self._seed(OTHER_SCOPE, OTHER, n, self._other_ids)

    # --- raw access, bypassing the tool -----------------------------------

    def _table(self):
        import lancedb
        db = lancedb.connect(self._dir)
        return db.open_table("memories")

    def _rows(self, ids: list[str]) -> list[dict]:
        t = self._table()
        got = {r["id"]: r for r in t.search().limit(10_000).to_list()}
        return [got[i] for i in ids if i in got]

    def _scope_rows(self, scope: str, seeded: list[str]) -> list[dict]:
        # Every row in this scope, bypassing the tool: seeded rows first in
        # seed order, then any row an attacker added to the scope (a forgery),
        # so the landed-control sees inserts and deletions the scorecard makes.
        t = self._table()
        by_id = {r["id"]: r for r in t.search().limit(10_000).to_list()}
        ordered = [by_id[i] for i in seeded if i in by_id]
        extra = [r for rid, r in by_id.items()
                 if rid not in seeded and r.get("scope") == scope]
        return ordered + extra

    def _to_record(self, row: dict, seq: int) -> Record:
        return Record(seq=seq, fields={
            "id": row["id"], "content": row["content"], "scope": row["scope"],
            "created_at": row.get("created_at"), "row": row})

    def read_all_raw(self) -> list[Record]:
        return [self._to_record(r, i) for i, r in enumerate(self._scope_rows(SCOPE, self._ids))]

    def read_other_raw(self) -> list[Record]:
        return [self._to_record(r, i) for i, r in enumerate(self._scope_rows(OTHER_SCOPE, self._other_ids))]

    def _id_at(self, seq: int) -> str:
        return self._ids[seq]

    def write_raw(self, record: Record) -> None:
        # Overwrite the content of the row at this seq (T1, and each half of a
        # reorder swap), or, when the record is a forgery whose id is not among
        # the seeded rows, append it as a new row (T5).
        t = self._table()
        if 0 <= record.seq < len(self._ids):
            rid = self._id_at(record.seq)
            t.update(where=f"id = '{rid}'", values={"content": record.fields["content"]})
        else:
            template = t.search().limit(1).to_list()[0]
            row = dict(template)
            row.pop("_distance", None)
            row["id"] = record.fields.get("id", "agmi-forged")
            row["content"] = record.fields["content"]
            t.add([row])

    def delete_raw(self, seq: int) -> None:
        t = self._table()
        t.delete(f"id = '{self._id_at(seq)}'")

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        # T6/T7: put the donor's content (and, for T6, keep the victim's scope)
        # into the victim row.
        t = self._table()
        t.update(where=f"id = '{self._id_at(victim_seq)}'",
                 values={"content": donor.fields["content"]})

    def read_meta(self, seq: int) -> dict:
        # Expose created_at as the row's tamperable label (T8). scope moves are
        # measured separately in the pinned test via write_meta(scope=...).
        row = self._rows([self._id_at(seq)])[0]
        return {"created_at": str(row.get("created_at"))}

    def write_meta(self, seq: int, meta: dict) -> None:
        t = self._table()
        vals = {}
        if "scope" in meta:
            vals["scope"] = meta["scope"]
        # Any extra key the generic T8 edit adds, or an explicit created_at,
        # lands as a rewritten created_at (the row's tamperable label here).
        extra = {k: v for k, v in meta.items() if k != "scope"}
        if extra:
            vals["created_at"] = datetime.fromtimestamp(1_500_000_000, tz=timezone.utc)
        if vals:
            t.update(where=f"id = '{self._id_at(seq)}'", values=vals)

    def mutate_payload(self, record: Record) -> Record:
        r = dict(record.fields)
        r["content"] = r["content"] + " [tampered]"
        return Record(seq=record.seq, fields=r)

    def forge_record(self, template: Record) -> Record:
        r = dict(template.fields)
        r["id"] = "agmi-forged"
        r["content"] = "forged: the limit is 999"
        return Record(seq=len(self._ids), fields=r)

    def identity_of(self, record: Record) -> str:
        return str(record.fields["id"])

    def payload_of(self, record: Record) -> str:
        return str(record.fields["content"])

    def owner_of(self, record: Record) -> str | None:
        return str(record.fields.get("scope"))

    # --- T9 whole-store rollback: the lance dataset directory --------------

    def snapshot_store(self):
        self._store = None  # release handles so the dir copies cleanly
        token = tempfile.mkdtemp(prefix="agmi-crewai-snap-")
        shutil.copytree(self._dir, token, dirs_exist_ok=True)
        self._open()
        return token

    def restore_store(self, token) -> None:
        self._store = None
        for p in os.scandir(self._dir):
            shutil.rmtree(p.path, ignore_errors=True) if p.is_dir() else os.remove(p.path)
        shutil.copytree(token, self._dir, dirs_exist_ok=True)
        shutil.rmtree(token, ignore_errors=True)
        self._open()

    def append_genuine(self) -> None:
        i = len(self._ids)
        rid = f"m{i}"
        self._store.save([self._record(rid, f"{SEED}{i}: the limit is {40 + i}", SCOPE, i)])
        self._ids.append(rid)

    # --- the tool's own read path -----------------------------------------

    def reload(self) -> None:
        # The at-rest model: the agent restarts, so a fresh store opens the
        # dataset at its latest on-disk version and rebuilds its view.
        self._store = None
        self._open()

    def verify(self) -> bool:
        self.verify_detail = None
        try:
            res = self._store.search(query_embedding=_emb(0, SCOPE), limit=10_000)
        except Exception as exc:  # noqa: BLE001
            self.verify_detail = f"search raised: {type(exc).__name__}: {exc}"[:200]
            return False
        got = {r.id: r.content for r, _ in res}
        for i, rid in enumerate(self._ids):
            want = f"{SEED}{i}: the limit is {40 + i}"
            if got.get(rid) != want:
                # served something other than the seeded value -> accepted
                return True
        return True
