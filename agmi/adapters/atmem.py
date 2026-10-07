# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""AtMem (PyPI `atmem`, aetna000/atmem): an auditable agent memory engine
on one SQLite file, with a hash-chained audit log, an externally anchored
checkpoint, and a verifier that walks the chain.

What the engine keeps, as created by `Memory("memories.db")`:
    records(id PK, subject_id, content, source_type, trust_tier,
            created_at, status, scope, fact_key, raw, ...)   the memory
    audit_log(sequence, subject_id, event_type, record_id, payload,
              prev_hash, event_hash)                        the chain
plus episodes, entities, edges, FTS maps and the engine's own state.
`remember()` through the trusted `user_message` path writes a record and
appends `memory.record_created` to the chain with the record's
`content_sha256` in the event payload. `list()` and `recall()` read the
records table. `verify()` recomputes every event hash and link in
`audit_log`; with a checkpoints file it also checks that each pinned
(sequence, event_hash) is still present, which is how a truncated chain is
caught. `checkpoint()` writes the chain heads to a JSONL sink the docstring
says to keep where the database owner cannot rewrite it.

These rows take the records table as the memory store, because that is
what the agent reads back: seeded through `remember()`, read through
`list()` for the subject, in the engine's own order (created_at, id). The
attacker holds the SQLite file and edits records with the engine closed.
The audit is `verify()` for the subject. Two rows:

* `atmem-chain`: `verify()` alone, the chain as kept in the store.
* `atmem-chain+checkpoint`: `verify()` with a checkpoints file written by
  the engine after every genuine write and kept outside the store
  directory, where the attacker cannot reach it.

Detection point is the audit in both cases: nothing on the read path
consults the chain.

T8 metadata: the per-record metadata the engine keeps is `subject_id`,
`source_type`, `trust_tier` and `created_at`. The generic T8 edit adds a
key no column can hold, so `write_meta()` applies it as a rewritten
`source_type` (a trusted user note relabelled as a web page); `created_at`
is the engine's ordering key and is left alone so the record keeps its
slot. A changed `subject_id` (moving the record to another user) is
measured separately in the pinned tests.

T9: the store is the directory holding `memories.db` and its WAL, shm and
lock files, so a restore puts back everything the engine keeps on disk.
The checkpoints file is not in that directory.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

SUBJECT = "agmi-user-A"
OTHER = "agmi-user-B"
SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"
COLS = ("id", "subject_id", "content", "source_type", "trust_tier",
        "created_at", "status", "scope", "fact_key", "raw", "confidence")
# Columns a raw write may change on an existing row. `created_at` is the
# engine's ordering key, so it stays with the slot: a swap exchanges what two
# slots say, not where they sit. A new row (forge) carries its own timestamp.
_WRITABLE = ("content", "source_type", "trust_tier", "status",
             "scope", "fact_key", "raw", "confidence")
_INSERT = ("id", "subject_id", "created_at") + _WRITABLE


class AtMemChainAdapter(MemoryAdapter):
    """records as the store, verify() on the chain as the audit."""

    name = "atmem-chain"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = True
    detection_point = "audit"
    anchored = False

    def __init__(self):
        self._dir: str | None = None
        self._anchor_dir: str | None = None
        self._seeded = 0

    # --- lifecycle ---------------------------------------------------------

    def setup(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="agmi-atmem-")
        self._anchor_dir = tempfile.mkdtemp(prefix="agmi-atmem-anchor-")
        self._seeded = 0
        m = self._open()
        m.close()

    def teardown(self) -> None:
        for d in (self._dir, self._anchor_dir):
            if d:
                shutil.rmtree(d, ignore_errors=True)
        self._dir = self._anchor_dir = None

    @property
    def _db(self) -> Path:
        return Path(self._dir) / "memories.db"

    @property
    def _checkpoints(self) -> Path:
        return Path(self._anchor_dir) / "checkpoints.jsonl"

    def _open(self):
        from atmem import Memory
        return Memory(str(self._db))

    # --- the engine's own write path --------------------------------------

    def _remember(self, subject: str, text: str, turn: int) -> None:
        m = self._open()
        try:
            out = m.remember(subject, text, source_type="user_message", force=True,
                             session_id="agmi", turn_id=turn)
            if len(out.get("records", [])) != 1:
                raise RuntimeError(f"remember() stored {len(out.get('records', []))} records for {text!r}")
            if self.anchored and subject == SUBJECT:
                m.checkpoint(sink_path=self._checkpoints)
        finally:
            m.close()

    def seed(self, n: int) -> None:
        for i in range(n):
            self._remember(SUBJECT, f"{SEED_TOKEN}{i} kappa {40 + i}", i)
        self._seeded = n

    def seed_other(self, n: int) -> None:
        for i in range(n):
            self._remember(OTHER, f"{OTHER_TOKEN}{i} lambda {70 + i}", i)

    # --- raw access, the engine closed ------------------------------------

    def _raw(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db)
        conn.row_factory = sqlite3.Row
        return conn

    def _rows(self, subject: str) -> list[Record]:
        conn = self._raw()
        try:
            rows = conn.execute(
                f"SELECT {', '.join(COLS)} FROM records WHERE subject_id = ? "
                "AND status = 'active' ORDER BY created_at ASC, id ASC",
                (subject,)).fetchall()
        finally:
            conn.close()
        return [Record(seq=i, fields=dict(r)) for i, r in enumerate(rows)]

    def read_all_raw(self) -> list[Record]:
        return self._rows(SUBJECT)

    def read_other_raw(self) -> list[Record]:
        return self._rows(OTHER)

    def _id_at(self, seq: int) -> str | None:
        recs = self.read_all_raw()
        return recs[seq].fields["id"] if seq < len(recs) else None

    def write_raw(self, record: Record) -> None:
        f = record.fields
        target = self._id_at(record.seq)
        conn = self._raw()
        try:
            if target is None:
                conn.execute(
                    f"INSERT INTO records ({', '.join(_INSERT)}) VALUES ({', '.join('?' * len(_INSERT))})",
                    tuple(f.get(c) for c in _INSERT))
            else:
                sets = ", ".join(f"{c} = ?" for c in _WRITABLE)
                conn.execute(f"UPDATE records SET {sets} WHERE id = ?",
                             tuple(f.get(c) for c in _WRITABLE) + (target,))
            conn.commit()
        finally:
            conn.close()

    def delete_raw(self, seq: int) -> None:
        target = self._id_at(seq)
        if target is None:
            return
        conn = self._raw()
        try:
            conn.execute("DELETE FROM records WHERE id = ?", (target,))
            conn.commit()
        finally:
            conn.close()

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        target = self._id_at(victim_seq)
        if target is None:
            raise RuntimeError("no victim row at that position")
        conn = self._raw()
        try:
            conn.execute("UPDATE records SET content = ?, raw = ? WHERE id = ?",
                         (donor.fields["content"], donor.fields["raw"], target))
            conn.commit()
        finally:
            conn.close()

    # --- payload hooks ------------------------------------------------------

    def mutate_payload(self, record: Record) -> Record:
        record.fields["content"] = record.fields["content"] + " [TAMPERED]"
        return record

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["id"] = "rec_agmi_forged"
        forged.fields["content"] = "Agmi-forged kappa 999."
        forged.fields["created_at"] = "2099-01-01T00:00:00.000000+00:00"
        return forged

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return str(record.fields["id"])

    def payload_of(self, record):
        return str(record.fields["content"])

    def owner_of(self, record):
        return str(record.fields["subject_id"])

    # --- T8 metadata --------------------------------------------------------

    def read_meta(self, seq: int) -> dict:
        r = self.read_all_raw()[seq].fields
        return {"subject_id": r["subject_id"], "source_type": r["source_type"],
                "trust_tier": r["trust_tier"], "created_at": r["created_at"]}

    def write_meta(self, seq: int, meta: dict) -> None:
        target = self._id_at(seq)
        if target is None:
            raise RuntimeError("no row at that position")
        current = self.read_meta(seq)
        new = {k: meta.get(k, current[k]) for k in current}
        if set(meta) - set(current) and new == current:
            # No column can hold the extra key: apply the tamper to the source
            # label instead, so the metadata edit is real on disk. The
            # timestamp is the engine's ordering key and is left alone, so the
            # record keeps its slot; a trusted user note now reads as a web page.
            new["source_type"] = "webpage"
        conn = self._raw()
        try:
            conn.execute(
                "UPDATE records SET subject_id = ?, source_type = ?, trust_tier = ?, "
                "created_at = ? WHERE id = ?",
                (new["subject_id"], new["source_type"], new["trust_tier"],
                 new["created_at"], target))
            conn.commit()
        finally:
            conn.close()

    # --- restart and the audit ---------------------------------------------

    def reload(self) -> None:
        return  # nothing is cached in process; every call opens the engine afresh

    def verify(self) -> bool:
        self.verify_detail = None
        m = self._open()
        try:
            try:
                served = m.list(SUBJECT)
            except Exception as e:  # noqa: BLE001
                self.verify_detail = f"list(): {type(e).__name__}: {e}"[:200]
                return False
            report = m.verify(SUBJECT, checkpoints_path=self._checkpoints if self.anchored else None)
        finally:
            m.close()
        subject = report.get("subjects", {}).get(SUBJECT, {})
        if not report.get("valid", False):
            failures = subject.get("failures") or []
            reason = failures[0].get("reason") if failures else "chain_valid is false"
            self.verify_detail = f"verify: {reason}"[:200]
            return False
        if len(served) != self._seeded:
            self.verify_detail = (f"list returned {len(served)} of {self._seeded}; "
                                  f"verify valid, checkpoints_checked={subject.get('checkpoints_checked', 0)}")
        return True

    # --- T9 whole-store rollback: the store directory rolls back, the
    # --- checkpoints file (a separate directory) does not -----------------

    def snapshot_store(self):
        token = tempfile.mkdtemp(prefix="agmi-atmem-snap-")
        shutil.copytree(self._dir, token, dirs_exist_ok=True)
        return token

    def restore_store(self, token) -> None:
        for p in Path(self._dir).iterdir():
            p.unlink() if p.is_file() else shutil.rmtree(p, ignore_errors=True)
        shutil.copytree(token, self._dir, dirs_exist_ok=True)
        shutil.rmtree(token, ignore_errors=True)

    def append_genuine(self) -> None:
        self._remember(SUBJECT, f"{SEED_TOKEN}late kappa 99", 99)


class AtMemAnchoredAdapter(AtMemChainAdapter):
    """Chain plus a checkpoints file the attacker cannot reach."""

    name = "atmem-chain+checkpoint"
    anchored = True
