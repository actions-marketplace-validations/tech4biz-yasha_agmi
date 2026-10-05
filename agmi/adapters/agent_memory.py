# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""agent-memory: the MythologIQ Agent Memory reference runtime.

Package `agent-memory-reference` (Apache-2.0, not on PyPI; installed from
github.com/MythologIQ-Labs-LLC/agent-memory at a pinned commit). The
developer facade `AgentMemory.open(state_dir, tenant=...)` gives
`remember()`, `recall()`, `history()`, `posture()` and `close()` over a
governed SQLite runtime. The state directory holds one SQLite file
(`agent-memory.sqlite3`) and a `configuration-binding.json` sidecar that
records the last committed generation and the store's root digests.

What the store claims: every canonical row is hashed into a bucketed
Merkle digest (`digest_rows`, `digest_buckets`), the governance log is
hash-chained, and the sidecar binds the configuration to the base
checkpoint's generation and digests. `open()` fails closed: a digest
mismatch or a generation that disagrees with the sidecar raises
`RuntimeRecoveryError` and no memory is served.

The memory the agent reads back is the `facts` table (one row per
remembered fact, keyed by uuid, owned by `group_id`, which is the tenant).
This adapter edits that table directly and leaves the digest tables and
the sidecar alone, as every other row does: the eight edits are raw
storage edits, not an attacker who recomputes the store's own unkeyed
SHA-256 digests. That attacker is outside the eight and is noted on the
row.

Detection point is the read path: the agent cannot read a single fact
without `open()`, and `open()` is where the check runs. `verify()` opens
the store and runs one `recall()`; a refused open is "rejected".

Second context for T6: Agent Memory refuses to open a state directory
under a different tenant, so the other context is a second state
directory under its own tenant. `replay_onto()` copies that store's
genuine fact bytes onto a victim row here, keeping the victim's uuid.

T8 metadata: `created_at` and `valid_at` on the fact row.

Issue #639 on the Agent Memory repo records which persisted unit the
maintainers consider the supported target; this adapter targets the
SQLite canonical substrate and names it on the row.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

TENANT = "tenant:agmi-a"
OTHER_TENANT = "tenant:agmi-b"
SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"
DB_NAME = "agent-memory.sqlite3"
COLS = ("uuid", "fact_text", "group_id", "episode_uuids_json", "valid_at",
        "invalid_at", "created_at", "expired_at", "attributes_json")


class AgentMemoryAdapter(MemoryAdapter):
    name = "agent-memory"
    detection_point = "read"
    supports_replay = True
    supports_metadata = True

    def __init__(self):
        self._root: str | None = None
        self._seeded = 0

    # --- lifecycle ------------------------------------------------------
    def _dir(self, tenant: str) -> Path:
        return Path(self._root) / tenant.replace(":", "-")

    def _db(self, tenant: str = TENANT) -> Path:
        return self._dir(tenant) / DB_NAME

    def _open(self, tenant: str):
        from agentmem_ref import AgentMemory
        return AgentMemory.open(str(self._dir(tenant)), tenant=tenant)

    def setup(self) -> None:
        self._root = tempfile.mkdtemp(prefix="agmi-agent-memory-")
        self._seeded = 0
        self._dir(TENANT).mkdir()

    def teardown(self) -> None:
        if self._root:
            shutil.rmtree(self._root, ignore_errors=True)
        self._root = None

    def _seed_into(self, tenant: str, token: str, n: int) -> None:
        m = self._open(tenant)
        try:
            for i in range(n):
                m.remember(f"memory:{token}{i}", f"{token}{i}")
        finally:
            m.close()

    def seed(self, n: int) -> None:
        self._seed_into(TENANT, SEED_TOKEN, n)
        self._seeded = n

    # --- raw access -----------------------------------------------------
    def _rows(self, tenant: str) -> list[Record]:
        conn = sqlite3.connect(self._db(tenant))
        rows = conn.execute(
            "SELECT " + ", ".join(COLS) + " FROM facts ORDER BY rowid ASC").fetchall()
        conn.close()
        return [Record(seq=i, fields=dict(zip(COLS, r))) for i, r in enumerate(rows)]

    def read_all_raw(self) -> list[Record]:
        return self._rows(TENANT)

    def _uuid_at(self, seq: int) -> str | None:
        recs = self.read_all_raw()
        return recs[seq].fields["uuid"] if seq < len(recs) else None

    def write_raw(self, record: Record) -> None:
        f = record.fields
        target = self._uuid_at(record.seq)
        conn = sqlite3.connect(self._db())
        if target is None:
            conn.execute(
                "INSERT INTO facts (" + ", ".join(COLS) + ") VALUES (" +
                ",".join("?" * len(COLS)) + ")", tuple(f[c] for c in COLS))
        else:
            sets = ", ".join(f"{c}=?" for c in COLS if c != "uuid")
            conn.execute(f"UPDATE facts SET {sets} WHERE uuid=?",
                         tuple(f[c] for c in COLS if c != "uuid") + (target,))
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        target = self._uuid_at(seq)
        if target is None:
            return
        conn = sqlite3.connect(self._db())
        conn.execute("DELETE FROM facts WHERE uuid=?", (target,))
        conn.commit()
        conn.close()

    def reload(self) -> None:
        # Nothing is cached between calls: every verify() opens the store
        # afresh, which is the restart.
        return None

    def verify(self) -> bool:
        self.verify_detail = None
        try:
            m = self._open(TENANT)
        except Exception as e:  # noqa: BLE001
            self.verify_detail = f"{type(e).__name__}: {e}"
            return False
        try:
            refs = tuple(f"memory:{SEED_TOKEN}{i}" for i in range(self._seeded))
            r = m.recall(SEED_TOKEN, logical_memory_refs=refs)
            admitted = r.get("admitted", [])
            if len(admitted) < self._seeded:
                self.verify_detail = (f"open succeeded; recall admitted "
                                      f"{len(admitted)} of {self._seeded}, no error raised")
            return True
        except Exception as e:  # noqa: BLE001
            self.verify_detail = f"{type(e).__name__}: {e}"
            return False
        finally:
            m.close()

    # --- payload hooks --------------------------------------------------
    def mutate_payload(self, record: Record) -> Record:
        text = record.fields["fact_text"]
        for i in range(100):
            if text == f"{SEED_TOKEN}{i}":
                record.fields["fact_text"] = f"agmi-TAMP-{i}"
                return record
        raise RuntimeError("seed token not found in fact_text")

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["uuid"] = "ref-agmi-forged"
        return self.mutate_payload(forged)

    # --- hooks for T6/T7/T8 ---------------------------------------------
    def seed_other(self, n: int) -> None:
        self._dir(OTHER_TENANT).mkdir(exist_ok=True)
        self._seed_into(OTHER_TENANT, OTHER_TOKEN, n)

    def read_other_raw(self) -> list[Record]:
        return self._rows(OTHER_TENANT)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        target = self._uuid_at(victim_seq)
        if target is None:
            raise RuntimeError("no victim row at that position")
        d = donor.fields
        conn = sqlite3.connect(self._db())
        conn.execute(
            "UPDATE facts SET fact_text=?, episode_uuids_json=?, attributes_json=? WHERE uuid=?",
            (d["fact_text"], d["episode_uuids_json"], d["attributes_json"], target))
        conn.commit()
        conn.close()

    # --- hooks for T9: the state directory is the store ------------------
    supports_snapshot = True

    def snapshot_store(self):
        return self._copy_store(self._dir(TENANT))

    def restore_store(self, token) -> None:
        self._restore_store(token, self._dir(TENANT))

    def append_genuine(self) -> None:
        self._seed_into(TENANT, SEED_TOKEN + "late-", 1)

    # --- guard hooks (control C3): slot, content, owner ------------------
    def identity_of(self, record):
        # Each store numbers its rows from ref-0001, so a row's slot is the
        # pair (store, uuid): two stores' ref-0004 are different slots.
        return f'{record.fields["group_id"]}/{record.fields["uuid"]}'

    def payload_of(self, record):
        return json.dumps({"fact_text": record.fields["fact_text"],
                           "attributes_json": record.fields["attributes_json"]},
                          sort_keys=True)

    def owner_of(self, record):
        return str(record.fields["group_id"])

    def read_meta(self, seq: int) -> dict:
        r = self.read_all_raw()[seq].fields
        return {"created_at": r["created_at"], "valid_at": r["valid_at"]}

    def write_meta(self, seq: int, meta: dict) -> None:
        target = self._uuid_at(seq)
        created = "2030-01-01T00:00:00Z" if meta.get("agmi_meta_tampered") else meta.get("created_at")
        conn = sqlite3.connect(self._db())
        conn.execute("UPDATE facts SET created_at=? WHERE uuid=?", (created, target))
        conn.commit()
        conn.close()
