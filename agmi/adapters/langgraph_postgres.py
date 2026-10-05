# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""LangGraph `PostgresSaver` (langgraph-checkpoint-postgres): the checkpointer
production LangGraph deployments run on.

Schema: `checkpoints` (thread_id, checkpoint_ns, checkpoint_id,
parent_checkpoint_id, type, checkpoint JSONB, metadata JSONB) plus
`checkpoint_blobs` for non-primitive channel values and `checkpoint_writes`
for pending writes. With primitive state the channel values sit inline in
the `checkpoint` JSONB, which is what these edits touch.

Connection comes from AGMI_POSTGRES_URI (for example
postgresql://postgres:agmi@localhost:5433/agmi). Each run uses its own
schema named agmi_<random> so a shared database is never touched, and the
schema is dropped on teardown.

The read path is `PostgresSaver.get()` and `.list()`, unchanged; there is
no integrity logic on the store, so this row is measured for the record,
the same as SqliteSaver.
"""

from __future__ import annotations

import json
import os
import secrets

from agmi.adapters.base import MemoryAdapter, Record

THREAD = "agmi-thread"
OTHER_THREAD = "agmi-thread-B"
SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"
COLS = ("thread_id", "checkpoint_ns", "checkpoint_id", "parent_checkpoint_id",
        "type", "checkpoint", "metadata")


def postgres_uri() -> str | None:
    return os.environ.get("AGMI_POSTGRES_URI")


class LangGraphPostgresAdapter(MemoryAdapter):
    name = "langgraph-postgres"
    supports_replay = True
    supports_metadata = True
    detection_point = "read"

    def __init__(self, uri: str | None = None):
        self._uri = uri or postgres_uri()
        self._schema: str | None = None
        self._saver_cm = None
        self._saver = None

    # --- lifecycle ---------------------------------------------------------

    def _conn(self):
        import psycopg
        conn = psycopg.connect(self._uri, autocommit=True)
        conn.execute(f'SET search_path TO "{self._schema}"')
        return conn

    def _open_saver(self):
        from langgraph.checkpoint.postgres import PostgresSaver
        from psycopg import Connection
        from psycopg.rows import dict_row
        conn = Connection.connect(self._uri, autocommit=True, prepare_threshold=0,
                                  row_factory=dict_row,
                                  options=f'-c search_path="{self._schema}"')
        self._conn_obj = conn
        self._saver = PostgresSaver(conn)

    def setup(self) -> None:
        if not self._uri:
            raise RuntimeError("AGMI_POSTGRES_URI is not set")
        self._schema = f"agmi_{secrets.token_hex(4)}"
        import psycopg
        with psycopg.connect(self._uri, autocommit=True) as c:
            c.execute(f'CREATE SCHEMA "{self._schema}"')
        self._open_saver()
        self._saver.setup()

    def teardown(self) -> None:
        try:
            self._conn_obj.close()
        except Exception:  # noqa: BLE001
            pass
        self._saver = None
        if self._schema:
            import psycopg
            try:
                with psycopg.connect(self._uri, autocommit=True) as c:
                    c.execute(f'DROP SCHEMA "{self._schema}" CASCADE')
            except Exception:  # noqa: BLE001
                pass
        self._schema = None

    # --- the tool's own write path ----------------------------------------

    def _seed_thread(self, thread_id: str, token: str, n: int) -> None:
        from langgraph.checkpoint.base import create_checkpoint, empty_checkpoint
        cfg = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
        cp = empty_checkpoint()
        for i in range(n):
            cp = create_checkpoint(cp, {"state": f"{token}{i}"}, i)
            cp["channel_values"] = {"state": f"{token}{i}"}
            cfg = self._saver.put(cfg, cp, {"source": "loop", "step": i, "writes": {}},
                                  {"state": str(i + 1)})

    def seed(self, n: int) -> None:
        self._seed_thread(THREAD, SEED_TOKEN, n)

    def seed_other(self, n: int) -> None:
        self._seed_thread(OTHER_THREAD, OTHER_TOKEN, n)

    # --- raw access, bypassing the tool -----------------------------------

    def _rows(self, thread_id: str) -> list[tuple]:
        with self._conn() as c:
            return c.execute(
                "SELECT thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id, "
                "type, checkpoint::text, metadata::text FROM checkpoints "
                "WHERE thread_id = %s ORDER BY checkpoint_id ASC", (thread_id,)).fetchall()

    def _read_thread(self, thread_id: str) -> list[Record]:
        return [Record(seq=i, fields=dict(zip(COLS, r)))
                for i, r in enumerate(self._rows(thread_id))]

    def read_all_raw(self) -> list[Record]:
        return self._read_thread(THREAD)

    def read_other_raw(self) -> list[Record]:
        return self._read_thread(OTHER_THREAD)

    def _id_at(self, seq: int) -> str | None:
        rows = self._rows(THREAD)
        return rows[seq][2] if seq < len(rows) else None

    def write_raw(self, record: Record) -> None:
        f = record.fields
        target = self._id_at(record.seq)
        with self._conn() as c:
            if target is None:
                c.execute(
                    "INSERT INTO checkpoints (thread_id, checkpoint_ns, checkpoint_id, "
                    "parent_checkpoint_id, type, checkpoint, metadata) "
                    "VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)",
                    (THREAD, f["checkpoint_ns"], f["checkpoint_id"], f["parent_checkpoint_id"],
                     f["type"], f["checkpoint"], f["metadata"]))
            else:
                c.execute(
                    "UPDATE checkpoints SET type=%s, checkpoint=%s::jsonb, metadata=%s::jsonb "
                    "WHERE thread_id=%s AND checkpoint_id=%s",
                    (f["type"], f["checkpoint"], f["metadata"], THREAD, target))

    def delete_raw(self, seq: int) -> None:
        target = self._id_at(seq)
        with self._conn() as c:
            c.execute("DELETE FROM checkpoints WHERE thread_id=%s AND checkpoint_id=%s",
                      (THREAD, target))

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        target = self._id_at(victim_seq)
        d = donor.fields
        with self._conn() as c:
            c.execute(
                "UPDATE checkpoints SET type=%s, checkpoint=%s::jsonb, metadata=%s::jsonb "
                "WHERE thread_id=%s AND checkpoint_id=%s",
                (d["type"], d["checkpoint"], d["metadata"], THREAD, target))

    def mutate_payload(self, record: Record) -> Record:
        doc = json.loads(record.fields["checkpoint"])
        state = doc["channel_values"]["state"]
        doc["channel_values"]["state"] = state.replace("agmi-seed-", "agmi-TAMP-") \
            if "agmi-seed-" in state else state + " [TAMPERED]"
        record.fields["checkpoint"] = json.dumps(doc)
        return record

    @staticmethod
    def _later_id(tip_id: str) -> str:
        head, _, tail = tip_id.rpartition("-")
        return f"{head}-{format(int(tail, 16) + 1, '012x')}"

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["parent_checkpoint_id"] = template.fields["checkpoint_id"]
        forged.fields["checkpoint_id"] = self._later_id(template.fields["checkpoint_id"])
        doc = json.loads(forged.fields["checkpoint"])
        doc["id"] = forged.fields["checkpoint_id"]
        forged.fields["checkpoint"] = json.dumps(doc)
        return self.mutate_payload(forged)

    def read_meta(self, seq: int) -> dict:
        return json.loads(self._rows(THREAD)[seq][6])

    def write_meta(self, seq: int, meta: dict) -> None:
        target = self._id_at(seq)
        with self._conn() as c:
            c.execute("UPDATE checkpoints SET metadata=%s::jsonb WHERE thread_id=%s AND checkpoint_id=%s",
                      (json.dumps(meta), THREAD, target))

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return str(record.fields["checkpoint_id"])

    def payload_of(self, record):
        doc = json.loads(record.fields["checkpoint"])
        return json.dumps(doc.get("channel_values"), sort_keys=True)

    def owner_of(self, record):
        return str(record.fields["thread_id"])

    # --- hooks for T9: the schema's tables are the store --------------------
    # Snapshot and restore go through COPY in binary format, so every byte
    # of every row comes back exactly as the saver wrote it. Nothing outside
    # the schema is touched.
    supports_snapshot = True
    _TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")

    def snapshot_store(self):
        snap = {}
        with self._conn() as c:
            for t in self._TABLES:
                with c.cursor().copy(f"COPY {t} TO STDOUT (FORMAT BINARY)") as cp:
                    snap[t] = b"".join(cp)
        return snap

    def restore_store(self, token) -> None:
        with self._conn() as c:
            for t in self._TABLES:
                c.execute(f"TRUNCATE {t}")
                with c.cursor().copy(f"COPY {t} FROM STDIN (FORMAT BINARY)") as cp:
                    cp.write(token[t])

    def append_genuine(self) -> None:
        from langgraph.checkpoint.base import create_checkpoint
        cfg = {"configurable": {"thread_id": THREAD, "checkpoint_ns": ""}}
        tup = self._saver.get_tuple(cfg)
        cp = create_checkpoint(tup.checkpoint, {"state": f"{SEED_TOKEN}late"}, 99)
        cp["channel_values"] = {"state": f"{SEED_TOKEN}late"}
        self._saver.put(tup.config, cp, {"source": "loop", "step": 99, "writes": {}},
                        {"state": "late"})

    # --- the tool's own read path -----------------------------------------

    def reload(self) -> None:
        try:
            self._conn_obj.close()
        except Exception:  # noqa: BLE001
            pass
        self._open_saver()

    def verify(self) -> bool:
        cfg = {"configurable": {"thread_id": THREAD}}
        self.verify_detail = None
        try:
            if self._saver.get(cfg) is None:
                self.verify_detail = "get() returned no checkpoint"
                return False
            list(self._saver.list(cfg))
            return True
        except Exception as exc:  # noqa: BLE001
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
