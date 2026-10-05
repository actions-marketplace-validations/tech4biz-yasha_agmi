# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""LangGraph `RedisSaver` (langgraph-checkpoint-redis) on Redis 8.

Layout: one JSON document per checkpoint at
`checkpoint:<thread>:<ns>:<checkpoint_id>` carrying thread_id,
checkpoint_id, parent_checkpoint_id, checkpoint_ts, the checkpoint itself
(channel values inline for primitive state) and metadata as a JSON string,
plus a plain string `checkpoint_latest:<thread>:<ns>` holding the key of
the newest document. `get()` follows that pointer; `list()` queries the
search index over the documents.

The pointer is what SQLite and Postgres do not have. Delete the newest
document and leave the pointer alone and `get()` returns None: the thread
reads as empty, which is a loss, not a detection. An attacker with store
access moves the pointer as well, so the truncation and forge edits here
repoint it to the new tip, and the row records both behaviours.

Connection from AGMI_REDIS_URI (for example redis://localhost:6380). Each
run uses its own thread ids under a random prefix and deletes its keys on
teardown; the shared checkpoint index is left in place.
"""

from __future__ import annotations

import json
import os
import secrets

from agmi.adapters.base import MemoryAdapter, Record

NS = "__empty__"
COLS = ("key", "thread_id", "checkpoint_id", "parent_checkpoint_id", "doc")


def redis_uri() -> str | None:
    return os.environ.get("AGMI_REDIS_URI")


class LangGraphRedisAdapter(MemoryAdapter):
    name = "langgraph-redis"
    supports_replay = True
    supports_metadata = True
    detection_point = "read"

    def __init__(self, uri: str | None = None):
        self._uri = uri or redis_uri()
        self._prefix: str | None = None
        self._saver_cm = None
        self._saver = None
        self._r = None

    @property
    def thread(self) -> str:
        return f"{self._prefix}-A"

    @property
    def other_thread(self) -> str:
        return f"{self._prefix}-B"

    # --- lifecycle ---------------------------------------------------------

    def _open_saver(self):
        from langgraph.checkpoint.redis import RedisSaver
        self._saver_cm = RedisSaver.from_conn_string(self._uri)
        self._saver = self._saver_cm.__enter__()
        self._saver.setup()

    def setup(self) -> None:
        if not self._uri:
            raise RuntimeError("AGMI_REDIS_URI is not set")
        import redis
        self._prefix = f"agmi-{secrets.token_hex(4)}"
        self._r = redis.Redis.from_url(self._uri)
        self._open_saver()

    def _close_saver(self) -> None:
        try:
            self._saver_cm.__exit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass

    def teardown(self) -> None:
        self._close_saver()
        self._saver = None
        if self._r is not None and self._prefix:
            for pat in (f"checkpoint:{self._prefix}-*", f"checkpoint_latest:{self._prefix}-*",
                        f"checkpoint_write:{self._prefix}-*", f"checkpoint_blob:{self._prefix}-*"):
                keys = list(self._r.scan_iter(pat))
                if keys:
                    self._r.delete(*keys)
        self._prefix = None

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
        self._seed_thread(self.thread, "agmi-seed-", n)

    def seed_other(self, n: int) -> None:
        self._seed_thread(self.other_thread, "agmi-other-", n)

    # --- raw access, bypassing the tool -----------------------------------

    def _pointer_key(self, thread_id: str) -> str:
        return f"checkpoint_latest:{thread_id}:{NS}"

    def _doc_keys(self, thread_id: str) -> list[str]:
        keys = [k.decode() for k in self._r.scan_iter(f"checkpoint:{thread_id}:{NS}:*")]
        return sorted(keys, key=lambda k: k.rsplit(":", 1)[1])

    def _read_thread(self, thread_id: str) -> list[Record]:
        out = []
        for i, k in enumerate(self._doc_keys(thread_id)):
            doc = json.loads(self._r.execute_command("JSON.GET", k))
            out.append(Record(seq=i, fields={
                "key": k, "thread_id": doc["thread_id"], "checkpoint_id": doc["checkpoint_id"],
                "parent_checkpoint_id": doc.get("parent_checkpoint_id"), "doc": doc}))
        return out

    def read_all_raw(self) -> list[Record]:
        return self._read_thread(self.thread)

    def read_other_raw(self) -> list[Record]:
        return self._read_thread(self.other_thread)

    def _set_doc(self, key: str, doc: dict) -> None:
        self._r.execute_command("JSON.SET", key, "$", json.dumps(doc))

    def _write_into_slot(self, key: str, donor_doc: dict) -> None:
        """Keep the slot's identity (key, thread, checkpoint_id, parent),
        take the donor's checkpoint content, metadata and timestamp."""
        cur = json.loads(self._r.execute_command("JSON.GET", key))
        new = dict(donor_doc)
        for f in ("thread_id", "checkpoint_id", "parent_checkpoint_id", "checkpoint_ns"):
            new[f] = cur[f]
        new["checkpoint"] = dict(donor_doc["checkpoint"])
        new["checkpoint"]["id"] = cur["checkpoint_id"]
        self._set_doc(key, new)

    def write_raw(self, record: Record) -> None:
        keys = self._doc_keys(self.thread)
        if record.seq < len(keys):
            self._write_into_slot(keys[record.seq], record.fields["doc"])
        else:
            key = f"checkpoint:{self.thread}:{NS}:{record.fields['checkpoint_id']}"
            self._set_doc(key, record.fields["doc"])
            # a forger making their record the head moves the pointer too
            self._r.set(self._pointer_key(self.thread), key)

    def delete_raw(self, seq: int) -> None:
        keys = self._doc_keys(self.thread)
        target = keys[seq]
        self._r.delete(target)
        if self._r.get(self._pointer_key(self.thread)) == target.encode():
            remaining = self._doc_keys(self.thread)
            if remaining:
                self._r.set(self._pointer_key(self.thread), remaining[-1])
            else:
                self._r.delete(self._pointer_key(self.thread))

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        self._write_into_slot(self._doc_keys(self.thread)[victim_seq], donor.fields["doc"])

    def read_meta(self, seq: int) -> dict:
        doc = self.read_all_raw()[seq].fields["doc"]
        return json.loads(doc["metadata"]) if isinstance(doc["metadata"], str) else dict(doc["metadata"])

    def write_meta(self, seq: int, meta: dict) -> None:
        key = self._doc_keys(self.thread)[seq]
        doc = json.loads(self._r.execute_command("JSON.GET", key))
        doc["metadata"] = json.dumps(meta)
        self._set_doc(key, doc)

    def mutate_payload(self, record: Record) -> Record:
        doc = json.loads(json.dumps(record.fields["doc"]))
        state = doc["checkpoint"]["channel_values"]["state"]
        doc["checkpoint"]["channel_values"]["state"] = (
            state.replace("agmi-seed-", "agmi-TAMP-") if "agmi-seed-" in state else state + " [TAMPERED]")
        record.fields["doc"] = doc
        return record

    @staticmethod
    def _later_id(tip_id: str) -> str:
        head, _, tail = tip_id.rpartition("-")
        return f"{head}-{format(int(tail, 16) + 1, '012x')}"

    def forge_record(self, template: Record) -> Record:
        doc = json.loads(json.dumps(template.fields["doc"]))
        new_id = self._later_id(template.fields["checkpoint_id"])
        doc["checkpoint_id"] = new_id
        doc["checkpoint"]["id"] = new_id
        doc["parent_checkpoint_id"] = template.fields["checkpoint_id"]
        forged = Record(seq=template.seq + 1, fields={
            "key": f"checkpoint:{self.thread}:{NS}:{new_id}", "thread_id": self.thread,
            "checkpoint_id": new_id, "parent_checkpoint_id": template.fields["checkpoint_id"],
            "doc": doc})
        return self.mutate_payload(forged)

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return str(record.fields["checkpoint_id"])

    def payload_of(self, record):
        return json.dumps(record.fields["doc"]["checkpoint"].get("channel_values"), sort_keys=True)

    def owner_of(self, record):
        return str(record.fields["thread_id"])

    # --- hooks for T9: this run's keys are the store -------------------------
    # DUMP and RESTORE carry each key's exact serialized value, JSON documents
    # included, so the restored store is byte for byte the older one.
    supports_snapshot = True

    def _store_patterns(self) -> list[str]:
        return [f"checkpoint:{self._prefix}-*", f"checkpoint_latest:{self._prefix}-*",
                f"checkpoint_write:{self._prefix}-*", f"checkpoint_blob:{self._prefix}-*"]

    def _store_keys(self) -> list[bytes]:
        keys: list[bytes] = []
        for pat in self._store_patterns():
            keys.extend(self._r.scan_iter(pat))
        return keys

    def snapshot_store(self):
        return {k: self._r.dump(k) for k in self._store_keys()}

    def restore_store(self, token) -> None:
        self._close_saver()
        keys = self._store_keys()
        if keys:
            self._r.delete(*keys)
        for k, blob in token.items():
            self._r.restore(k, 0, blob, replace=True)
        self._open_saver()

    def append_genuine(self) -> None:
        from langgraph.checkpoint.base import create_checkpoint
        cfg = {"configurable": {"thread_id": self.thread, "checkpoint_ns": ""}}
        tup = self._saver.get_tuple(cfg)
        cp = create_checkpoint(tup.checkpoint, {"state": "agmi-seed-late"}, 99)
        cp["channel_values"] = {"state": "agmi-seed-late"}
        self._saver.put(tup.config, cp, {"source": "loop", "step": 99, "writes": {}},
                        {"state": "late"})

    # --- the tool's own read path -----------------------------------------

    def reload(self) -> None:
        self._close_saver()
        self._open_saver()

    def verify(self) -> bool:
        cfg = {"configurable": {"thread_id": self.thread}}
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
