# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""Adapter for OpenFang's Merkle audit chain.

OpenFang's audit log (crates/openfang-runtime/src/audit.rs) is a SQLite-backed
hash chain: each row stores prev_hash and a SHA-256 hash over
(seq, timestamp, agent_id, action, detail, outcome, prev_hash). On load it
walks the chain forward and recomputes each hash.

To exercise the attack suite without shelling out to the Rust binary, this
adapter reimplements that exact chain logic and schema in Python. The hashing
formula and column set mirror the real code byte for byte, so an attack that
succeeds here succeeds against the real store. When wiring the actual binary
later, only the internals of this class change; the attacks do not.

The `strict_tip` flag models the two states of the real code:
  strict_tip=False -> pre-fix OpenFang: forward-only walk, no stored tip.
  strict_tip=True  -> post-fix OpenFang: persists the tip hash and checks it
                      on load (the truncation fix built this week).
"""

from __future__ import annotations

import hashlib
import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

GENESIS = "0" * 64


def _entry_hash(seq, timestamp, agent_id, action, detail, outcome, prev_hash):
    h = hashlib.sha256()
    h.update(str(seq).encode())
    h.update(timestamp.encode())
    h.update(agent_id.encode())
    h.update(action.encode())
    h.update(detail.encode())
    h.update(outcome.encode())
    h.update(prev_hash.encode())
    return h.hexdigest()


class OpenFangAdapter(MemoryAdapter):
    name = "openfang"

    def __init__(self, strict_tip: bool = False):
        self.strict_tip = strict_tip
        self._dir: tempfile.TemporaryDirectory | None = None
        self._db_path: Path | None = None

    # --- lifecycle -----------------------------------------------------
    def setup(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._db_path = Path(self._dir.name) / "audit.db"
        conn = self._connect()
        conn.execute(
            """CREATE TABLE audit_entries (
                seq INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL,
                outcome TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                hash TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS audit_chain_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                tip_hash TEXT NOT NULL
            )"""
        )
        conn.commit()
        conn.close()

    def teardown(self) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    # --- normal tool API (used to seed legitimately) -------------------
    def seed(self, n: int) -> None:
        conn = self._connect()
        tip = GENESIS
        for i in range(n):
            ts = f"2026-09-06T10:00:{i:02d}+00:00"
            agent, action = "agent-1", "ToolInvoke"
            detail, outcome = f"action number {i}", "ok"
            h = _entry_hash(i, ts, agent, action, detail, outcome, tip)
            conn.execute(
                "INSERT INTO audit_entries VALUES (?,?,?,?,?,?,?,?)",
                (i, ts, agent, action, detail, outcome, tip, h),
            )
            tip = h
        conn.execute(
            "INSERT INTO audit_chain_state (id, tip_hash) VALUES (1, ?) "
            "ON CONFLICT(id) DO UPDATE SET tip_hash = excluded.tip_hash",
            (tip,),
        )
        conn.commit()
        conn.close()

    # --- raw store access (used by attacks) ----------------------------
    def read_all_raw(self) -> list[Record]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT seq, timestamp, agent_id, action, detail, outcome, "
            "prev_hash, hash FROM audit_entries ORDER BY seq ASC"
        ).fetchall()
        conn.close()
        cols = ["seq", "timestamp", "agent_id", "action", "detail",
                "outcome", "prev_hash", "hash"]
        return [Record(seq=r[0], fields=dict(zip(cols, r))) for r in rows]

    def write_raw(self, record: Record) -> None:
        f = record.fields
        conn = self._connect()
        conn.execute(
            "INSERT INTO audit_entries "
            "(seq, timestamp, agent_id, action, detail, outcome, prev_hash, hash) "
            "VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(seq) DO UPDATE SET "
            "timestamp=excluded.timestamp, agent_id=excluded.agent_id, "
            "action=excluded.action, detail=excluded.detail, "
            "outcome=excluded.outcome, prev_hash=excluded.prev_hash, "
            "hash=excluded.hash",
            (record.seq, f["timestamp"], f["agent_id"], f["action"],
             f["detail"], f["outcome"], f["prev_hash"], f["hash"]),
        )
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        conn = self._connect()
        conn.execute("DELETE FROM audit_entries WHERE seq = ?", (seq,))
        conn.commit()
        conn.close()

    # --- hooks for T9: the SQLite file is the store, tip row included ----
    supports_snapshot = True

    def snapshot_store(self):
        return self._copy_store(self._db_path)

    def restore_store(self, token) -> None:
        self._restore_store(token, self._db_path)

    def append_genuine(self) -> None:
        conn = self._connect()
        last = conn.execute("SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1").fetchone()
        i, tip = last[0] + 1, last[1]
        ts = f"2026-09-06T10:01:{i:02d}+00:00"
        agent, action, detail, outcome = "agent-1", "ToolInvoke", f"action number {i}", "ok"
        h = _entry_hash(i, ts, agent, action, detail, outcome, tip)
        conn.execute("INSERT INTO audit_entries VALUES (?,?,?,?,?,?,?,?)",
                     (i, ts, agent, action, detail, outcome, tip, h))
        conn.execute("INSERT INTO audit_chain_state (id, tip_hash) VALUES (1, ?) "
                     "ON CONFLICT(id) DO UPDATE SET tip_hash = excluded.tip_hash", (h,))
        conn.commit()
        conn.close()

    # --- reload + verify (the tool's own integrity answer) -------------
    def reload(self) -> None:
        # The real code re-reads all rows into memory here. Nothing to cache
        # in this model; verify() reads straight from the store on demand.
        pass

    def verify(self) -> bool:
        self.verify_detail = None
        conn = self._connect()
        rows = conn.execute(
            "SELECT seq, timestamp, agent_id, action, detail, outcome, "
            "prev_hash, hash FROM audit_entries ORDER BY seq ASC"
        ).fetchall()
        stored_tip = conn.execute(
            "SELECT tip_hash FROM audit_chain_state WHERE id = 1"
        ).fetchone()
        conn.close()

        expected_prev = GENESIS
        for row in rows:
            seq, ts, agent, action, detail, outcome, prev_hash, h = row
            if prev_hash != expected_prev:
                self.verify_detail = f"chain break at seq {seq}"
                return False  # chain break (catches reorder, delete-middle)
            recomputed = _entry_hash(seq, ts, agent, action, detail,
                                     outcome, prev_hash)
            if recomputed != h:
                self.verify_detail = f"hash mismatch at seq {seq}"
                return False  # content or forgery mismatch
            expected_prev = h

        if self.strict_tip and stored_tip is not None:
            # Post-fix behaviour: the walked tip must match the persisted tip.
            walked_tip = rows[-1][7] if rows else GENESIS
            if walked_tip != stored_tip[0]:
                self.verify_detail = "walked tip differs from persisted tip"
                return False  # catches truncation

        return True
