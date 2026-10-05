# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""CONTINUUM: a hash-chained, append-only event log an agent recovers from.

The package (PyPI `continuum-agent`, Cyrax321/CONTINUUM) keeps one event
log per run in SQLite. Every `append_event()` row carries `sequence`,
`event_id`, `type`, `timestamp`, `payload`, `prev_hash` and `hash`
(SHA-256 over the row's canonical form and its predecessor's hash). After
a crash the agent replays the log with `project()` to rebuild its state,
and `verify_events()` re-walks the chain and reports every violation with
the sequence it occurred at.

These rows take the run's `events` table as the memory store, the way the
README's quick start does: the agent appends WORK_COMPLETED events and a
fresh process projects them. A second run stands in for the second
context. The attacker edits rows in the table through SQLite and does not
re-chain; `event_id` is unique across the table, so a row moved into
another slot keeps that slot's id and brings every other column; the README's threat model covers the re-chaining attacker with
`continuum attest`, which signs the chain head for an external verifier.

Two rows:

* `continuum-events`: `verify_events()` alone.
* `continuum-events+attest`: the head is signed with `sign_chain()` into
  an attestation kept outside the store, and the audit is the check
  `continuum attest-verify` performs: chain intact, signature valid, and
  the live head's sequence and hash equal to the signed point.

Detection point is the audit in both: `project()` replays whatever rows
are there, and the audit is a separate call.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

RUN = "agmi-run-A"
OTHER_RUN = "agmi-run-B"
COLS = ("run_id", "sequence", "event_id", "type", "timestamp", "payload",
        "causer_event_id", "source", "prev_hash", "hash")


class ContinuumEventsAdapter(MemoryAdapter):
    name = "continuum-events"
    supports_replay = True
    supports_metadata = True
    detection_point = "audit"
    attested = False

    def __init__(self):
        self._dir: str | None = None
        self._store = None
        self._attestation: dict | None = None

    # --- lifecycle ---------------------------------------------------------

    @property
    def _db(self) -> Path:
        return Path(self._dir) / "agent.db"

    def _open(self):
        from continuum import SQLiteStorage
        self._store = SQLiteStorage(self._db)

    def setup(self) -> None:
        from continuum import Run
        self._dir = tempfile.mkdtemp(prefix="agmi-continuum-")
        self._open()
        for run_id in (RUN, OTHER_RUN):
            self._store.create_run(Run(run_id=run_id, goal=f"agmi {run_id}"))

    def teardown(self) -> None:
        try:
            self._store.close()
        except Exception:  # noqa: BLE001
            pass
        self._store = None
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None

    # --- the tool's own write path ----------------------------------------

    def _seed_run(self, run_id: str, n: int) -> None:
        from continuum import EventType
        for i in range(n):
            self._store.append_event(run_id, EventType.WORK_COMPLETED,
                                     {"doc": i, "note": f"agmi-{run_id}-{i}: the limit is {40 + i}"})

    def seed(self, n: int) -> None:
        self._seed_run(RUN, n)
        if self.attested:
            from continuum.security.attestation import generate_keypair, sign_chain
            priv, _pub = generate_keypair()
            head = self._store.read_events(RUN)[-1]
            self._attestation = sign_chain(priv, RUN, head.sequence, head.hash,
                                           signer="agmi").to_dict()

    def seed_other(self, n: int) -> None:
        self._seed_run(OTHER_RUN, n)

    # --- raw access, bypassing the tool -----------------------------------

    def _raw(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db)

    def _rows(self, run_id: str) -> list[tuple]:
        conn = self._raw()
        rows = conn.execute(
            f"SELECT {', '.join(COLS)} FROM events WHERE run_id = ? ORDER BY sequence ASC",
            (run_id,)).fetchall()
        conn.close()
        return rows

    def _read_run(self, run_id: str) -> list[Record]:
        return [Record(seq=i, fields=dict(zip(COLS, r)))
                for i, r in enumerate(self._rows(run_id))]

    def read_all_raw(self) -> list[Record]:
        return self._read_run(RUN)

    def read_other_raw(self) -> list[Record]:
        return self._read_run(OTHER_RUN)

    def _seq_at(self, seq: int) -> int | None:
        rows = self._rows(RUN)
        return rows[seq][1] if seq < len(rows) else None

    def write_raw(self, record: Record) -> None:
        """Write the record's columns into the row at position `seq`, keeping
        that row's run_id and sequence. Past the tail, insert a new row with
        the next sequence number."""
        f = record.fields
        target = self._seq_at(record.seq)
        conn = self._raw()
        if target is None:
            last = conn.execute("SELECT COALESCE(MAX(sequence), 0) FROM events WHERE run_id = ?",
                                (RUN,)).fetchone()[0]
            conn.execute(
                "INSERT INTO events (run_id, sequence, event_id, type, timestamp, payload, "
                "causer_event_id, source, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (RUN, last + 1, f["event_id"], f["type"], f["timestamp"], f["payload"],
                 f["causer_event_id"], f["source"], f["prev_hash"], f["hash"]))
        else:
            # event_id is UNIQUE across the table, so a row moved into another
            # slot cannot bring its id along; the slot keeps its own id and
            # takes every other column of the record.
            conn.execute(
                "UPDATE events SET type=?, timestamp=?, payload=?, causer_event_id=?, "
                "source=?, prev_hash=?, hash=? WHERE run_id=? AND sequence=?",
                (f["type"], f["timestamp"], f["payload"], f["causer_event_id"],
                 f["source"], f["prev_hash"], f["hash"], RUN, target))
        conn.commit()
        conn.close()

    def delete_raw(self, seq: int) -> None:
        target = self._seq_at(seq)
        conn = self._raw()
        conn.execute("DELETE FROM events WHERE run_id=? AND sequence=?", (RUN, target))
        conn.commit()
        conn.close()

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        """Genuine donor columns under the victim's run_id and sequence."""
        d = dict(donor.fields)
        self.write_raw(Record(seq=victim_seq, fields=d))

    def read_meta(self, seq: int) -> dict:
        return {"timestamp": self._rows(RUN)[seq][4]}

    def write_meta(self, seq: int, meta: dict) -> None:
        target = self._seq_at(seq)
        ts = "2030-01-01T00:00:00+00:00" if meta.get("agmi_meta_tampered") else meta.get("timestamp")
        conn = self._raw()
        conn.execute("UPDATE events SET timestamp=? WHERE run_id=? AND sequence=?", (ts, RUN, target))
        conn.commit()
        conn.close()

    def mutate_payload(self, record: Record) -> Record:
        p = json.loads(record.fields["payload"])
        p["note"] += "  [TAMPERED]"
        record.fields["payload"] = json.dumps(p)
        return record

    def forge_record(self, template: Record) -> Record:
        f = dict(template.fields)
        f["event_id"] = "event_agmiforged000000000000000000"
        f["payload"] = json.dumps({"doc": 999, "note": "agmi-forged: the limit is 999"})
        return Record(seq=template.seq + 1, fields=f)

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return f"{record.fields['run_id']}:{record.fields['sequence']}"

    def payload_of(self, record):
        return json.loads(record.fields["payload"]).get("note")

    def owner_of(self, record):
        return record.fields["run_id"]

    # --- the audit ----------------------------------------------------------

    def reload(self) -> None:
        try:
            self._store.close()
        except Exception:  # noqa: BLE001
            pass
        self._open()

    # --- T9 whole-store rollback: the store directory rolls back; the signed
    # --- head (attested row) is held outside it ------------------------------

    supports_snapshot = True

    def _close(self) -> None:
        try:
            self._store.close()
        except Exception:  # noqa: BLE001
            pass

    def snapshot_store(self):
        self._close()
        token = tempfile.mkdtemp(prefix="agmi-continuum-snap-")
        shutil.copytree(self._dir, token, dirs_exist_ok=True)
        self._open()
        return token

    def restore_store(self, token) -> None:
        self._close()
        for p in Path(self._dir).iterdir():
            p.unlink() if p.is_file() else shutil.rmtree(p, ignore_errors=True)
        shutil.copytree(token, self._dir, dirs_exist_ok=True)
        shutil.rmtree(token, ignore_errors=True)
        self._open()

    def append_genuine(self) -> None:
        from continuum import EventType
        n = len(self._store.read_events(RUN))
        self._store.append_event(RUN, EventType.WORK_COMPLETED,
                                 {"doc": n, "note": f"agmi-{RUN}-{n}: the limit is {40 + n}"})
        if self.attested:
            # the tool's own path: attest the new head after writing it
            from continuum.security.attestation import generate_keypair, sign_chain
            priv, _pub = generate_keypair()
            head = self._store.read_events(RUN)[-1]
            self._attestation = sign_chain(priv, RUN, head.sequence, head.hash,
                                           signer="agmi").to_dict()

    def verify(self) -> bool:
        self.verify_detail = None
        rep = self._store.verify_events(RUN)
        if not (rep.ok and not rep.truncated):
            v = rep.violations[0] if rep.violations else None
            self.verify_detail = (f"verify_events: {v}" if v else
                                  f"verify_events: truncated={rep.truncated}")[:200]
            return False
        if self.attested and self._attestation is not None:
            # What `continuum attest-verify` does: signature, then live head.
            from continuum.security.attestation import verify_attestation
            events = self._store.read_events(RUN)
            live_seq = events[-1].sequence if events else 0
            live_hash = events[-1].hash if events else None
            if not verify_attestation(self._attestation):
                self.verify_detail = "attest-verify: UNTRUSTED (signature invalid)"
                return False
            if (self._attestation.get("trusted_through_seq") != live_seq
                    or self._attestation.get("chain_hash") != live_hash):
                self.verify_detail = (f"attest-verify: ALTERED (signed seq "
                                      f"{self._attestation.get('trusted_through_seq')}, live seq {live_seq})")
                return False
        return True


class ContinuumEventsAttestedAdapter(ContinuumEventsAdapter):
    """Chain plus a signed head kept outside the store."""

    name = "continuum-events+attest"
    attested = True
