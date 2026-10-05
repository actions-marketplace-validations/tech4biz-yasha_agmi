# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""A minimal at-rest reference store that passes every T1-T8 edit.

Not a product. It exists so the eight at-rest attacks are self-validating:
if an attack cannot be caught even by a store built to catch it, the attack
proves nothing. Each record carries an HMAC over its content, its context
id, its position in the sequence, its previous record's tag (a hash chain)
AND its metadata; the store keeps a signed head pointer per context and
rechecks everything on load. The key is the store's; the attacker has the
raw rows but not the key, which is the whole threat model.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

_KEY = b"agmi-reference-atrest-key-not-a-secret"
CTX = "ctx-A"
OTHER_CTX = "ctx-B"
SEED = "ref-seed-"
OTHER_SEED = "ref-other-"


def _tag(ctx, seq, content, meta_json, prev_tag):
    m = hmac.new(_KEY, digestmod=hashlib.sha256)
    for part in (ctx, str(seq), content, meta_json, prev_tag):
        m.update(b"\x1f")
        m.update(part.encode())
    return m.hexdigest()


class ReferenceAtRestAdapter(MemoryAdapter):
    """The store every at-rest attack must fail against."""

    name = "reference-atrest"
    supports_replay = True
    supports_metadata = True

    def __init__(self):
        self._dir: tempfile.TemporaryDirectory | None = None
        self._db: Path | None = None
        #: The witness: the last head (seq, tag) for CTX, held by the tool
        #: off the store. Models a head handed to another machine. The
        #: attacker has the files, not this.
        self._witness: tuple | None = None

    def setup(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self._db = Path(self._dir.name) / "ref.db"
        c = self._raw()
        c.execute("CREATE TABLE rec (ctx TEXT, seq INT, content TEXT, "
                  "meta TEXT, tag TEXT, PRIMARY KEY (ctx, seq))")
        c.execute("CREATE TABLE head (ctx TEXT PRIMARY KEY, seq INT, "
                  "tag TEXT, head_sig TEXT)")
        c.commit()
        c.close()

    def teardown(self) -> None:
        if self._dir is not None:
            self._dir.cleanup()
            self._dir = None

    def _raw(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db)

    def _seed_ctx(self, ctx: str, token: str, n: int) -> None:
        c = self._raw()
        prev = "0" * 64
        for i in range(n):
            content = f"{token}{i}"
            meta = json.dumps({"owner": ctx, "source": "user", "ts": i})
            tag = _tag(ctx, i, content, meta, prev)
            c.execute("INSERT INTO rec VALUES (?,?,?,?,?)",
                      (ctx, i, content, meta, tag))
            prev = tag
        head_sig = hmac.new(_KEY, f"{ctx}|{n-1}|{prev}".encode(),
                            hashlib.sha256).hexdigest()
        c.execute("INSERT OR REPLACE INTO head VALUES (?,?,?,?)",
                  (ctx, n - 1, prev, head_sig))
        c.commit()
        c.close()
        if ctx == CTX:
            self._witness = (n - 1, prev)

    def seed(self, n: int) -> None:
        self._seed_ctx(CTX, SEED, n)

    # --- hooks for T9: the SQLite file is the store; the witness is not --
    supports_snapshot = True

    def snapshot_store(self):
        return self._copy_store(self._db)

    def restore_store(self, token) -> None:
        self._restore_store(token, self._db)

    def append_genuine(self) -> None:
        c = self._raw()
        last = c.execute("SELECT seq, tag FROM rec WHERE ctx=? ORDER BY seq DESC LIMIT 1",
                         (CTX,)).fetchone()
        # The witness advances only forward. A genuine write must build on the
        # head the tool last witnessed; if the chain on disk has fallen below
        # it (a truncation or rollback happened before this write), refuse to
        # append rather than re-anchor the head to the shortened chain. Without
        # this, truncate-then-write would launder the deletion: the write would
        # re-stamp head and witness onto the shorter chain and the lost records
        # would vanish with no trace. (Found by the composition engine.)
        if self._witness is not None and (last[0], last[1]) != self._witness:
            c.close()
            raise RuntimeError(
                "cannot append: the chain on disk is below the witnessed head "
                f"(disk seq {last[0]}, witnessed seq {self._witness[0]}); the "
                "store was truncated or rolled back before this write")
        seq, prev = last[0] + 1, last[1]
        content = f"{SEED}late"
        meta = json.dumps({"owner": CTX, "source": "user", "ts": seq})
        tag = _tag(CTX, seq, content, meta, prev)
        c.execute("INSERT INTO rec VALUES (?,?,?,?,?)", (CTX, seq, content, meta, tag))
        head_sig = hmac.new(_KEY, f"{CTX}|{seq}|{tag}".encode(), hashlib.sha256).hexdigest()
        c.execute("INSERT OR REPLACE INTO head VALUES (?,?,?,?)", (CTX, seq, tag, head_sig))
        c.commit()
        c.close()
        self._witness = (seq, tag)

    def seed_other(self, n: int) -> None:
        self._seed_ctx(OTHER_CTX, OTHER_SEED, n)

    def _read_ctx(self, ctx: str) -> list[Record]:
        c = self._raw()
        rows = c.execute("SELECT ctx, seq, content, meta, tag FROM rec "
                         "WHERE ctx=? ORDER BY seq ASC", (ctx,)).fetchall()
        c.close()
        return [Record(seq=r[1], fields={"ctx": r[0], "seq": r[1],
                                         "content": r[2], "meta": r[3],
                                         "tag": r[4]}) for r in rows]

    def read_all_raw(self) -> list[Record]:
        return self._read_ctx(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._read_ctx(OTHER_CTX)

    def write_raw(self, record: Record) -> None:
        f = record.fields
        c = self._raw()
        c.execute("INSERT OR REPLACE INTO rec VALUES (?,?,?,?,?)",
                  (CTX, record.seq, f["content"], f["meta"], f["tag"]))
        c.commit()
        c.close()

    def delete_raw(self, seq: int) -> None:
        c = self._raw()
        c.execute("DELETE FROM rec WHERE ctx=? AND seq=?", (CTX, seq))
        c.commit()
        c.close()

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        c = self._raw()
        c.execute("UPDATE rec SET content=?, meta=?, tag=? WHERE ctx=? AND seq=?",
                  (donor.fields["content"], donor.fields["meta"],
                   donor.fields["tag"], CTX, victim_seq))
        c.commit()
        c.close()

    # --- guard hooks (control C3): slot, content, owner ------------------
    def identity_of(self, record):
        return f"{record.fields['ctx']}:{record.fields['seq']}"

    def payload_of(self, record):
        return str(record.fields["content"])

    def owner_of(self, record):
        return str(record.fields["ctx"])

    def read_meta(self, seq: int) -> dict:
        c = self._raw()
        row = c.execute("SELECT meta FROM rec WHERE ctx=? AND seq=?",
                        (CTX, seq)).fetchone()
        c.close()
        return json.loads(row[0]) if row else {}

    def write_meta(self, seq: int, meta: dict) -> None:
        c = self._raw()
        c.execute("UPDATE rec SET meta=? WHERE ctx=? AND seq=?",
                  (json.dumps(meta), CTX, seq))
        c.commit()
        c.close()

    def mutate_payload(self, record: Record) -> Record:
        record.fields["content"] = record.fields["content"] + "  [TAMPERED]"
        return record

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1, fields=dict(template.fields))
        forged.fields["content"] = "ref-forged"
        return forged

    def reload(self) -> None:
        pass

    def verify(self) -> bool:
        self.verify_detail = None
        c = self._raw()
        recs = c.execute("SELECT seq, content, meta, tag FROM rec WHERE ctx=? "
                         "ORDER BY seq ASC", (CTX,)).fetchall()
        head = c.execute("SELECT seq, tag, head_sig FROM head WHERE ctx=?",
                         (CTX,)).fetchone()
        c.close()
        if head is None:
            self.verify_detail = "no head pointer"
            return False
        prev = "0" * 64
        for seq, content, meta, tag in recs:
            if _tag(CTX, seq, content, meta, prev) != tag:
                self.verify_detail = f"tag mismatch at seq {seq}"
                return False
            prev = tag
        want_sig = hmac.new(_KEY, f"{CTX}|{head[0]}|{head[1]}".encode(),
                           hashlib.sha256).hexdigest()
        if head[2] != want_sig:
            self.verify_detail = "head signature invalid"
            return False
        if not recs or recs[-1][0] != head[0] or prev != head[1]:
            self.verify_detail = "head does not match last record (truncated or rolled back)"
            return False
        if self._witness is not None and (head[0], head[1]) != self._witness:
            self.verify_detail = "stored head is older than the witnessed head (store rolled back)"
            return False
        return True
