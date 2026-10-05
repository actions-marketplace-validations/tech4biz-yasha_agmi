# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Atelya Attest: a hash-chained attestation of an agent's memory op-log,
with an optional checkpoint ledger kept under separate control.

The package (PyPI `atelya-attest`, Apache 2.0, standard library only)
wraps each op-log event into a chain entry carrying `seq`, `event_id`,
`ts`, the event `payload`, `prev_hash` and `curr_hash` (SHA-256, or
HMAC-SHA256 with a key). `verify_chain()` walks the chain and names the
first bad entry: a sequence gap or reorder, a broken link, or a payload
that no longer matches its hash. `amem_anchor` checkpoints the chain head
(seq, length, root) into a separate ledger and `consistency()` checks the
current chain is still an append-only superset of what was anchored.

These rows take the chain file as the memory store, one entry per memory
event, the way the README's 60-second proof does: the agent appends
events, attests them, and replays the chain. A second chain file stands
in for the second context. The attacker edits the chain file and does not
hold the HMAC key; the README is explicit that an attacker who rewrites
the op-log and re-attests beats the chain alone, and that is what the
anchor row exists for. Two rows, keyed chain in both:

* `atelya-attest-chain`: `verify_chain()` alone.
* `atelya-attest-chain+anchor`: `verify_chain()` and consistency against
  the last checkpoint in a ledger the attacker cannot reach.

Detection point is the audit in both cases: the agent replays the chain
file as written, and `verify` is a separate call.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from agmi.adapters.base import MemoryAdapter, Record

CTX = "ctx-A"
OTHER = "ctx-B"
KEY = b"agmi-attest-key-not-in-the-store"


class AtelyaAttestChainAdapter(MemoryAdapter):
    """Chain file as the store, verify_chain() as the audit."""

    name = "atelya-attest-chain"
    supports_replay = True
    supports_metadata = True
    detection_point = "audit"
    anchored = False

    def __init__(self):
        self._dir: str | None = None
        self._ledger_dir: str | None = None
        self._events: dict[str, list[dict]] = {}

    # --- lifecycle ---------------------------------------------------------

    def setup(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="agmi-atelya-")
        self._ledger_dir = tempfile.mkdtemp(prefix="agmi-atelya-anchor-")
        self._events = {CTX: [], OTHER: []}
        for ctx in (CTX, OTHER):
            self._write_chain(ctx, [])

    def teardown(self) -> None:
        for d in (self._dir, self._ledger_dir):
            if d:
                shutil.rmtree(d, ignore_errors=True)
        self._dir = self._ledger_dir = None

    def _chain_path(self, ctx: str) -> Path:
        return Path(self._dir) / f"{ctx}.chain.jsonl"

    @property
    def _ledger_path(self) -> Path:
        return Path(self._ledger_dir) / "anchors.jsonl"

    def _read_chain(self, ctx: str) -> list[dict]:
        p = self._chain_path(ctx)
        if not p.exists():
            return []
        return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def _write_chain(self, ctx: str, chain: list[dict]) -> None:
        self._chain_path(ctx).write_text(
            "".join(json.dumps(e, sort_keys=True) + "\n" for e in chain), encoding="utf-8")

    # --- the tool's own write path ----------------------------------------

    def _seed_ctx(self, ctx: str, n: int) -> None:
        from amem_attest import build_chain
        for i in range(n):
            self._events[ctx].append({
                "op": "add", "id": f"{ctx}-m{i}", "key": f"slot{i}",
                "text": f"agmi-{ctx}-{i}: the limit is {40 + i}",
                "created_at": 1_700_000_000 + i,
            })
        self._write_chain(ctx, build_chain(self._events[ctx], KEY))
        if self.anchored and ctx == CTX:
            self._anchor()

    def _anchor(self) -> None:
        from amem_anchor import GENESIS, chain_head, make_entry
        chain = self._read_chain(CTX)
        seq, n, root = chain_head(chain)
        ledger = self._read_ledger()
        prev = ledger[-1]["curr_hash"] if ledger else GENESIS
        entry = make_entry(prev, anchored_at="2026-10-02T00:00:00Z", label=CTX,
                           seq=seq, n_entries=n, root=root, key=KEY)
        with open(self._ledger_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    def _read_ledger(self) -> list[dict]:
        p = self._ledger_path
        if not p.exists():
            return []
        return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def seed(self, n: int) -> None:
        self._seed_ctx(CTX, n)

    def seed_other(self, n: int) -> None:
        self._seed_ctx(OTHER, n)

    # --- raw access, bypassing the tool -----------------------------------

    def _read_ctx(self, ctx: str) -> list[Record]:
        return [Record(seq=i, fields={"ctx": ctx, "entry": e})
                for i, e in enumerate(self._read_chain(ctx))]

    def read_all_raw(self) -> list[Record]:
        return self._read_ctx(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._read_ctx(OTHER)

    def write_raw(self, record: Record) -> None:
        chain = self._read_chain(CTX)
        if record.seq < len(chain):
            chain[record.seq] = record.fields["entry"]
        else:
            chain.append(record.fields["entry"])
        self._write_chain(CTX, chain)

    def delete_raw(self, seq: int) -> None:
        chain = self._read_chain(CTX)
        del chain[seq]
        self._write_chain(CTX, chain)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        chain = self._read_chain(CTX)
        chain[victim_seq] = dict(donor.fields["entry"])
        self._write_chain(CTX, chain)

    def read_meta(self, seq: int) -> dict:
        return {"ts": self._read_chain(CTX)[seq].get("ts")}

    def write_meta(self, seq: int, meta: dict) -> None:
        # The entry's timestamp is its label; the hash is left as it was.
        chain = self._read_chain(CTX)
        if meta.get("agmi_meta_tampered"):
            chain[seq]["ts"] = "2030-01-01T00:00:00Z"
        elif "ts" in meta:
            chain[seq]["ts"] = meta["ts"]
        self._write_chain(CTX, chain)

    def mutate_payload(self, record: Record) -> Record:
        record.fields["entry"]["payload"]["text"] += "  [TAMPERED]"
        return record

    def forge_record(self, template: Record) -> Record:
        forged = json.loads(json.dumps(template.fields["entry"]))
        forged["seq"] = template.seq + 1
        forged["event_id"] = "agmi-forged"
        forged["payload"]["id"] = "agmi-forged"
        forged["payload"]["text"] = "agmi-forged: the limit is 999"
        return Record(seq=template.seq + 1, fields={"ctx": CTX, "entry": forged})

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return f"{record.fields['ctx']}:{record.seq}"

    def payload_of(self, record):
        return str(record.fields["entry"]["payload"].get("text"))

    def owner_of(self, record):
        return record.fields["ctx"]

    # --- the audit ----------------------------------------------------------

    def reload(self) -> None:
        return  # the store is the file; nothing is cached

    # --- T9 whole-store rollback: the chain files roll back, the anchor ledger
    # --- (a separate directory the attacker cannot reach) does not ----------

    supports_snapshot = True

    def snapshot_store(self):
        token = tempfile.mkdtemp(prefix="agmi-atelya-snap-")
        shutil.copytree(self._dir, token, dirs_exist_ok=True)
        return token, {k: list(v) for k, v in self._events.items()}

    def restore_store(self, token) -> None:
        d, events = token
        for p in Path(self._dir).iterdir():
            p.unlink() if p.is_file() else shutil.rmtree(p, ignore_errors=True)
        shutil.copytree(d, self._dir, dirs_exist_ok=True)
        shutil.rmtree(d, ignore_errors=True)
        self._events = {k: list(v) for k, v in events.items()}

    def append_genuine(self) -> None:
        from amem_attest import build_chain
        i = len(self._events[CTX])
        self._events[CTX].append({
            "op": "add", "id": f"{CTX}-m{i}", "key": f"slot{i}",
            "text": f"agmi-{CTX}-{i}: the limit is {40 + i}",
            "created_at": 1_700_000_000 + i,
        })
        self._write_chain(CTX, build_chain(self._events[CTX], KEY))
        if self.anchored:
            self._anchor()

    def verify(self) -> bool:
        from amem_attest import verify_chain
        self.verify_detail = None
        chain = self._read_chain(CTX)
        ok, bad, reason = verify_chain(chain, KEY)
        if not ok:
            self.verify_detail = f"verify_chain: seq={bad}: {reason}"[:200]
            return False
        if self.anchored:
            from amem_anchor import consistency
            ledger = self._read_ledger()
            if ledger:
                ok, reason = consistency(chain, ledger[-1])
                if not ok:
                    self.verify_detail = f"anchor: {reason}"[:200]
                    return False
        return True


class AtelyaAttestAnchoredAdapter(AtelyaAttestChainAdapter):
    """Chain plus a head checkpoint in a ledger the attacker cannot reach."""

    name = "atelya-attest-chain+anchor"
    anchored = True
