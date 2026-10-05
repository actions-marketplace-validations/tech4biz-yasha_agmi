# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""acrf-memory-guard: a per-entry HMAC over a key-value memory store.

The package (PyPI `acrf-memory-guard`, Apache 2.0) implements the ACRF-04
"memory poisoning" defence: every entry is signed with HMAC-SHA256 over its
canonical JSON when written (`sign_entry`), the signature travels inside
the entry under `_integrity`, and every read recomputes it (`read_safe`),
raising `MemoryIntegrityError` on a mismatch or a missing signature. The
secret comes from the environment, never from the store.

This adapter follows the package's own "Real-world use" section: a dict
store keyed by entry id, persisted as the JSON file its CLI verifies,
written through `sign_entry` and read through `read_safe`, one secret per
deployment. Two contexts (two users) share one store and one secret, as
the quick start does; keys are namespaced `<ctx>::<nn>`, and the entry
carries the owner inside the signed content the way the README's
`user_id` does.

Detection point is the read path: `verify()` is the agent's own read of
the first context's entries through `read_safe`, so a refusal there is a
refusal before the record reaches a decision.

What the package claims, in its own words: MP-1 every write signed, MP-2
every read validated, MP-3 deny on mismatch; and it does not protect
against rollback to a different signed version. The scorecard measures
exactly that boundary. The signature covers one entry's bytes and nothing
about its slot or its neighbours, so a genuine signed entry under another
key, in another position, or in another user's slot verifies, and a
missing entry leaves nothing to fail.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile

from agmi.adapters.base import MemoryAdapter, Record

CTX = "ctx-A"
OTHER = "ctx-B"
SECRET = "agmi-test-secret-not-in-the-store"


class AcrfMemoryGuardAdapter(MemoryAdapter):
    name = "acrf-memory-guard"
    supports_replay = True
    supports_metadata = True
    detection_point = "read"

    def __init__(self):
        self._dir: str | None = None
        self._store: dict | None = None

    # --- lifecycle ---------------------------------------------------------

    def setup(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="agmi-acrf-")
        self._store = {}
        self._flush()

    def teardown(self) -> None:
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
        self._dir = None
        self._store = None

    @property
    def path(self) -> str:
        return os.path.join(self._dir, "memory_store.json")

    def _flush(self) -> None:
        with open(self.path, "w") as f:
            json.dump(self._store, f, indent=1, sort_keys=True)

    def _load(self) -> dict:
        with open(self.path) as f:
            return json.load(f)

    # --- the tool's own write path ----------------------------------------

    def _seed_ctx(self, ctx: str, n: int) -> None:
        from acrf_memory_guard import sign_entry
        store = self._load()
        for i in range(n):
            entry = {"owner": ctx, "text": f"agmi-{ctx}-{i}: the limit is {40 + i}",
                     "ts": 1_700_000_000 + i}
            store[f"{ctx}::{i:02d}"] = sign_entry(entry, SECRET)
        self._store = store
        self._flush()

    def seed(self, n: int) -> None:
        self._seed_ctx(CTX, n)

    def seed_other(self, n: int) -> None:
        self._seed_ctx(OTHER, n)

    # --- raw access, bypassing the tool -----------------------------------

    def _keys(self, ctx: str, store: dict | None = None) -> list[str]:
        store = self._load() if store is None else store
        return sorted(k for k in store if k.startswith(ctx + "::"))

    def _read_ctx(self, ctx: str) -> list[Record]:
        store = self._load()
        return [Record(seq=i, fields={"key": k, "entry": dict(store[k])})
                for i, k in enumerate(self._keys(ctx, store))]

    def read_all_raw(self) -> list[Record]:
        return self._read_ctx(CTX)

    def read_other_raw(self) -> list[Record]:
        return self._read_ctx(OTHER)

    def write_raw(self, record: Record) -> None:
        """Write the record's entry into the slot its seq names. A seq past
        the end appends under the next key (the forge path)."""
        store = self._load()
        keys = self._keys(CTX, store)
        key = keys[record.seq] if record.seq < len(keys) else f"{CTX}::{len(keys):02d}"
        store[key] = dict(record.fields["entry"])
        self._store = store
        self._flush()

    def delete_raw(self, seq: int) -> None:
        store = self._load()
        del store[self._keys(CTX, store)[seq]]
        self._store = store
        self._flush()

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        """Genuine donor bytes, signature included, under the victim's key."""
        store = self._load()
        store[self._keys(CTX, store)[victim_seq]] = dict(donor.fields["entry"])
        self._store = store
        self._flush()

    def read_meta(self, seq: int) -> dict:
        store = self._load()
        entry = store[self._keys(CTX, store)[seq]]
        return {"ts": entry.get("ts")}

    def write_meta(self, seq: int, meta: dict) -> None:
        # The store has no field outside the signed entry, so a label
        # edit is an in-place edit of the entry's `ts`; the signature is
        # left as it was, which is what a keyless attacker can do.
        store = self._load()
        key = self._keys(CTX, store)[seq]
        store[key]["ts"] = meta.get("ts", store[key].get("ts"))
        if meta.get("agmi_meta_tampered"):
            store[key]["ts"] = int(store[key].get("ts") or 0) + 86_400
        self._store = store
        self._flush()

    def mutate_payload(self, record: Record) -> Record:
        record.fields["entry"]["text"] += "  [TAMPERED]"
        return record

    def forge_record(self, template: Record) -> Record:
        forged = Record(seq=template.seq + 1,
                        fields={"key": None, "entry": dict(template.fields["entry"])})
        forged.fields["entry"]["text"] = "agmi-forged: the limit is 999"
        return forged

    # --- guard hooks (control C3) -----------------------------------------

    def identity_of(self, record):
        return str(record.fields["key"])

    def payload_of(self, record):
        return str(record.fields["entry"].get("text"))

    def owner_of(self, record):
        return str(record.fields["key"]).split("::", 1)[0]

    # --- the tool's own read path -----------------------------------------

    def reload(self) -> None:
        self._store = self._load()

    # --- T9 whole-store rollback: the JSON file is the whole store -----------

    supports_snapshot = True

    def snapshot_store(self):
        token = tempfile.mkdtemp(prefix="agmi-acrf-snap-")
        shutil.copy2(self.path, os.path.join(token, "memory_store.json"))
        return token

    def restore_store(self, token) -> None:
        shutil.copy2(os.path.join(token, "memory_store.json"), self.path)
        shutil.rmtree(token, ignore_errors=True)
        self._store = self._load()

    def append_genuine(self) -> None:
        from acrf_memory_guard import sign_entry
        store = self._load()
        i = len(self._keys(CTX, store))
        entry = {"owner": CTX, "text": f"agmi-{CTX}-{i}: the limit is {40 + i}",
                 "ts": 1_700_000_000 + i}
        store[f"{CTX}::{i:02d}"] = sign_entry(entry, SECRET)
        self._store = store
        self._flush()

    def verify(self) -> bool:
        """The agent reads its own entries through read_safe. A raise is a
        refusal on the read path."""
        from acrf_memory_guard import MemoryIntegrityError, read_safe
        self.verify_detail = None
        store = self._load()
        for key in self._keys(CTX, store):
            try:
                read_safe(store[key], SECRET)
            except MemoryIntegrityError as exc:
                self.verify_detail = f"read_safe({key}): {exc}"
                return False
        return True
