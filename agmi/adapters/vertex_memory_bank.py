# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""Vertex AI Agent Engine Memory Bank (Google Cloud; the product is now named
Agent Platform, the API is still aiplatform.googleapis.com).

This is the first managed store on the board, and the attacker is different
from every file- or database-backed row: there is no disk to edit. "Store
access" here means a principal holding the data-plane IAM role on the project
(Agent Platform User, roles/aiplatform.user) outside the agent's own session:
a leaked service-account key, a second workload in the same project, or a
platform operator. That principal edits memories through the management API
(memories.patch, memories.delete, memories.create) while the agent's own read
path is memories.retrieve for its scope. The position is the same one the
Postgres and Redis rows measure: someone with write access to the store that
is not the agent.

What the API allows, mapped to the nine edits:

  T1 tamper          patch the memory's fact                       applies
  T2 truncate        delete the newest two memories                applies
  T3 delete_middle   delete one memory                             applies
  T4 reorder         not applicable: order is create_time, which the API
                     cannot set, so there is no positional edit to make
  T5 forge           create a memory in the agent's scope          applies
  T6 cross_replay    patch a victim's fact with another scope's    applies
  T7 rollback_replay patch a fact back to an older one             applies
  T8 metadata_tamper patch the memory's metadata                   applies
  T9 snapshot_rb     not applicable: a managed store exposes no snapshot
                     or restore of its own state

Memory Bank keeps a revision per change to a memory's fact (the
memoryRevisions sub-resource). The read path does not consult it and the
service raises nothing on an out-of-band patch, so revisions are an audit
record an investigator can read afterwards, not a check the agent gets. The
verify() here is the agent's read path, retrieve for its scope, which has no
integrity logic; this row is measured for the record, like the LangGraph
checkpointers. Cloud Audit Logs can record the patch and delete calls at the
platform layer when Data Access logging is switched on for aiplatform (it is
off by default); that is outside the store and not part of this row.

Needs: AGMI_GCP_PROJECT set, Google application default credentials
(GOOGLE_APPLICATION_CREDENTIALS pointing at a service-account key with
roles/aiplatform.user), the Agent Platform API enabled on the project, and
google-cloud-aiplatform (vertexai 2.x with the genai client). Optional:
AGMI_GCP_LOCATION (default us-central1), AGMI_VERTEX_ENGINE (an existing
Agent Engine resource name to reuse; otherwise one is created per process
and deleted at exit unless AGMI_VERTEX_KEEP_ENGINE=1).

Each adapter instance uses its own scope (user_id agmi-<random>), so runs
never see each other's memories, and teardown deletes the scope's memories.
"""

from __future__ import annotations

import atexit
import os
import secrets
import time

from agmi.adapters.base import MemoryAdapter, Record

SEED_TOKEN = "agmi-seed-"
OTHER_TOKEN = "agmi-other-"
SCOPE_KEY = "user_id"

_ENGINE_CACHE: dict[str, str] = {}


def gcp_project() -> str | None:
    return os.environ.get("AGMI_GCP_PROJECT")


def gcp_location() -> str:
    return os.environ.get("AGMI_GCP_LOCATION", "us-central1")


def _iso(dt) -> str | None:
    if dt is None:
        return None
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


def _meta_to_python(meta: dict | None) -> dict:
    out: dict = {}
    for k, v in (meta or {}).items():
        if v is None:
            continue
        for attr in ("string_value", "bool_value", "double_value", "int_value"):
            val = getattr(v, attr, None) if not isinstance(v, dict) else v.get(attr)
            if val is not None:
                out[k] = val
                break
    return out


def _meta_to_api(meta: dict, rest: bool = False) -> dict:
    """MemoryMetadataValue in the shape the caller needs: snake_case field
    names for the SDK's create config, camelCase for a raw REST body."""
    b, d, st = ("boolValue", "doubleValue", "stringValue") if rest else ("bool_value", "double_value", "string_value")
    out: dict = {}
    for k, v in meta.items():
        if isinstance(v, bool):
            out[k] = {b: v}
        elif isinstance(v, (int, float)):
            out[k] = {d: float(v)}
        else:
            out[k] = {st: str(v)}
    return out


class VertexMemoryBankAdapter(MemoryAdapter):
    name = "vertex-memory-bank"
    supports_replay = True
    supports_metadata = True
    supports_snapshot = False
    detection_point = "read"

    #: How long to wait for the service to show a write (eventual consistency).
    settle_seconds = 30.0

    def __init__(self, project: str | None = None, location: str | None = None,
                 engine: str | None = None):
        self._project = project or gcp_project()
        self._location = location or gcp_location()
        self._engine_arg = engine or os.environ.get("AGMI_VERTEX_ENGINE")
        self._client = None
        self._engine: str | None = None
        self._scope_id: str | None = None
        self._other_scope_id: str | None = None

    # --- client and engine ------------------------------------------------

    def _mem(self):
        return self._client.agent_engines.memories

    def _connect(self) -> None:
        if self._client is not None:
            return
        if not self._project:
            raise RuntimeError("AGMI_GCP_PROJECT is not set")
        from vertexai import Client  # google-cloud-aiplatform 1.1xx / vertexai 2.x
        self._client = Client(project=self._project, location=self._location)
        self._engine = self._ensure_engine()

    def _ensure_engine(self) -> str:
        if self._engine_arg:
            return self._engine_arg
        key = f"{self._project}/{self._location}"
        if key in _ENGINE_CACHE:
            return _ENGINE_CACHE[key]
        engine = self._client.agent_engines.create(
            config={"display_name": "agmi-memory-bank",
                    "description": "agmi conformance run; safe to delete"})
        name = engine.api_resource.name
        _ENGINE_CACHE[key] = name
        if os.environ.get("AGMI_VERTEX_KEEP_ENGINE") != "1":
            client = self._client

            def _cleanup(n=name, c=client):
                try:
                    c.agent_engines.delete(name=n, force=True)
                except Exception:  # noqa: BLE001 - best effort at interpreter exit
                    pass
            atexit.register(_cleanup)
        return name

    # --- lifecycle --------------------------------------------------------

    def setup(self) -> None:
        self._connect()
        self._scope_id = f"agmi-{secrets.token_hex(4)}"
        self._other_scope_id = f"{self._scope_id}-B"

    def teardown(self) -> None:
        if self._client is None:
            return
        for sid in (self._scope_id, self._other_scope_id):
            if not sid:
                continue
            for m in self._list_scope(sid):
                try:
                    self._mem().delete(name=m.name)
                except Exception:  # noqa: BLE001 - teardown is best effort
                    pass

    def _scope(self, sid: str | None = None) -> dict:
        return {SCOPE_KEY: sid or self._scope_id}

    def _create(self, sid: str, fact: str, metadata: dict | None = None) -> str:
        config: dict = {"wait_for_completion": True}
        if metadata:
            config["metadata"] = _meta_to_api(metadata)
        op = self._mem().create(name=self._engine, fact=fact, scope=self._scope(sid), config=config)
        resp = getattr(op, "response", None)
        name = getattr(resp, "name", None)
        if not name:
            # fall back to the newest memory carrying this fact in this scope
            for m in self._list_scope(sid):
                if m.fact == fact:
                    name = m.name
        if not name:
            raise RuntimeError("memory create returned no resource name")
        return name

    def _seed_scope(self, sid: str, token: str, n: int) -> None:
        for i in range(n):
            self._create(sid, f"{token}{i}: the limit is {50 + i}")
        self._wait_count(sid, n)

    def seed(self, n: int) -> None:
        self._seed_scope(self._scope_id, SEED_TOKEN, n)

    def seed_other(self, n: int) -> None:
        self._seed_scope(self._other_scope_id, OTHER_TOKEN, n)

    # --- reading ----------------------------------------------------------

    def _list_scope(self, sid: str) -> list:
        out = []
        for m in self._mem().list(name=self._engine):
            if (m.scope or {}).get(SCOPE_KEY) == sid:
                out.append(m)
        out.sort(key=lambda m: (m.create_time or 0, m.name or ""))
        return out

    def _wait_count(self, sid: str, n: int) -> None:
        deadline = time.time() + self.settle_seconds
        while time.time() < deadline:
            if len(self._list_scope(sid)) == n:
                return
            time.sleep(1.0)
        raise RuntimeError(f"scope {sid} did not settle at {n} memories within {self.settle_seconds}s")

    def _to_record(self, seq: int, m) -> Record:
        return Record(seq=seq, fields={
            "name": m.name,
            "fact": m.fact,
            "scope": dict(m.scope or {}),
            "create_time": _iso(m.create_time),
            "update_time": _iso(m.update_time),
            "metadata": _meta_to_python(m.metadata),
        })

    def _read_scope(self, sid: str) -> list[Record]:
        return [self._to_record(i, m) for i, m in enumerate(self._list_scope(sid))]

    def read_all_raw(self) -> list[Record]:
        return self._read_scope(self._scope_id)

    def read_other_raw(self) -> list[Record]:
        return self._read_scope(self._other_scope_id)

    def _name_at(self, seq: int) -> str:
        ms = self._list_scope(self._scope_id)
        if seq < 0 or seq >= len(ms):
            raise RuntimeError(f"no memory at position {seq}")
        return ms[seq].name

    # --- the data-plane edits (the attacker's moves) ----------------------

    def _patch(self, memory_name: str, body: dict, mask: str) -> None:
        """memories.patch: the SDK in this version has no helper for it, so the
        call is made the way the SDK makes its own, through the genai api
        client, against the memory's resource name."""
        api = self._client.agent_engines._api_client
        api.request("patch", f"{memory_name}?updateMask={mask}", body, None)

    def _wait_fact(self, memory_name: str, fact: str) -> None:
        deadline = time.time() + self.settle_seconds
        while time.time() < deadline:
            m = self._mem().get(name=memory_name)
            if m.fact == fact:
                return
            time.sleep(1.0)
        raise RuntimeError("patched fact did not read back within the settle window")

    def write_raw(self, record: Record) -> None:
        f = record.fields
        name = f.get("name")
        if not name:
            # a forgery: a new memory in the agent's scope through the API
            self._create(self._scope_id, f["fact"], f.get("metadata") or None)
            self._wait_count(self._scope_id, len(self._list_scope(self._scope_id)))
            return
        current = self._list_scope(self._scope_id)
        pos = next((i for i, m in enumerate(current) if m.name == name), None)
        if pos is None:
            raise RuntimeError(f"memory {name} is not in this scope")
        if pos != record.seq:
            raise RuntimeError(
                "not applicable: Memory Bank orders memories by create_time, which the "
                "API cannot set, so a record cannot be moved to another position")
        self._patch(name, {"fact": f["fact"]}, "fact")
        self._wait_fact(name, f["fact"])

    def delete_raw(self, seq: int) -> None:
        name = self._name_at(seq)
        n = len(self._list_scope(self._scope_id))
        self._mem().delete(name=name)
        self._wait_count(self._scope_id, n - 1)

    def replay_onto(self, victim_seq: int, donor: Record) -> None:
        name = self._name_at(victim_seq)
        fact = donor.fields["fact"]
        self._patch(name, {"fact": fact}, "fact")
        self._wait_fact(name, fact)

    def mutate_payload(self, record: Record) -> Record:
        f = dict(record.fields)
        f["fact"] = f["fact"] + " [agmi-tampered]"
        return Record(seq=record.seq, fields=f)

    def forge_record(self, template: Record) -> Record:
        return Record(seq=template.seq + 1, fields={
            "fact": f"{SEED_TOKEN}forged: the limit is 999",
            "scope": dict(template.fields.get("scope") or self._scope()),
        })

    def read_meta(self, seq: int) -> dict:
        m = self._mem().get(name=self._name_at(seq))
        return _meta_to_python(m.metadata)

    def write_meta(self, seq: int, meta: dict) -> None:
        name = self._name_at(seq)
        self._patch(name, {"fact": self._mem().get(name=name).fact, "metadata": _meta_to_api(meta, rest=True)}, "metadata")
        deadline = time.time() + self.settle_seconds
        while time.time() < deadline:
            if _meta_to_python(self._mem().get(name=name).metadata) == {
                k: (float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else v)
                for k, v in meta.items()}:
                return
            time.sleep(1.0)
        raise RuntimeError("patched metadata did not read back within the settle window")

    # --- identity --------------------------------------------------------

    def identity_of(self, record: Record) -> str:
        return record.fields["name"]

    def payload_of(self, record: Record) -> str:
        return record.fields["fact"]

    def owner_of(self, record: Record) -> str | None:
        return (record.fields.get("scope") or {}).get(SCOPE_KEY)

    # --- the agent's read path --------------------------------------------

    def reload(self) -> None:
        # A managed store has no process to restart; the next read is a fresh
        # call to the service, which is what a restarted agent would make.
        self._client = None
        self._connect()

    def verify(self) -> bool:
        """The agent's own read: retrieve for its scope. Memory Bank performs
        no integrity check on the way out, so this returns True whenever the
        service answers; a refusal here would be the service failing closed."""
        self.verify_detail = None
        try:
            _ = list(self._mem().retrieve(name=self._engine, scope=self._scope(),
                                          simple_retrieval_params={}))
            _ = self._list_scope(self._scope_id)
        except Exception as exc:  # noqa: BLE001 - a raise is the service refusing, which is detection
            self.verify_detail = f"{type(exc).__name__}: {exc}"[:160]
            return False
        return True
