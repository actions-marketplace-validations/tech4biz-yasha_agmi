# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The eight at-rest attacks, each with its landed check (control C3).

All five assume the attacker has gained write access to the backing store
(the SQLite file, the Postgres rows, the JSON blob) but NOT access to the
tool's own signing keys or in-process integrity logic. This is the standard
"database compromise / privileged write at rest" threat model behind the
real LangGraph checkpointer CVEs.

Each attack mutates the raw store, then the harness reloads the tool and
asks whether it noticed.
"""

from __future__ import annotations

from agmi.adapters.base import MemoryAdapter
from agmi.attacks.base import Attack
from agmi.attacks.guard import (
    Snap, changed_positions, expect, same_records, snapshot,
)


class TamperAttack(Attack):
    """Modify the contents of one existing entry in place."""

    name = "tamper"
    description = "Alter the payload of a stored entry without touching its links."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to tamper with")
        target = records[len(records) // 2]
        self._ctx["pos"] = len(records) // 2
        # The adapter knows how to change meaning without breaking encoding.
        adapter.write_raw(adapter.mutate_payload(target))

    def check_landed(self, adapter, before, after):
        pos = self._ctx["pos"]
        moved = changed_positions(before, after)
        expect(moved == [pos], f"expected only record {pos} to change, changed {moved}")
        expect(before[pos].payload != after[pos].payload,
               f"record {pos} was rewritten but its content did not change")
        expect(before[pos].identity == after[pos].identity,
               f"record {pos} lost its identity")


class TruncateAttack(Attack):
    """Delete entries from the END of the chain.

    This is the one that slipped past OpenFang: forward-only link checks
    stay valid because the surviving prefix still chains correctly.
    """

    name = "truncate"
    description = "Remove the most recent entries from the tail of the store."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to truncate")
        # Drop the last two entries, tail first, so adapters that address
        # rows by ordinal position stay valid after the first delete.
        for rec in reversed(records[-2:]):
            adapter.delete_raw(rec.seq)

    def check_landed(self, adapter, before, after):
        expect(len(after) == len(before) - 2,
               f"expected {len(before) - 2} records after truncation, found {len(after)}")
        expect(same_records(before[:-2], after),
               "records that should have survived the truncation changed")


class DeleteMiddleAttack(Attack):
    """Remove a single entry from the MIDDLE of the chain."""

    name = "delete_middle"
    description = "Remove one interior entry, leaving a gap in the sequence."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 3:
            raise RuntimeError("need at least 3 records to delete a middle one")
        victim = records[len(records) // 2]
        self._ctx["pos"] = len(records) // 2
        adapter.delete_raw(victim.seq)

    def check_landed(self, adapter, before, after):
        pos = self._ctx["pos"]
        expect(len(after) == len(before) - 1,
               f"expected {len(before) - 1} records after the delete, found {len(after)}")
        expect(same_records(before[:pos] + before[pos + 1:], after),
               f"a record other than {pos} changed or the wrong record was removed")


class ReorderAttack(Attack):
    """Swap the position of two adjacent entries."""

    name = "reorder"
    description = "Exchange two entries so events appear in the wrong order."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to reorder")
        i = len(records) // 2
        a, b = records[i - 1], records[i]
        a_seq = a.seq
        b_seq = b.seq
        a.seq, b.seq = b_seq, a_seq
        self._ctx["pos"] = i
        adapter.write_raw(a)
        adapter.write_raw(b)

    def check_landed(self, adapter, before, after):
        i = self._ctx["pos"]
        moved = changed_positions(before, after)
        expect(sorted(moved) == [i - 1, i],
               f"expected only records {i - 1} and {i} to change, changed {moved}")
        expect(before[i - 1].payload != before[i].payload,
               "the two records to swap carry the same content, so a swap is a no-op")
        expect(after[i - 1].payload == before[i].payload
               and after[i].payload == before[i - 1].payload,
               f"records {i - 1} and {i} changed but did not exchange content")


class ForgeAttack(Attack):
    """Insert a brand-new entry that mimics a legitimate one."""

    name = "forge"
    description = "Append a fabricated entry crafted to look authentic."

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to base a forgery on")
        adapter.write_raw(adapter.forge_record(records[-1]))

    def check_landed(self, adapter, before, after):
        expect(len(after) == len(before) + 1,
               f"expected exactly one new record, count went {len(before)} to {len(after)}")
        expect(same_records(before, after[:-1]),
               "the existing records changed; a forgery must only append")
        expect(after[-1].payload != before[-1].payload,
               "the appended record repeats the last genuine record")


class CrossContextReplayAttack(Attack):
    """T6. Copy a genuine record from a SECOND context over a record in the
    first, keeping the first record's identity. Real bytes, wrong owner.

    Passes through any at-rest encryption that does not bind ciphertext to
    the record's place: the donor bytes decrypt and verify. Only a store
    that binds a record to its context (thread/user/session) rejects it."""

    name = "cross_replay"
    description = ("Replay a genuine record from another context onto this "
                   "one, keeping the victim's identity.")

    def run(self, adapter: MemoryAdapter):
        from agmi.attacks.base import AttackResult
        if not getattr(adapter, "supports_replay", False):
            return AttackResult(self.name, adapter.name, detected=False,
                                error="adapter does not model a second context",
                                version=self.version)
        return super().run(adapter)

    def tamper(self, adapter: MemoryAdapter) -> None:
        adapter.seed_other(self.seed_count)
        donors = adapter.read_other_raw()
        victims = adapter.read_all_raw()
        if not donors or not victims:
            raise RuntimeError("need records in both contexts to replay")
        self._ctx["donor"] = snapshot(adapter, [donors[-1]])[0]
        self._ctx["donors"] = snapshot(adapter, donors)
        # The victim pool is read after seed_other, so the guard compares
        # against that, not the snapshot taken before the second context.
        self._ctx["victims"] = snapshot(adapter, victims)
        adapter.replay_onto(victims[-1].seq, donors[-1])

    def check_landed(self, adapter, before, after):
        victims: list[Snap] = self._ctx["victims"]
        donor: Snap = self._ctx["donor"]
        expect(same_records(before, victims),
               "seeding the second context changed the first context's records")
        expect(all(v.identity != donor.identity for v in victims),
               "the donor is one of the victim records: no crossing")
        expect(donor.payload not in {v.payload for v in victims},
               "the donor's content already sits in the first context: no crossing")
        expect(donor.owner is not None and victims[-1].owner is not None,
               "adapter does not report record owners, so a crossing cannot be proven")
        expect(donor.owner != victims[-1].owner,
               f"donor and victim share owner {donor.owner!r}: no crossing")
        moved = changed_positions(victims, after)
        last = len(victims) - 1
        expect(moved == [last], f"expected only record {last} to change, changed {moved}")
        expect(after[last].identity == victims[last].identity,
               "the victim slot lost its identity; a replay keeps it")
        expect(after[last].owner == victims[last].owner,
               "the victim slot changed owner; a replay keeps it")
        expect(after[last].payload == donor.payload,
               "the victim slot does not hold the donor's content")
        others = snapshot(adapter, adapter.read_other_raw())
        expect(same_records(self._ctx["donors"], others),
               "the second context changed; only the victim slot may move")


class RollbackReplayAttack(Attack):
    """T7. Copy an OLDER genuine record of the SAME context over its newest,
    winding the context back in time. Every record is genuine; only the
    order is rewritten. AAD that binds a record to its own place does not
    catch this; catching it needs coverage of the sequence."""

    name = "rollback_replay"
    description = ("Replay an older genuine record of this context over its "
                   "newest, rolling state back.")

    def run(self, adapter: MemoryAdapter):
        from agmi.attacks.base import AttackResult
        if not getattr(adapter, "supports_replay", False):
            return AttackResult(self.name, adapter.name, detected=False,
                                error="adapter does not support replay",
                                version=self.version)
        return super().run(adapter)

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if len(records) < 2:
            raise RuntimeError("need at least 2 records to roll back")
        adapter.replay_onto(records[-1].seq, records[0])

    def check_landed(self, adapter, before, after):
        last = len(before) - 1
        expect(last >= 1, "need at least 2 records to roll back")
        expect(before[0].payload != before[last].payload,
               "oldest and newest records carry the same content: a rollback is a no-op")
        moved = changed_positions(before, after)
        expect(moved == [last], f"expected only record {last} to change, changed {moved}")
        expect(after[last].identity == before[last].identity,
               "the newest slot lost its identity; a replay keeps it")
        expect(after[last].owner == before[last].owner,
               "the newest slot changed owner; a rollback stays inside one context")
        expect(after[last].payload == before[0].payload,
               "the newest slot does not hold the oldest record's content")


class MetadataTamperAttack(Attack):
    """T8. Change a record's metadata (owner, source, role, timestamp) and
    leave its content untouched. A store that authenticates content but not
    its labels serves the record with the attacker's metadata, enough to
    move a record to another user or mark an untrusted source as trusted."""

    name = "metadata_tamper"
    description = ("Alter a record's owner/source/timestamp without changing "
                   "its content.")

    def run(self, adapter: MemoryAdapter):
        from agmi.attacks.base import AttackResult
        if not getattr(adapter, "supports_metadata", False):
            return AttackResult(self.name, adapter.name, detected=False,
                                error="adapter does not expose record metadata",
                                version=self.version)
        return super().run(adapter)

    def tamper(self, adapter: MemoryAdapter) -> None:
        records = adapter.read_all_raw()
        if not records:
            raise RuntimeError("no records to tamper metadata on")
        seq = records[len(records) // 2].seq
        self._ctx["pos"] = len(records) // 2
        self._ctx["meta_before"] = dict(adapter.read_meta(seq))
        meta = adapter.read_meta(seq)
        meta["agmi_meta_tampered"] = True
        adapter.write_meta(seq, meta)
        self._ctx["meta_after"] = dict(adapter.read_meta(seq))

    def check_landed(self, adapter, before, after):
        pos = self._ctx["pos"]
        expect(self._ctx["meta_before"] != self._ctx["meta_after"],
               f"record {pos}'s metadata reads back unchanged after the write")
        if len(after) == len(before) - 1:
            # The edit moved the record to another owner, and the first
            # context's view no longer lists it. Everything else must stand.
            expect(same_records(before[:pos] + before[pos + 1:], after),
                   f"record {pos} left the context but other records changed too")
            return
        moved = changed_positions(before, after)
        expect(moved in ([pos], []),
               f"expected only record {pos} to change, changed {moved}")
        expect(after[pos].payload == before[pos].payload,
               f"record {pos}'s content changed; a metadata edit leaves it alone")
        expect(after[pos].identity == before[pos].identity,
               f"record {pos} lost its identity")


class SnapshotRollbackAttack(Attack):
    """T9. Restore an older complete copy of the store after one more
    genuine record was written through the tool's own API. Nothing in the
    restored copy is forged or out of place: every record, digest, chain
    link and head the store keeps beside itself is as the store wrote it.
    The store is simply older than it should be, and the newest record is
    gone. A head kept anywhere the attacker can restore along with the
    files (a sidecar, a tip row, a file in the same directory) rolls back
    with them; only a head held off the store catches this.

    T7 copies one older record over the newest; T9 rolls back the whole
    store. The two differ in what passes: per-record binding and a stored
    head stop T7, and neither stops T9."""

    name = "snapshot_rollback"
    description = ("Restore an older complete copy of the store, taken "
                   "before the newest genuine record was written.")

    def run(self, adapter: MemoryAdapter):
        from agmi.attacks.base import AttackResult
        if not getattr(adapter, "supports_snapshot", False):
            return AttackResult(self.name, adapter.name, detected=False,
                                error="adapter does not support a store snapshot",
                                version=self.version)
        return super().run(adapter)

    def tamper(self, adapter: MemoryAdapter) -> None:
        token = adapter.snapshot_store()
        adapter.append_genuine()
        self._ctx["grown"] = snapshot(adapter, adapter.read_all_raw())
        adapter.restore_store(token)

    def check_landed(self, adapter, before, after):
        grown: list[Snap] = self._ctx["grown"]
        expect(len(grown) == len(before) + 1,
               f"append_genuine did not add exactly one record: {len(before)} -> {len(grown)}")
        expect(same_records(before, grown[:-1]),
               "appending a genuine record changed the records already stored")
        expect(len(after) == len(before),
               f"restore did not bring the store back to {len(before)} records, found {len(after)}")
        expect(same_records(before, after),
               "the restored copy differs from the store as it was before the append")

    def detail_on(self, detected: bool) -> str:
        return ("the store noticed it was older than its last committed state"
                if detected else
                "the older copy opened as current; the newest genuine record is gone without an error")


ALL_AT_REST_ATTACKS: list[type[Attack]] = [
    TamperAttack,
    TruncateAttack,
    DeleteMiddleAttack,
    ReorderAttack,
    ForgeAttack,
    CrossContextReplayAttack,
    RollbackReplayAttack,
    MetadataTamperAttack,
]

#: The eight edits plus T9. The scorecard runs this list; the eight-edit
#: list stays as the pinned contract until every adapter carries the
#: snapshot hooks, at which point T9 joins it.
AT_REST_ATTACKS_WITH_SNAPSHOT: list[type[Attack]] = ALL_AT_REST_ATTACKS + [SnapshotRollbackAttack]
