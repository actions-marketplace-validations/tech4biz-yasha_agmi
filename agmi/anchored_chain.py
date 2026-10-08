# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT
"""An independent verifier for the `anchored-record-chain/v1` corpus
(probityai/agent-evidence-vectors, `vectors-anchored-chain`).

    python -m agmi.anchored_chain <case-dir>/case.json --json

The corpus applies the nine storage-level edits of this suite (T1 to T9) to a
signed record chain whose head is anchored by a key the store does not hold,
and asks a verifier for a decision and a reason. This module is agmi's own
reading of that contract, written from the corpus README and not from the
package's reader, so that the two can be compared: it checks, in the order
the contract fixes, record signatures, the anchor signature, chain identity,
chain links, the anchored record's presence and its digest, and names the
first check that fails. A store that passes all six is `verified`, with
`chain_anchored` when the anchor names the last stored record and
`records_after_last_anchor` when records follow it.

Signatures are Ed25519 over the RFC 8785 (JCS) form of the signed body. The
corpus bodies hold only ASCII strings and integers, so the canonical form is
the key-sorted, separator-free JSON this module produces.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

GENESIS = "0" * 64
CHECKS = ("signature_invalid", "anchor_signature_invalid", "record_from_other_chain",
          "chain_link_broken", "anchored_head_missing", "anchored_head_mismatch")


def jcs(value) -> bytes:
    """RFC 8785 canonical JSON for objects of strings, integers, lists and bools."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def ed25519_ok(public_key_hex: str, message: bytes, signature_b64: str) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        key.verify(base64.b64decode(signature_b64, validate=True), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_case(case_path: Path) -> dict:
    case = json.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    lines = [ln for ln in (base / case["store"]).read_bytes().split(b"\n") if ln]
    anchor = json.loads((base / case["anchor"]).read_text(encoding="utf-8"))
    envelopes = [json.loads(ln) for ln in lines]
    producer, anchor_key = case["keys"]["producer"], case["keys"]["anchor"]
    index = int(anchor["anchor"]["index"])

    def check(name: str) -> bool:
        if name == "signature_invalid":
            return not all(isinstance(e.get("record"), dict) and ed25519_ok(producer, jcs(e["record"]), str(e.get("sig", "")))
                           for e in envelopes)
        if name == "anchor_signature_invalid":
            return not ed25519_ok(anchor_key, jcs(anchor["anchor"]), str(anchor.get("sig", "")))
        if name == "record_from_other_chain":
            return any(e["record"].get("chain") != case["chain"] for e in envelopes)
        if name == "chain_link_broken":
            return any(e["record"].get("prev") != (GENESIS if i == 0 else sha(lines[i - 1]))
                       for i, e in enumerate(envelopes))
        if name == "anchored_head_missing":
            return index >= len(lines)
        if name == "anchored_head_mismatch":
            return index >= len(lines) or sha(lines[index]) != anchor["anchor"]["head"]
        raise ValueError(name)

    for name in CHECKS:
        if check(name):
            return {"decision": "rejected", "reason": name}
    reason = "records_after_last_anchor" if len(lines) - 1 - index > 0 else "chain_anchored"
    return {"decision": "verified", "reason": reason}


def main(argv: list[str] | None = None) -> int:
    args = [a for a in (argv if argv is not None else sys.argv[1:]) if a != "--json"]
    if len(args) != 1:
        print("usage: python -m agmi.anchored_chain <case.json> [--json]", file=sys.stderr)
        return 2
    result = verify_case(Path(args[0]))
    result["verifier"] = "agmi.anchored_chain"
    print(json.dumps(result, sort_keys=True))
    return 0 if result["decision"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
