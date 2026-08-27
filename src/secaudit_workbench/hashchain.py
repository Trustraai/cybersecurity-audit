"""Tamper-evident evidence ledger.

Every ledger entry (artifact upload, scan result, auditor decision, sign-off)
is hash-linked to the previous entry within an engagement:

    entry_hash = sha256(prev_hash + canonical_json(entry))

Altering any historical entry breaks every hash after it, which is what lets
a third party recompute the chain and confirm the trail was never rewritten
after sign-off.
"""

import hashlib
import json
from typing import Any, Dict, Iterable, Optional, Tuple

GENESIS = "0" * 64


def canonical(payload: Dict[str, Any]) -> str:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def link(prev_hash: Optional[str], payload: Dict[str, Any]) -> str:
    """Compute this entry's chain hash from the previous hash and payload."""
    prev = prev_hash or GENESIS
    digest = hashlib.sha256()
    digest.update(prev.encode("ascii"))
    digest.update(canonical(payload).encode("utf-8"))
    return digest.hexdigest()


def file_hash(data: bytes) -> str:
    """SHA-256 of an evidence artifact's raw bytes."""
    return hashlib.sha256(data).hexdigest()


def verify_chain(entries: Iterable[Tuple[Dict[str, Any], str]],
                  starting_hash: Optional[str] = None) -> Tuple[bool, int]:
    """Verify (payload, stored_hash) pairs in order.

    Returns (ok, index_of_first_break). Index is -1 when the chain holds.
    """
    prev = starting_hash or GENESIS
    for index, (payload, stored) in enumerate(entries):
        if link(prev, payload) != stored:
            return False, index
        prev = stored
    return True, -1
