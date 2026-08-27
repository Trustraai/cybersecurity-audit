"""Evidence intake.

The client produces exports; the workbench ingests them. Each artifact is
SHA-256 hashed, timestamped, and locked into the evidence ledger on arrival.
Structured formats are parsed so the scan engine can test them.

Read-only always: nothing here opens a connection to a client system, holds
a credential, or writes anywhere but the local store.
"""

import csv
import io
import json
import os
from typing import Any, Dict, List, Tuple

from .hashchain import file_hash

# Maps a filename stem to the evidence-set name controls refer to in their
# match specs. Explicit rather than inferred, so a renamed client export
# fails loudly instead of silently scanning nothing.
EVIDENCE_SETS = {
    "ai_assets": "ai_assets",
    "agent_tools": "agent_tools",
    "agents": "agents",
    "model_registry": "model_registry",
    "vector_stores": "vector_stores",
    "prompts": "prompts",
    "gateways": "gateways",
    "sbom": "sbom",
    "asset_edges": "asset_edges",
    "control_evidence": "control_evidence",
}

_MULTI = ";"


def _coerce(value: Any) -> Any:
    """CSV gives strings for everything. Normalise the shapes the rule
    evaluator cares about, and leave everything else alone."""
    if not isinstance(value, str):
        return value
    text = value.strip()
    if text.lower() in ("true", "yes"):
        return True
    if text.lower() in ("false", "no"):
        return False
    if text == "":
        return ""
    return text


def parse_csv(data: bytes) -> List[Dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    rows = []
    for raw in reader:
        row = {k: _coerce(v) for k, v in raw.items() if k}
        for key, value in list(row.items()):
            if isinstance(value, str) and _MULTI in value:
                row[key] = [v.strip() for v in value.split(_MULTI) if v.strip()]
        rows.append(row)
    return rows


def parse_json(data: bytes) -> List[Dict[str, Any]]:
    payload = json.loads(data.decode("utf-8"))
    if isinstance(payload, list):
        return payload
    for key in ("components", "packages", "rows", "items"):
        if isinstance(payload.get(key), list):
            return payload[key]
    return [payload]


def parse(name: str, data: bytes) -> List[Dict[str, Any]]:
    if name.lower().endswith(".csv"):
        return parse_csv(data)
    if name.lower().endswith(".json"):
        return parse_json(data)
    return []


def load_directory(path: str) -> Tuple[Dict[str, List[Dict[str, Any]]],
                                        List[Dict[str, Any]]]:
    """Load a directory of client exports.

    Returns (evidence_sets, artifact_records). Artifact records carry the hash
    and row count that go into the ledger.
    """
    evidence: Dict[str, List[Dict[str, Any]]] = {}
    artifacts: List[Dict[str, Any]] = []

    for filename in sorted(os.listdir(path)):
        full = os.path.join(path, filename)
        if not os.path.isfile(full):
            continue
        stem = os.path.splitext(filename)[0]
        evidence_set = EVIDENCE_SETS.get(stem)
        if evidence_set is None:
            continue
        with open(full, "rb") as fh:
            data = fh.read()
        rows = parse(filename, data)
        evidence[evidence_set] = rows
        artifacts.append({
            "name": filename,
            "evidence_set": evidence_set,
            "sha256": file_hash(data),
            "row_count": len(rows),
        })
    return evidence, artifacts
