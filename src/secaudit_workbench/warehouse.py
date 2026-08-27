"""Vulnerability knowledge warehouse loader.

The warehouse is a small graph of weaknesses and vulnerabilities, decoupled
from the control library (`controls.json`). A snapshot is immutable and
hash-sealed: loading validates the digest and refuses a bundle that fails,
so an engagement pinned to a snapshot reproduces its results exactly.

The bundled `data/warehouse.json` and `data/controls.json` are a small,
illustrative sample (a handful of weaknesses, one sample vulnerability, and
five sample controls) so this engine is runnable out of the box. They are
NOT Trustra's production knowledge warehouse or control library. See
docs/ARCHITECTURE.md.
"""

import hashlib
import json
import os
from typing import Any, Dict, List, Optional

from .hashchain import canonical

_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_HERE, "data")


class SnapshotIntegrityError(Exception):
    """Raised when a warehouse bundle fails its digest check."""


class Warehouse:
    def __init__(self, warehouse_path: Optional[str] = None,
                 controls_path: Optional[str] = None,
                 verify_digest: bool = True):
        warehouse_path = warehouse_path or os.path.join(_DATA_DIR, "warehouse.json")
        controls_path = controls_path or os.path.join(_DATA_DIR, "controls.json")

        with open(warehouse_path, encoding="utf-8") as fh:
            self._wh = json.load(fh)
        with open(controls_path, encoding="utf-8") as fh:
            self._lib = json.load(fh)

        if verify_digest:
            self.verify()

        self._by_id = {n["id"]: n for n in self._wh["nodes"]}
        self._controls_by_id = {c["id"]: c for c in self._lib["controls"]}

        self._by_alias: Dict[str, str] = {}
        for node in self._wh["nodes"]:
            for alias in node.get("aliases", []):
                self._by_alias[alias] = node["id"]

        self._out: Dict[str, List[Dict[str, Any]]] = {}
        self._in: Dict[str, List[Dict[str, Any]]] = {}
        for edge in self._wh["edges"]:
            self._out.setdefault(edge["source"], []).append(edge)
            self._in.setdefault(edge["target"], []).append(edge)

    # --- integrity --------------------------------------------------------

    def computed_digest(self) -> str:
        return hashlib.sha256(canonical({
            "nodes": self._wh["nodes"], "edges": self._wh["edges"],
        }).encode("utf-8")).hexdigest()

    def verify(self) -> None:
        """Refuse to run against a bundle whose digest does not match."""
        stored = self._wh.get("digest")
        if not stored:
            raise SnapshotIntegrityError("snapshot carries no digest")
        actual = self.computed_digest()
        if stored != actual:
            raise SnapshotIntegrityError(
                "snapshot digest mismatch: stored %s, computed %s"
                % (stored[:16], actual[:16]))

    # --- nodes and edges --------------------------------------------------

    @property
    def version(self) -> str:
        return self._wh["version"]

    @property
    def digest(self) -> str:
        return self._wh["digest"]

    @property
    def modules(self) -> Dict[str, str]:
        return self._lib["modules"]

    @property
    def severity_weights(self) -> Dict[str, int]:
        return self._lib["severity_weights"]

    @property
    def opinion_bands(self) -> List[Dict[str, Any]]:
        return self._lib["opinion_bands"]

    def node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._by_id.get(node_id)

    def resolve_alias(self, alias: str) -> Optional[Dict[str, Any]]:
        node_id = self._by_alias.get(alias)
        return self._by_id.get(node_id) if node_id else None

    def by_dimension(self, dimension: str) -> List[Dict[str, Any]]:
        return [n for n in self._wh["nodes"] if n["dimension"] == dimension]

    def out_edges(self, node_id: str, relation: Optional[str] = None) -> List[Dict[str, Any]]:
        edges = self._out.get(node_id, [])
        return [e for e in edges if relation is None or e["relation"] == relation]

    def in_edges(self, node_id: str, relation: Optional[str] = None) -> List[Dict[str, Any]]:
        edges = self._in.get(node_id, [])
        return [e for e in edges if relation is None or e["relation"] == relation]

    # --- controls ---------------------------------------------------------

    def controls(self) -> List[Dict[str, Any]]:
        return list(self._lib["controls"])

    def control(self, control_id: str) -> Optional[Dict[str, Any]]:
        return self._controls_by_id.get(control_id)
