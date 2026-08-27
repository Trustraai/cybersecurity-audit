"""Engagement store and the append-only evidence ledger.

SQLite for local and offline use. The ledger is append-only: there is
deliberately no update or delete path for ledger entries.
"""

import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

from .hashchain import GENESIS, link, verify_chain

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ref TEXT UNIQUE NOT NULL,
    client TEXT NOT NULL,
    period_start TEXT,
    period_end TEXT,
    warehouse_version TEXT NOT NULL,
    warehouse_digest TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE INDEX IF NOT EXISTS idx_ledger_eng ON ledger(engagement_id, seq);
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    evidence_set TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    row_count INTEGER NOT NULL DEFAULT 0,
    at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    control_id TEXT NOT NULL,
    state TEXT NOT NULL,
    rationale TEXT NOT NULL,
    tier INTEGER NOT NULL,
    confidence REAL NOT NULL DEFAULT 1.0,
    lifecycle TEXT NOT NULL DEFAULT 'proposed',
    offenders TEXT NOT NULL DEFAULT '[]',
    auditor TEXT,
    override_rationale TEXT,
    UNIQUE (engagement_id, control_id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
CREATE TABLE IF NOT EXISTS signoffs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    scope TEXT NOT NULL,
    lead_auditor TEXT NOT NULL,
    chain_head TEXT NOT NULL,
    at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
"""


class Storage:
    def __init__(self, path: str = "secaudit.db"):
        self._path = path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # --- engagements --------------------------------------------------

    def create_engagement(self, ref: str, client: str,
                           warehouse_version: str, warehouse_digest: str,
                           period_start: str = "", period_end: str = "") -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO engagements (ref, client, period_start, period_end, "
                "warehouse_version, warehouse_digest) VALUES (?, ?, ?, ?, ?, ?)",
                (ref, client, period_start, period_end, warehouse_version,
                 warehouse_digest))
            self._conn.commit()
            return cur.lastrowid

    def engagement(self, engagement_id: int) -> Optional[Dict[str, Any]]:
        row = self._conn.execute("SELECT * FROM engagements WHERE id = ?",
                                  (engagement_id,)).fetchone()
        return dict(row) if row else None

    # --- the ledger (append-only) ----------------------------------------

    def chain_head(self, engagement_id: int) -> str:
        row = self._conn.execute(
            "SELECT entry_hash FROM ledger WHERE engagement_id = ? "
            "ORDER BY seq DESC LIMIT 1", (engagement_id,)).fetchone()
        return row["entry_hash"] if row else GENESIS

    def append(self, engagement_id: int, action: str, actor: str,
               payload: Dict[str, Any]) -> str:
        """Append one hash-linked entry. There is no update or delete path."""
        with self._lock:
            row = self._conn.execute(
                "SELECT seq, entry_hash FROM ledger WHERE engagement_id = ? "
                "ORDER BY seq DESC LIMIT 1", (engagement_id,)).fetchone()
            seq = (row["seq"] + 1) if row else 0
            prev = row["entry_hash"] if row else GENESIS

            body = {"seq": seq, "action": action, "actor": actor, "payload": payload}
            entry_hash = link(prev, body)
            self._conn.execute(
                "INSERT INTO ledger (engagement_id, seq, action, actor, payload, "
                "entry_hash) VALUES (?, ?, ?, ?, ?, ?)",
                (engagement_id, seq, action, actor,
                 json.dumps(payload, sort_keys=True), entry_hash))
            self._conn.commit()
            return entry_hash

    def ledger(self, engagement_id: int) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM ledger WHERE engagement_id = ? ORDER BY seq",
            (engagement_id,)).fetchall()
        return [dict(r) for r in rows]

    def ledger_pairs(self, engagement_id: int) -> List[Tuple[Dict[str, Any], str]]:
        out = []
        for row in self.ledger(engagement_id):
            body = {"seq": row["seq"], "action": row["action"],
                    "actor": row["actor"], "payload": json.loads(row["payload"])}
            out.append((body, row["entry_hash"]))
        return out

    def verify_ledger(self, engagement_id: int) -> Tuple[bool, int]:
        return verify_chain(self.ledger_pairs(engagement_id))

    # --- artifacts --------------------------------------------------------

    def add_artifact(self, engagement_id: int, name: str, evidence_set: str,
                      sha256: str, row_count: int) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO artifacts (engagement_id, name, evidence_set, sha256, "
                "row_count) VALUES (?, ?, ?, ?, ?)",
                (engagement_id, name, evidence_set, sha256, row_count))
            self._conn.commit()
            return cur.lastrowid

    def artifacts(self, engagement_id: int) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM artifacts WHERE engagement_id = ? ORDER BY id",
            (engagement_id,)).fetchall()
        return [dict(r) for r in rows]

    # --- results ------------------------------------------------------

    def upsert_result(self, engagement_id: int, result: Dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO results (engagement_id, control_id, state, rationale, "
                "tier, confidence, lifecycle, offenders) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(engagement_id, control_id) DO UPDATE SET "
                "state=excluded.state, rationale=excluded.rationale, "
                "tier=excluded.tier, confidence=excluded.confidence, "
                "offenders=excluded.offenders",
                (engagement_id, result["control_id"], result["state"],
                 result["rationale"], result["tier"],
                 result.get("confidence", 1.0), result.get("lifecycle", "proposed"),
                 json.dumps(result.get("offenders") or [])))
            self._conn.commit()

    def set_lifecycle(self, engagement_id: int, control_id: str, lifecycle: str,
                       auditor: str, override_rationale: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE results SET lifecycle = ?, auditor = ?, "
                "override_rationale = ? WHERE engagement_id = ? AND control_id = ?",
                (lifecycle, auditor, override_rationale, engagement_id, control_id))
            self._conn.commit()

    def results(self, engagement_id: int) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM results WHERE engagement_id = ? ORDER BY control_id",
            (engagement_id,)).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["offenders"] = json.loads(item.get("offenders") or "[]")
            out.append(item)
        return out

    # --- sign-off -----------------------------------------------------

    def sign_off(self, engagement_id: int, scope: str, lead_auditor: str,
                 chain_head: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO signoffs (engagement_id, scope, lead_auditor, "
                "chain_head) VALUES (?, ?, ?, ?)",
                (engagement_id, scope, lead_auditor, chain_head))
            self._conn.commit()
            return cur.lastrowid

    def signoffs(self, engagement_id: int) -> List[Dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM signoffs WHERE engagement_id = ? ORDER BY id",
            (engagement_id,)).fetchall()
        return [dict(r) for r in rows]
