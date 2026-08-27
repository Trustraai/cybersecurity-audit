"""Minimal FastAPI service exposing engagement verification."""

from fastapi import FastAPI, HTTPException

from ..storage import Storage
from ..warehouse import Warehouse

app = FastAPI(title="Trustra Cybersecurity Audit Workbench (rails)")

_wh = Warehouse()


@app.get("/warehouse")
def warehouse_info():
    return {"version": _wh.version, "digest": _wh.digest,
            "controls": len(_wh.controls())}


@app.get("/engagements/{engagement_id}/verify")
def verify_engagement(engagement_id: int, db: str = "secaudit.db"):
    store = Storage(db)
    engagement = store.engagement(engagement_id)
    if not engagement:
        store.close()
        raise HTTPException(status_code=404, detail="engagement not found")
    ok, break_at = store.verify_ledger(engagement_id)
    store.close()
    return {"engagement_id": engagement_id, "valid": ok,
            "break_index": break_at if not ok else None}
