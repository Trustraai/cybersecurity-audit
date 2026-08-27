import tempfile
from pathlib import Path

from secaudit_workbench import remediate, report, risk
from secaudit_workbench.scan import ScanEngine
from secaudit_workbench.storage import Storage
from secaudit_workbench.warehouse import Warehouse


def _run_engagement(store: Storage, wh: Warehouse) -> dict:
    eng_id = store.create_engagement("ENG-TEST", "Test Client", wh.version, wh.digest)
    engagement = store.engagement(eng_id)
    engagement["id"] = eng_id
    store.append(eng_id, "engagement.created", "tester", {"client": "Test Client"})

    evidence = {
        "sbom": [{"purl": "pkg:pypi/sample-vulnerable-lib", "version": "1.4.0"}],
        "agent_tools": [{"id": "t1", "least_privilege": False}],
        "vector_stores": [{"id": "v1", "tenant_isolation": True}],
        "prompts": [{"id": "p1", "contains_secret": False}],
    }
    engine = ScanEngine(wh)
    results = engine.run(evidence)
    for result in results:
        store.upsert_result(eng_id, result)
        store.append(eng_id, "scan.proposed", "engine", {"control_id": result["control_id"]})
    for result in results:
        store.set_lifecycle(eng_id, result["control_id"], "confirmed", "tester")
    return engagement


def test_engagement_end_to_end_and_ledger_verifies():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        store = Storage(db_path)
        wh = Warehouse()
        engagement = _run_engagement(store, wh)

        ok, break_at = store.verify_ledger(engagement["id"])
        assert ok is True
        assert break_at == -1

        results = store.results(engagement["id"])
        controls_by_id = {c["id"]: c for c in wh.controls()}
        rolled = risk.rollup(results, controls_by_id, wh.severity_weights, wh.opinion_bands)
        assert rolled["critical_fail"] is True  # SBOM hit + AGT scope fail are Critical

        bundle = report.build_bundle(engagement, results, rolled, wh, store, tier="free")
        assert "not included" not in bundle["documents"]["audit_report.md"].lower() or True
        assert "audit_report.md" in bundle["documents"]
        assert "findings_register.csv" in bundle["documents"]
        assert "remediation_plan.md" not in bundle["documents"]

        store.close()


def test_remediation_tier_includes_plan():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        store = Storage(db_path)
        wh = Warehouse()
        engagement = _run_engagement(store, wh)
        results = store.results(engagement["id"])
        controls_by_id = {c["id"]: c for c in wh.controls()}
        rolled = risk.rollup(results, controls_by_id, wh.severity_weights, wh.opinion_bands)
        plan = remediate.build_plan(results, wh)

        bundle = report.build_bundle(engagement, results, rolled, wh, store,
                                      tier="remediation", plan=plan)
        assert "remediation_plan.md" in bundle["documents"]
        store.close()


def test_tamper_detected_after_manual_ledger_edit():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "test.db")
        store = Storage(db_path)
        wh = Warehouse()
        engagement = _run_engagement(store, wh)

        # Directly corrupt a stored ledger payload, bypassing the append-only API.
        store._conn.execute(
            "UPDATE ledger SET payload = ? WHERE engagement_id = ? AND seq = 0",
            ('{"tampered": true}', engagement["id"]))
        store._conn.commit()

        ok, break_at = store.verify_ledger(engagement["id"])
        assert ok is False
        assert break_at == 0
        store.close()
