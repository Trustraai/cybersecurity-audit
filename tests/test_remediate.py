from secaudit_workbench import remediate
from secaudit_workbench.scan import ScanEngine
from secaudit_workbench.warehouse import Warehouse


def _confirmed_results():
    wh = Warehouse()
    evidence = {
        "sbom": [{"purl": "pkg:pypi/sample-vulnerable-lib", "version": "1.4.0"}],
        "agent_tools": [{"id": "t1", "least_privilege": False}],
    }
    results = ScanEngine(wh).run(evidence)
    for r in results:
        r["lifecycle"] = "confirmed"
    return results, wh


def test_cluster_groups_by_offender():
    results, wh = _confirmed_results()
    groups = remediate.cluster(results, wh)
    assert len(groups) >= 1
    assert all("subject" in g for g in groups)


def test_build_plan_sorts_by_leverage_desc():
    results, wh = _confirmed_results()
    plan = remediate.build_plan(results, wh)
    leverages = [w["leverage"] for w in plan["workstreams"]]
    assert leverages == sorted(leverages, reverse=True)


def test_render_plan_contains_sequence_table():
    results, wh = _confirmed_results()
    plan = remediate.build_plan(results, wh)
    text = remediate.render_plan(
        {"client": "X", "ref": "E1", "warehouse_version": wh.version,
         "warehouse_digest": wh.digest, "period_start": "", "period_end": ""},
        plan, wh, "REF-1")
    assert "## Sequence" in text
