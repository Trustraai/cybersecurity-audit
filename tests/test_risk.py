from secaudit_workbench.risk import posture_score, rollup

CONTROLS = {
    "C1": {"module": "AIS", "severity": "Critical", "tier": 1},
    "C2": {"module": "LLM", "severity": "Medium", "tier": 2},
}
WEIGHTS = {"Low": 1, "Medium": 3, "High": 7, "Critical": 20}
BANDS = [
    {"label": "No material exposure identified", "max_risk_pct": 5, "definition": "d1"},
    {"label": "Exposure identified with findings", "max_risk_pct": 30, "definition": "d2"},
    {"label": "Material exposure identified", "max_risk_pct": 100, "definition": "d3"},
]


def test_rollup_all_pass_zero_risk():
    results = [{"control_id": "C1", "state": "pass"}, {"control_id": "C2", "state": "pass"}]
    out = rollup(results, CONTROLS, WEIGHTS, BANDS)
    assert out["risk_pct"] == 0.0
    assert out["proposed_opinion"]["label"] == "No material exposure identified"


def test_critical_fail_forces_opinion_out_of_top_band():
    results = [{"control_id": "C1", "state": "fail"}, {"control_id": "C2", "state": "pass"}]
    out = rollup(results, CONTROLS, WEIGHTS, BANDS)
    assert out["critical_fail"] is True
    assert out["proposed_opinion"]["label"] != "No material exposure identified"


def test_not_applicable_excluded_from_denominator():
    results = [{"control_id": "C1", "state": "not_applicable"},
               {"control_id": "C2", "state": "fail"}]
    out = rollup(results, CONTROLS, WEIGHTS, BANDS)
    assert out["total_weight"] == 3.0


def test_posture_score_inverse_of_risk():
    out = {"risk_pct": 30.0}
    assert posture_score(out) == 70
