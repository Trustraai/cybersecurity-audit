"""Severity-to-risk rollup and opinion bands.

Weighted by severity: Low 1, Medium 3, High 7, Critical 20.

The auditor, not the software, owns the final opinion: the tool proposes a
band and the auditor confirms or adjusts it with rationale. Any Critical-
severity confirmed fail forces the opinion out of the top band and requires
explicit auditor commentary.

No model call and no network call in this module, asserted by test.
"""

from typing import Any, Dict, List

_STATE_RISK = {
    "pass": 0.0,
    "not_applicable": 0.0,
    "needs_review": 0.5,
    "fail": 1.0,
}


def rollup(results: List[Dict[str, Any]],
           controls_by_id: Dict[str, Dict[str, Any]],
           severity_weights: Dict[str, int],
           opinion_bands: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Counts, weighted risk %, and the proposed opinion band."""
    counts = {"pass": 0, "fail": 0, "needs_review": 0, "not_applicable": 0}
    by_module: Dict[str, Dict[str, int]] = {}
    by_tier: Dict[int, int] = {}
    total_weight = 0.0
    risk_weight = 0.0
    critical_fails: List[str] = []

    for result in results:
        control = controls_by_id.get(result["control_id"])
        if not control:
            continue
        state = result["state"]
        counts[state] = counts.get(state, 0) + 1

        module = control["module"]
        mod = by_module.setdefault(module, {"pass": 0, "fail": 0,
                                             "needs_review": 0, "not_applicable": 0})
        mod[state] = mod.get(state, 0) + 1

        tier = result.get("tier", control.get("tier", 2))
        by_tier[tier] = by_tier.get(tier, 0) + 1

        if state == "not_applicable":
            continue
        weight = severity_weights.get(control.get("severity", "Medium"), 3)
        total_weight += weight
        risk_weight += weight * _STATE_RISK.get(state, 0.0)

        if state == "fail" and control.get("severity") == "Critical":
            critical_fails.append(result["control_id"])

    risk_pct = round((risk_weight / total_weight) * 100, 1) if total_weight else 0.0
    proposed = _propose_band(risk_pct, bool(critical_fails), opinion_bands)

    return {
        "counts": counts,
        "by_module": by_module,
        "by_tier": by_tier,
        "risk_pct": risk_pct,
        "risk_weight": round(risk_weight, 1),
        "total_weight": round(total_weight, 1),
        "critical_fail": bool(critical_fails),
        "critical_fails": critical_fails,
        "proposed_opinion": proposed,
    }


def _propose_band(risk_pct: float, critical_fail: bool,
                   opinion_bands: List[Dict[str, Any]]) -> Dict[str, Any]:
    """First band whose ceiling the risk fits under. A Critical-severity fail
    forces the conclusion out of the top band."""
    bands = sorted(opinion_bands, key=lambda b: b["max_risk_pct"])
    chosen = bands[-1]
    for band in bands:
        if risk_pct <= band["max_risk_pct"]:
            chosen = band
            break
    if critical_fail and chosen is bands[0]:
        chosen = bands[1] if len(bands) > 1 else bands[-1]
    out = dict(chosen)
    out["forced_by_critical"] = critical_fail
    out["note"] = ("A Critical-severity fail forces the opinion out of the top "
                   "band and requires explicit auditor commentary."
                   if critical_fail else "")
    return out


def posture_score(rollup_result: Dict[str, Any]) -> int:
    """Engagement dashboard score, 0-100. Inverse of weighted risk."""
    return max(0, round(100 - rollup_result["risk_pct"]))
