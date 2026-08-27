"""Remediation planning (paid tier).

A findings register is a list. A remediation plan is an order. This module
turns one into the other:

    1. cluster    collapse findings onto the systems that cause them
    2. leverage   score each cluster by severity weight closed per unit effort
    3. sequence   order by leverage, then by severity

No model call and no network call: this is arithmetic over the engagement's
own confirmed findings, so the plan is reproducible and explainable. It does
not depend on any cross-client corpus - see CONTRIBUTING.md for why that
capability is deliberately not part of this repository.
"""

from typing import Any, Dict, List, Optional

from .report import findings

_EFFORT_WEIGHT = {"hours": 1.0, "days": 3.0, "weeks": 10.0}
_SEVERITY_WEIGHT = {"Critical": 20, "High": 7, "Medium": 3, "Low": 1}

_URGENCY = [
    (18.0, "Immediate", "Start today. High exposure closed for little effort."),
    (7.0, "This week", "Schedule into the current sprint."),
    (2.5, "This month", "Plan into the next cycle."),
    (0.0, "Backlog", "Track and address on the normal cadence."),
]


def _urgency(score: float):
    for threshold, label, guidance in _URGENCY:
        if score >= threshold:
            return label, guidance
    return _URGENCY[-1][1], _URGENCY[-1][2]


def cluster(results: List[Dict[str, Any]], wh) -> List[Dict[str, Any]]:
    """Group confirmed findings by the evidence row that actually triggered them."""
    found = findings(results, wh)
    by_control = {r["control_id"]: r for r in results}

    groups: Dict[str, Dict[str, Any]] = {}
    for finding in found:
        result = by_control.get(finding["control_id"], {})
        offenders = result.get("offenders") or []
        if isinstance(offenders, str):
            offenders = [offenders]
        if not offenders:
            offenders = ["(estate-wide)"]

        for subject in offenders:
            group = groups.setdefault(subject, {
                "subject": subject, "findings": [], "max_severity": "Low",
                "severity_weight": 0,
            })
            group["findings"].append(finding)
            if (_SEVERITY_WEIGHT.get(finding["severity"], 0)
                    > _SEVERITY_WEIGHT.get(group["max_severity"], 0)):
                group["max_severity"] = finding["severity"]
            group["severity_weight"] += _SEVERITY_WEIGHT.get(finding["severity"], 0)

    return sorted(groups.values(),
                  key=lambda g: (-g["severity_weight"], g["subject"]))


def build_plan(results: List[Dict[str, Any]], wh,
               default_effort: str = "days") -> Dict[str, Any]:
    """The sequenced remediation plan.

    leverage = severity weight closed / effort weight

    Every term is visible in the output.
    """
    groups = cluster(results, wh)
    workstreams = []
    for group in groups:
        effort_weight = _EFFORT_WEIGHT.get(default_effort, 3.0)
        leverage = round(group["severity_weight"] / effort_weight, 2)
        label, guidance = _urgency(leverage)
        if group["max_severity"] == "Critical" and label in ("This month", "Backlog"):
            label, guidance = "This week", (
                "Confirmed Critical. Effort is non-trivial, but it cannot wait a cycle.")
        workstreams.append({
            "subject": group["subject"],
            "max_severity": group["max_severity"],
            "finding_ids": [f["control_id"] for f in group["findings"]],
            "finding_count": len(group["findings"]),
            "effort": default_effort,
            "urgency": label,
            "guidance": guidance,
            "leverage": leverage,
            "basis": ("closes %d finding(s) worth %d severity weight; effort %s"
                      % (len(group["findings"]), group["severity_weight"],
                         default_effort)),
        })

    workstreams.sort(key=lambda w: (-w["leverage"],
                                     -_SEVERITY_WEIGHT.get(w["max_severity"], 0)))

    findings_total = len(findings(results, wh))
    return {
        "workstreams": workstreams,
        "findings_total": findings_total,
        "subjects_total": len(workstreams),
        "concentration": _concentration(workstreams, findings_total),
    }


def _concentration(workstreams: List[Dict[str, Any]], total: int) -> Optional[str]:
    if not workstreams or not total:
        return None
    largest = max(workstreams, key=lambda w: w["finding_count"])
    if largest["finding_count"] >= max(2, total * 0.3):
        return ("%d of %d findings trace to a single subject (%s). Addressing it "
                "is one decision, not %d pieces of work."
                % (largest["finding_count"], total, largest["subject"],
                   largest["finding_count"]))
    top = workstreams[0]
    return ("%d findings across %d subjects; the highest-leverage first action is "
            "%s." % (total, len(workstreams), top["subject"]))


def render_plan(engagement: Dict[str, Any], plan: Dict[str, Any], wh,
                 reference: str) -> str:
    from .report import _header

    lines = _header("Remediation Plan", engagement, reference)
    lines += [
        "> This plan is ordered by **leverage**, not by severity alone: the "
        "finding with the worst label is not always the one to fix first.", "",
    ]
    if plan.get("concentration"):
        lines += ["## The headline", "", plan["concentration"], ""]

    workstreams = plan.get("workstreams", [])
    lines += [
        "## Sequence", "",
        "%d findings resolve into %d workstreams."
        % (plan.get("findings_total", 0), plan.get("subjects_total", 0)), "",
        "| # | Subject | Urgency | Effort | Closes | Leverage |",
        "|---|---|---|---|---|---|",
    ]
    for n, work in enumerate(workstreams, 1):
        lines.append("| %d | `%s` | **%s** | %s | %d finding(s) | %.2f |" % (
            n, work["subject"], work["urgency"], work["effort"],
            work["finding_count"], work["leverage"]))
    if not workstreams:
        lines.append("| - | No confirmed findings to remediate. | | | | |")
    lines.append("")

    lines += ["## Workstreams", ""]
    for n, work in enumerate(workstreams, 1):
        lines += [
            "### %d. %s" % (n, work["subject"]), "",
            "**Urgency:** %s | **Effort:** %s | **Highest severity:** %s | "
            "**Leverage:** %.2f" % (work["urgency"], work["effort"],
                                     work["max_severity"], work["leverage"]), "",
            "%s" % work["guidance"], "",
            "*Why here.* %s" % work["basis"], "",
            "*Closes.* %s" % ", ".join("`%s`" % f for f in work["finding_ids"]), "",
            "**Owner:** _______________  **Target date:** _______________", "",
        ]
    return "\n".join(lines)
