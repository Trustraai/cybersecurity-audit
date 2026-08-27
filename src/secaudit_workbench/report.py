"""Report generation - the deliverable artifacts.

All are projections of the SAME engagement dataset: no duplicate entry, no
version drift. Each is SHA-256 sealed and carries the verification reference
plus the warehouse version it was produced against.

    Audit Report        formal, opinion-led deliverable (Markdown)
    Working Papers       control-by-control evidentiary backing
    Executive Summary    leadership view
    Findings Register    machine-readable CSV
    Remediation Plan      paid tier only (see remediate.py)

This repository does not implement corpus-based prediction (latent
weakness, attack-path, or control-decay forecasting) - see
docs/ARCHITECTURE.md and CONTRIBUTING.md for why that is out of scope.
"""

import csv
import datetime
import hashlib
import io
from typing import Any, Dict, List, Optional

from .attribution import verification_reference
from .entitlements import Entitlement

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def _seal(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _header(title: str, engagement: Dict[str, Any], reference: str) -> List[str]:
    return [
        "# %s" % title,
        "",
        "**Client:** %s  " % engagement["client"],
        "**Engagement:** %s  " % engagement["ref"],
        "**Period:** %s to %s  " % (engagement.get("period_start") or "-",
                                     engagement.get("period_end") or "-"),
        "**Warehouse version:** %s  " % engagement["warehouse_version"],
        "**Warehouse digest:** `%s`  " % engagement["warehouse_digest"][:16],
        "**Verification reference:** `%s`" % reference,
        "",
    ]


def _confirmed(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Only auditor-confirmed or signed results reach the formal report."""
    return [r for r in results if r.get("lifecycle") in ("confirmed", "signed")]


def findings(results: List[Dict[str, Any]], wh) -> List[Dict[str, Any]]:
    out = []
    for result in _confirmed(results):
        if result["state"] != "fail":
            continue
        control = wh.control(result["control_id"])
        if not control:
            continue
        weakness = wh.node(control.get("weakness")) or {}
        out.append({
            "control_id": control["id"],
            "module": control["module_name"],
            "title": control["title"],
            "severity": control["severity"],
            "tier": result.get("tier", control.get("tier")),
            "weakness": weakness.get("title", control.get("weakness")),
            "weakness_id": control.get("weakness"),
            "narrative": control["finding_template"],
            "rationale": result["rationale"],
        })
    out.sort(key=lambda f: (_SEVERITY_ORDER.get(f["severity"], 9), f["control_id"]))
    return out


# --- artifact 1: audit report ----------------------------------------------

def audit_report(engagement, results, rollup, wh, reference,
                  opinion_override=None, auditor_commentary="") -> str:
    lines = _header("Cybersecurity Vulnerability Audit Report", engagement, reference)

    opinion = opinion_override or rollup["proposed_opinion"]
    lines += [
        "## 1. Opinion", "",
        "**%s**" % opinion["label"], "",
        opinion["definition"], "",
        "Weighted risk: **%.1f%%** across %d applicable control(s)."
        % (rollup["risk_pct"], sum(v for k, v in rollup["counts"].items()
                                    if k != "not_applicable")), "",
    ]
    if rollup["critical_fail"]:
        lines += [
            "> A Critical-severity failure was confirmed (%s). The opinion is "
            "forced out of the top band and requires explicit auditor "
            "commentary." % ", ".join(rollup["critical_fails"]), "",
        ]
    if auditor_commentary:
        lines += ["**Auditor commentary.** %s" % auditor_commentary, ""]

    lines += ["## 2. Scope and methodology", "",
              "The engagement tested the client's declared evidence against the "
              "knowledge warehouse at version %s. Results were proposed by the "
              "scan engine and decided by the named auditor; no automated result "
              "is final without sign-off." % engagement["warehouse_version"],
              "", "| Result | Count |", "|---|---|"]
    for state, count in rollup["counts"].items():
        lines.append("| %s | %d |" % (state.replace("_", " "), count))
    lines.append("")

    found = findings(results, wh)
    lines += ["## 3. Confirmed findings", ""]
    if not found:
        lines += ["No confirmed findings.", ""]
    for n, finding in enumerate(found, 1):
        lines += [
            "### 3.%d %s - %s" % (n, finding["control_id"], finding["title"]), "",
            "**Severity:** %s  " % finding["severity"],
            "**Weakness:** %s (`%s`)  " % (finding["weakness"], finding["weakness_id"]),
            "**Match tier:** %s" % finding["tier"], "",
            finding["narrative"].replace("{client}", engagement["client"]), "",
            "*Basis.* %s" % finding["rationale"], "",
        ]

    lines += ["## 4. Module summary", "", "| Module | Pass | Fail | Review | N/A |",
              "|---|---|---|---|---|"]
    for module, counts in sorted(rollup["by_module"].items()):
        lines.append("| %s | %d | %d | %d | %d |" % (
            wh.modules.get(module, module), counts["pass"], counts["fail"],
            counts["needs_review"], counts["not_applicable"]))
    lines += ["", "---", "",
              "This is a product-generated audit instrument, not a security "
              "certification."]
    return "\n".join(lines)


# --- artifact 2: working papers ---------------------------------------------

def working_papers(engagement, results, wh, reference, artifacts, ledger) -> str:
    lines = _header("Working Papers", engagement, reference)

    lines += ["## Evidence artifacts", "",
              "| Artifact | Evidence set | Rows | SHA-256 |",
              "|---|---|---|---|"]
    for art in artifacts:
        lines.append("| %s | %s | %d | `%s` |" % (
            art["name"], art["evidence_set"], art["row_count"], art["sha256"][:16]))
    if not artifacts:
        lines.append("| (none) | | | |")
    lines.append("")

    lines += ["## Control-by-control record", ""]
    for result in sorted(results, key=lambda r: r["control_id"]):
        control = wh.control(result["control_id"])
        if not control:
            continue
        lines += [
            "### %s - %s" % (control["id"], control["title"]), "",
            "**Module:** %s  " % control["module_name"],
            "**Severity:** %s  " % control["severity"],
            "**Match tier:** %s  " % result.get("tier", control.get("tier")),
            "**Engine proposal:** %s  " % result["state"],
            "**Lifecycle:** %s  " % result.get("lifecycle", "proposed"),
            "**Auditor:** %s" % (result.get("auditor") or "-"), "",
            "*Obligation.* %s" % control["obligation"], "",
            "*Test applied.* %s" % control["logic"], "",
            "*Result basis.* %s" % result["rationale"], "",
        ]
        if result.get("override_rationale"):
            lines += ["*Auditor override rationale.* %s"
                      % result["override_rationale"], ""]

    lines += ["## Ledger", "",
              "Append-only, hash-chained: `entry_hash = sha256(prev_hash + "
              "canonical_json(entry))`. Altering any entry breaks every hash "
              "after it.", "",
              "| Seq | Action | Actor | Entry hash |", "|---|---|---|---|"]
    for entry in ledger:
        lines.append("| %d | %s | %s | `%s` |" % (
            entry["seq"], entry["action"], entry["actor"], entry["entry_hash"][:16]))
    lines.append("")
    return "\n".join(lines)


# --- artifact 3: executive summary ------------------------------------------

def executive_summary(engagement, results, rollup, wh, reference) -> str:
    lines = _header("Executive Summary", engagement, reference)
    opinion = rollup["proposed_opinion"]

    lines += [
        "## Position", "",
        "**%s** - weighted risk %.1f%%." % (opinion["label"], rollup["risk_pct"]), "",
    ]

    found = findings(results, wh)
    critical = [f for f in found if f["severity"] == "Critical"]
    high = [f for f in found if f["severity"] == "High"]
    lines += [
        "%d confirmed finding(s): %d Critical, %d High."
        % (len(found), len(critical), len(high)), "",
        "## Priorities", "",
    ]
    for n, finding in enumerate(found[:5], 1):
        lines.append("%d. **%s** (%s)" % (n, finding["title"], finding["severity"]))
    if not found:
        lines.append("No remediation priorities arise from confirmed findings.")
    lines.append("")
    return "\n".join(lines)


# --- artifact 4: findings register (CSV) ------------------------------------

def findings_register(engagement, results, wh, reference) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow([
        "engagement_ref", "verification_reference", "warehouse_version",
        "control_id", "module", "title", "severity", "match_tier",
        "weakness_id", "weakness", "basis",
    ])
    for finding in findings(results, wh):
        writer.writerow([
            engagement["ref"], reference, engagement["warehouse_version"],
            finding["control_id"], finding["module"], finding["title"],
            finding["severity"], finding["tier"], finding["weakness_id"],
            finding["weakness"], finding["rationale"],
        ])
    return buf.getvalue()


# --- bundle ------------------------------------------------------------

def upgrade_notice(entitlement: Entitlement, counts: Dict[str, int]) -> List[str]:
    """The block a free report carries in place of the paid sections.

    Declared and counted, never a silent omission.
    """
    withheld = entitlement.withheld()
    if not withheld:
        return []
    lines = [
        "## Not included at this tier", "",
        "This engagement was produced at the **%s** tier. The audit above is "
        "complete: findings, severity, the opinion, and the evidence chain are "
        "all here and independently verifiable." % entitlement.label, "",
        "What is not included:", "",
    ]
    for capability in withheld:
        notice = entitlement.notice(capability, counts.get(capability))
        if notice:
            lines.append("- %s" % notice)
    lines.append("")
    return lines


def build_bundle(engagement, results, rollup, wh, storage,
                  report_version: int = 1, auditor_commentary: str = "",
                  tier: str = "free", plan=None) -> Dict[str, Any]:
    """Generate every artifact from the one dataset and seal each."""
    chain_head = storage.chain_head(engagement["id"])
    reference = verification_reference(
        engagement["ref"], chain_head, engagement["warehouse_version"],
        report_version)

    artifacts = storage.artifacts(engagement["id"])
    ledger = storage.ledger(engagement["id"])
    ent = Entitlement(tier)

    counts = {
        "remediation_steps": len(findings(results, wh)),
        "root_cause_analysis": (plan or {}).get("subjects_total", 0),
        "remediation_plan": (plan or {}).get("subjects_total", 0),
    }

    docs = {
        "audit_report.md": audit_report(
            engagement, results, rollup, wh, reference,
            auditor_commentary=auditor_commentary),
        "working_papers.md": working_papers(
            engagement, results, wh, reference, artifacts, ledger),
        "executive_summary.md": executive_summary(
            engagement, results, rollup, wh, reference),
        "findings_register.csv": findings_register(
            engagement, results, wh, reference),
    }

    if ent.allows("remediation_plan") and plan is not None:
        from .remediate import render_plan
        docs["remediation_plan.md"] = render_plan(engagement, plan, wh, reference)

    notice = upgrade_notice(ent, counts)
    if notice:
        docs["audit_report.md"] = docs["audit_report.md"] + "\n\n" + "\n".join(notice)

    seals = {name: _seal(body) for name, body in docs.items()}

    return {
        "reference": reference,
        "chain_head": chain_head,
        "warehouse_version": engagement["warehouse_version"],
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "entitlement": ent.manifest(),
        "documents": docs,
        "seals": seals,
    }
