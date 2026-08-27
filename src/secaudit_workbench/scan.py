"""Scan and match engine, and the result state machine.

The engine *proposes*; a named auditor *decides*. No automated result is
final until the lead auditor signs it.

Two match tiers are implemented here, in descending confidence:

    Tier 1  deterministic identity match - an identifier in the evidence
            resolves to a warehouse node (e.g. an SBOM package to a known
            vulnerability). Fully reproducible.
    Tier 2  rule match - a declarative predicate over parsed evidence
            fields. Rules live in the control library as data, not code.
            Fully reproducible.

A Tier 3 hook (`propose_tier3`) is included for unstructured, assisted
matching, but this repository does not implement or wire an assist model:
with none provided, a Tier 3 control simply falls to auditor judgment,
which is the correct default, not a degraded one.

Result states: pass | fail | needs_review | not_applicable.

IMPORTANT: this module and risk.py compute results and severity, and
contain no model call and no network call. That is asserted by test, not
left to convention.
"""

import re
from typing import Any, Callable, Dict, List, Optional

RESULT_STATES = ("pass", "fail", "needs_review", "not_applicable")
LIFECYCLE = ("proposed", "reviewed", "confirmed", "overridden", "signed")

_TRANSITIONS = {
    "proposed": {"reviewed", "confirmed", "overridden"},
    "reviewed": {"confirmed", "overridden"},
    "confirmed": {"overridden", "signed"},
    "overridden": {"confirmed", "signed"},
    "signed": set(),
}


def can_transition(current: str, target: str) -> bool:
    return target in _TRANSITIONS.get(current, set())


class ProposedResult:
    def __init__(self, state: str, rationale: str, tier: int,
                 confidence: float = 1.0, offenders: Optional[List[Any]] = None):
        assert state in RESULT_STATES, state
        self.state = state
        self.rationale = rationale
        self.tier = tier
        self.confidence = confidence
        self.offenders = offenders or []

    def as_dict(self) -> Dict[str, Any]:
        return {"state": self.state, "rationale": self.rationale,
                "tier": self.tier, "confidence": self.confidence,
                "offenders": self.offenders}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<%s tier%d %s>" % (self.state, self.tier, self.rationale[:40])


# --- Tier 2: the declarative rule evaluator -------------------------------

_FALSY_WORDS = ("0", "false", "no", "n", "none", "null", "nil",
                "absent", "missing", "n/a", "na", "-")


def _truthy(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        text = value.strip()
        return bool(text) and text.lower() not in _FALSY_WORDS
    return bool(value)


def _norm(value: Any) -> str:
    return str(value).strip().lower() if value is not None else ""


def _test_condition(row: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """Evaluate one condition against one evidence row."""
    value = row.get(condition["field"])

    if "truthy" in condition:
        return _truthy(value) is bool(condition["truthy"])
    if "falsy" in condition:
        return (not _truthy(value)) is bool(condition["falsy"])
    if "in" in condition:
        return _norm(value) in [_norm(v) for v in condition["in"]]
    if "not_in" in condition:
        return _norm(value) not in [_norm(v) for v in condition["not_in"]]
    if "eq" in condition:
        return _norm(value) == _norm(condition["eq"])
    if "matches" in condition:
        return bool(re.search(condition["matches"], str(value or ""), re.I))
    if "gte" in condition:
        try:
            return float(value) >= float(condition["gte"])
        except (TypeError, ValueError):
            return False
    if "lte" in condition:
        try:
            return float(value) <= float(condition["lte"])
        except (TypeError, ValueError):
            return False
    raise ValueError("unrecognised condition: %r" % condition)


def _row_label(row: Dict[str, Any]) -> str:
    for key in ("id", "name", "asset", "tool", "model", "store", "source", "purl"):
        if row.get(key):
            return str(row[key])
    return "(unlabelled row)"


def evaluate_rule(rows: List[Dict[str, Any]], match: Dict[str, Any]) -> ProposedResult:
    """Apply a control's declarative rule to its tagged evidence rows."""
    if not rows:
        return ProposedResult(match.get("on_empty", "needs_review"),
                               "No evidence provided for this control.", 2, 1.0)

    scope_filter = match.get("scope_filter")
    scoped = [r for r in rows if _test_condition(r, scope_filter)] if scope_filter else list(rows)

    if not scoped:
        return ProposedResult(
            "not_applicable",
            "No rows in scope for this control (%d row(s) reviewed, none matched "
            "the scope filter)." % len(rows), 2, 1.0)

    require = match["require"]
    quantifier, condition = next(iter(require.items()))

    verdicts = [(row, _test_condition(row, condition)) for row in scoped]
    holds = [row for row, held in verdicts if held]
    fails = [row for row, held in verdicts if not held]

    if quantifier == "all":
        offenders = fails
        ok = not offenders
    elif quantifier == "none":
        offenders = holds
        ok = not offenders
    elif quantifier == "any":
        offenders = [] if holds else scoped
        ok = bool(holds)
    else:
        raise ValueError("unrecognised quantifier: %s" % quantifier)

    if ok:
        return ProposedResult(
            "pass", "All %d in-scope item(s) satisfy the control." % len(scoped),
            2, 1.0)

    labels = ", ".join(_row_label(r) for r in offenders[:5])
    if len(offenders) > 5:
        labels += ", and %d more" % (len(offenders) - 5)
    return ProposedResult(
        "fail",
        "%d of %d in-scope item(s) fail the control: %s"
        % (len(offenders), len(scoped), labels),
        2, 1.0, [_row_label(r) for r in offenders])


# --- Tier 1: deterministic identity match ---------------------------------

def _version_tuple(version: str):
    parts = re.findall(r"\d+", str(version or ""))
    return tuple(int(p) for p in parts[:4]) or (0,)


def _in_range(version: str, spec: str) -> bool:
    """Supports '<X.Y.Z' and '<=X.Y.Z' and '==X.Y.Z' range specs."""
    spec = (spec or "").strip()
    if spec.startswith("<="):
        return _version_tuple(version) <= _version_tuple(spec[2:])
    if spec.startswith("<"):
        return _version_tuple(version) < _version_tuple(spec[1:])
    if spec.startswith("=="):
        return _version_tuple(version) == _version_tuple(spec[2:])
    return False


def match_vulnerabilities(rows: List[Dict[str, Any]], wh) -> List[Dict[str, Any]]:
    """Tier 1: resolve SBOM packages to warehouse vulnerabilities by purl."""
    hits = []
    for vuln in wh.by_dimension("vulnerability"):
        affects = vuln.get("affects", {})
        for row in rows:
            purl = str(row.get("purl") or row.get("package") or "")
            if not purl or not purl.startswith(affects.get("purl", "\0")):
                continue
            if not _in_range(row.get("version", ""), affects.get("versions", "")):
                continue
            hits.append({
                "vulnerability": vuln["id"],
                "title": vuln["title"],
                "aliases": vuln.get("aliases", []),
                "package": purl,
                "version": row.get("version"),
                "fixed_in": vuln.get("fixed_in"),
                "kev": vuln.get("kev", False),
                "asset": row.get("asset"),
            })
    return hits


def propose_vulnerability_result(hits: List[Dict[str, Any]],
                                  rows: List[Dict[str, Any]]) -> ProposedResult:
    if not rows:
        return ProposedResult("needs_review", "No SBOM provided.", 1, 1.0)
    if not hits:
        return ProposedResult(
            "pass", "No component in the %d-package SBOM matches a known "
                    "vulnerability in this snapshot." % len(rows), 1, 1.0)
    kev = [h for h in hits if h["kev"]]
    if kev:
        labels = ", ".join("%s (%s)" % (h["package"], ", ".join(h["aliases"]) or h["vulnerability"])
                            for h in kev[:5])
        return ProposedResult(
            "fail",
            "%d component(s) carry vulnerabilities with confirmed exploitation "
            "in the wild: %s" % (len(kev), labels), 1, 1.0,
            [h["package"] for h in kev])
    return ProposedResult(
        "needs_review",
        "%d component(s) match known vulnerabilities, none currently listed as "
        "exploited in the wild. Auditor to assess reachability." % len(hits),
        1, 1.0, [h["package"] for h in hits])


# --- Tier 3: assisted match (hook only, no model wired) --------------------

def propose_tier3(control: Dict[str, Any],
                   assist: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
                   ) -> ProposedResult:
    """Assisted matching over unstructured evidence.

    The model call is injected rather than imported, so this offline core has
    no model dependency and the independence guardrail holds by construction.
    With no assist function wired (the default), the control falls to auditor
    judgment, which is the correct default, not a degraded one.

    Tier 3 confidence is capped below Tiers 1 and 2 and is never
    auto-confirmed, regardless of what an assist function reports.
    """
    if assist is None:
        return ProposedResult(
            "needs_review",
            "Auditor review required (tier 3 control): %s" % control.get("logic", ""),
            3, 0.0)
    proposed = assist(control)
    return ProposedResult(
        proposed.get("state", "needs_review"),
        proposed.get("rationale", ""), 3,
        min(float(proposed.get("confidence", 0.5)), 0.75))


# --- the engine ------------------------------------------------------------

class ScanEngine:
    """Runs the control library against an engagement's parsed evidence.

    `evidence` maps an evidence-set name (as named in a control's match spec)
    to a list of parsed rows.
    """

    def __init__(self, warehouse, assist: Optional[Callable] = None):
        self.wh = warehouse
        self.assist = assist

    def propose(self, control: Dict[str, Any],
                evidence: Dict[str, List[Dict[str, Any]]]) -> ProposedResult:
        if not control.get("applicable", True):
            return ProposedResult("not_applicable",
                                   control.get("scope_reason", "Out of scope."), 2, 1.0)

        match = control.get("match")
        if not match:
            return propose_tier3(control, self.assist)

        rows = evidence.get(match["evidence"], [])

        if match.get("tier1") == "vulnerability_match":
            hits = match_vulnerabilities(rows, self.wh)
            return propose_vulnerability_result(hits, rows)

        if control.get("tier") == 3:
            return propose_tier3(control, self.assist)

        return evaluate_rule(rows, match)

    def run(self, evidence: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """Scan every control in the loaded warehouse. Results enter as `proposed`."""
        results = []
        for control in self.wh.controls():
            proposed = self.propose(control, evidence)
            results.append({
                "control_id": control["id"],
                "module": control["module"],
                "severity": control["severity"],
                "weakness": control.get("weakness"),
                "state": proposed.state,
                "rationale": proposed.rationale,
                "tier": proposed.tier,
                "confidence": proposed.confidence,
                "offenders": proposed.offenders,
                "lifecycle": "proposed",
            })
        return results
