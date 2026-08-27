from secaudit_workbench.scan import (
    ProposedResult, can_transition, evaluate_rule, match_vulnerabilities,
    propose_tier3, propose_vulnerability_result,
)
from secaudit_workbench.warehouse import Warehouse


def test_can_transition_lifecycle():
    assert can_transition("proposed", "confirmed")
    assert not can_transition("signed", "confirmed")


def test_evaluate_rule_all_pass():
    rows = [{"id": "a", "least_privilege": True}, {"id": "b", "least_privilege": True}]
    match = {"evidence": "agent_tools",
             "require": {"all": {"field": "least_privilege", "truthy": True}}}
    result = evaluate_rule(rows, match)
    assert result.state == "pass"


def test_evaluate_rule_all_fail_lists_offenders():
    rows = [{"id": "a", "least_privilege": True}, {"id": "b", "least_privilege": False}]
    match = {"evidence": "agent_tools",
             "require": {"all": {"field": "least_privilege", "truthy": True}}}
    result = evaluate_rule(rows, match)
    assert result.state == "fail"
    assert result.offenders == ["b"]


def test_evaluate_rule_no_evidence_needs_review():
    match = {"evidence": "agent_tools",
             "require": {"all": {"field": "least_privilege", "truthy": True}}}
    result = evaluate_rule([], match)
    assert result.state == "needs_review"


def test_match_vulnerabilities_and_propose():
    wh = Warehouse()
    rows = [{"purl": "pkg:pypi/sample-vulnerable-lib", "version": "1.4.0"}]
    hits = match_vulnerabilities(rows, wh)
    assert len(hits) == 1
    assert hits[0]["kev"] is True
    result = propose_vulnerability_result(hits, rows)
    assert result.state == "fail"


def test_match_vulnerabilities_out_of_range_no_hit():
    wh = Warehouse()
    rows = [{"purl": "pkg:pypi/sample-vulnerable-lib", "version": "9.9.9"}]
    hits = match_vulnerabilities(rows, wh)
    assert hits == []


def test_propose_tier3_no_assist_needs_review():
    result = propose_tier3({"logic": "manual review"})
    assert result.state == "needs_review"
    assert result.tier == 3
    assert result.confidence == 0.0


def test_propose_tier3_with_assist_capped_confidence():
    def assist(control):
        return {"state": "pass", "rationale": "looks fine", "confidence": 0.99}
    result = propose_tier3({"logic": "x"}, assist=assist)
    assert result.state == "pass"
    assert result.confidence <= 0.75
