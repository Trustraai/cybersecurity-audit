import pytest

from secaudit_workbench.entitlements import Entitlement


def test_free_tier_withholds_remediation():
    ent = Entitlement("free")
    assert ent.allows("findings")
    assert not ent.allows("remediation_plan")
    assert "remediation_plan" in ent.withheld()


def test_remediation_tier_allows_everything():
    ent = Entitlement("remediation")
    assert ent.withheld() == []


def test_gate_declares_count_never_silently_drops():
    ent = Entitlement("free")
    gated = ent.gate("remediation_plan", [1, 2, 3])
    assert gated["locked"] is True
    assert gated["count"] == 3
    assert gated["items"] == []
    assert "3 withheld" in gated["notice"]


def test_unknown_tier_rejected():
    with pytest.raises(ValueError):
        Entitlement("enterprise")
