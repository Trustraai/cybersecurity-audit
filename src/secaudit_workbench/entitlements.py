"""Tier entitlements (free audit, paid remediation).

The commercial line is diagnosis versus prescription:

    free          what is wrong, how bad it is, and proof it was not rewritten
    remediation   what to do about it, in what order, and why that order

Free is a complete, defensible audit on its own: findings, severity, the
opinion, the ranked exposure, and the verifiable evidence chain. It is not a
crippled demo.

ONE RULE THAT IS NOT NEGOTIABLE: locked content is declared, never silently
omitted. A free report that quietly dropped a section would let a reader
conclude nothing was found there. In a security product that is not a
missing feature, it is a false assurance. Every gate emits a notice carrying
the count of what is withheld.

Entitlements are declarative data: adding a tier means editing this table,
not threading flags through the engine.
"""

from typing import Any, Dict, List, Optional

# Every gated capability in this rails layer.
CAPABILITIES = (
    "findings",             # confirmed findings with severity
    "risk_opinion",         # weighted risk and the opinion band
    "evidence_chain",       # hash-chained ledger and verification reference
    "findings_register",    # machine-readable CSV
    "remediation_steps",    # concrete actions per weakness
    "root_cause_analysis",  # collapse findings onto the systems causing them
    "remediation_plan",     # sequenced plan artifact
)

TIERS: Dict[str, Dict[str, Any]] = {
    "free": {
        "label": "Audit",
        "summary": "A complete audit: what is wrong, how bad, and provable.",
        "capabilities": ["findings", "risk_opinion", "evidence_chain",
                          "findings_register"],
        "upgrade_to": "remediation",
    },
    "remediation": {
        "label": "Audit + Remediation",
        "summary": "Everything in Audit, plus what to do about it and in what order.",
        "capabilities": list(CAPABILITIES),
        "upgrade_to": None,
    },
}

DEFAULT_TIER = "free"

_LOCKED_COPY = {
    "remediation_steps": (
        "Remediation steps for each finding are part of the Remediation tier."),
    "root_cause_analysis": (
        "These findings collapse onto a smaller number of underlying systems. "
        "The root-cause grouping is part of the Remediation tier."),
    "remediation_plan": (
        "A sequenced remediation plan, ordered by what each action closes, is "
        "part of the Remediation tier."),
}


class Entitlement:
    """Resolves what an engagement may render, and describes what it may not."""

    def __init__(self, tier: str = DEFAULT_TIER):
        if tier not in TIERS:
            raise ValueError("unknown tier %r; expected one of %s"
                              % (tier, ", ".join(sorted(TIERS))))
        self.tier = tier
        self._spec = TIERS[tier]

    @property
    def label(self) -> str:
        return self._spec["label"]

    @property
    def summary(self) -> str:
        return self._spec["summary"]

    @property
    def upgrade_to(self) -> Optional[str]:
        return self._spec["upgrade_to"]

    def allows(self, capability: str) -> bool:
        if capability not in CAPABILITIES:
            raise ValueError("unknown capability %r" % capability)
        return capability in self._spec["capabilities"]

    def withheld(self) -> List[str]:
        return [c for c in CAPABILITIES if not self.allows(c)]

    def notice(self, capability: str, count: Optional[int] = None) -> Optional[str]:
        """The honest disclosure for a withheld capability."""
        if self.allows(capability):
            return None
        copy = _LOCKED_COPY.get(capability, "This section is part of a paid tier.")
        if count:
            return "%d withheld. %s" % (count, copy)
        return copy

    def gate(self, capability: str, items: List[Any]) -> Dict[str, Any]:
        """Return items when entitled, or a declared, counted placeholder."""
        if self.allows(capability):
            return {"locked": False, "count": len(items), "items": items,
                    "notice": None}
        return {"locked": True, "count": len(items), "items": [],
                "notice": self.notice(capability, len(items))}

    def manifest(self) -> Dict[str, Any]:
        return {
            "tier": self.tier,
            "label": self.label,
            "capabilities": sorted(self._spec["capabilities"]),
            "withheld": self.withheld(),
            "upgrade_to": self.upgrade_to,
        }
