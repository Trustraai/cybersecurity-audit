"""Verification references for sealed engagement reports.

A verification reference is a deterministic value bound to the sealed ledger
state (chain head, warehouse version, report version). Anyone holding the
report and the ledger export can recompute it: if the ledger is altered, the
chain head changes and the reference no longer matches.
"""

import hashlib
from typing import Any, Dict, Optional

DEFAULT_REF_PREFIX = "AUDIT"


def verification_reference(engagement_id: str, chain_head: str,
                            warehouse_version: str, report_version: int = 1,
                            prefix: str = DEFAULT_REF_PREFIX) -> str:
    """Deterministic, recomputable reference bound to the sealed ledger state."""
    seed = "|".join([engagement_id, chain_head or "", warehouse_version,
                      "r%d" % report_version])
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20].upper()
    grouped = "-".join(digest[i:i + 4] for i in range(0, 20, 4))
    return "%s-%s" % (prefix, grouped)


def resolve(reference: str, engagement_id: str, chain_head: str,
            warehouse_version: str, report_version: int = 1,
            prefix: str = DEFAULT_REF_PREFIX) -> bool:
    """Confirm a reference matches the current sealed ledger state."""
    return reference == verification_reference(
        engagement_id, chain_head, warehouse_version, report_version, prefix)


def attribution_profile(firm_name: str, surface_branding: str = "firm",
                         firm_logo_ref: Optional[str] = None) -> Dict[str, Any]:
    """Configurable surface attribution for a firm-operated engagement."""
    if surface_branding not in ("firm", "operator", "co-branded"):
        surface_branding = "firm"
    return {
        "surface_branding": surface_branding,
        "firm_name": firm_name,
        "firm_logo_ref": firm_logo_ref,
    }
