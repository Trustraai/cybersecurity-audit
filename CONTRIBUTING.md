# Contributing

Thanks for considering a contribution to the Trustra Cybersecurity Audit
Workbench (rails layer).

## Scope of this repository

This project is the mechanical, auditable layer of a cybersecurity
vulnerability audit workbench:

- The tamper-evident evidence ledger (hash chain).
- Evidence intake and parsing (CSV/JSON exports).
- A deterministic scan and match engine (Tier 1 identity match, Tier 2
  declarative rule match, and a Tier 3 hook for assisted matching that this
  repository does not implement).
- Severity-weighted risk rollup and opinion bands.
- Declarative tier entitlements (free audit vs. paid remediation).
- SQLite-backed storage for engagements, results, and sign-off.
- Report generation (audit report, working papers, executive summary,
  findings register, remediation plan).
- A small, clearly-labeled **illustrative sample** knowledge base (a handful
  of controls and warehouse nodes), so the engine is runnable out of the box.

## Out of scope — will not be merged

**Pull requests that add a corpus-based or peer-pattern prediction
capability (learning latent weaknesses, attack-path likelihood, or control
decay from an accumulated cross-client dataset) will not be accepted into
this repository.** That capability is Trustra's product and its most
important defensibility argument: a competitor holding identical open
source starts with an empty corpus and can predict nothing. Adding it here
would give that away for free, and would also require a real, non-public
corpus this repository cannot ship anyway.

Also out of scope:

- A full production-grade vulnerability knowledge warehouse (CVE/KEV/EPSS
  ingestion at scale, a large control library). The bundled sample data is
  intentionally small and illustrative — see
  `docs/ARCHITECTURE.md`.
- Anything that presents this tool's output as an independent security
  certification or attestation. It produces a product-generated audit
  instrument, not a certification.
- Active exploitation, fuzzing, or proof-of-exploit tooling against target
  systems. This is a read-only, evidence-driven audit instrument, not a
  penetration testing tool.

## What's welcome

- Bug fixes in the ledger, scan engine, risk rollup, or reporting.
- New Tier 1/Tier 2 match rule types, as long as they stay declarative and
  reproducible (no model or network calls in the scan/risk path — this is
  enforced by a call-graph test).
- Additional evidence format parsers.
- Documentation and test coverage improvements.
- Additional illustrative sample controls, clearly marked as illustrative.

## Development

```
pip install -e ".[dev]"
pytest -q
ruff check src tests
```

## Independence guardrail

`scan.py` and `risk.py` compute match results, severity, and risk with no
model call and no network call, by construction. A test asserts the call
graph of those modules stays free of both. Please keep that property when
contributing to either file.

## License

By contributing, you agree your contribution is licensed under
AGPL-3.0-or-later, the same license as the rest of this repository.
