# Trustra Cybersecurity Audit Workbench (rails)

Open-source rails for building a cybersecurity vulnerability audit
workbench for an organisation's AI stack: a tamper-evident evidence
ledger, a deterministic scan-and-match engine, a severity-weighted risk
rollup, declarative tier entitlements, and report generation.

## What this is, and what it deliberately is not

This repository is the mechanical, auditable layer: the plumbing for
running a structured cybersecurity audit engagement end to end. It is not
a certified security assessment, not a penetration testing tool, and not
Trustra's actual prediction engine or production vulnerability knowledge
warehouse.

Specifically:

- **Included:** a tamper-evident hash-chained evidence ledger, evidence
  intake and parsing (CSV/JSON exports), a deterministic scan engine
  (Tier 1 identity match against a vulnerability warehouse, Tier 2
  declarative rule matching, a Tier 3 hook for assisted matching that this
  repository does not implement), severity-to-risk rollup with opinion
  bands, declarative free/paid tier entitlements, SQLite-backed engagement
  storage, and report generation (audit report, working papers, executive
  summary, findings register, and a leverage-based remediation plan). A
  small, clearly-labeled **illustrative sample** knowledge base (five
  sample controls, a handful of weakness nodes, one sample vulnerability)
  ships so the engine is runnable out of the box.
- **Not included:** any corpus-based or peer-pattern prediction capability
  (learning latent weaknesses, attack-path likelihood, or control decay
  from an accumulated cross-client dataset). That is Trustra's product and
  its most important defensibility argument — see `CONTRIBUTING.md`. Also
  not included: a production-grade vulnerability knowledge warehouse with
  real CVE/KEV/EPSS ingestion, and the full proprietary control library.

If you want an actual independent cybersecurity vulnerability audit, or
access to the prediction engine and full control library, that is a
Trustra product, not something this repository provides on its own.

## What it does

- Runs a full engagement offline: evidence intake, scan, auditor
  confirmation, sign-off, and reporting.
- Matches SBOM components against a small sample vulnerability set
  (Tier 1) and evaluates declarative rules against structured evidence
  (Tier 2).
- Rolls confirmed results up into a severity-weighted risk percentage and
  a proposed opinion band, with any confirmed Critical-severity failure
  forcing the opinion out of the top band.
- Gates paid-tier content (the remediation plan) behind a declarative
  entitlements table that **declares and counts what is withheld, never
  silently omits it** — a free report that dropped a section without
  saying so would be a false assurance in a security product.
- Generates a Markdown audit report, working papers, executive summary,
  findings register (CSV), and — at the remediation tier — a
  leverage-ordered remediation plan.
- Ships a CLI (`secaudit-workbench`) and a small FastAPI service.

## Quickstart

```
pip install -e .
secaudit-workbench run --evidence examples/sample-evidence --out out --tier free
secaudit-workbench run --evidence examples/sample-evidence --out out --tier remediation
secaudit-workbench verify --ref ENG-0001
```

## Project layout

```
src/secaudit_workbench/
  hashchain.py      Tamper-evident evidence ledger (hash chain)
  evidence.py        Evidence intake and parsing
  scan.py            Tier 1/2 deterministic scan and match engine, Tier 3 hook
  risk.py            Severity-weighted risk rollup and opinion bands
  entitlements.py    Declarative free/paid tier gating
  warehouse.py        Loads and digest-verifies the (sample) knowledge warehouse
  data/               Small illustrative sample warehouse and control library
  storage.py          SQLite-backed engagement store and ledger
  attribution.py     Deterministic verification references
  report.py           Audit report, working papers, executive summary, findings CSV
  remediate.py       Leverage-based remediation plan (paid tier)
  cli.py              Command-line interface
  api/                 FastAPI service
examples/sample-evidence/  Small illustrative evidence set for the CLI walkthrough
docs/
  ARCHITECTURE.md
tests/                Unit tests
```

## Not a certification

This is a product-generated audit instrument, not a security
certification. The bundled sample knowledge base is illustrative and not
a substitute for a real, actively maintained vulnerability feed.

## Contributing

Contributions are welcome, see `CONTRIBUTING.md`. Licensed under
AGPL-3.0-or-later. Note the scope restriction in `CONTRIBUTING.md`:
contributions that add corpus-based prediction are out of scope for this
repository.

## License

GNU Affero General Public License v3.0 or later. See `LICENSE`.
