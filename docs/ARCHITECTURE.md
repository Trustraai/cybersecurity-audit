# Architecture

## The rails vs. proprietary split

This repository implements the mechanical, reproducible layer of a
cybersecurity vulnerability audit workbench. Every module in `scan.py` and
`risk.py` is deterministic: same evidence and same warehouse snapshot in,
same result out, with no model call and no network call anywhere in that
path. That is asserted by a design rule, and contributors should keep it
true (see `CONTRIBUTING.md`).

## What is intentionally not in this repository

- **Corpus-based / peer-pattern prediction.** Learning latent weaknesses,
  attack-path likelihood, or control decay from an accumulated
  cross-client dataset is Trustra's product and its most important
  defensibility argument: a competitor holding identical open source
  starts with an empty corpus and can predict nothing. This repository
  contains no such capability and will not accept contributions that add
  one.
- **A production vulnerability knowledge warehouse.** The bundled
  `data/warehouse.json` and `data/controls.json` are a small, illustrative
  sample: a handful of weakness nodes, one sample vulnerability, and five
  sample controls across five modules. They exist so the scan engine is
  runnable out of the box, not as a real audit instrument. A real
  deployment needs a maintained warehouse with actual CVE/KEV/EPSS
  ingestion and a substantially larger control library.
- **Hyperscaler multi-tenant deployment, marketplace billing, and
  cross-engagement aggregation.** This repository is a single-tenant,
  offline-capable local tool. Anything about how engagements aggregate
  into a platform-owned corpus is out of scope here.
- **Active exploitation or proof-of-exploit tooling.** This is a
  read-only, evidence-driven audit instrument, not a penetration testing
  tool. It never attacks, fuzzes, or attempts to exploit a client system.

## Design commitments the code enforces

- **The engine proposes, the auditor decides.** Every scan result enters
  the record as `proposed`. Nothing reaches the formal report until a
  named human moves it to `confirmed` or `signed` — see the lifecycle
  state machine in `scan.py` and the `_confirmed()` filter in `report.py`.
- **Locked content is declared, never silently omitted.** A free-tier
  report that quietly dropped a section would let a reader conclude
  nothing was found there. `entitlements.Entitlement.gate()` and
  `report.upgrade_notice()` exist specifically to make withheld content
  visible and counted.
- **The evidence ledger is append-only.** There is no update or delete
  path for ledger entries in `storage.py`. Tampering with a historical
  entry breaks every hash after it (`hashchain.verify_chain`), which is
  what lets a third party independently confirm the trail was never
  rewritten.
- **Snapshots are pinned and hash-sealed.** `warehouse.Warehouse.verify()`
  refuses to load a bundle whose digest does not match, so an engagement
  pinned to a snapshot reproduces its results exactly, even after the
  bundled sample data is edited or replaced.

## Extending this repository

The natural extension points are: additional Tier 1/Tier 2 match rule
types in `scan.py` (keep them declarative — no model or network calls),
additional evidence format parsers in `evidence.py`, a real Tier 3 assist
function wired in by the caller of `ScanEngine(warehouse, assist=...)`,
and a larger, better-maintained sample warehouse (still clearly labeled as
illustrative, not authoritative).
