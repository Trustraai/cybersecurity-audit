"""Command-line interface for the Cybersecurity Audit Workbench (rails)."""

import os

import typer

from . import evidence as ev
from . import remediate, report, risk
from .scan import ScanEngine, can_transition
from .storage import Storage
from .warehouse import Warehouse

app = typer.Typer(add_completion=False,
                   help="Trustra Cybersecurity Audit Workbench (rails layer).")

LEAD_AUDITOR = "Lead Auditor"


def _wh_and_store(db: str) -> tuple:
    wh = Warehouse()
    store = Storage(db)
    return wh, store


@app.command()
def run(evidence_dir: str = typer.Option(..., "--evidence", help="Directory of evidence exports."),
        out: str = typer.Option("out", "--out", help="Output directory for reports."),
        db: str = typer.Option("secaudit.db", "--db"),
        client: str = typer.Option("Sample Client", "--client"),
        ref: str = typer.Option("ENG-0001", "--ref"),
        tier: str = typer.Option("free", "--tier", help="free or remediation"),
        auto_confirm: bool = typer.Option(
            True, "--auto-confirm/--no-auto-confirm",
            help="Confirm every proposed result as the named auditor (demo convenience; "
                 "a real engagement reviews each result individually).")):
    """Run a complete engagement end to end against a directory of evidence."""
    os.makedirs(out, exist_ok=True)
    wh = Warehouse()
    typer.echo("warehouse   %s  digest %s" % (wh.version, wh.digest[:16]))

    store = Storage(db)
    eng_id = store.create_engagement(ref, client, wh.version, wh.digest,
                                      period_start="2026-01-01", period_end="2026-06-30")
    engagement = store.engagement(eng_id)
    engagement["id"] = eng_id
    store.append(eng_id, "engagement.created", LEAD_AUDITOR,
                 {"client": client, "warehouse_version": wh.version})

    evidence, artifacts = ev.load_directory(evidence_dir)
    for art in artifacts:
        store.add_artifact(eng_id, art["name"], art["evidence_set"],
                            art["sha256"], art["row_count"])
        store.append(eng_id, "evidence.ingested", LEAD_AUDITOR, art)
    typer.echo("evidence    %d artifact(s), %d row(s)"
               % (len(artifacts), sum(a["row_count"] for a in artifacts)))

    engine = ScanEngine(wh)
    results = engine.run(evidence)
    for result in results:
        store.upsert_result(eng_id, result)
        store.append(eng_id, "scan.proposed", "engine", {
            "control_id": result["control_id"], "state": result["state"],
            "tier": result["tier"]})
    proposed_fails = sum(1 for r in results if r["state"] == "fail")
    typer.echo("scan        %d control(s), %d proposed fail(s)"
               % (len(results), proposed_fails))

    if auto_confirm:
        for result in results:
            assert can_transition("proposed", "confirmed")
            store.set_lifecycle(eng_id, result["control_id"], "confirmed", LEAD_AUDITOR)
            store.append(eng_id, "result.confirmed", LEAD_AUDITOR,
                         {"control_id": result["control_id"], "state": result["state"]})

    controls_by_id = {c["id"]: c for c in wh.controls()}
    rolled = risk.rollup(store.results(eng_id), controls_by_id, wh.severity_weights,
                         wh.opinion_bands)
    typer.echo("risk        %.1f%%  ->  %s"
              % (rolled["risk_pct"], rolled["proposed_opinion"]["label"]))

    head = store.chain_head(eng_id)
    store.sign_off(eng_id, "engagement", LEAD_AUDITOR, head)
    store.append(eng_id, "engagement.signed", LEAD_AUDITOR,
                 {"scope": "engagement", "chain_head": head})

    ok, break_at = store.verify_ledger(eng_id)
    typer.echo("ledger      %d entries, chain %s"
              % (len(store.ledger(eng_id)), "intact" if ok else "BROKEN at %d" % break_at))

    plan = None
    if tier == "remediation":
        plan = remediate.build_plan(store.results(eng_id), wh)

    bundle = report.build_bundle(engagement, store.results(eng_id), rolled, wh, store,
                                  tier=tier, plan=plan)
    for name, body in bundle["documents"].items():
        path = os.path.join(out, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
    typer.echo("tier        %s (%s)" % (tier, bundle["entitlement"]["label"]))
    typer.echo("reports     %d artifact(s) -> %s" % (len(bundle["documents"]), out))
    typer.echo("reference   %s" % bundle["reference"])
    store.close()


@app.command()
def verify(db: str = typer.Option("secaudit.db", "--db"),
           ref: str = typer.Option(..., "--ref")):
    """Verify the evidence ledger's hash chain for one engagement."""
    store = Storage(db)
    engagement = None
    for row in [store.engagement(i) for i in range(1, 10_000)]:
        if row and row["ref"] == ref:
            engagement = row
            break
        if row is None:
            break
    if not engagement:
        typer.echo("No engagement found with ref %r" % ref)
        raise typer.Exit(code=1)
    ok, break_at = store.verify_ledger(engagement["id"])
    typer.echo("Chain valid: %s (break at %s), %d item(s)"
              % (ok, break_at if not ok else None, len(store.ledger(engagement["id"]))))
    store.close()
    if not ok:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
