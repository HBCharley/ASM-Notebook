from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import typer
from rich import print
from rich.table import Table
from sqlalchemy import select

from .db import SessionLocal
from .init_db import init_db
from .models import Company, CompanyDomain, ScanArtifact, ScanRun
from .plugins.ct import ct_subdomains
from .plugins.dns import resolve_dns
from .plugins.risk_score import compute_risk_score
from .plugins.shodan_idb import shodan_idb
from .plugins.subfinder import subfinder_subdomains
from .plugins.wayback import wayback_subdomains

app = typer.Typer(no_args_is_help=True)


@app.callback()
def cli():
    """ASM Notebook — passive attack-surface management."""
    init_db()


# ---------------------------------------------------------------------------
# Helpers shared with api_main
# ---------------------------------------------------------------------------


def _in_scope(domain: str, roots: set[str]) -> bool:
    d = domain.lower().strip(".")
    for r in roots:
        rr = r.lower().strip(".")
        if d == rr or d.endswith("." + rr):
            return True
    return False


def _upsert_artifact(s, scan_id: int, atype: str, payload: object) -> None:
    txt = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    existing = s.execute(
        select(ScanArtifact).where(
            ScanArtifact.scan_id == scan_id,
            ScanArtifact.artifact_type == atype,
        )
    ).scalar_one_or_none()
    if existing:
        existing.json_text = txt
    else:
        s.add(ScanArtifact(scan_id=scan_id, artifact_type=atype, json_text=txt))


# ---------------------------------------------------------------------------
# Company commands
# ---------------------------------------------------------------------------

company_app = typer.Typer(no_args_is_help=True)
app.add_typer(company_app, name="company")


@company_app.command("add")
def company_add(
    slug: str,
    name: str,
    domain: list[str] = typer.Option(..., "--domain", help="Root domain(s) in scope"),
):
    """Register a new company with one or more root domains."""
    with SessionLocal() as s:
        if s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none():
            raise typer.BadParameter("Company slug already exists.")
        c = Company(slug=slug, name=name)
        s.add(c)
        s.flush()
        for d in domain:
            s.add(CompanyDomain(company_id=c.id, domain=d.strip().lower().strip(".")))
        s.commit()
    print(f"[green]Added[/green] {slug} ({name})")


@company_app.command("list")
def company_list():
    """List all registered companies."""
    with SessionLocal() as s:
        items = s.execute(select(Company).order_by(Company.slug)).scalars().all()
    if not items:
        print("[yellow]No companies yet.[/yellow]")
        return
    t = Table("Slug", "Name", "Domains")
    for c in items:
        t.add_row(c.slug, c.name, ", ".join(d.domain for d in c.domains))
    print(t)


@company_app.command("show")
def company_show(slug: str):
    """Show domains registered for a company."""
    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise typer.BadParameter("Company not found.")
        print(f"[bold]{c.name}[/bold] ({c.slug})")
        for d in c.domains:
            print(f"  - {d.domain}")


@company_app.command("set-domain")
def company_set_domain(
    slug: str,
    domain: list[str] = typer.Option(..., "--domain"),
):
    """Replace all domains for a company."""
    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise typer.BadParameter("Company not found.")
        for d in list(c.domains):
            s.delete(d)
        for d in domain:
            s.add(CompanyDomain(company_id=c.id, domain=d.strip().lower().strip(".")))
        s.commit()
    print(f"[green]Updated domains for[/green] {slug}")


# ---------------------------------------------------------------------------
# Scan commands
# ---------------------------------------------------------------------------

scan_app = typer.Typer(no_args_is_help=True)
app.add_typer(scan_app, name="scan")


@scan_app.command("run")
def scan_run(company_slug: str):
    """Run a full passive scan (CT + Wayback + Subfinder + DNS + Shodan IDB + Risk)."""
    with SessionLocal() as s:
        company = s.execute(
            select(Company).where(Company.slug == company_slug)
        ).scalar_one_or_none()
        if not company:
            raise typer.BadParameter("Company not found.")
        roots = {d.domain for d in company.domains}
        if not roots:
            raise typer.BadParameter("Company has no domains.")

        scan = ScanRun(
            company_id=company.id,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        s.add(scan)
        s.commit()
        s.refresh(scan)
        scan_id = scan.id

    print(f"[dim]Scan {scan_id} started for[/dim] {company_slug}")

    async def _run():
        # Stage 1: parallel discovery
        discovery_tasks = []
        for root in roots:
            discovery_tasks.extend([
                ct_subdomains(root),
                wayback_subdomains(root),
                subfinder_subdomains(root),
            ])
        discovery_results = await asyncio.gather(*discovery_tasks, return_exceptions=True)

        all_domains: set[str] = set(roots)
        for result in discovery_results:
            if isinstance(result, set):
                all_domains |= result

        domains_scoped = sorted(d for d in all_domains if _in_scope(d, roots))
        print(f"[dim]  {len(domains_scoped)} in-scope domains discovered[/dim]")

        # Stage 2: DNS
        sem = asyncio.Semaphore(25)

        async def dns_task(d: str):
            async with sem:
                return resolve_dns(d)

        dns_records = list(await asyncio.gather(*[dns_task(d) for d in domains_scoped]))
        print(f"[dim]  DNS resolved[/dim]")

        # Stage 3: Shodan IDB
        all_ips: set[str] = set()
        for rec in dns_records:
            all_ips.update(rec.get("ips", []))
        idb_data = await shodan_idb(sorted(all_ips))
        print(f"[dim]  Shodan IDB: {len(idb_data)} IPs enriched[/dim]")

        return {
            "domains": {"roots": sorted(roots), "domains": domains_scoped},
            "dns": {"records": dns_records},
            "shodan_idb": idb_data,
        }

    try:
        artifacts = asyncio.run(_run())
        artifacts["risk"] = compute_risk_score(artifacts)

        risk_summary = artifacts["risk"]["summary"]
        print(
            f"[dim]  Risk:[/dim] "
            f"[red]critical={risk_summary['critical']}[/red] "
            f"[yellow]high={risk_summary['high']}[/yellow] "
            f"medium={risk_summary['medium']} "
            f"low={risk_summary['low']}"
        )

        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            assert scan is not None
            for atype, data in artifacts.items():
                _upsert_artifact(s, scan_id, atype, data)
            scan.status = "success"
            scan.completed_at = datetime.now(timezone.utc)
            s.commit()

        print(f"[green]Scan {scan_id} complete[/green]")

    except Exception as e:
        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.notes = str(e)[:250]
                s.commit()
        raise


@scan_app.command("list")
def scan_list(company_slug: str):
    """List scans for a company."""
    with SessionLocal() as s:
        company = s.execute(
            select(Company).where(Company.slug == company_slug)
        ).scalar_one_or_none()
        if not company:
            raise typer.BadParameter("Company not found.")
        scans = s.execute(
            select(ScanRun)
            .where(ScanRun.company_id == company.id)
            .order_by(ScanRun.id.desc())
        ).scalars().all()

    if not scans:
        print("[yellow]No scans yet.[/yellow]")
        return

    t = Table("ID", "Status", "Started", "Completed", "Notes")
    for sc in scans:
        t.add_row(
            str(sc.id),
            sc.status,
            str(sc.started_at)[:19],
            str(sc.completed_at)[:19] if sc.completed_at else "-",
            sc.notes or "",
        )
    print(t)


@scan_app.command("risk")
def scan_risk(scan_id: int):
    """Print risk findings for a completed scan."""
    with SessionLocal() as s:
        scan = s.get(ScanRun, scan_id)
        if not scan:
            raise typer.BadParameter("Scan not found.")
        rows = s.execute(
            select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)
        ).scalars().all()
        arts = {a.artifact_type: json.loads(a.json_text) for a in rows}

    risk = arts.get("risk") or compute_risk_score(arts)
    findings = risk.get("findings", [])
    summary = risk.get("summary", {})

    print(
        f"[bold]Risk summary[/bold]: "
        f"[red]critical={summary.get('critical', 0)}[/red]  "
        f"[yellow]high={summary.get('high', 0)}[/yellow]  "
        f"medium={summary.get('medium', 0)}  "
        f"low={summary.get('low', 0)}"
    )

    COLOURS = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim", "info": "dim"}
    t = Table("Severity", "Category", "Domain / IP", "Detail")
    for f in sorted(findings, key=lambda x: ["critical", "high", "medium", "low", "info"].index(x["severity"])):
        colour = COLOURS.get(f["severity"], "white")
        t.add_row(
            f"[{colour}]{f['severity']}[/{colour}]",
            f["category"],
            f["domain"],
            f["detail"][:80],
        )
    print(t)


@scan_app.command("export")
def scan_export(scan_id: int, out_json: str = "out.json"):
    """Export all scan artifacts to a JSON file."""
    with SessionLocal() as s:
        scan = s.get(ScanRun, scan_id)
        if not scan:
            raise typer.BadParameter("Scan not found.")
        company = s.get(Company, scan.company_id)
        rows = s.execute(
            select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)
        ).scalars().all()
        by_type = {a.artifact_type: json.loads(a.json_text) for a in rows}

    blob = {
        "company": {"slug": company.slug, "name": company.name} if company else None,
        "scan": {
            "id": scan.id,
            "status": scan.status,
            "started_at": str(scan.started_at),
            "completed_at": str(scan.completed_at),
            "notes": scan.notes,
        },
        "artifacts": by_type,
    }
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(blob, f, indent=2, ensure_ascii=False)
    print(f"[green]Wrote[/green] {out_json}")


def main():
    app()


if __name__ == "__main__":
    main()
