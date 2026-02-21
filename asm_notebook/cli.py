from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import typer
from rich import print
from sqlalchemy import select

from .init_db import init_db
from .db import SessionLocal
from .models import Company, CompanyDomain, ScanRun, ScanArtifact
from .plugins.ct import ct_subdomains
from .plugins.dns import resolve_dns

app = typer.Typer(no_args_is_help=True)

@app.callback()
def cli():
    """ASM Notebook (passive)."""
    # Ensure tables exist
    init_db()


# -------------------------
# Company commands
# -------------------------
company_app = typer.Typer(no_args_is_help=True)
app.add_typer(company_app, name="company")

@company_app.command("set-domain")
def company_set_domain(slug: str, domain: list[str] = typer.Option(..., "--domain")):
    """Replace company domains."""
    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise typer.BadParameter("Company not found.")

        # delete existing domains
        for d in list(c.domains):
            s.delete(d)

        # add new ones
        for d in domain:
            s.add(CompanyDomain(company_id=c.id, domain=d.strip().lower().strip(".")))

        s.commit()

    print(f"[green]Updated domains for[/green] {slug}")

@company_app.command("add")
def company_add(
    slug: str,
    name: str,
    domain: list[str] = typer.Option(..., "--domain", help="Root domain(s) in scope"),
):
    with SessionLocal() as s:
        existing = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if existing:
            raise typer.BadParameter("Company slug already exists.")
        c = Company(slug=slug, name=name)
        s.add(c)
        s.flush()
        for d in domain:
            s.add(CompanyDomain(company_id=c.id, domain=d.strip().lower().strip(".")))
        s.commit()
    print(f"[green]Added[/green] {slug}")

@company_app.command("list")
def company_list():
    with SessionLocal() as s:
        items = s.execute(select(Company).order_by(Company.slug)).scalars().all()
    if not items:
        print("[yellow]No companies yet.[/yellow]")
        return
    for c in items:
        print(f"- [bold]{c.slug}[/bold]  {c.name}")

@company_app.command("show")
def company_show(slug: str):
    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise typer.BadParameter("Company not found.")
        print(f"[bold]{c.name}[/bold] ({c.slug})")
        for d in c.domains:
            print(f"  - domain: {d.domain}")


# -------------------------
# Scan commands
# -------------------------
scan_app = typer.Typer(no_args_is_help=True)
app.add_typer(scan_app, name="scan")

def _in_scope(domain: str, roots: set[str]) -> bool:
    d = domain.lower().strip(".")
    for r in roots:
        rr = r.lower().strip(".")
        if d == rr or d.endswith("." + rr):
            return True
    return False

@scan_app.command("run")
def scan_run(company_slug: str):
    """Run passive scan (CT + DNS) and store results."""
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == company_slug)).scalar_one_or_none()
        if not company:
            raise typer.BadParameter("Company not found.")
        roots = {d.domain for d in company.domains}
        if not roots:
            raise typer.BadParameter("Company has no domains.")

        scan = ScanRun(company_id=company.id, status="running", started_at=datetime.now(timezone.utc))
        s.add(scan)
        s.commit()
        s.refresh(scan)
        scan_id = scan.id

    async def _run():
        # 1) CT
        all_domains: set[str] = set(roots)
        for root in roots:
            subs = await ct_subdomains(root)
            all_domains |= subs
        all_domains = {d for d in all_domains if _in_scope(d, roots)}
        domains_sorted = sorted(all_domains)

        # 2) DNS (bounded concurrency)
        sem = asyncio.Semaphore(25)

        async def dns_task(d: str):
            async with sem:
                return resolve_dns(d)

        dns_records = await asyncio.gather(*[dns_task(d) for d in domains_sorted])

        return domains_sorted, dns_records

    try:
        domains_sorted, dns_records = asyncio.run(_run())
        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            assert scan is not None

            def upsert(atype: str, payload: object):
                existing = s.execute(
                    select(ScanArtifact).where(
                        ScanArtifact.scan_id == scan_id,
                        ScanArtifact.artifact_type == atype
                    )
                ).scalar_one_or_none()
                txt = json.dumps(payload, indent=2, ensure_ascii=False)
                if existing:
                    existing.json_text = txt
                else:
                    s.add(ScanArtifact(scan_id=scan_id, artifact_type=atype, json_text=txt))

            upsert("domains", {"roots": sorted(roots), "domains": domains_sorted})
            upsert("dns", {"records": dns_records})

            scan.status = "success"
            scan.completed_at = datetime.now(timezone.utc)
            s.commit()

        print(f"[green]Scan complete[/green] scan_id={scan_id}")

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
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == company_slug)).scalar_one_or_none()
        if not company:
            raise typer.BadParameter("Company not found.")
        scans = s.execute(
            select(ScanRun).where(ScanRun.company_id == company.id).order_by(ScanRun.id.desc())
        ).scalars().all()

    if not scans:
        print("[yellow]No scans yet.[/yellow]")
        return

    for sc in scans:
        print(f"- id={sc.id} status={sc.status} started={sc.started_at} completed={sc.completed_at} notes={sc.notes}")

@scan_app.command("export")
def scan_export(scan_id: int, out_json: str = "out.json"):
    """Export scan artifacts to a JSON file."""
    with SessionLocal() as s:
        scan = s.get(ScanRun, scan_id)
        if not scan:
            raise typer.BadParameter("Scan not found.")
        company = s.get(Company, scan.company_id)
        artifacts = s.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)).scalars().all()
        by_type = {a.artifact_type: json.loads(a.json_text) for a in artifacts}

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