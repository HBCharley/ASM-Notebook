from __future__ import annotations

from datetime import datetime, timezone
import asyncio
import json

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from .init_db import init_db
from .db import SessionLocal
from .models import Company, CompanyDomain, ScanRun, ScanArtifact
from .plugins.ct import ct_subdomains
from .plugins.dns import resolve_dns

app = FastAPI(title="ASM Notebook API")


class CompanyCreate(BaseModel):
    slug: str
    name: str
    domains: list[str]


class DomainReplace(BaseModel):
    domains: list[str]


@app.on_event("startup")
def _startup():
    init_db()


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/companies", status_code=201)
def create_company(payload: CompanyCreate):
    slug = payload.slug.strip()
    name = payload.name.strip()
    domains = [d.strip().lower().strip(".") for d in payload.domains]

    if not slug or not name or not domains:
        raise HTTPException(status_code=400, detail="slug, name, domains are required")

    with SessionLocal() as s:
        existing = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail="Company slug already exists")

        c = Company(slug=slug, name=name)
        s.add(c)
        s.flush()
        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))
        s.commit()
        return {"id": c.id, "slug": c.slug, "name": c.name, "domains": domains}


@app.get("/companies")
def list_companies():
    with SessionLocal() as s:
        items = s.execute(select(Company).order_by(Company.slug)).scalars().all()
        return [
            {
                "id": c.id,
                "slug": c.slug,
                "name": c.name,
                "domains": [d.domain for d in c.domains],
            }
            for c in items
        ]


@app.put("/companies/{slug}/domains")
def replace_domains(slug: str, payload: DomainReplace):
    domains = [d.strip().lower().strip(".") for d in payload.domains]
    if not domains:
        raise HTTPException(status_code=400, detail="domains must not be empty")

    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")

        for d in list(c.domains):
            s.delete(d)
        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))
        s.commit()

    return {"slug": slug, "domains": domains}


def _in_scope(domain: str, roots: set[str]) -> bool:
    d = domain.lower().strip(".")
    for r in roots:
        rr = r.lower().strip(".")
        if d == rr or d.endswith("." + rr):
            return True
    return False


@app.post("/companies/{slug}/scans", status_code=201)
def trigger_scan(slug: str):
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        roots = {d.domain for d in company.domains}
        if not roots:
            raise HTTPException(status_code=400, detail="Company has no domains")

        scan = ScanRun(company_id=company.id, status="running", started_at=datetime.now(timezone.utc))
        s.add(scan)
        s.commit()
        s.refresh(scan)
        scan_id = scan.id

    async def _run():
        all_domains: set[str] = set(roots)
        for root in roots:
            subs = await ct_subdomains(root)
            all_domains |= subs
        all_domains_scoped = {d for d in all_domains if _in_scope(d, roots)}
        domains_sorted = sorted(all_domains_scoped)

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
            if not scan:
                raise RuntimeError("Scan disappeared")

            def upsert(atype: str, payload_obj: object):
                existing = s.execute(
                    select(ScanArtifact).where(
                        ScanArtifact.scan_id == scan_id, ScanArtifact.artifact_type == atype
                    )
                ).scalar_one_or_none()
                txt = json.dumps(payload_obj, indent=2, ensure_ascii=False)
                if existing:
                    existing.json_text = txt
                else:
                    s.add(ScanArtifact(scan_id=scan_id, artifact_type=atype, json_text=txt))

            upsert("domains", {"roots": sorted(roots), "domains": domains_sorted})
            upsert("dns", {"records": dns_records})

            scan.status = "success"
            scan.completed_at = datetime.now(timezone.utc)
            s.commit()

        return {"scan_id": scan_id, "status": "success"}

    except Exception as e:
        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.notes = str(e)[:250]
                s.commit()
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")


@app.get("/companies/{slug}/scans")
def list_scans(slug: str):
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scans = (
            s.execute(select(ScanRun).where(ScanRun.company_id == company.id).order_by(ScanRun.id.desc()))
            .scalars()
            .all()
        )
        return [
            {
                "id": sc.id,
                "status": sc.status,
                "started_at": sc.started_at,
                "completed_at": sc.completed_at,
                "notes": sc.notes,
            }
            for sc in scans
        ]


@app.get("/scans/{scan_id}/artifacts")
def get_scan_artifacts(scan_id: int):
    with SessionLocal() as s:
        scan = s.get(ScanRun, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        artifacts = s.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)).scalars().all()
        return {a.artifact_type: json.loads(a.json_text) for a in artifacts}