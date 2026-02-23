# asm_notebook/api_main.py
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func

from .db import SessionLocal
from .init_db import init_db
from .models import Company, CompanyDomain, ScanArtifact, ScanRun
from .plugins.ct import ct_subdomains
from .plugins.dns import resolve_dns

app = FastAPI(title="ASM Notebook API")


# -------------------------
# Schemas
# -------------------------
class CompanyCreate(BaseModel):
    slug: str
    name: str
    domains: List[str]


class DomainReplace(BaseModel):
    domains: List[str]


# -------------------------
# Startup
# -------------------------
@app.on_event("startup")
def _startup() -> None:
    init_db()


# -------------------------
# Helpers
# -------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_domain(d: str) -> str:
    return d.strip().lower().strip(".")


def _in_scope(domain: str, roots: Set[str]) -> bool:
    d = _normalize_domain(domain)
    for r in roots:
        rr = _normalize_domain(r)
        if d == rr or d.endswith("." + rr):
            return True
    return False


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _company_by_slug(session: SessionLocal, slug: str) -> Company | None:
    return session.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()


# -------------------------
# Basic
# -------------------------
@app.get("/health")
def health() -> Dict[str, bool]:
    return {"ok": True}


# -------------------------
# Companies
# -------------------------
@app.post("/companies", status_code=201)
def create_company(payload: CompanyCreate) -> Dict[str, Any]:
    slug = payload.slug.strip()
    name = payload.name.strip()
    domains = [_normalize_domain(d) for d in payload.domains if d and d.strip()]

    if not slug or not name or not domains:
        raise HTTPException(status_code=400, detail="slug, name, domains are required")

    with SessionLocal() as s:
        existing = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail="Company slug already exists")

        c = Company(slug=slug, name=name)
        s.add(c)
        s.flush()  # populate c.id

        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))

        s.commit()
        return {"id": c.id, "slug": c.slug, "name": c.name, "domains": domains}


@app.get("/companies")
def list_companies() -> List[Dict[str, Any]]:
    with SessionLocal() as s:
        companies = s.execute(select(Company).order_by(Company.slug)).scalars().all()
        return [
            {
                "id": c.id,
                "slug": c.slug,
                "name": c.name,
                "domains": [d.domain for d in c.domains],
            }
            for c in companies
        ]


@app.put("/companies/{slug}/domains")
def replace_domains(slug: str, payload: DomainReplace) -> Dict[str, Any]:
    domains = [_normalize_domain(d) for d in payload.domains if d and d.strip()]
    if not domains:
        raise HTTPException(status_code=400, detail="domains must not be empty")

    with SessionLocal() as s:
        c = _company_by_slug(s, slug)
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")

        # Remove existing domains
        for d in list(c.domains):
            s.delete(d)

        # Add new domains
        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))

        s.commit()

    return {"slug": slug, "domains": domains}


@app.delete("/companies/{slug}", status_code=204)
def delete_company(slug: str) -> None:
    with SessionLocal() as s:
        c = _company_by_slug(s, slug)
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")
        s.delete(c)
        s.commit()


# -------------------------
# Scans (company-scoped)
# -------------------------
@app.post("/companies/{slug}/scans", status_code=201)
def trigger_scan(slug: str) -> Dict[str, Any]:
    """
    Triggers a passive scan:
      - CT subdomain discovery
      - DNS resolution (passive)
    Persists:
      - ScanRun row
      - ScanArtifact rows (domains, dns)
    """
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        roots = {d.domain for d in company.domains}
        if not roots:
            raise HTTPException(status_code=400, detail="Company has no domains")

        last_num = (
            s.execute(
                select(func.max(ScanRun.company_scan_number)).where(
                    ScanRun.company_id == company.id
                )
            )
            .scalar_one()
        )
        next_num = (last_num or 0) + 1

        scan = ScanRun(
            company_id=company.id,
            company_scan_number=next_num,
            status="running",
            started_at=_now_utc(),
        )
        s.add(scan)
        s.commit()
        s.refresh(scan)
        scan_id = scan.id

    async def _run() -> Tuple[List[str], List[Any]]:
        # Collect domains from CT + roots
        all_domains: Set[str] = set(roots)
        for root in roots:
            subs = await ct_subdomains(root)
            all_domains |= subs

        # Apply scope filtering
        scoped = {d for d in all_domains if _in_scope(d, roots)}
        domains_sorted = sorted(scoped)

        # Passive DNS lookups (bounded concurrency)
        sem = asyncio.Semaphore(25)

        async def dns_task(d: str) -> Any:
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

            def upsert_artifact(atype: str, payload_obj: Any) -> None:
                existing = s.execute(
                    select(ScanArtifact).where(
                        ScanArtifact.scan_id == scan_id,
                        ScanArtifact.artifact_type == atype,
                    )
                ).scalar_one_or_none()

                txt = _json_dumps(payload_obj)
                if existing:
                    existing.json_text = txt
                else:
                    s.add(ScanArtifact(scan_id=scan_id, artifact_type=atype, json_text=txt))

            upsert_artifact("domains", {"roots": sorted(roots), "domains": domains_sorted})
            upsert_artifact("dns", {"records": dns_records})

            scan.status = "success"
            scan.completed_at = _now_utc()
            s.commit()

        return {
            "company_slug": slug,
            "scan_id": scan_id,
            "company_scan_number": next_num,
            "status": "success",
        }

    except Exception as e:
        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = _now_utc()
                scan.notes = str(e)[:250]
                s.commit()
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")


@app.get("/companies/{slug}/scans")
def list_scans(slug: str) -> List[Dict[str, Any]]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scans = (
            s.execute(
                select(ScanRun)
                .where(ScanRun.company_id == company.id)
                .order_by(ScanRun.id.desc())
            )
            .scalars()
            .all()
        )

        return [
            {
                "id": sc.id,
                "company_scan_number": sc.company_scan_number,
                "status": sc.status,
                "started_at": sc.started_at,
                "completed_at": sc.completed_at,
                "notes": sc.notes,
            }
            for sc in scans
        ]


# Optional hardening: these endpoints scope scan access to the company
@app.get("/companies/{slug}/scans/{scan_id}")
def get_company_scan(slug: str, scan_id: int) -> Dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        # HARDENED: fetch scan scoped to this company in a single query
        scan = s.execute(
            select(ScanRun).where(ScanRun.id == scan_id, ScanRun.company_id == company.id)
        ).scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        return {
            "id": scan.id,
            "company_scan_number": scan.company_scan_number,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "notes": scan.notes,
        }


@app.get("/companies/{slug}/scans/by-number/{company_scan_number}")
def get_company_scan_by_number(slug: str, company_scan_number: int) -> Dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = s.execute(
            select(ScanRun).where(
                ScanRun.company_id == company.id,
                ScanRun.company_scan_number == company_scan_number,
            )
        ).scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        return {
            "id": scan.id,
            "company_scan_number": scan.company_scan_number,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "notes": scan.notes,
        }


@app.get("/companies/{slug}/scans/{scan_id}/artifacts")
def get_company_scan_artifacts(slug: str, scan_id: int) -> Dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        # HARDENED: ensure scan belongs to company
        scan = s.execute(
            select(ScanRun).where(ScanRun.id == scan_id, ScanRun.company_id == company.id)
        ).scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        artifacts = (
            s.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id))
            .scalars()
            .all()
        )

        out: Dict[str, Any] = {}
        for a in artifacts:
            try:
                out[a.artifact_type] = json.loads(a.json_text)
            except Exception:
                out[a.artifact_type] = {"_error": "invalid_json", "raw": a.json_text}

        return out


# -------------------------
# (Optional) Debug endpoints
# Keep if useful during development; remove later if you want stricter scoping.
# -------------------------
@app.get("/scans/{scan_id}/artifacts")
def get_scan_artifacts(scan_id: int) -> Dict[str, Any]:
    with SessionLocal() as s:
        scan = s.get(ScanRun, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        artifacts = (
            s.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id))
            .scalars()
            .all()
        )

        out: Dict[str, Any] = {}
        for a in artifacts:
            try:
                out[a.artifact_type] = json.loads(a.json_text)
            except Exception:
                out[a.artifact_type] = {"_error": "invalid_json", "raw": a.json_text}

        return out


@app.delete("/companies/{slug}/scans/{scan_id}", status_code=204)
def delete_company_scan(slug: str, scan_id: int) -> None:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = s.execute(
            select(ScanRun).where(ScanRun.id == scan_id, ScanRun.company_id == company.id)
        ).scalar_one_or_none()

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        s.delete(scan)
        s.commit()
