from __future__ import annotations

from datetime import datetime, timezone
import asyncio
import json
from collections import Counter
import re

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from .init_db import init_db
from .db import SessionLocal
from .models import Company, CompanyDomain, ScanRun, ScanArtifact
from .plugins.ct import ct_subdomains
from .plugins.dns import resolve_dns
from .plugins.http_meta import fetch_http_metadata

app = FastAPI(title="ASM Notebook API")


class CompanyCreate(BaseModel):
    slug: str
    name: str
    domains: list[str]


class DomainReplace(BaseModel):
    domains: list[str]


class CompanyUpdate(BaseModel):
    name: str


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


@app.get("/companies/{slug}")
def get_company(slug: str):
    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")
        return {
            "id": c.id,
            "slug": c.slug,
            "name": c.name,
            "domains": [d.domain for d in c.domains],
        }


@app.patch("/companies/{slug}")
def update_company(slug: str, payload: CompanyUpdate):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name must not be empty")

    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")
        c.name = name
        s.commit()
        return {
            "id": c.id,
            "slug": c.slug,
            "name": c.name,
            "domains": [d.domain for d in c.domains],
        }


@app.put("/companies/{slug}/domains")
def replace_domains(slug: str, payload: DomainReplace):
    domains = list(dict.fromkeys([d.strip().lower().strip(".") for d in payload.domains if d and d.strip()]))
    if not domains:
        raise HTTPException(status_code=400, detail="domains must not be empty")

    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")

        for d in list(c.domains):
            s.delete(d)
        # Ensure deletes are issued before inserts to avoid unique constraint conflicts.
        s.flush()
        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))
        s.commit()

    return {"slug": slug, "domains": domains}


@app.delete("/companies/{slug}", status_code=204)
def delete_company(slug: str):
    with SessionLocal() as s:
        c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")
        s.delete(c)
        s.commit()


def _in_scope(domain: str, roots: set[str]) -> bool:
    d = domain.lower().strip(".")
    for r in roots:
        rr = r.lower().strip(".")
        if d == rr or d.endswith("." + rr):
            return True
    return False


def _provider_hints(rec: dict) -> list[str]:
    hay = " ".join(
        [
            *(rec.get("CNAME") or []),
            *(rec.get("NS") or []),
            *(rec.get("MX") or []),
        ]
    ).lower()
    hints = []
    checks = [
        ("cloudflare", ["cloudflare"]),
        ("aws", ["amazonaws", "awsdns"]),
        ("azure", ["azure", "trafficmanager", "cloudapp"]),
        ("gcp", ["google", "googledomains"]),
        ("akamai", ["akamai"]),
        ("fastly", ["fastly"]),
        ("vercel", ["vercel"]),
        ("github-pages", ["github.io"]),
        ("netlify", ["netlify"]),
    ]
    for name, needles in checks:
        if any(n in hay for n in needles):
            hints.append(name)
    return sorted(set(hints))


def _edge_and_server(domain: str, rec: dict, web: dict | None) -> dict:
    web = web or {}
    headers = (web.get("headers") or {}) if isinstance(web, dict) else {}
    server = headers.get("server", "")
    server_version = ""
    m = re.search(r"([A-Za-z][A-Za-z0-9._-]*/[0-9][^\s,;]*)", server or "")
    if m:
        server_version = m.group(1)

    hay = " ".join(
        [
            *(rec.get("CNAME") or []),
            *(rec.get("NS") or []),
            *(rec.get("MX") or []),
            str(server or ""),
            str(headers.get("via", "")),
            str(headers.get("x-cache", "")),
            str(headers.get("x-served-by", "")),
            str(headers.get("cf-ray", "")),
            str(headers.get("x-amz-cf-id", "")),
        ]
    ).lower()
    provider_map = [
        ("cloudflare", ["cloudflare", "cf-ray"]),
        ("cloudfront", ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"]),
        ("fastly", ["fastly", "x-served-by"]),
        ("akamai", ["akamai"]),
        ("vercel", ["vercel"]),
        ("netlify", ["netlify"]),
        ("azure-front-door", ["azurefd", "azure front door"]),
        ("google", ["google", "gws"]),
    ]
    provider = ""
    for name, needles in provider_map:
        if any(n in hay for n in needles):
            provider = name
            break

    signals = []
    for k in ("via", "x-cache", "x-served-by", "cf-ray", "x-amz-cf-id", "x-amz-cf-pop"):
        if headers.get(k):
            signals.append(f"header:{k}")
    if provider:
        signals.append(f"provider:{provider}")
    is_edge = bool(provider or signals)
    return {
        "is_cdn_or_proxy": is_edge,
        "cdn_or_proxy_provider": provider or ("unknown-edge" if is_edge else ""),
        "server_header": server,
        "server_version_hint": server_version,
        "edge_signals": signals,
    }


def _domain_intel(domain: str, roots: set[str], rec: dict, web: dict | None) -> dict:
    d = domain.lower().strip(".")
    root = next((r for r in sorted(roots) if d == r or d.endswith("." + r)), None)
    txt = [t.lower() for t in (rec.get("TXT") or [])]
    ips = rec.get("ips") or []
    has_ipv4 = any("." in ip for ip in ips)
    has_ipv6 = any(":" in ip for ip in ips)
    edge = _edge_and_server(domain, rec, web)
    return {
        "domain": domain,
        "root": root,
        "is_wildcard": domain.startswith("*."),
        "is_apex": bool(root and d == root),
        "label_depth": len([p for p in d.split(".") if p]),
        "resolves": bool(ips),
        "ip_count": len(ips),
        "has_ipv4": has_ipv4,
        "has_ipv6": has_ipv6,
        "has_cname": bool(rec.get("CNAME")),
        "has_mx": bool(rec.get("MX")),
        "has_spf": any("v=spf1" in t for t in txt),
        "has_dmarc": any("v=dmarc1" in t for t in txt),
        "has_caa": bool(rec.get("CAA")),
        "provider_hints": _provider_hints(rec),
        "web": {
            "reachable": bool((web or {}).get("reachable")),
            "scheme": (web or {}).get("scheme", ""),
            "status_code": (web or {}).get("status_code"),
            "final_url": (web or {}).get("final_url", ""),
            "title": (web or {}).get("title", ""),
            **edge,
        },
    }


def _intel_summary(intel_rows: list[dict]) -> dict:
    providers = Counter()
    for row in intel_rows:
        for p in row.get("provider_hints", []):
            providers[p] += 1
    return {
        "domains_total": len(intel_rows),
        "resolved_domains": sum(1 for r in intel_rows if r.get("resolves")),
        "apex_domains": sum(1 for r in intel_rows if r.get("is_apex")),
        "wildcard_domains": sum(1 for r in intel_rows if r.get("is_wildcard")),
        "mail_enabled_domains": sum(1 for r in intel_rows if r.get("has_mx")),
        "spf_domains": sum(1 for r in intel_rows if r.get("has_spf")),
        "dmarc_domains": sum(1 for r in intel_rows if r.get("has_dmarc")),
        "caa_domains": sum(1 for r in intel_rows if r.get("has_caa")),
        "ipv4_domains": sum(1 for r in intel_rows if r.get("has_ipv4")),
        "ipv6_domains": sum(1 for r in intel_rows if r.get("has_ipv6")),
        "provider_hints": dict(sorted(providers.items())),
    }


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
        resolvable_domains = [d for d in domains_sorted if not d.startswith("*.")]

        sem = asyncio.Semaphore(25)

        async def dns_task(d: str):
            async with sem:
                return resolve_dns(d)

        dns_records = await asyncio.gather(*[dns_task(d) for d in resolvable_domains])
        dns_by_domain = {r.get("domain"): r for r in dns_records}
        web_targets = [d for d in resolvable_domains if (dns_by_domain.get(d, {}).get("ips") or dns_by_domain.get(d, {}).get("CNAME"))]
        web_records = await asyncio.gather(*[fetch_http_metadata(d) for d in web_targets])
        return domains_sorted, resolvable_domains, dns_records, web_records

    try:
        domains_sorted, resolvable_domains, dns_records, web_records = asyncio.run(_run())
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

            unique_ips = sorted({ip for rec in dns_records for ip in rec.get("ips", [])})
            resolved_domains = sum(1 for rec in dns_records if rec.get("ips"))
            upsert(
                "domains",
                {
                    "roots": sorted(roots),
                    "domains": domains_sorted,
                    "resolvable_domains": resolvable_domains,
                },
            )
            upsert(
                "dns",
                {
                    "records": dns_records,
                    "summary": {
                        "scanned_domains": len(resolvable_domains),
                        "resolved_domains": resolved_domains,
                        "unresolved_domains": len(resolvable_domains) - resolved_domains,
                        "unique_ip_count": len(unique_ips),
                        "unique_ips": unique_ips,
                    },
                },
            )
            web_reachable = sum(1 for w in web_records if w.get("reachable"))
            upsert(
                "web",
                {
                    "records": web_records,
                    "summary": {
                        "checked_domains": len(web_records),
                        "reachable_domains": web_reachable,
                        "unreachable_domains": len(web_records) - web_reachable,
                    },
                },
            )
            dns_by_domain = {r.get("domain"): r for r in dns_records}
            web_by_domain = {w.get("domain"): w for w in web_records}
            intel_rows = [
                _domain_intel(d, roots, dns_by_domain.get(d, {}), web_by_domain.get(d, {}))
                for d in domains_sorted
            ]
            upsert(
                "dns_intel",
                {
                    "domains": intel_rows,
                    "summary": _intel_summary(intel_rows),
                },
            )

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
        total = len(scans)
        return [
            {
                "id": sc.id,
                "company_scan_number": total - idx,
                "status": sc.status,
                "started_at": sc.started_at,
                "completed_at": sc.completed_at,
                "notes": sc.notes,
            }
            for idx, sc in enumerate(scans)
        ]


@app.get("/companies/{slug}/scans/latest")
def get_latest_scan(slug: str):
    scans = list_scans(slug)
    if not scans:
        raise HTTPException(status_code=404, detail="No scans for company")
    return scans[0]


@app.get("/companies/{slug}/scans/{scan_id}")
def get_scan(slug: str, scan_id: int):
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        scan = s.get(ScanRun, scan_id)
        if not scan or scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        newer = (
            s.execute(
                select(ScanRun)
                .where(ScanRun.company_id == company.id, ScanRun.id > scan.id)
                .order_by(ScanRun.id.asc())
            )
            .scalars()
            .all()
        )

        return {
            "id": scan.id,
            "company_scan_number": len(newer) + 1,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "notes": scan.notes,
        }


@app.get("/scans/{scan_id}/artifacts")
def get_scan_artifacts(scan_id: int):
    with SessionLocal() as s:
        scan = s.get(ScanRun, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        artifacts = s.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)).scalars().all()
        return {a.artifact_type: json.loads(a.json_text) for a in artifacts}


@app.get("/companies/{slug}/scans/{scan_id}/artifacts")
def get_company_scan_artifacts(slug: str, scan_id: int):
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        scan = s.get(ScanRun, scan_id)
        if not scan or scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for company")
    return get_scan_artifacts(scan_id)


@app.delete("/companies/{slug}/scans/{scan_id}", status_code=204)
def delete_scan(slug: str, scan_id: int):
    with SessionLocal() as s:
        company = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        scan = s.get(ScanRun, scan_id)
        if not scan or scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for company")
        s.delete(scan)
        s.commit()
