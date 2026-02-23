from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import re
import secrets
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from .db import SessionLocal
from .init_db import init_db
from .models import Company, CompanyDomain, ScanArtifact, ScanRun
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
def _startup() -> None:
    init_db()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _normalize_domain(d: str) -> str:
    return d.strip().lower().strip(".")


def _in_scope(domain: str, roots: set[str]) -> bool:
    d = _normalize_domain(domain)
    for r in roots:
        rr = _normalize_domain(r)
        if d == rr or d.endswith("." + rr):
            return True
    return False


def _is_test_mode() -> bool:
    return os.getenv("ASM_TEST_MODE", "").strip() == "1"


def _basic_auth_enabled() -> bool:
    return bool(os.getenv("ASM_BASIC_AUTH_USER")) and bool(os.getenv("ASM_BASIC_AUTH_PASS"))


def _unauthorized_response() -> JSONResponse:
    return JSONResponse(
        status_code=401,
        headers={"WWW-Authenticate": 'Basic realm="ASM Notebook"'},
        content={"detail": "Unauthorized"},
    )


def _has_valid_basic_auth(request: Request) -> bool:
    expected_user = os.getenv("ASM_BASIC_AUTH_USER", "")
    expected_pass = os.getenv("ASM_BASIC_AUTH_PASS", "")
    header = request.headers.get("Authorization", "")
    if not header.startswith("Basic "):
        return False
    token = header[len("Basic ") :].strip()
    try:
        decoded = base64.b64decode(token).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return False
    user, sep, password = decoded.partition(":")
    if not sep:
        return False
    return secrets.compare_digest(user, expected_user) and secrets.compare_digest(
        password, expected_pass
    )


@app.middleware("http")
async def enforce_basic_auth(request: Request, call_next):
    if _basic_auth_enabled() and request.url.path != "/health":
        if not _has_valid_basic_auth(request):
            return _unauthorized_response()
    return await call_next(request)


def _company_by_slug(session: SessionLocal, slug: str) -> Company | None:
    return session.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()


def _provider_hints(rec: dict[str, Any]) -> list[str]:
    hay = " ".join(
        [
            *(rec.get("CNAME") or []),
            *(rec.get("NS") or []),
            *(rec.get("MX") or []),
        ]
    ).lower()
    hints: list[str] = []
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


def _edge_and_server(domain: str, rec: dict[str, Any], web: dict[str, Any] | None) -> dict[str, Any]:
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

    signals: list[str] = []
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


def _domain_intel(
    domain: str, roots: set[str], rec: dict[str, Any], web: dict[str, Any] | None
) -> dict[str, Any]:
    d = _normalize_domain(domain)
    root = next((r for r in sorted(roots) if d == r or d.endswith("." + r)), None)
    txt = [str(t).lower() for t in (rec.get("TXT") or [])]
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


def _intel_summary(intel_rows: list[dict[str, Any]]) -> dict[str, Any]:
    providers: Counter[str] = Counter()
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


async def _collect_scan_data(roots: set[str]) -> tuple[list[str], list[str], list[Any], list[Any]]:
    all_domains: set[str] = set(roots)
    for root in roots:
        subs = await ct_subdomains(root)
        all_domains |= subs

    scoped = {d for d in all_domains if _in_scope(d, roots)}
    domains_sorted = sorted(scoped)
    resolvable_domains = [d for d in domains_sorted if not d.startswith("*.")]

    sem = asyncio.Semaphore(25)

    async def dns_task(d: str) -> Any:
        async with sem:
            return resolve_dns(d)

    dns_records = await asyncio.gather(*[dns_task(d) for d in resolvable_domains])
    dns_by_domain = {r.get("domain"): r for r in dns_records}
    web_targets = [
        d
        for d in resolvable_domains
        if (dns_by_domain.get(d, {}).get("ips") or dns_by_domain.get(d, {}).get("CNAME"))
    ]
    web_records = await asyncio.gather(*[fetch_http_metadata(d) for d in web_targets])
    return domains_sorted, resolvable_domains, dns_records, web_records


def _collect_scan_data_test_mode(
    roots: set[str],
) -> tuple[list[str], list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    domains_sorted = sorted({_normalize_domain(d) for d in roots})
    resolvable_domains = [d for d in domains_sorted if not d.startswith("*.")]
    dns_records: list[dict[str, Any]] = []
    for domain in resolvable_domains:
        dns_records.append(
            {
                "domain": domain,
                "resolved_at": _now_utc().isoformat(),
                "A": [],
                "AAAA": [],
                "CNAME": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "SOA": [],
                "CAA": [],
                "ips": [],
                "PTR": {},
            }
        )
    return domains_sorted, resolvable_domains, dns_records, []


def _execute_scan(scan_id: int, roots: list[str]) -> None:
    roots_set = set(roots)
    try:
        if _is_test_mode():
            domains_sorted, resolvable_domains, dns_records, web_records = _collect_scan_data_test_mode(
                roots_set
            )
        else:
            domains_sorted, resolvable_domains, dns_records, web_records = asyncio.run(
                _collect_scan_data(roots_set)
            )

        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if not scan:
                return

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

            unique_ips = sorted({ip for rec in dns_records for ip in rec.get("ips", [])})
            resolved_domains = sum(1 for rec in dns_records if rec.get("ips"))
            upsert_artifact(
                "domains",
                {
                    "roots": sorted(roots_set),
                    "domains": domains_sorted,
                    "resolvable_domains": resolvable_domains,
                },
            )
            upsert_artifact(
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
            upsert_artifact(
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
                _domain_intel(d, roots_set, dns_by_domain.get(d, {}), web_by_domain.get(d, {}))
                for d in domains_sorted
            ]
            upsert_artifact(
                "dns_intel",
                {
                    "domains": intel_rows,
                    "summary": _intel_summary(intel_rows),
                },
            )

            scan.status = "success"
            scan.completed_at = _now_utc()
            s.commit()
    except Exception as e:
        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = _now_utc()
                scan.notes = str(e)[:250]
                s.commit()


@app.get("/health")
def health() -> dict[str, bool]:
    return {"ok": True}


@app.post("/companies", status_code=201)
def create_company(payload: CompanyCreate) -> dict[str, Any]:
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
        s.flush()
        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))
        s.commit()
        return {"id": c.id, "slug": c.slug, "name": c.name, "domains": domains}


@app.get("/companies")
def list_companies() -> list[dict[str, Any]]:
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


@app.get("/companies/{slug}")
def get_company(slug: str) -> dict[str, Any]:
    with SessionLocal() as s:
        c = _company_by_slug(s, slug)
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")
        return {
            "id": c.id,
            "slug": c.slug,
            "name": c.name,
            "domains": [d.domain for d in c.domains],
        }


@app.patch("/companies/{slug}")
def update_company(slug: str, payload: CompanyUpdate) -> dict[str, Any]:
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="name must not be empty")

    with SessionLocal() as s:
        c = _company_by_slug(s, slug)
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")
        c.name = name
        s.commit()
        return {"id": c.id, "slug": c.slug, "name": c.name, "domains": [d.domain for d in c.domains]}


@app.put("/companies/{slug}/domains")
def replace_domains(slug: str, payload: DomainReplace) -> dict[str, Any]:
    domains = list(dict.fromkeys([_normalize_domain(d) for d in payload.domains if d and d.strip()]))
    if not domains:
        raise HTTPException(status_code=400, detail="domains must not be empty")

    with SessionLocal() as s:
        c = _company_by_slug(s, slug)
        if not c:
            raise HTTPException(status_code=404, detail="Company not found")

        for d in list(c.domains):
            s.delete(d)
        s.flush()
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


@app.post("/companies/{slug}/scans", status_code=201)
def trigger_scan(slug: str, background_tasks: BackgroundTasks) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        roots = {_normalize_domain(d.domain) for d in company.domains}
        if not roots:
            raise HTTPException(status_code=400, detail="Company has no domains")

        last_num = (
            s.execute(select(func.max(ScanRun.company_scan_number)).where(ScanRun.company_id == company.id))
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

    background_tasks.add_task(_execute_scan, scan.id, sorted(roots))
    return {
        "company_slug": slug,
        "scan_id": scan.id,
        "company_scan_number": scan.company_scan_number,
        "status": "running",
    }


@app.get("/companies/{slug}/scans")
def list_scans(slug: str) -> list[dict[str, Any]]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
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
                "company_scan_number": sc.company_scan_number,
                "status": sc.status,
                "started_at": sc.started_at,
                "completed_at": sc.completed_at,
                "notes": sc.notes,
            }
            for sc in scans
        ]


@app.get("/companies/{slug}/scans/latest")
def get_latest_scan(slug: str) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = (
            s.execute(select(ScanRun).where(ScanRun.company_id == company.id).order_by(ScanRun.id.desc()).limit(1))
            .scalars()
            .first()
        )
        if not scan:
            raise HTTPException(status_code=404, detail="No scans for company")
        return {
            "id": scan.id,
            "company_scan_number": scan.company_scan_number,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "notes": scan.notes,
        }


@app.get("/companies/{slug}/scans/{scan_id}")
def get_company_scan(slug: str, scan_id: int) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

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
def get_company_scan_by_number(slug: str, company_scan_number: int) -> dict[str, Any]:
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
def get_company_scan_artifacts(slug: str, scan_id: int) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = s.execute(
            select(ScanRun).where(ScanRun.id == scan_id, ScanRun.company_id == company.id)
        ).scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        artifacts = s.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)).scalars().all()
        out: dict[str, Any] = {}
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
