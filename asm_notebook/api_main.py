from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Body, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
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

app = FastAPI(title="ASM Notebook API", version="0.2.0")
router = APIRouter(prefix="/api/v1")

_DIST = Path(__file__).parent / "frontend" / "dist"


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


@app.on_event("startup")
def _startup() -> None:
    init_db()


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class CompanyCreate(BaseModel):
    slug: str
    name: str
    domains: list[str]


class CompanyPatch(BaseModel):
    name: str


class DomainReplace(BaseModel):
    domains: list[str]


class ScanTrigger(BaseModel):
    deep_scan: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _in_scope(domain: str, roots: set[str]) -> bool:
    d = domain.lower().strip(".")
    for r in roots:
        rr = r.lower().strip(".")
        if d == rr or d.endswith("." + rr):
            return True
    return False


def _get_company_or_404(s, slug: str) -> Company:
    c = s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="Company not found")
    return c


def _get_scan_or_404(s, scan_id: int) -> ScanRun:
    sc = s.get(ScanRun, scan_id)
    if not sc:
        raise HTTPException(status_code=404, detail="Scan not found")
    return sc


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


def _load_artifacts(s, scan_id: int) -> dict:
    rows = s.execute(
        select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)
    ).scalars().all()
    return {a.artifact_type: json.loads(a.json_text) for a in rows}


# ---------------------------------------------------------------------------
# Health / Auth stubs
# ---------------------------------------------------------------------------


@router.get("/health")
def health():
    return {"ok": True}


@router.get("/me")
def get_me():
    """Return a single admin user — this backend has no auth layer."""
    return {
        "role": "admin",
        "email": "admin@local",
        "allowed_company_slugs": [],
        "public_company_slugs": [],
        "max_companies": 9999,
        "owned_company_count": 0,
        "scan_limits": {"cooldown_seconds": 0, "scans_per_hour": 9999},
    }


@router.get("/me/preferences/{key}", include_in_schema=False)
def get_preference(key: str):
    return None


@router.put("/me/preferences/{key}", status_code=204, include_in_schema=False)
def set_preference(key: str):
    return None


@router.get("/admin/groups", include_in_schema=False)
def list_groups():
    return []


# ---------------------------------------------------------------------------
# Company endpoints
# ---------------------------------------------------------------------------


@router.post("/companies", status_code=201)
def create_company(payload: CompanyCreate):
    slug = payload.slug.strip()
    name = payload.name.strip()
    domains = [d.strip().lower().strip(".") for d in payload.domains]

    if not slug or not name or not domains:
        raise HTTPException(status_code=400, detail="slug, name, domains are required")

    with SessionLocal() as s:
        if s.execute(select(Company).where(Company.slug == slug)).scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Company slug already exists")

        c = Company(slug=slug, name=name)
        s.add(c)
        s.flush()
        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))
        s.commit()
        return {"id": c.id, "slug": c.slug, "name": c.name, "domains": domains}


@router.get("/companies")
def list_companies():
    with SessionLocal() as s:
        items = s.execute(select(Company).order_by(Company.slug)).scalars().all()
        return [
            {"id": c.id, "slug": c.slug, "name": c.name, "domains": [d.domain for d in c.domains]}
            for c in items
        ]


@router.get("/companies/{slug}")
def get_company(slug: str):
    with SessionLocal() as s:
        c = _get_company_or_404(s, slug)
        return {"id": c.id, "slug": c.slug, "name": c.name, "domains": [d.domain for d in c.domains]}


@router.patch("/companies/{slug}")
def patch_company(slug: str, payload: CompanyPatch):
    with SessionLocal() as s:
        c = _get_company_or_404(s, slug)
        c.name = payload.name.strip()
        s.commit()
        return {"id": c.id, "slug": c.slug, "name": c.name}


@router.put("/companies/{slug}/domains")
def replace_domains(slug: str, payload: DomainReplace):
    domains = [d.strip().lower().strip(".") for d in payload.domains]
    if not domains:
        raise HTTPException(status_code=400, detail="domains must not be empty")

    with SessionLocal() as s:
        c = _get_company_or_404(s, slug)
        for d in list(c.domains):
            s.delete(d)
        for d in domains:
            s.add(CompanyDomain(company_id=c.id, domain=d))
        s.commit()
    return {"slug": slug, "domains": domains}


@router.delete("/companies/{slug}", status_code=204)
def delete_company(slug: str):
    with SessionLocal() as s:
        c = _get_company_or_404(s, slug)
        s.delete(c)
        s.commit()


# ---------------------------------------------------------------------------
# Scan execution
# ---------------------------------------------------------------------------


def _set_scan_progress(scan_id: int, step: int, total: int, message: str) -> None:
    """Update scan notes with progress so the frontend progress bar works."""
    with SessionLocal() as s:
        scan = s.get(ScanRun, scan_id)
        if scan:
            scan.notes = f"{step}/{total} {message}"
            s.commit()


async def _run_scan(scan_id: int, roots: set[str]) -> None:
    """Background coroutine: run full pipeline and persist artifacts."""
    try:
        # Stage 1: subdomain discovery
        _set_scan_progress(scan_id, 1, 4, "Discovering subdomains...")
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

        # Stage 2: DNS
        _set_scan_progress(scan_id, 2, 4, f"Resolving DNS for {len(domains_scoped)} domains...")
        sem = asyncio.Semaphore(25)

        async def dns_task(d: str):
            async with sem:
                return await asyncio.to_thread(resolve_dns, d)

        dns_records = list(await asyncio.gather(*[dns_task(d) for d in domains_scoped]))

        # Stage 3: Shodan InternetDB
        all_ips: set[str] = set()
        for rec in dns_records:
            all_ips.update(rec.get("ips", []))
        _set_scan_progress(scan_id, 3, 4, f"Enriching {len(all_ips)} IPs via Shodan...")
        idb_data = await shodan_idb(sorted(all_ips))

        # Stage 4: risk scoring
        _set_scan_progress(scan_id, 4, 4, "Scoring risk...")
        artifacts: dict = {
            "domains": {"roots": sorted(roots), "domains": domains_scoped},
            "dns": {"records": dns_records},
            "shodan_idb": idb_data,
        }
        artifacts["risk"] = compute_risk_score(artifacts)

        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if scan:
                for atype, data in artifacts.items():
                    _upsert_artifact(s, scan_id, atype, data)
                scan.status = "success"
                scan.completed_at = datetime.now(timezone.utc)
                scan.notes = None
                s.commit()

    except Exception as e:
        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.now(timezone.utc)
                scan.notes = str(e)[:250]
                s.commit()


@router.post("/companies/{slug}/scans", status_code=201)
async def trigger_scan(
    slug: str,
    background_tasks: BackgroundTasks,
    payload: ScanTrigger = Body(default=ScanTrigger()),
):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        roots = {d.domain for d in company.domains}
        if not roots:
            raise HTTPException(status_code=400, detail="Company has no domains")

        scan = ScanRun(
            company_id=company.id,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        s.add(scan)
        s.commit()
        s.refresh(scan)
        scan_id = scan.id

    background_tasks.add_task(_run_scan, scan_id, roots)
    return {"scan_id": scan_id, "status": "running"}


# ---------------------------------------------------------------------------
# Scan listing / retrieval
# ---------------------------------------------------------------------------


@router.get("/companies/{slug}/scans")
def list_scans(slug: str):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
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
                "status": sc.status,
                "started_at": sc.started_at,
                "completed_at": sc.completed_at,
                "notes": sc.notes,
            }
            for sc in scans
        ]


@router.get("/companies/{slug}/scans/latest")
def get_latest_scan(slug: str):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        scan = (
            s.execute(
                select(ScanRun)
                .where(ScanRun.company_id == company.id)
                .order_by(ScanRun.id.desc())
                .limit(1)
            )
            .scalar_one_or_none()
        )
        if not scan:
            raise HTTPException(status_code=404, detail="No scans found for this company")
        return {
            "id": scan.id,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "notes": scan.notes,
        }


@router.get("/companies/{slug}/scans/{scan_id}")
def get_scan(slug: str, scan_id: int):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        scan = _get_scan_or_404(s, scan_id)
        if scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for this company")
        return {
            "id": scan.id,
            "status": scan.status,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "notes": scan.notes,
        }


@router.get("/companies/{slug}/scans/{scan_id}/artifacts")
def get_scan_artifacts(slug: str, scan_id: int):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        scan = _get_scan_or_404(s, scan_id)
        if scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for this company")
        return _load_artifacts(s, scan_id)


@router.delete("/companies/{slug}/scans/{scan_id}", status_code=204)
def delete_scan(slug: str, scan_id: int):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        scan = _get_scan_or_404(s, scan_id)
        if scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for this company")
        s.delete(scan)
        s.commit()


# ---------------------------------------------------------------------------
# Scan diff endpoint
# ---------------------------------------------------------------------------


@router.get("/companies/{slug}/scans/{scan_id}/diff")
def scan_diff(slug: str, scan_id: int, base_id: int | None = None):
    """
    Compare scan_id against base_id (or the previous scan if base_id is omitted).

    Returns:
    {
      "base_scan_id": N,
      "head_scan_id": N,
      "domains": { "added": [...], "removed": [...] },
      "ips":     { "added": [...], "removed": [...] },
      "dns_changes": [
        {
          "domain": "...",
          "changes": {
            "A":   { "added": [...], "removed": [...] },
            ...
          }
        }
      ],
      "risk_changes": {
        "new_findings": [...],
        "resolved_findings": [...]
      }
    }
    """
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)

        head_scan = _get_scan_or_404(s, scan_id)
        if head_scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for this company")

        if base_id is not None:
            base_scan = _get_scan_or_404(s, base_id)
            if base_scan.company_id != company.id:
                raise HTTPException(status_code=404, detail="Base scan not found for this company")
        else:
            # Auto-select the scan immediately before head_scan
            base_scan = (
                s.execute(
                    select(ScanRun)
                    .where(
                        ScanRun.company_id == company.id,
                        ScanRun.id < scan_id,
                        ScanRun.status == "success",
                    )
                    .order_by(ScanRun.id.desc())
                    .limit(1)
                )
                .scalar_one_or_none()
            )
            if not base_scan:
                raise HTTPException(
                    status_code=404,
                    detail="No previous successful scan to diff against. Pass ?base_id= explicitly.",
                )

        head_arts = _load_artifacts(s, head_scan.id)
        base_arts = _load_artifacts(s, base_scan.id)

    # --- Domain diff ---
    head_domains = set(head_arts.get("domains", {}).get("domains", []))
    base_domains = set(base_arts.get("domains", {}).get("domains", []))

    # --- IP diff ---
    def _all_ips(arts: dict) -> set[str]:
        ips: set[str] = set()
        for rec in arts.get("dns", {}).get("records", []):
            ips.update(rec.get("ips", []))
        return ips

    head_ips = _all_ips(head_arts)
    base_ips = _all_ips(base_arts)

    # --- DNS record diffs per domain ---
    DNS_KEYS = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

    head_dns: dict[str, dict] = {r["domain"]: r for r in head_arts.get("dns", {}).get("records", [])}
    base_dns: dict[str, dict] = {r["domain"]: r for r in base_arts.get("dns", {}).get("records", [])}

    dns_changes = []
    all_domains_union = head_domains | base_domains
    for domain in sorted(all_domains_union):
        h = head_dns.get(domain, {})
        b = base_dns.get(domain, {})
        changes: dict[str, dict] = {}
        for key in DNS_KEYS:
            h_vals = set(h.get(key, []))
            b_vals = set(b.get(key, []))
            added = sorted(h_vals - b_vals)
            removed = sorted(b_vals - h_vals)
            if added or removed:
                changes[key] = {"added": added, "removed": removed}
        if changes:
            dns_changes.append({"domain": domain, "changes": changes})

    # --- Risk finding diff ---
    def _finding_key(f: dict) -> str:
        return f"{f['category']}|{f['domain']}|{f['detail']}"

    head_findings = head_arts.get("risk", {}).get("findings", [])
    base_findings = base_arts.get("risk", {}).get("findings", [])
    head_keys = {_finding_key(f): f for f in head_findings}
    base_keys = {_finding_key(f): f for f in base_findings}

    new_findings = [v for k, v in head_keys.items() if k not in base_keys]
    resolved_findings = [v for k, v in base_keys.items() if k not in head_keys]

    return {
        "base_scan_id": base_scan.id,
        "head_scan_id": head_scan.id,
        "domains": {
            "added": sorted(head_domains - base_domains),
            "removed": sorted(base_domains - head_domains),
        },
        "ips": {
            "added": sorted(head_ips - base_ips),
            "removed": sorted(base_ips - head_ips),
        },
        "dns_changes": dns_changes,
        "risk_changes": {
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
        },
    }


# ---------------------------------------------------------------------------
# Risk endpoint (standalone — re-scores without re-scanning)
# ---------------------------------------------------------------------------


@router.get("/companies/{slug}/scans/{scan_id}/risk")
def get_scan_risk(slug: str, scan_id: int):
    """Return risk findings for a completed scan, computing fresh if not cached."""
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        scan = _get_scan_or_404(s, scan_id)
        if scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found for this company")

        arts = _load_artifacts(s, scan_id)

    # Return stored risk artifact if present; else compute on the fly
    if "risk" in arts:
        return arts["risk"]

    return compute_risk_score(arts)


# ---------------------------------------------------------------------------
# SOC overview  (drives the SOC Analyst Workspace view)
# ---------------------------------------------------------------------------

_SEV_MAP = {"critical": "critical", "high": "investigate", "medium": "watch", "low": "info", "info": "info"}

_CPE_PROVIDER: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare"),
    ("amazon", "AWS"),
    ("elastic_load_balancing", "AWS"),
    ("microsoft", "Azure"),
    ("azure", "Azure"),
    ("google", "GCP"),
    ("fastly", "Fastly"),
    ("akamai", "Akamai"),
    ("nginx", "NGINX"),
    ("apache", "Apache"),
    ("f5", "F5"),
]

_HOSTNAME_PROVIDER: list[tuple[str, str]] = [
    ("amazonaws.com", "AWS"),
    ("azure", "Azure"),
    ("googleusercontent.com", "GCP"),
    ("googleapis.com", "GCP"),
    ("cloudfront.net", "AWS CloudFront"),
    ("fastly.net", "Fastly"),
    ("akamaiedge.net", "Akamai"),
]

_CNAME_EDGE: list[tuple[str, str]] = [
    ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("cloudfront.net", "AWS CloudFront"),
    ("edgesuite.net", "Akamai"),
    ("hscoscdn", "HubSpot CDN"),
]


def _soc_asset_from_dns(domain: str, roots: set[str], dns: dict, idb: dict, findings_by_domain: dict, prev_domains: set[str]) -> dict:
    ips: list[str] = dns.get("ips", [])
    cnames: list[str] = dns.get("CNAME", [])

    provider_hints: set[str] = set()
    edge_families: set[str] = set()
    tls_present = False
    web_reachable = False

    for ip in ips:
        entry = idb.get(ip, {})
        ports = entry.get("ports", [])
        if 443 in ports:
            tls_present = True
        if 80 in ports or 443 in ports:
            web_reachable = True
        for cpe in entry.get("cpes", []):
            for key, label in _CPE_PROVIDER:
                if key in cpe:
                    provider_hints.add(label)
                    if label in ("Cloudflare", "Akamai", "Fastly", "AWS CloudFront"):
                        edge_families.add(label)
                    break
        for h in entry.get("hostnames", []):
            for key, label in _HOSTNAME_PROVIDER:
                if key in h:
                    provider_hints.add(label)
                    break
        for tag in entry.get("tags", []):
            if tag == "cdn":
                edge_families.add("CDN")

    for cname in cnames:
        for key, label in _CNAME_EDGE:
            if key in cname:
                edge_families.add(label)
                provider_hints.add(label)
                break

    root_domain = next((r for r in roots if domain == r or domain.endswith(f".{r}")), None)
    asset_type = "root" if domain in roots else "subdomain"

    # Aggregate findings for this domain and its IPs
    raw_findings = list(findings_by_domain.get(domain, []))
    for ip in ips:
        raw_findings.extend(findings_by_domain.get(ip, []))

    finding_counts: dict[str, int] = {"critical": 0, "investigate": 0, "watch": 0, "info": 0}
    for f in raw_findings:
        k = _SEV_MAP.get(f["severity"], "info")
        finding_counts[k] += 1

    change_state = "unchanged"
    if prev_domains:
        change_state = "added" if domain not in prev_domains else "unchanged"

    return {
        "hostname": domain,
        "root_domain": root_domain,
        "asset_type": asset_type,
        "resolves": bool(ips),
        "web_reachable": web_reachable,
        "status_code": None,
        "title": None,
        "provider_hint": ", ".join(sorted(provider_hints)) or None,
        "edge_family": ", ".join(sorted(edge_families)) or None,
        "ip_count": len(ips),
        "ipv6_present": bool(dns.get("AAAA")),
        "tls_present": tls_present,
        "hsts_present": False,
        "finding_counts": finding_counts,
        "change": {"state": change_state},
        "last_seen": dns.get("resolved_at"),
        "final_url": (
            f"https://{domain}" if tls_present
            else f"http://{domain}" if web_reachable
            else None
        ),
        "_ips": ips,
        "_raw_findings": raw_findings,
    }


def _build_soc_response(arts: dict, prev_arts: dict, scan: ScanRun, prev_scan) -> dict:
    domains: list[str] = arts.get("domains", {}).get("domains", [])
    roots: set[str] = set(arts.get("domains", {}).get("roots", []))
    dns_index: dict[str, dict] = {r["domain"]: r for r in arts.get("dns", {}).get("records", [])}
    idb: dict[str, dict] = arts.get("shodan_idb", {})
    risk_findings: list[dict] = arts.get("risk", {}).get("findings", [])
    prev_domains: set[str] = set(prev_arts.get("domains", {}).get("domains", [])) if prev_arts else set()

    findings_by_domain: dict[str, list] = {}
    for f in risk_findings:
        findings_by_domain.setdefault(f["domain"], []).append(f)

    assets = []
    for domain in domains:
        if domain.startswith("*"):
            continue
        dns = dns_index.get(domain, {})
        asset = _soc_asset_from_dns(domain, roots, dns, idb, findings_by_domain, prev_domains)
        assets.append(asset)

    # SOC findings list (flattened, severity-mapped)
    soc_findings = []
    for i, f in enumerate(risk_findings):
        soc_findings.append({
            "id": f"{f['domain']}-{f['category']}-{i}",
            "severity": _SEV_MAP.get(f["severity"], "info"),
            "title": f["detail"][:100],
            "asset_hostname": f["domain"],
            "category": f["category"],
            "status": "open",
        })

    # Summary counters
    curr_domains = {a["hostname"] for a in assets}
    removed = sum(1 for d in prev_domains if d not in curr_domains and not d.startswith("*")) if prev_domains else 0

    summary = {
        "assets_discovered": len(assets),
        "live_web_assets": sum(1 for a in assets if a["web_reachable"]),
        "unresolved_assets": sum(1 for a in assets if not a["resolves"]),
        "assets_with_critical_findings": sum(1 for a in assets if a["finding_counts"].get("critical", 0) > 0),
        "assets_with_investigate_findings": sum(1 for a in assets if a["finding_counts"].get("investigate", 0) > 0),
        "missing_hsts_assets": sum(1 for a in assets if a["tls_present"] and not a["hsts_present"]),
        "assets_changed": sum(1 for a in assets if a["change"]["state"] != "unchanged"),
        "removed_assets": removed,
    }

    # Strip internal fields
    for a in assets:
        a.pop("_ips", None)
        a.pop("_raw_findings", None)

    return {
        "assets": assets,
        "findings": soc_findings,
        "summary": summary,
        "scan": {"id": scan.id, "status": scan.status, "company_scan_number": scan.id},
        "previous_scan": {"company_scan_number": prev_scan.id} if prev_scan else None,
    }


def _get_soc_scan(s, company, scan_id: int | None):
    if scan_id:
        scan = _get_scan_or_404(s, scan_id)
        if scan.company_id != company.id:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan
    scan = s.execute(
        select(ScanRun)
        .where(ScanRun.company_id == company.id, ScanRun.status == "success")
        .order_by(ScanRun.id.desc()).limit(1)
    ).scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="No successful scan found")
    return scan


@router.get("/companies/{slug}/soc")
def get_soc_overview(slug: str, scan_id: int | None = None):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        scan = _get_soc_scan(s, company, scan_id)
        prev_scan = s.execute(
            select(ScanRun)
            .where(ScanRun.company_id == company.id, ScanRun.id < scan.id, ScanRun.status == "success")
            .order_by(ScanRun.id.desc()).limit(1)
        ).scalar_one_or_none()
        arts = _load_artifacts(s, scan.id)
        prev_arts = _load_artifacts(s, prev_scan.id) if prev_scan else {}

    return _build_soc_response(arts, prev_arts, scan, prev_scan)


@router.get("/companies/{slug}/soc/assets/{hostname:path}")
def get_soc_asset_detail(slug: str, hostname: str, scan_id: int | None = None):
    with SessionLocal() as s:
        company = _get_company_or_404(s, slug)
        scan = _get_soc_scan(s, company, scan_id)
        prev_scan = s.execute(
            select(ScanRun)
            .where(ScanRun.company_id == company.id, ScanRun.id < scan.id, ScanRun.status == "success")
            .order_by(ScanRun.id.desc()).limit(1)
        ).scalar_one_or_none()
        arts = _load_artifacts(s, scan.id)
        prev_arts = _load_artifacts(s, prev_scan.id) if prev_scan else {}

    roots = set(arts.get("domains", {}).get("roots", []))
    dns_index = {r["domain"]: r for r in arts.get("dns", {}).get("records", [])}
    idb = arts.get("shodan_idb", {})
    risk_findings = arts.get("risk", {}).get("findings", [])
    prev_domains = set(prev_arts.get("domains", {}).get("domains", [])) if prev_arts else set()

    findings_by_domain: dict[str, list] = {}
    for f in risk_findings:
        findings_by_domain.setdefault(f["domain"], []).append(f)

    dns = dns_index.get(hostname, {})
    # When hostname is a bare IP, synthesize a minimal dns record so IDB lookup works
    if not dns and re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', hostname):
        dns = {"ips": [hostname]}
    asset = _soc_asset_from_dns(hostname, roots, dns, idb, findings_by_domain, prev_domains)

    ips = asset.pop("_ips", [])
    raw_findings = asset.pop("_raw_findings", [])

    # Enrich with Shodan detail per IP
    ip_detail = []
    for ip in ips:
        entry = idb.get(ip, {})
        if entry:
            ip_detail.append({"ip": ip, **entry})

    soc_findings = [
        {
            "id": f"{f['domain']}-{f['category']}-{i}",
            "severity": _SEV_MAP.get(f["severity"], "info"),
            "title": f["detail"][:100],
            "asset_hostname": f["domain"],
            "category": f["category"],
            "detail": f["detail"],
            "status": "open",
        }
        for i, f in enumerate(raw_findings)
    ]

    dns_records = {k: v for k, v in dns.items() if isinstance(v, list) and v}

    # Shape the response to match the nested structure the drawer expects
    return {
        "asset": {
            "hostname": asset["hostname"],
            "root_domain": asset.get("root_domain"),
            "asset_type": asset.get("asset_type"),
            "resolves": asset.get("resolves", False),
            "edge_family": asset.get("edge_family"),
            "provider_hint": asset.get("provider_hint"),
            "has_ipv4": asset.get("ip_count", 0) > 0,
            "has_ipv6": asset.get("ipv6_present", False),
            "ip_count": asset.get("ip_count", 0),
            "last_seen": asset.get("last_seen"),
            "finding_counts": asset.get("finding_counts", {}),
            "change": asset.get("change", {"state": "unchanged"}),
            "findings": soc_findings,
            "web": {
                "reachable": asset.get("web_reachable", False),
                "final_url": asset.get("final_url"),
                "status_code": asset.get("status_code"),
                "title": asset.get("title"),
                "tls_present": asset.get("tls_present", False),
                "hsts": {"header": "present"} if asset.get("hsts_present") else {},
            },
            "dns": {
                **dns_records,
                "ips": dns_records.get("ips", dns_records.get("A", [])),
            },
            "ip_detail": ip_detail,
            "raw": {**asset, "dns_records": dns_records, "ip_detail": ip_detail},
        }
    }


# ---------------------------------------------------------------------------
# Legacy compat: artifact access without company slug prefix
# ---------------------------------------------------------------------------


@router.get("/scans/{scan_id}/artifacts")
def get_scan_artifacts_legacy(scan_id: int):
    with SessionLocal() as s:
        _get_scan_or_404(s, scan_id)
        return _load_artifacts(s, scan_id)


app.include_router(router)


# ---------------------------------------------------------------------------
# Static files + SPA catch-all  (must come last so API routes take priority)
# ---------------------------------------------------------------------------

if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/favicon.png", include_in_schema=False)
    def favicon():
        return FileResponse(_DIST / "favicon.png")

    @app.get("/{path:path}", include_in_schema=False)
    def spa_fallback(path: str):
        return FileResponse(_DIST / "index.html")
