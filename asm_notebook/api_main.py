from __future__ import annotations

import asyncio
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func, select

from .db import SessionLocal
from .init_db import init_db
from .models import Company, CompanyDomain, ScanArtifact, ScanRun
from .plugins.ct import ct_subdomains
from .plugins.dns import resolve_dns, resolve_ips
from .plugins.http_meta import fetch_http_metadata
from .plugins.ip_intel import lookup_asn_for_ips

app = FastAPI(title="ASM Notebook API")


def _cors_origins() -> list[str]:
    raw = os.getenv("ASM_CORS_ALLOW_ORIGINS", "").strip()
    if raw:
        return [o.strip() for o in raw.split(",") if o.strip()]
    return [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CompanyCreate(BaseModel):
    slug: str
    name: str
    domains: list[str]


class DomainReplace(BaseModel):
    domains: list[str]


class ScanRequest(BaseModel):
    deep_scan: bool = False


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


def _mx_providers(mx_records: list[str]) -> list[str]:
    providers: list[str] = []
    for mx in mx_records or []:
        host = str(mx).split()[-1].lower().strip(".")
        if "aspmx.l.google.com" in host or host.endswith(".google.com"):
            providers.append("google-workspace")
        elif "outlook.com" in host or "protection.outlook.com" in host:
            providers.append("microsoft-365")
        elif "pphosted.com" in host:
            providers.append("proofpoint")
        elif "mimecast.com" in host:
            providers.append("mimecast")
        elif "barracudanetworks.com" in host:
            providers.append("barracuda")
        elif "zoho.com" in host:
            providers.append("zoho")
        elif "fastmail.com" in host:
            providers.append("fastmail")
    return sorted(set(providers))


def _email_security_score(
    has_mx: bool,
    has_spf: bool,
    has_dmarc: bool,
    dmarc_policy: str,
    has_mta_sts: bool,
    has_bimi: bool,
    dkim_count: int,
) -> tuple[int, list[str]]:
    if not has_mx:
        return 0, ["no_mx"]
    score = 0
    factors: list[str] = []
    if has_spf:
        score += 2
    else:
        factors.append("spf_missing")
    if has_dmarc:
        score += 2
        if dmarc_policy in ("reject", "quarantine"):
            score += 1
    else:
        factors.append("dmarc_missing")
    if has_mta_sts:
        score += 2
    else:
        factors.append("mta_sts_missing")
    if has_bimi:
        score += 1
    if dkim_count > 0:
        score += 2
    else:
        factors.append("dkim_missing")
    return min(score, 10), factors


def _takeover_targets(cname_list: list[str]) -> list[str]:
    patterns = [
        "herokuapp.com",
        "github.io",
        "bitbucket.io",
        "netlify.app",
        "readme.io",
        "azurewebsites.net",
        "cloudapp.net",
        "trafficmanager.net",
        "amazonaws.com",
        "s3.amazonaws.com",
        "storage.googleapis.com",
        "blob.core.windows.net",
        "pantheonsite.io",
    ]
    targets: list[str] = []
    for cname in cname_list:
        for p in patterns:
            if p in cname:
                targets.append(cname)
                break
    return sorted(set(targets))


def _surface_class(domain: str) -> str:
    d = domain.lower()
    if d.startswith(("api.", "api-")) or ".api." in d:
        return "api"
    if d.startswith(("admin.", "admin-")) or ".admin." in d:
        return "admin"
    if d.startswith(("staging.", "stage.", "dev.", "test.")) or any(
        x in d for x in (".staging.", ".stage.", ".dev.", ".test.")
    ):
        return "staging"
    if d.startswith(("mail.", "smtp.", "mx.")) or ".mail." in d:
        return "email"
    if d.startswith(("vpn.", "remote.")) or ".vpn." in d:
        return "vpn"
    return "web"


def _service_hints_from_ptr(ptr: dict[str, list[str]]) -> list[str]:
    hints: list[str] = []
    for names in (ptr or {}).values():
        for name in names:
            lower = name.lower()
            if "amazonaws.com" in lower:
                hints.append("aws")
            if "cloudapp.net" in lower or "windows.net" in lower:
                hints.append("azure")
            if "googleusercontent.com" in lower:
                hints.append("gcp")
            if "fastly" in lower:
                hints.append("fastly")
            if "cloudflare" in lower:
                hints.append("cloudflare")
    return sorted(set(hints))


def _compute_exposure_score(row: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    factors: list[str] = []
    web = row.get("web", {}) or {}
    has_mx = row.get("has_mx", False)
    if row.get("dangling_cname"):
        score += 5
        factors.append("dangling_cname")
    if row.get("resolves") and not (web.get("edge_provider") or {}).get("provider"):
        score += 2
        factors.append("no_edge_provider")
    if has_mx and not row.get("has_dmarc"):
        score += 1
        factors.append("no_dmarc")
    if has_mx and not row.get("has_spf"):
        score += 1
        factors.append("no_spf")
    if has_mx and not row.get("has_mta_sts"):
        score += 1
        factors.append("no_mta_sts")
    if has_mx and (row.get("dkim_txt_records") or 0) == 0:
        score += 1
        factors.append("no_dkim")
    if web.get("reachable") and not (web.get("hsts") or {}).get("header"):
        score += 1
        factors.append("no_hsts")
    if web.get("reachable") and web.get("scheme") == "http":
        score += 1
        factors.append("http_only")
    return min(score, 10), factors


_CVE_LOOKUP = {
    ("apache", "2.4.49"): [
        {"cve": "CVE-2021-41773", "severity": "High", "note": "Path traversal / RCE"}
    ],
    ("log4j", "2.14.1"): [
        {"cve": "CVE-2021-44228", "severity": "Critical", "note": "Log4Shell"}
    ],
    ("openssl", "1.0.2"): [
        {"cve": "CVE-2016-2107", "severity": "High", "note": "Padding oracle"}
    ],
}


def _cve_findings(reported_versions: list[dict[str, str]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for entry in reported_versions or []:
        name = entry.get("name", "").lower()
        version = entry.get("version", "")
        if not name or not version:
            continue
        key = (name, version)
        for row in _CVE_LOOKUP.get(key, []):
            findings.append({"component": name, "version": version, **row})
    return findings

def _flatten_cert_entity(entity: Any) -> str:
    if not entity:
        return ""
    if isinstance(entity, list):
        parts: list[str] = []
        for entry in entity:
            if isinstance(entry, (list, tuple)):
                if len(entry) == 2 and all(isinstance(x, str) for x in entry):
                    parts.append(f"{entry[0]}={entry[1]}")
                else:
                    parts.append(_flatten_cert_entity(entry))
            elif isinstance(entry, dict):
                parts.extend([f"{k}={v}" for k, v in entry.items()])
            else:
                parts.append(str(entry))
        return " ".join([p for p in parts if p])
    if isinstance(entity, dict):
        return " ".join([f"{k}={v}" for k, v in entity.items()])
    return str(entity)


def _detect_edge_provider(
    rec: dict[str, Any],
    web: dict[str, Any] | None,
    ip_asn: list[dict[str, Any]],
) -> dict[str, Any]:
    web = web or {}
    headers = (web.get("headers") or {}) if isinstance(web, dict) else {}
    cname_targets = [str(c).lower() for c in (rec.get("CNAME") or [])]
    ns_targets = [str(n).lower() for n in (rec.get("NS") or [])]
    server = str(headers.get("server", "")).lower()
    via = str(headers.get("via", "")).lower()
    x_cache = str(headers.get("x-cache", "")).lower()
    x_served_by = str(headers.get("x-served-by", "")).lower()
    x_powered_by = str(headers.get("x-powered-by", "")).lower()
    tls_issuer = _flatten_cert_entity((web.get("tls") or {}).get("cert", {}).get("issuer", "")).lower()

    signals: dict[str, list[str]] = {}

    def add(provider: str, signal: str) -> None:
        signals.setdefault(provider, []).append(signal)

    cname_map = {
        "cloudfront": ["cloudfront.net"],
        "akamai": ["akamaiedge.net", "akamaitechnologies.com", "edgesuite.net", "edgekey.net"],
        "cloudflare": ["cloudflare.net"],
        "fastly": ["fastly.net", "fastlylb.net"],
        "azure-cdn": ["azureedge.net"],
        "azure-front-door": ["azurefd.net", "azurefd.us"],
        "imperva": ["incapsula.com", "imperva.com"],
        "edgio": ["edgio.net", "llnwd.net", "limelight.com"],
        "stackpath": ["stackpathcdn.com", "stackpathdns.com"],
    }
    for target in cname_targets:
        for provider, patterns in cname_map.items():
            if any(p in target for p in patterns):
                add(provider, f"cname:{target}")

    for target in ns_targets:
        if "cloudflare" in target:
            add("cloudflare", f"ns:{target}")

    if "cloudflare" in server or headers.get("cf-ray"):
        add("cloudflare", "header:cf-ray/server")
    if "akamai" in server or headers.get("x-akamai-transformed") or headers.get("akamai-origin-hop"):
        add("akamai", "header:akamai")
    if "fastly" in via or "fastly" in x_served_by or headers.get("x-fastly-request-id"):
        add("fastly", "header:fastly")
    if "cloudfront" in via or headers.get("x-amz-cf-id"):
        add("cloudfront", "header:cloudfront")
    if headers.get("x-iinfo"):
        add("imperva", "header:imperva")
    if "azure" in server or "azure" in x_powered_by:
        add("azure-cdn", "header:azure")
    if "google" in server or "gws" in server:
        add("google-cloud-cdn", "header:google")

    if "cloudflare" in tls_issuer:
        add("cloudflare", "tls:issuer")
    if "amazon" in tls_issuer:
        add("cloudfront", "tls:issuer")
    if "akamai" in tls_issuer:
        add("akamai", "tls:issuer")
    if "fastly" in tls_issuer:
        add("fastly", "tls:issuer")
    if "imperva" in tls_issuer:
        add("imperva", "tls:issuer")
    if "microsoft" in tls_issuer or "azure" in tls_issuer:
        add("azure-cdn", "tls:issuer")
    if "google" in tls_issuer:
        add("google-cloud-cdn", "tls:issuer")

    asn_hint_map = {
        "cloudflare": ["cloudflare"],
        "akamai": ["akamai"],
        "fastly": ["fastly"],
        "cloudfront": ["amazon", "aws"],
        "azure-cdn": ["microsoft", "azure"],
        "google-cloud-cdn": ["google"],
        "imperva": ["imperva"],
        "edgio": ["limelight", "edgio"],
        "stackpath": ["stackpath"],
    }
    asn_signals: dict[str, list[str]] = {}
    for row in ip_asn:
        desc = str(row.get("asn_description", "")).lower()
        asn = str(row.get("asn", "")).strip()
        for provider, needles in asn_hint_map.items():
            if any(n in desc for n in needles):
                add(provider, f"asn:{asn}")
                asn_signals.setdefault(provider, []).append(f"asn:{asn}")

    if not signals:
        return {"provider": "", "confidence": "none", "signals": [], "asn_provider": "", "asn_signals": []}

    ranked = sorted(signals.items(), key=lambda kv: len(kv[1]), reverse=True)
    provider, provider_signals = ranked[0]
    asn_provider = ""
    asn_provider_signals: list[str] = []
    if asn_signals:
        ranked_asn = sorted(asn_signals.items(), key=lambda kv: len(kv[1]), reverse=True)
        asn_provider, asn_provider_signals = ranked_asn[0]
    confidence = "low"
    if any(s.startswith("cname:") for s in provider_signals):
        confidence = "high"
    elif len(provider_signals) >= 2:
        confidence = "high"
    elif any(s.startswith("header:") or s.startswith("tls:") for s in provider_signals):
        confidence = "medium"

    return {
        "provider": provider,
        "confidence": confidence,
        "signals": provider_signals,
        "asn_provider": asn_provider,
        "asn_signals": asn_provider_signals,
    }


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
    domain: str,
    roots: set[str],
    rec: dict[str, Any],
    web: dict[str, Any] | None,
    asn_by_ip: dict[str, dict[str, Any]] | None = None,
    cname_targets: dict[str, bool] | None = None,
    wildcard_roots: dict[str, bool] | None = None,
) -> dict[str, Any]:
    d = _normalize_domain(domain)
    root = next((r for r in sorted(roots) if d == r or d.endswith("." + r)), None)
    txt = [str(t).lower() for t in (rec.get("TXT") or [])]
    cname_list = [str(c).lower() for c in (rec.get("CNAME") or [])]
    ips = rec.get("ips") or []
    asn_by_ip = asn_by_ip or {}
    cname_targets = cname_targets or {}
    wildcard_roots = wildcard_roots or {}
    ip_asn = [asn_by_ip[ip] for ip in ips if ip in asn_by_ip]
    has_ipv4 = any("." in ip for ip in ips)
    has_ipv6 = any(":" in ip for ip in ips)
    edge = _edge_and_server(domain, rec, web)
    edge_provider = _detect_edge_provider(rec, web, ip_asn)
    spf_records = [t for t in txt if "v=spf1" in t]
    dmarc_records = [t for t in txt if "v=dmarc1" in t]
    has_spf = bool(spf_records)
    has_dmarc = bool(dmarc_records)
    dmarc_policy = ""
    if dmarc_records:
        m = re.search(r"\bp=([a-z]+)", dmarc_records[0])
        dmarc_policy = m.group(1) if m else ""
    has_mta_sts = any("v=stsv1" in t for t in txt)
    has_bimi = any("v=bimi1" in t for t in txt)
    dkim_records = [t for t in txt if "v=dkim1" in t]
    cname_resolves = any(cname_targets.get(t) for t in cname_list)
    dangling_cname = bool(cname_list) and not ips and not cname_resolves
    takeover_targets = _takeover_targets(cname_list) if dangling_cname else []
    takeover_risk = bool(takeover_targets)
    mail_providers = _mx_providers(rec.get("MX") or [])
    email_score, email_factors = _email_security_score(
        bool(rec.get("MX")),
        has_spf,
        has_dmarc,
        dmarc_policy,
        has_mta_sts,
        has_bimi,
        len(dkim_records),
    )
    surface_class = _surface_class(domain)
    service_hints = _service_hints_from_ptr(rec.get("PTR") or {})
    root_wildcard = bool(root and wildcard_roots.get(root))
    web_block = {
        "reachable": bool((web or {}).get("reachable")),
        "scheme": (web or {}).get("scheme", ""),
        "status_code": (web or {}).get("status_code"),
        "final_url": (web or {}).get("final_url", ""),
        "title": (web or {}).get("title", ""),
        "security_headers": (web or {}).get("security_headers") or {},
        "fingerprints": (web or {}).get("fingerprints") or [],
        "reported_versions": (web or {}).get("reported_versions") or [],
        "technologies": (web or {}).get("technologies") or [],
        "hsts": (web or {}).get("hsts") or {},
        "tls": (web or {}).get("tls") or {},
        "cloud_storage": (web or {}).get("cloud_storage") or {},
        "deep_scan": (web or {}).get("deep_scan") or {},
        "edge_provider": edge_provider,
        **edge,
    }
    row = {
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
        "dangling_cname": dangling_cname,
        "takeover_risk": takeover_risk,
        "takeover_targets": takeover_targets,
        "has_mx": bool(rec.get("MX")),
        "has_spf": has_spf,
        "spf_txt_records": len(spf_records),
        "spf_multiple": len(spf_records) > 1,
        "has_dmarc": has_dmarc,
        "dmarc_policy": dmarc_policy,
        "dmarc_txt_records": len(dmarc_records),
        "has_mta_sts": has_mta_sts,
        "has_bimi": has_bimi,
        "dkim_txt_records": len(dkim_records),
        "has_caa": bool(rec.get("CAA")),
        "ip_asn": ip_asn,
        "provider_hints": _provider_hints(rec),
        "mail_providers": mail_providers,
        "email_security_score": email_score,
        "email_security_factors": email_factors,
        "surface_class": surface_class,
        "service_hints": service_hints,
        "root_wildcard": root_wildcard,
        "web": web_block,
    }
    exposure_score, exposure_factors = _compute_exposure_score(row)
    row["exposure_score"] = exposure_score
    row["exposure_factors"] = exposure_factors
    row["cve_findings"] = _cve_findings(web_block.get("reported_versions") or [])
    return row


def _intel_summary(intel_rows: list[dict[str, Any]]) -> dict[str, Any]:
    providers: Counter[str] = Counter()
    dmarc_policy: Counter[str] = Counter()
    surfaces: Counter[str] = Counter()
    mail_providers: Counter[str] = Counter()
    exposure_scores: list[int] = []
    for row in intel_rows:
        for p in row.get("provider_hints", []):
            providers[p] += 1
        if row.get("dmarc_policy"):
            dmarc_policy[row["dmarc_policy"]] += 1
        if row.get("surface_class"):
            surfaces[row["surface_class"]] += 1
        for p in row.get("mail_providers", []):
            mail_providers[p] += 1
        if isinstance(row.get("exposure_score"), int):
            exposure_scores.append(row["exposure_score"])
    return {
        "domains_total": len(intel_rows),
        "resolved_domains": sum(1 for r in intel_rows if r.get("resolves")),
        "apex_domains": sum(1 for r in intel_rows if r.get("is_apex")),
        "wildcard_domains": sum(1 for r in intel_rows if r.get("is_wildcard")),
        "mail_enabled_domains": sum(1 for r in intel_rows if r.get("has_mx")),
        "spf_domains": sum(1 for r in intel_rows if r.get("has_spf")),
        "multiple_spf_domains": sum(1 for r in intel_rows if r.get("spf_multiple")),
        "dmarc_domains": sum(1 for r in intel_rows if r.get("has_dmarc")),
        "dmarc_policy": dict(sorted(dmarc_policy.items())),
        "mta_sts_domains": sum(1 for r in intel_rows if r.get("has_mta_sts")),
        "bimi_domains": sum(1 for r in intel_rows if r.get("has_bimi")),
        "dkim_domains": sum(1 for r in intel_rows if (r.get("dkim_txt_records") or 0) > 0),
        "caa_domains": sum(1 for r in intel_rows if r.get("has_caa")),
        "ipv4_domains": sum(1 for r in intel_rows if r.get("has_ipv4")),
        "ipv6_domains": sum(1 for r in intel_rows if r.get("has_ipv6")),
        "dangling_cname_domains": sum(1 for r in intel_rows if r.get("dangling_cname")),
        "takeover_risk_domains": sum(1 for r in intel_rows if r.get("takeover_risk")),
        "wildcard_roots": sum(1 for r in intel_rows if r.get("root_wildcard")),
        "tls_domains": sum(1 for r in intel_rows if r.get("web", {}).get("tls")),
        "hsts_domains": sum(1 for r in intel_rows if r.get("web", {}).get("hsts")),
        "hsts_preload_eligible_domains": sum(
            1
            for r in intel_rows
            if (r.get("web", {}).get("hsts") or {}).get("preload_eligible")
        ),
        "provider_hints": dict(sorted(providers.items())),
        "mail_providers": dict(sorted(mail_providers.items())),
        "surface_classes": dict(sorted(surfaces.items())),
        "exposure_score_avg": round(sum(exposure_scores) / len(exposure_scores), 2)
        if exposure_scores
        else 0,
    }


def _change_summary(
    current: list[dict[str, Any]],
    previous: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    if not previous:
        return {"has_previous": False, "new_domains": [], "removed_domains": []}
    current_by_domain = {row.get("domain"): row for row in current if row.get("domain")}
    prev_by_domain = {row.get("domain"): row for row in previous if row.get("domain")}
    current_domains = set(current_by_domain.keys())
    prev_domains = set(prev_by_domain.keys())
    new_domains = sorted(current_domains - prev_domains)
    removed_domains = sorted(prev_domains - current_domains)
    provider_changes = []
    tech_changes = []
    for domain in sorted(current_domains & prev_domains):
        cur = current_by_domain[domain]
        prev = prev_by_domain[domain]
        cur_provider = (cur.get("web", {}).get("edge_provider") or {}).get("provider", "")
        prev_provider = (prev.get("web", {}).get("edge_provider") or {}).get("provider", "")
        if cur_provider != prev_provider:
            provider_changes.append(
                {"domain": domain, "from": prev_provider, "to": cur_provider}
            )
        cur_tech = {t.get("name") for t in (cur.get("web", {}).get("technologies") or [])}
        prev_tech = {t.get("name") for t in (prev.get("web", {}).get("technologies") or [])}
        if cur_tech != prev_tech:
            tech_changes.append(
                {
                    "domain": domain,
                    "added": sorted(cur_tech - prev_tech),
                    "removed": sorted(prev_tech - cur_tech),
                }
            )
    return {
        "has_previous": True,
        "new_domains": new_domains,
        "removed_domains": removed_domains,
        "provider_changes": provider_changes,
        "technology_changes": tech_changes,
    }

async def _collect_scan_data(
    roots: set[str],
    progress_cb: Callable[[int, int, str], None] | None = None,
    deep_scan: bool = False,
) -> tuple[
    list[str],
    list[str],
    list[Any],
    list[Any],
    dict[str, bool],
    dict[str, Any],
    dict[str, bool],
]:
    all_domains: set[str] = set(roots)
    sorted_roots = sorted(roots)
    root_count = len(sorted_roots)
    ct_hits: dict[str, list[str]] = {}
    for idx, root in enumerate(sorted_roots, start=1):
        if progress_cb:
            progress_cb(2, 6, f"Collecting CT for {root} ({idx}/{root_count})")
        subs = await ct_subdomains(root)
        ct_hits[root] = sorted(subs)
        all_domains |= subs

    scoped = {d for d in all_domains if _in_scope(d, roots)}
    domains_sorted = sorted(scoped)
    resolvable_domains = [d for d in domains_sorted if not d.startswith("*.")]
    if progress_cb:
        progress_cb(2, 6, f"Resolving DNS for {len(resolvable_domains)} domains")

    sem = asyncio.Semaphore(25)

    async def dns_task(d: str) -> Any:
        async with sem:
            return await asyncio.to_thread(resolve_dns, d)

    dns_records = await asyncio.gather(*[dns_task(d) for d in resolvable_domains])
    dns_by_domain = {r.get("domain"): r for r in dns_records}
    cname_targets = sorted(
        {
            target.rstrip(".").lower()
            for rec in dns_records
            for target in (rec.get("CNAME") or [])
            if target
        }
    )
    if progress_cb and cname_targets:
        progress_cb(2, 6, f"Checking {len(cname_targets)} CNAME targets")

    async def cname_task(target: str) -> tuple[str, bool]:
        async with sem:
            ips = await asyncio.to_thread(resolve_ips, target)
            return target, bool(ips)

    cname_results = await asyncio.gather(*[cname_task(t) for t in cname_targets])
    cname_resolves = {target: ok for target, ok in cname_results}

    wildcard_roots: dict[str, bool] = {}
    if progress_cb and sorted_roots:
        progress_cb(2, 6, f"Checking wildcard DNS for {len(sorted_roots)} roots")

    async def wildcard_task(root: str) -> tuple[str, bool]:
        label = f"wild-{os.urandom(3).hex()}"
        target = f"{label}.{root}"
        async with sem:
            ips = await asyncio.to_thread(resolve_ips, target)
            return root, bool(ips)

    wildcard_results = await asyncio.gather(*[wildcard_task(r) for r in sorted_roots])
    wildcard_roots = {root: ok for root, ok in wildcard_results}

    web_targets = [
        d
        for d in resolvable_domains
        if (dns_by_domain.get(d, {}).get("ips") or dns_by_domain.get(d, {}).get("CNAME"))
    ]
    if progress_cb:
        note = "Checking HTTP metadata"
        if deep_scan:
            note = "Checking HTTP metadata + deep resources"
        progress_cb(2, 6, f"{note} for {len(web_targets)} domains")
    web_records = await asyncio.gather(
        *[fetch_http_metadata(d, deep_scan=deep_scan) for d in web_targets]
    )
    suspicious_keywords = [
        "dev",
        "test",
        "staging",
        "stage",
        "internal",
        "admin",
        "vpn",
        "old",
    ]
    suspicious_hosts: list[str] = []
    for root, hosts in ct_hits.items():
        for host in hosts:
            if any(k in host for k in suspicious_keywords):
                suspicious_hosts.append(host)
    ct_enrichment = {
        "roots": sorted_roots,
        "ct_hostnames": sum(len(v) for v in ct_hits.values()),
        "suspicious_hostnames": sorted(set(suspicious_hosts)),
    }
    return (
        domains_sorted,
        resolvable_domains,
        dns_records,
        web_records,
        cname_resolves,
        ct_enrichment,
        wildcard_roots,
    )


def _collect_scan_data_test_mode(
    roots: set[str],
) -> tuple[
    list[str],
    list[str],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, bool],
    dict[str, Any],
    dict[str, bool],
]:
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
    return domains_sorted, resolvable_domains, dns_records, [], {}, {"roots": [], "ct_hostnames": 0, "suspicious_hostnames": []}, {}


def _execute_scan(scan_id: int, roots: list[str], deep_scan: bool = False) -> None:
    roots_set = set(roots)

    def set_progress(step: int, total: int, message: str) -> None:
        with SessionLocal() as s:
            scan = s.get(ScanRun, scan_id)
            if not scan:
                return
            scan.notes = f"{step}/{total} {message}"[:250]
            s.commit()

    try:
        set_progress(1, 6, "Preparing scan")
        if _is_test_mode():
            set_progress(2, 6, "Collecting domains (test mode)")
            (
                domains_sorted,
                resolvable_domains,
                dns_records,
                web_records,
                cname_resolves,
                ct_enrichment,
                wildcard_roots,
            ) = _collect_scan_data_test_mode(
                roots_set
            )
        else:
            set_progress(2, 6, "Collecting in-scope domains from CT")
            (
                domains_sorted,
                resolvable_domains,
                dns_records,
                web_records,
                cname_resolves,
                ct_enrichment,
                wildcard_roots,
            ) = asyncio.run(
                _collect_scan_data(roots_set, progress_cb=set_progress, deep_scan=deep_scan)
            )

        set_progress(3, 6, "Persisting domains and DNS artifacts")
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
            s.commit()

            set_progress(4, 6, "Persisting web metadata")
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
            s.commit()

            upsert_artifact("ct_enrichment", ct_enrichment)
            upsert_artifact(
                "wildcard",
                {
                    "roots": sorted(roots_set),
                    "wildcard_roots": sorted([r for r, ok in wildcard_roots.items() if ok]),
                },
            )

            set_progress(5, 6, "Computing intel summary")
            dns_by_domain = {r.get("domain"): r for r in dns_records}
            web_by_domain = {w.get("domain"): w for w in web_records}
            unique_ips = sorted({ip for rec in dns_records for ip in rec.get("ips", [])})
            set_progress(5, 6, f"Looking up ASN for {len(unique_ips)} IPs")
            asn_by_ip = lookup_asn_for_ips(unique_ips)
            intel_rows = [
                _domain_intel(
                    d,
                    roots_set,
                    dns_by_domain.get(d, {}),
                    web_by_domain.get(d, {}),
                    asn_by_ip=asn_by_ip,
                    cname_targets=cname_resolves,
                    wildcard_roots=wildcard_roots,
                )
                for d in domains_sorted
            ]
            prev_intel_rows: list[dict[str, Any]] | None = None
            prev_scan = s.execute(
                select(ScanRun).where(
                    ScanRun.company_id == scan.company_id,
                    ScanRun.company_scan_number == scan.company_scan_number - 1,
                )
            ).scalar_one_or_none()
            if prev_scan:
                prev_art = s.execute(
                    select(ScanArtifact).where(
                        ScanArtifact.scan_id == prev_scan.id,
                        ScanArtifact.artifact_type == "dns_intel",
                    )
                ).scalar_one_or_none()
                if prev_art:
                    try:
                        prev_payload = json.loads(prev_art.json_text)
                        prev_intel_rows = prev_payload.get("domains") or []
                    except Exception:
                        prev_intel_rows = None
            upsert_artifact(
                "dns_intel",
                {
                    "domains": intel_rows,
                    "summary": _intel_summary(intel_rows),
                },
            )
            upsert_artifact(
                "change_summary",
                _change_summary(intel_rows, prev_intel_rows),
            )

            set_progress(6, 6, "Finalizing scan")
            scan.status = "success"
            scan.completed_at = _now_utc()
            scan.notes = "6/6 Scan complete"
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
def trigger_scan(
    slug: str, background_tasks: BackgroundTasks, payload: ScanRequest | None = None
) -> dict[str, Any]:
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

    deep_scan = bool(payload.deep_scan) if payload else False
    background_tasks.add_task(_execute_scan, scan.id, sorted(roots), deep_scan)
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
