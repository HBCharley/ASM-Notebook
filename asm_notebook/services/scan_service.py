from __future__ import annotations

import asyncio
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

import httpx
from fastapi import BackgroundTasks, HTTPException
from sqlalchemy import func, select

from ..db import SessionLocal
from ..models import Company, ScanArtifact, ScanRun
from ..plugins.ct import ct_subdomains
from ..plugins.dns import resolve_dns, resolve_ips
from ..plugins.http_meta import fetch_http_metadata
from ..plugins.ip_intel import lookup_asn_for_ips
from .company_service import normalize_domain
from .cve_service import find_cves


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _in_scope(domain: str, roots: set[str]) -> bool:
    d = normalize_domain(domain)
    for root in roots:
        rr = normalize_domain(root)
        if d == rr or d.endswith("." + rr):
            return True
    return False


def _is_test_mode() -> bool:
    return os.getenv("ASM_TEST_MODE", "").strip() == "1"


def _company_by_slug(session: SessionLocal, slug: str) -> Company | None:
    return session.execute(
        select(Company).where(Company.slug == slug)
    ).scalar_one_or_none()


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


def _rdap_entity_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    for entry in vcard[1]:
        if not isinstance(entry, list) or not entry:
            continue
        if entry[0] in {"fn", "org", "name"}:
            if len(entry) > 3 and entry[3]:
                return str(entry[3])
            if len(entry) > 1 and entry[1]:
                return str(entry[1])
    return None


def _fetch_domain_whois(roots: list[str]) -> list[dict[str, Any]]:
    if _is_test_mode():
        return []
    results: list[dict[str, Any]] = []
    with httpx.Client(timeout=10, follow_redirects=True) as client:
        for root in roots:
            try:
                ascii_root = root.encode("idna").decode("ascii")
            except Exception:
                ascii_root = root
            try:
                resp = client.get(f"https://rdap.org/domain/{ascii_root}")
                if resp.status_code != 200:
                    results.append(
                        {
                            "domain": root,
                            "error": f"RDAP {resp.status_code}",
                        }
                    )
                    continue
                data = resp.json()
            except Exception as exc:
                results.append({"domain": root, "error": str(exc)})
                continue

            registrar = None
            for ent in data.get("entities") or []:
                roles = ent.get("roles") or []
                if "registrar" in roles:
                    registrar = _rdap_entity_name(ent) or ent.get("handle")
                    break
            events = []
            for ev in data.get("events") or []:
                action = ev.get("eventAction")
                date = ev.get("eventDate")
                if action or date:
                    events.append({"action": action, "date": date})
            results.append(
                {
                    "domain": root,
                    "registrar": registrar,
                    "status": data.get("status") or [],
                    "nameservers": [
                        ns.get("ldhName")
                        for ns in (data.get("nameservers") or [])
                        if ns.get("ldhName")
                    ],
                    "events": events,
                }
            )
    return results


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
        score += 1
    else:
        factors.append("mta_sts_missing")
    if has_bimi:
        score += 1
    else:
        factors.append("bimi_missing")
    if dkim_count:
        score += 1
    else:
        factors.append("dkim_missing")
    return score, factors


def _takeover_targets(cname_list: list[str]) -> list[str]:
    targets = []
    for cname in cname_list:
        for provider in (
            "amazonaws.com",
            "cloudfront.net",
            "azureedge.net",
            "trafficmanager.net",
            "herokudns.com",
            "github.io",
            "bitbucket.io",
            "fastly.net",
            "wpengine.com",
        ):
            if provider in cname:
                targets.append(provider)
    return sorted(set(targets))


def _surface_class(domain: str) -> str:
    parts = domain.split(".")
    if len(parts) <= 2:
        return "root"
    if len(parts) == 3:
        return "subdomain"
    if len(parts) >= 4:
        return "deep-subdomain"
    return "unknown"


def _service_hints_from_ptr(ptr: dict[str, list[str]]) -> list[str]:
    hints = []
    for values in (ptr or {}).values():
        for item in values or []:
            if "amazonaws.com" in item:
                hints.append("aws")
            elif "cloudapp.azure.com" in item:
                hints.append("azure")
            elif "compute.amazonaws.com" in item:
                hints.append("aws")
            elif "googleusercontent.com" in item:
                hints.append("gcp")
    return sorted(set(hints))


def _compute_exposure_score(row: dict[str, Any]) -> tuple[int, list[str]]:
    score = 0
    factors: list[str] = []
    if row.get("takeover_risk"):
        score += 4
        factors.append("takeover_risk")
    if row.get("dangling_cname"):
        score += 2
        factors.append("dangling_cname")
    if row.get("has_caa"):
        score -= 1
        factors.append("caa_present")
    if row.get("has_spf") and row.get("has_dmarc"):
        score -= 1
        factors.append("email_controls")
    if row.get("web", {}).get("reachable"):
        score += 1
        factors.append("http_exposed")
    if row.get("web", {}).get("tls"):
        score -= 1
        factors.append("tls_present")
    return score, factors


def _cve_findings(reported_versions: list[dict[str, str]]) -> list[dict[str, Any]]:
    return find_cves(reported_versions or [])


def _flatten_cert_entity(entity: Any) -> str:
    if not entity:
        return ""
    if isinstance(entity, str):
        return entity
    out = []
    for item in entity:
        for key, value in item:
            out.append(f"{key}={value}")
    return ", ".join(out)


def _detect_edge_provider(
    rec: dict[str, Any],
    web: dict[str, Any] | None,
    ip_asn: list[dict[str, Any]],
) -> dict[str, Any]:
    provider = ""
    confidence = "none"
    signals = []
    asn_provider = ""
    asn_signals: list[str] = []
    web = web or {}
    headers = web.get("headers") or {}
    cloudflare_headers = ["cf-ray", "cf-cache-status", "server"]
    if any(k in headers for k in cloudflare_headers):
        provider = "cloudflare"
        confidence = "high"
        signals.append("header:cloudflare")
    if web.get("hsts", {}).get("include_subdomains"):
        signals.append("hsts:include_subdomains")
    for row in ip_asn:
        name = str(row.get("name", "")).lower()
        if "cloudflare" in name:
            asn_provider = "cloudflare"
            asn_signals.append("asn:cloudflare")
        if "amazon" in name:
            asn_provider = "aws"
            asn_signals.append("asn:aws")
        if "google" in name:
            asn_provider = "gcp"
            asn_signals.append("asn:gcp")
        if "microsoft" in name:
            asn_provider = "azure"
            asn_signals.append("asn:azure")
    if asn_provider and not provider:
        provider = asn_provider
        confidence = "medium"
    return {
        "provider": provider,
        "confidence": confidence,
        "signals": signals,
        "asn_provider": asn_provider,
        "asn_signals": asn_signals,
    }


def _edge_and_server(
    domain: str, rec: dict[str, Any], web: dict[str, Any] | None
) -> dict[str, Any]:
    web = web or {}
    headers = web.get("headers") or {}
    server = headers.get("server", "")
    server_version = ""
    if server and "/" in server:
        server_version = server.split("/")[1].split(" ")[0]
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
    for key in (
        "via",
        "x-cache",
        "x-served-by",
        "cf-ray",
        "x-amz-cf-id",
        "x-amz-cf-pop",
    ):
        if headers.get(key):
            signals.append(f"header:{key}")
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
    d = normalize_domain(domain)
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
        for provider in row.get("provider_hints", []):
            providers[provider] += 1
        if row.get("dmarc_policy"):
            dmarc_policy[row["dmarc_policy"]] += 1
        if row.get("surface_class"):
            surfaces[row["surface_class"]] += 1
        for provider in row.get("mail_providers", []):
            mail_providers[provider] += 1
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
        "dkim_domains": sum(
            1 for r in intel_rows if (r.get("dkim_txt_records") or 0) > 0
        ),
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
        "exposure_score_avg": (
            round(sum(exposure_scores) / len(exposure_scores), 2)
            if exposure_scores
            else 0
        ),
    }


def _change_summary(
    intel_rows: list[dict[str, Any]], prev_intel_rows: list[dict[str, Any]] | None
) -> dict[str, Any]:
    if not prev_intel_rows:
        return {"has_previous": False}
    prev_by_domain = {row.get("domain"): row for row in prev_intel_rows}
    curr_by_domain = {row.get("domain"): row for row in intel_rows}
    new_domains = [d for d in curr_by_domain if d not in prev_by_domain]
    removed_domains = [d for d in prev_by_domain if d not in curr_by_domain]

    provider_changes = []
    technology_changes = []
    for domain, row in curr_by_domain.items():
        prev = prev_by_domain.get(domain)
        if not prev:
            continue
        curr_provider = row.get("provider_hints", [])
        prev_provider = prev.get("provider_hints", [])
        if curr_provider != prev_provider:
            provider_changes.append(domain)
        curr_tech = [t.get("name") for t in row.get("web", {}).get("technologies", [])]
        prev_tech = [t.get("name") for t in prev.get("web", {}).get("technologies", [])]
        if curr_tech != prev_tech:
            technology_changes.append(domain)

    return {
        "has_previous": True,
        "new_domains": sorted(new_domains),
        "removed_domains": sorted(removed_domains),
        "provider_changes": sorted(provider_changes),
        "technology_changes": sorted(technology_changes),
    }


async def _collect_scan_data(
    roots: set[str],
    progress_cb: Callable[[int, int, str], None] | None = None,
    deep_scan: bool = False,
) -> tuple[
    list[str],
    list[str],
    list[dict[str, Any]],
    list[dict[str, Any]],
    dict[str, bool],
    dict[str, Any],
    dict[str, bool],
]:
    progress_cb = progress_cb or (lambda *args, **kwargs: None)
    progress_cb(2, 6, "Collecting in-scope domains from CT")
    domains: set[str] = set()
    ct_results = await asyncio.gather(*[ct_subdomains(root) for root in roots])
    for result in ct_results:
        domains.update(result)
    domains_sorted = sorted({normalize_domain(d) for d in domains})
    progress_cb(2, 6, f"Resolving DNS for {len(domains_sorted)} domains")
    resolvable_domains = []
    dns_records: list[dict[str, Any]] = []
    cname_resolves: dict[str, bool] = {}
    for domain in domains_sorted:
        rec = resolve_dns(domain)
        dns_records.append(rec)
        if rec.get("ips"):
            resolvable_domains.append(domain)
        for cname in rec.get("CNAME") or []:
            cname_resolves[str(cname).lower()] = True

    progress_cb(2, 6, f"Collecting HTTP metadata for {len(resolvable_domains)} domains")
    web_records = []
    for domain in resolvable_domains:
        web_records.append(await fetch_http_metadata(domain, deep_scan=deep_scan))

    progress_cb(2, 6, "Resolving root wildcards")
    wildcard_roots: dict[str, bool] = {}
    for root in roots:
        wildcard = f"*.{root}"
        wildcard_roots[root] = bool(resolve_ips(wildcard))

    ct_enrichment = {
        "roots": sorted(roots),
        "ct_hostnames": len(domains_sorted),
        "suspicious_hostnames": [],
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
    domains_sorted = sorted({normalize_domain(d) for d in roots})
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
    return (
        domains_sorted,
        resolvable_domains,
        dns_records,
        [],
        {},
        {"roots": [], "ct_hostnames": 0, "suspicious_hostnames": []},
        {},
    )


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
            ) = _collect_scan_data_test_mode(roots_set)
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
                _collect_scan_data(
                    roots_set, progress_cb=set_progress, deep_scan=deep_scan
                )
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
                    s.add(
                        ScanArtifact(
                            scan_id=scan_id, artifact_type=atype, json_text=txt
                        )
                    )

            unique_ips = sorted(
                {ip for rec in dns_records for ip in rec.get("ips", [])}
            )
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
                        "unresolved_domains": len(resolvable_domains)
                        - resolved_domains,
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
                    "wildcard_roots": sorted(
                        [r for r, ok in wildcard_roots.items() if ok]
                    ),
                },
            )
            upsert_artifact(
                "whois",
                {
                    "roots": _fetch_domain_whois(sorted(roots_set)),
                },
            )

            set_progress(5, 6, "Computing intel summary")
            dns_by_domain = {r.get("domain"): r for r in dns_records}
            web_by_domain = {w.get("domain"): w for w in web_records}
            unique_ips = sorted(
                {ip for rec in dns_records for ip in rec.get("ips", [])}
            )
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


def trigger_scan(
    slug: str, background_tasks: BackgroundTasks, deep_scan: bool = False
) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        roots = {normalize_domain(d.domain) for d in company.domains}
        if not roots:
            raise HTTPException(status_code=400, detail="Company has no domains")

        last_num = s.execute(
            select(func.max(ScanRun.company_scan_number)).where(
                ScanRun.company_id == company.id
            )
        ).scalar_one()
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

    background_tasks.add_task(_execute_scan, scan.id, sorted(roots), deep_scan)
    return {
        "company_slug": slug,
        "scan_id": scan.id,
        "company_scan_number": scan.company_scan_number,
        "status": "running",
    }


def list_scans(slug: str) -> list[dict[str, Any]]:
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


def get_latest_scan(slug: str) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = (
            s.execute(
                select(ScanRun)
                .where(ScanRun.company_id == company.id)
                .order_by(ScanRun.id.desc())
                .limit(1)
            )
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


def get_company_scan(slug: str, scan_id: int) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = s.execute(
            select(ScanRun).where(
                ScanRun.id == scan_id, ScanRun.company_id == company.id
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


def get_company_scan_artifacts(slug: str, scan_id: int) -> dict[str, Any]:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = s.execute(
            select(ScanRun).where(
                ScanRun.id == scan_id, ScanRun.company_id == company.id
            )
        ).scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        artifacts = (
            s.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id))
            .scalars()
            .all()
        )
        out: dict[str, Any] = {}
        for a in artifacts:
            try:
                out[a.artifact_type] = json.loads(a.json_text)
            except Exception:
                out[a.artifact_type] = {"_error": "invalid_json", "raw": a.json_text}
        return out


def delete_company_scan(slug: str, scan_id: int) -> None:
    with SessionLocal() as s:
        company = _company_by_slug(s, slug)
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")

        scan = s.execute(
            select(ScanRun).where(
                ScanRun.id == scan_id, ScanRun.company_id == company.id
            )
        ).scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found for company")

        s.delete(scan)
        s.commit()
