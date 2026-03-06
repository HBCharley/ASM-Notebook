from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from asm_notebook.db import SessionLocal
from asm_notebook.models import Company, CompanyDomain, CompanyGroup, ScanArtifact, ScanRun
from asm_notebook.services import finding_service, group_service


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dumps(obj: object) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _mk_tls(days_valid: int = 90) -> dict:
    start = _now() - timedelta(days=1)
    end = _now() + timedelta(days=days_valid)
    return {"not_before": start.isoformat(), "not_after": end.isoformat(), "san": []}


def _intel_rows_v1() -> list[dict]:
    return [
        {
            "domain": "example.com",
            "root": "example.com",
            "is_apex": True,
            "resolves": True,
            "ip_count": 2,
            "has_ipv4": True,
            "has_ipv6": True,
            "takeover_risk": False,
            "takeover_targets": [],
            "has_cname": False,
            "web": {
                "reachable": True,
                "scheme": "https",
                "final_url": "https://example.com/",
                "status_code": 200,
                "title": "Example",
                "response_time_ms": 120,
                "technologies": ["nextjs"],
                "fingerprints": [],
                "security_headers": {
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff",
                    "referrer-policy": "no-referrer",
                    "permissions-policy": "geolocation=()",
                    "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
                },
                "hsts": {
                    "header": "max-age=31536000; includeSubDomains; preload",
                    "max_age": 31536000,
                    "include_subdomains": True,
                    "preload_directive": True,
                    "preload_eligible": True,
                },
                "tls": _mk_tls(90),
                "deep_scan": {"enabled": True},
            },
        },
        {
            "domain": "admin.example.com",
            "root": "example.com",
            "is_apex": False,
            "resolves": True,
            "ip_count": 1,
            "has_ipv4": True,
            "has_ipv6": False,
            "takeover_risk": False,
            "takeover_targets": [],
            "has_cname": False,
            "web": {
                "reachable": True,
                "scheme": "https",
                "final_url": "https://admin.example.com/login",
                "status_code": 200,
                "title": "Admin Console",
                "response_time_ms": 240,
                "technologies": ["react"],
                "fingerprints": [],
                "security_headers": {
                    "x-content-type-options": "nosniff",
                },
                "hsts": {},
                "tls": _mk_tls(10),
                "deep_scan": {
                    "enabled": True,
                    "favicon": {
                        "present": True,
                        "hash_fingerprint": "Jenkins",
                        "hash_mmh3": -1231873279,
                        "final_url": "https://admin.example.com/favicon.ico",
                    },
                    "robots": {
                        "present": False,
                        "status_code": 404,
                        "final_url": "https://admin.example.com/robots.txt",
                    },
                    "sitemap": {
                        "present": False,
                        "status_code": 404,
                        "final_url": "https://admin.example.com/sitemap.xml",
                    },
                },
            },
        },
        {
            "domain": "old.example.com",
            "root": "example.com",
            "is_apex": False,
            "resolves": False,
            "ip_count": 0,
            "has_ipv4": False,
            "has_ipv6": False,
            "takeover_risk": False,
            "takeover_targets": [],
            "has_cname": True,
            "web": {"reachable": False, "error": "request_failed"},
        },
        {
            "domain": "takeover.example.com",
            "root": "example.com",
            "is_apex": False,
            "resolves": False,
            "ip_count": 0,
            "has_ipv4": False,
            "has_ipv6": False,
            "takeover_risk": True,
            "takeover_targets": ["foo.herokudns.com"],
            "has_cname": True,
            "web": {"reachable": False, "error": "request_failed"},
        },
        {
            "domain": "redirect.example.com",
            "root": "example.com",
            "is_apex": False,
            "resolves": True,
            "ip_count": 1,
            "has_ipv4": True,
            "has_ipv6": False,
            "takeover_risk": False,
            "takeover_targets": [],
            "has_cname": False,
            "web": {
                "reachable": True,
                "scheme": "https",
                "final_url": "https://www.example.com/",
                "status_code": 301,
                "title": "",
                "response_time_ms": 180,
                "technologies": ["cloudflare"],
                "fingerprints": ["cloudflare"],
                "security_headers": {},
                "hsts": {},
                "tls": _mk_tls(120),
                "deep_scan": {"enabled": False},
            },
        },
        {
            "domain": "gone.example.com",
            "root": "example.com",
            "is_apex": False,
            "resolves": True,
            "ip_count": 1,
            "has_ipv4": True,
            "has_ipv6": False,
            "takeover_risk": False,
            "takeover_targets": [],
            "has_cname": False,
            "web": {
                "reachable": True,
                "scheme": "https",
                "final_url": "https://gone.example.com/",
                "status_code": 200,
                "title": "Deprecated host",
                "response_time_ms": 210,
                "technologies": ["nginx"],
                "fingerprints": [],
                "security_headers": {},
                "hsts": {},
                "tls": _mk_tls(45),
                "deep_scan": {"enabled": False},
            },
        },
    ]


def _intel_rows_v2() -> list[dict]:
    rows = [r.copy() for r in _intel_rows_v1() if r["domain"] != "gone.example.com"]
    # Introduce change examples.
    for r in rows:
        if r["domain"] == "redirect.example.com":
            r = r.copy()
            web = (r.get("web") or {}).copy()
            web["final_url"] = "https://redirect.example.com/app"
            web["status_code"] = 200
            web["title"] = "Redirect landing"
            web["technologies"] = ["nextjs"]
            r["web"] = web
        if r["domain"] == "old.example.com":
            r["resolves"] = True
            r["ip_count"] = 1
            r["has_ipv4"] = True
            r["web"] = {
                "reachable": False,
                "error": "connection_refused",
            }
        yield r


def main() -> None:
    slug = os.getenv("ASM_SOC_DEMO_SLUG", "soc-demo").strip() or "soc-demo"
    root = os.getenv("ASM_SOC_DEMO_ROOT", "example.com").strip().lower().strip(".") or "example.com"

    print(f"Seeding SOC demo data into company slug={slug!r} root={root!r}")
    group_service.ensure_default_groups()

    with SessionLocal() as s:
        existing = s.execute(select(Company).where(Company.slug == slug)).scalars().first()
        if existing:
            s.delete(existing)
            s.commit()

        company = Company(slug=slug, name="SOC Demo")
        s.add(company)
        s.flush()
        s.add(CompanyDomain(company_id=company.id, domain=root))
        unauth_id = group_service.resolve_group_id(group_service.UNAUTH_GROUP)
        default_id = group_service.resolve_group_id(group_service.DEFAULT_GROUP)
        s.add_all(
            [
                CompanyGroup(company_id=company.id, group_id=unauth_id),
                CompanyGroup(company_id=company.id, group_id=default_id),
            ]
        )
        s.commit()
        s.refresh(company)

        scan1 = ScanRun(
            company_id=company.id,
            company_scan_number=1,
            status="success",
            started_at=_now() - timedelta(minutes=15),
            completed_at=_now() - timedelta(minutes=14),
            notes="Seed scan #1",
        )
        scan2 = ScanRun(
            company_id=company.id,
            company_scan_number=2,
            status="success",
            started_at=_now() - timedelta(minutes=4),
            completed_at=_now() - timedelta(minutes=3),
            notes="Seed scan #2",
        )
        s.add_all([scan1, scan2])
        s.commit()
        s.refresh(scan1)
        s.refresh(scan2)

        intel1 = _intel_rows_v1()
        intel2 = list(_intel_rows_v2())

        dns1 = {
            "records": [
                {"domain": "example.com", "ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]},
                {"domain": "admin.example.com", "ips": ["1.2.3.4"]},
                {"domain": "redirect.example.com", "ips": ["5.6.7.8"]},
                {"domain": "gone.example.com", "ips": ["9.9.9.9"]},
            ]
        }
        dns2 = {
            "records": [
                {"domain": "example.com", "ips": ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]},
                {"domain": "admin.example.com", "ips": ["1.2.3.4"]},
                {"domain": "redirect.example.com", "ips": ["5.6.7.8"]},
                {"domain": "old.example.com", "ips": ["8.8.8.8"]},
            ]
        }

        s.add_all(
            [
                ScanArtifact(
                    scan_id=scan1.id,
                    artifact_type="scan_meta",
                    json_text=_dumps({"mode": "deep", "deep_scan": True}),
                ),
                ScanArtifact(
                    scan_id=scan1.id,
                    artifact_type="dns_intel",
                    json_text=_dumps({"domains": intel1, "summary": {}}),
                ),
                ScanArtifact(
                    scan_id=scan1.id, artifact_type="dns", json_text=_dumps(dns1)
                ),
                ScanArtifact(
                    scan_id=scan2.id,
                    artifact_type="scan_meta",
                    json_text=_dumps({"mode": "deep", "deep_scan": True}),
                ),
                ScanArtifact(
                    scan_id=scan2.id,
                    artifact_type="dns_intel",
                    json_text=_dumps({"domains": intel2, "summary": {}}),
                ),
                ScanArtifact(
                    scan_id=scan2.id, artifact_type="dns", json_text=_dumps(dns2)
                ),
            ]
        )
        s.commit()

        finding_service.persist_findings_for_scan(
            s,
            company_id=company.id,
            scan_id=scan1.id,
            intel_rows=intel1,
            prev_intel_rows=[],
        )
        finding_service.persist_findings_for_scan(
            s,
            company_id=company.id,
            scan_id=scan2.id,
            intel_rows=intel2,
            prev_intel_rows=intel1,
        )
        s.commit()

    print("Done.")
    print(f"- Company: {slug}")
    print("- Scans: #1 and #2 (seeded)")
    print("- Findings: populated across info/watch/investigate/critical")


if __name__ == "__main__":
    main()
