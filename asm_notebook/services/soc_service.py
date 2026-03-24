from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Company, Finding, ScanArtifact, ScanRun

SEVERITY_ORDER = {"critical": 0, "investigate": 1, "watch": 2, "info": 3}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_json(text: str) -> Any:
    try:
        return json.loads(text or "{}")
    except Exception:
        return {}


def _scan_meta(scan: ScanRun) -> dict[str, Any]:
    return {
        "id": scan.id,
        "company_scan_number": scan.company_scan_number,
        "status": scan.status,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "heartbeat_at": scan.heartbeat_at.isoformat() if scan.heartbeat_at else None,
        "notes": scan.notes,
    }


def _load_scan(session: Session, company: Company, scan_id: int | None) -> ScanRun:
    if scan_id is None:
        scan = (
            session.execute(
                select(ScanRun)
                .where(ScanRun.company_id == company.id)
                .order_by(ScanRun.company_scan_number.desc())
            )
            .scalars()
            .first()
        )
        if not scan:
            raise HTTPException(status_code=404, detail="No scans found for company")
        return scan
    scan = session.get(ScanRun, scan_id)
    if not scan or scan.company_id != company.id:
        raise HTTPException(status_code=404, detail="Scan not found for company")
    return scan


def _load_artifact(session: Session, scan_id: int, artifact_type: str) -> dict[str, Any] | None:
    art = (
        session.execute(
            select(ScanArtifact).where(
                ScanArtifact.scan_id == scan_id,
                ScanArtifact.artifact_type == artifact_type,
            )
        )
        .scalars()
        .first()
    )
    if not art:
        return None
    payload = _parse_json(art.json_text)
    return payload if isinstance(payload, dict) else {"value": payload}


def _domain_key(domain: str) -> str:
    return domain.strip().lower().strip(".")


def _asset_type(row: dict[str, Any]) -> str:
    if row.get("is_apex"):
        return "apex"
    if row.get("root"):
        return "subdomain"
    return "other"


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return bool(value)


def _host_web_reachable(row: dict[str, Any]) -> bool:
    web = row.get("web") or {}
    return _boolish(web.get("reachable")) or int(web.get("status_code") or 0) > 0


def _tls_present(row: dict[str, Any]) -> bool:
    web = row.get("web") or {}
    tls = web.get("tls") or {}
    return bool(tls)


def _hsts_present(row: dict[str, Any]) -> bool:
    web = row.get("web") or {}
    hsts = web.get("hsts") or {}
    if not isinstance(hsts, dict) or not hsts:
        return False
    return bool(hsts.get("max_age") or hsts.get("header"))


def _provider_hint(row: dict[str, Any]) -> str:
    web = row.get("web") or {}
    tech = web.get("technologies") or []
    fps = web.get("fingerprints") or []
    hints = []
    if isinstance(tech, list):
        for t in tech:
            if isinstance(t, str):
                v = t.strip()
            elif isinstance(t, dict):
                name = str(
                    t.get("name") or t.get("technology") or t.get("key") or ""
                ).strip()
                ver = str(t.get("version") or "").strip()
                v = f"{name}:{ver}" if name and ver else name
            else:
                v = str(t).strip()
            if v:
                hints.append(v)
    if isinstance(fps, list):
        hints.extend([str(f) for f in fps if str(f)])
    hints = [h for h in hints if h]
    return hints[0] if hints else ""


def _normalize_technology_set(value: Any) -> set[str]:
    if not value:
        return set()
    items: list[Any]
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    out: set[str] = set()
    for item in items:
        if item is None:
            continue
        if isinstance(item, str):
            s = item.strip().lower()
            if s:
                out.add(s)
            continue
        if isinstance(item, dict):
            name = str(item.get("name") or item.get("technology") or item.get("key") or "").strip()
            ver = str(item.get("version") or "").strip()
            if name and ver:
                out.add(f"{name}:{ver}".lower())
            elif name:
                out.add(name.lower())
            else:
                try:
                    out.add(json.dumps(item, sort_keys=True, separators=(",", ":")).lower())
                except Exception:
                    out.add(str(item).lower())
            continue
        out.add(str(item).strip().lower())
    return {s for s in out if s}


def _edge_family(row: dict[str, Any]) -> str:
    web = row.get("web") or {}
    edge_provider = web.get("edge_provider") or {}
    if isinstance(edge_provider, dict):
        provider = str(edge_provider.get("cdn_or_proxy_provider") or "").strip()
        if provider:
            return provider
        provider2 = str(edge_provider.get("provider") or "").strip()
        if provider2 and provider2 != "none":
            return provider2
    provider = str(web.get("cdn_or_proxy_provider") or "").strip()
    if provider and provider != "none":
        return provider
    return ""


def _compute_change(
    *,
    domain: str,
    curr: dict[str, Any],
    prev: dict[str, Any] | None,
    curr_dns: dict[str, Any] | None,
    prev_dns: dict[str, Any] | None,
) -> dict[str, Any]:
    if not prev:
        return {"state": "new", "flags": ["new_asset"], "previous": None}

    flags: list[str] = []
    if bool(curr.get("resolves")) != bool(prev.get("resolves")):
        flags.append("dns_resolves_changed")

    curr_web = curr.get("web") or {}
    prev_web = prev.get("web") or {}
    if _boolish(curr_web.get("reachable")) != _boolish(prev_web.get("reachable")):
        flags.append("web_reachability_changed")

    if str(curr_web.get("final_url") or "") != str(prev_web.get("final_url") or ""):
        if str(prev_web.get("final_url") or ""):
            flags.append("final_url_changed")

    if str(curr_web.get("title") or "") != str(prev_web.get("title") or ""):
        if str(prev_web.get("title") or ""):
            flags.append("title_changed")

    if _normalize_technology_set(curr_web.get("technologies")) != _normalize_technology_set(
        prev_web.get("technologies")
    ):
        if prev_web.get("technologies"):
            flags.append("technology_changed")

    curr_edge = _edge_family(curr)
    prev_edge = _edge_family(prev)
    if curr_edge != prev_edge and prev_edge:
        flags.append("edge_provider_changed")

    curr_tls = (curr_web.get("tls") or {}) if isinstance(curr_web.get("tls"), dict) else {}
    prev_tls = (prev_web.get("tls") or {}) if isinstance(prev_web.get("tls"), dict) else {}
    if curr_tls and prev_tls and str(curr_tls.get("not_after") or "") != str(prev_tls.get("not_after") or ""):
        flags.append("certificate_changed")

    curr_sec = (curr_web.get("security_headers") or {}) if isinstance(curr_web.get("security_headers"), dict) else {}
    prev_sec = (prev_web.get("security_headers") or {}) if isinstance(prev_web.get("security_headers"), dict) else {}
    if curr_sec != prev_sec and prev_sec:
        flags.append("security_headers_changed")

    if _hsts_present(curr) != _hsts_present(prev):
        if _hsts_present(prev):
            flags.append("hsts_changed")

    if curr_dns is not None and prev_dns is not None:
        curr_ips = sorted({*list(curr_dns.get("ips") or [])})
        prev_ips = sorted({*list(prev_dns.get("ips") or [])})
        if curr_ips != prev_ips and prev_ips:
            flags.append("ip_set_changed")

        curr_cname = sorted([str(v) for v in (curr_dns.get("CNAME") or [])])
        prev_cname = sorted([str(v) for v in (prev_dns.get("CNAME") or [])])
        if curr_cname != prev_cname and prev_cname:
            flags.append("cname_changed")

    state = "changed" if flags else "unchanged"
    return {
        "state": state,
        "flags": flags,
        "previous": {
            "resolves": bool(prev.get("resolves")),
            "web_reachable": _host_web_reachable(prev),
            "final_url": (prev.get("web") or {}).get("final_url", ""),
            "status_code": (prev.get("web") or {}).get("status_code"),
            "title": (prev.get("web") or {}).get("title", ""),
            "edge_family": _edge_family(prev),
        },
    }


def get_soc_overview(
    session: Session, *, company: Company, scan_id: int | None = None
) -> dict[str, Any]:
    scan = _load_scan(session, company, scan_id)
    dns_intel = _load_artifact(session, scan.id, "dns_intel") or {}
    intel_rows = dns_intel.get("domains") or []
    if not isinstance(intel_rows, list):
        intel_rows = []

    dns_art = _load_artifact(session, scan.id, "dns") or {}
    dns_records = dns_art.get("records") or []
    dns_by_domain = { _domain_key(str(r.get("domain") or "")): r for r in dns_records if isinstance(r, dict) }

    prev_scan = (
        session.execute(
            select(ScanRun).where(
                ScanRun.company_id == company.id,
                ScanRun.company_scan_number == scan.company_scan_number - 1,
            )
        )
        .scalars()
        .first()
    )
    prev_rows: list[dict[str, Any]] | None = None
    prev_dns_by_domain: dict[str, Any] | None = None
    if prev_scan:
        prev_intel = _load_artifact(session, prev_scan.id, "dns_intel") or {}
        prev_rows = prev_intel.get("domains") or []
        if not isinstance(prev_rows, list):
            prev_rows = []
        prev_dns_art = _load_artifact(session, prev_scan.id, "dns") or {}
        prev_dns_records = prev_dns_art.get("records") or []
        prev_dns_by_domain = {
            _domain_key(str(r.get("domain") or "")): r
            for r in prev_dns_records
            if isinstance(r, dict)
        }

    findings = (
        session.execute(
            select(Finding).where(
                Finding.company_id == company.id,
                Finding.scan_id == scan.id,
            )
        )
        .scalars()
        .all()
    )
    prev_findings: list[Finding] = []
    if prev_scan:
        prev_findings = (
            session.execute(
                select(Finding).where(
                    Finding.company_id == company.id,
                    Finding.scan_id == prev_scan.id,
                )
            )
            .scalars()
            .all()
        )
    finding_counts_by_asset: dict[str, dict[str, int]] = {}
    for f in findings:
        asset = _domain_key(f.asset_hostname)
        counts = finding_counts_by_asset.setdefault(
            asset, {"info": 0, "watch": 0, "investigate": 0, "critical": 0}
        )
        if f.severity in counts:
            counts[f.severity] += 1

    prev_by_domain = {
        _domain_key(str(r.get("domain") or "")): r
        for r in (prev_rows or [])
        if isinstance(r, dict)
    }
    curr_domains = set()
    assets: list[dict[str, Any]] = []
    for row in intel_rows:
        if not isinstance(row, dict):
            continue
        domain = _domain_key(str(row.get("domain") or ""))
        if not domain:
            continue
        curr_domains.add(domain)
        prev_row = prev_by_domain.get(domain)
        change = _compute_change(
            domain=domain,
            curr=row,
            prev=prev_row,
            curr_dns=dns_by_domain.get(domain),
            prev_dns=(prev_dns_by_domain or {}).get(domain) if prev_dns_by_domain else None,
        )
        web = row.get("web") or {}
        assets.append(
            {
                "hostname": domain,
                "root_domain": row.get("root") or "",
                "asset_type": _asset_type(row),
                "resolves": bool(row.get("resolves")),
                "web_reachable": _host_web_reachable(row),
                "final_url": web.get("final_url") or "",
                "status_code": web.get("status_code"),
                "title": web.get("title") or "",
                "provider_hint": _provider_hint(row),
                "edge_family": _edge_family(row),
                "ip_count": int(row.get("ip_count") or 0),
                "ipv6_present": bool(row.get("has_ipv6")),
                "tls_present": _tls_present(row),
                "hsts_present": _hsts_present(row),
                "finding_counts": finding_counts_by_asset.get(
                    domain, {"info": 0, "watch": 0, "investigate": 0, "critical": 0}
                ),
                "last_seen": (scan.completed_at or scan.started_at or _now_utc()).isoformat(),
                "change": change,
            }
        )

    removed_assets: list[dict[str, Any]] = []
    if prev_rows is not None:
        prev_domains = set(prev_by_domain.keys())
        removed = sorted(prev_domains - curr_domains)
        for d in removed:
            removed_assets.append(
                {
                    "hostname": d,
                    "last_seen": (
                        (prev_scan.completed_at or prev_scan.started_at or _now_utc()).isoformat()
                        if prev_scan
                        else None
                    ),
                }
            )

    findings_payload = [
        {
            "id": str(f.id),
            "asset_hostname": _domain_key(f.asset_hostname),
            "scan_id": f.scan_id,
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "explanation": f.explanation,
            "remediation": f.remediation,
            "rule_key": f.rule_key,
            "status": f.status,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "updated_at": f.updated_at.isoformat() if f.updated_at else None,
        }
        for f in findings
    ]
    findings_payload.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 99),
            f["asset_hostname"],
            f["rule_key"],
        )
    )

    summary = {
        "assets_discovered": len(assets),
        "live_web_assets": sum(1 for a in assets if a["web_reachable"]),
        "unresolved_assets": sum(1 for a in assets if not a["resolves"]),
        "missing_hsts_assets": sum(
            1 for a in assets if a["tls_present"] and not a["hsts_present"]
        ),
        "assets_changed": sum(
            1 for a in assets if (a.get("change") or {}).get("state") in {"new", "changed"}
        )
        if prev_rows is not None
        else 0,
        "removed_assets": len(removed_assets),
        "assets_with_critical_findings": len(
            {f.asset_hostname for f in findings if f.severity == "critical"}
        ),
        "assets_with_investigate_findings": len(
            {f.asset_hostname for f in findings if f.severity == "investigate"}
        ),
        "findings_by_severity": {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "investigate": sum(1 for f in findings if f.severity == "investigate"),
            "watch": sum(1 for f in findings if f.severity == "watch"),
            "info": sum(1 for f in findings if f.severity == "info"),
        },
    }
    if prev_scan:
        curr_keys = {(f.asset_hostname, f.rule_key) for f in findings}
        prev_keys = {(f.asset_hostname, f.rule_key) for f in prev_findings}
        new_keys = curr_keys - prev_keys
        cleared_keys = prev_keys - curr_keys
        summary["finding_deltas"] = {
            "new": len(new_keys),
            "cleared": len(cleared_keys),
        }
    else:
        summary["finding_deltas"] = {"new": 0, "cleared": 0}

    return {
        "company": {"slug": company.slug, "name": company.name},
        "scan": _scan_meta(scan),
        "previous_scan": _scan_meta(prev_scan) if prev_scan else None,
        "summary": summary,
        "assets": assets,
        "findings": findings_payload,
        "removed_assets": removed_assets,
    }


def get_soc_asset_detail(
    session: Session,
    *,
    company: Company,
    scan_id: int | None,
    hostname: str,
) -> dict[str, Any]:
    scan = _load_scan(session, company, scan_id)
    domain = _domain_key(hostname)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid hostname")

    dns_intel = _load_artifact(session, scan.id, "dns_intel") or {}
    intel_rows = dns_intel.get("domains") or []
    intel_by_domain = {
        _domain_key(str(r.get("domain") or "")): r
        for r in intel_rows
        if isinstance(r, dict)
    }
    row = intel_by_domain.get(domain)
    if not row:
        raise HTTPException(status_code=404, detail="Asset not found in scan")

    dns_art = _load_artifact(session, scan.id, "dns") or {}
    dns_records = dns_art.get("records") or []
    dns_by_domain = {
        _domain_key(str(r.get("domain") or "")): r
        for r in dns_records
        if isinstance(r, dict)
    }

    prev_scan = (
        session.execute(
            select(ScanRun).where(
                ScanRun.company_id == company.id,
                ScanRun.company_scan_number == scan.company_scan_number - 1,
            )
        )
        .scalars()
        .first()
    )
    prev_row = None
    prev_dns = None
    if prev_scan:
        prev_intel = _load_artifact(session, prev_scan.id, "dns_intel") or {}
        prev_rows = prev_intel.get("domains") or []
        prev_by_domain = {
            _domain_key(str(r.get("domain") or "")): r
            for r in prev_rows
            if isinstance(r, dict)
        }
        prev_row = prev_by_domain.get(domain)

        prev_dns_art = _load_artifact(session, prev_scan.id, "dns") or {}
        prev_dns_records = prev_dns_art.get("records") or []
        prev_dns_by_domain = {
            _domain_key(str(r.get("domain") or "")): r
            for r in prev_dns_records
            if isinstance(r, dict)
        }
        prev_dns = prev_dns_by_domain.get(domain)

    findings = (
        session.execute(
            select(Finding).where(
                Finding.company_id == company.id,
                Finding.scan_id == scan.id,
                Finding.asset_hostname == domain,
            )
        )
        .scalars()
        .all()
    )
    findings_payload = []
    for f in findings:
        findings_payload.append(
            {
                "id": str(f.id),
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "explanation": f.explanation,
                "remediation": f.remediation,
                "rule_key": f.rule_key,
                "status": f.status,
                "evidence": _parse_json(f.evidence_json),
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "updated_at": f.updated_at.isoformat() if f.updated_at else None,
            }
        )
    findings_payload.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(f["severity"], 99),
            f["category"],
            f["rule_key"],
        )
    )

    change = _compute_change(
        domain=domain,
        curr=row,
        prev=prev_row,
        curr_dns=dns_by_domain.get(domain),
        prev_dns=prev_dns,
    )

    web = row.get("web") or {}
    return {
        "company": {"slug": company.slug, "name": company.name},
        "scan": _scan_meta(scan),
        "previous_scan": _scan_meta(prev_scan) if prev_scan else None,
        "asset": {
            "hostname": domain,
            "root_domain": row.get("root") or "",
            "asset_type": _asset_type(row),
            "resolves": bool(row.get("resolves")),
            "ip_count": int(row.get("ip_count") or 0),
            "has_ipv4": bool(row.get("has_ipv4")),
            "has_ipv6": bool(row.get("has_ipv6")),
            "provider_hints": row.get("provider_hints") or [],
            "edge_family": _edge_family(row),
            "change": change,
            "dns": dns_by_domain.get(domain) or {},
            "web": web,
            "findings": findings_payload,
            "raw": row,
        },
    }
