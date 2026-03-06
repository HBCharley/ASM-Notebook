from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import Finding

SEVERITIES: tuple[str, ...] = ("info", "watch", "investigate", "critical")
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _as_set(value: Any) -> set[str]:
    if not value:
        return set()
    if isinstance(value, (list, tuple, set)):
        return {str(v).strip().lower() for v in value if str(v).strip()}
    return {str(value).strip().lower()} if str(value).strip() else set()


def _days_until(iso_dt: str | None) -> int | None:
    if not iso_dt:
        return None
    try:
        dt = datetime.fromisoformat(iso_dt.replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = dt - _now_utc()
    return int(delta.total_seconds() // 86400)


@dataclass(frozen=True)
class FindingDraft:
    company_id: uuid.UUID
    scan_id: int
    asset_hostname: str
    root_domain: str | None
    severity: str
    category: str
    title: str
    explanation: str
    evidence: dict[str, Any]
    remediation: str
    rule_key: str
    status: str = "open"


def generate_findings(
    *,
    company_id: uuid.UUID,
    scan_id: int,
    intel_rows: list[dict[str, Any]],
    prev_intel_rows: list[dict[str, Any]] | None = None,
) -> list[FindingDraft]:
    prev_by_domain = {str(r.get("domain") or ""): r for r in (prev_intel_rows or [])}
    results: list[FindingDraft] = []

    for row in intel_rows:
        domain = str(row.get("domain") or "").strip().lower().strip(".")
        if not domain:
            continue

        root = row.get("root")
        resolves = bool(row.get("resolves"))
        takeover_risk = bool(row.get("takeover_risk"))
        takeover_targets = row.get("takeover_targets") or []

        web = row.get("web") or {}
        web_reachable = bool(web.get("reachable"))
        scheme = (web.get("scheme") or "").lower()
        final_url = str(web.get("final_url") or "")
        title = str(web.get("title") or "")
        security_headers = (web.get("security_headers") or {}) if isinstance(web.get("security_headers"), dict) else {}
        hsts = web.get("hsts") or {}
        tls = web.get("tls") or {}
        deep = web.get("deep_scan") or {}

        prev = prev_by_domain.get(domain) or {}
        prev_web = prev.get("web") or {}

        def add(
            *,
            severity: str,
            category: str,
            title: str,
            explanation: str,
            evidence: dict[str, Any],
            remediation: str,
            rule_key: str,
        ) -> None:
            if severity not in SEVERITY_ORDER:
                raise ValueError(f"Invalid severity: {severity}")
            results.append(
                FindingDraft(
                    company_id=company_id,
                    scan_id=scan_id,
                    asset_hostname=domain,
                    root_domain=str(root) if root else None,
                    severity=severity,
                    category=category,
                    title=title,
                    explanation=explanation,
                    evidence=evidence,
                    remediation=remediation,
                    rule_key=rule_key,
                )
            )

        if takeover_risk:
            add(
                severity="critical",
                category="takeover",
                title="Potential subdomain takeover (dangling CNAME)",
                explanation="Hostname has a CNAME target that does not resolve and no A/AAAA records were observed.",
                evidence={"cname_targets": takeover_targets, "has_cname": bool(row.get("has_cname"))},
                remediation="Validate the CNAME target is claimed/owned, or remove the DNS record if it is no longer needed.",
                rule_key="takeover.dangling_cname",
            )

        if not resolves:
            add(
                severity="investigate",
                category="dns",
                title="Hostname does not resolve",
                explanation="No A/AAAA records were observed for this hostname during the scan window.",
                evidence={"ip_count": int(row.get("ip_count") or 0), "has_cname": bool(row.get("has_cname"))},
                remediation="Confirm DNS configuration, expired records, or decommissioned services; remove stale DNS if appropriate.",
                rule_key="dns.unresolved",
            )

        if resolves and not web_reachable:
            add(
                severity="watch",
                category="web",
                title="Host resolves but is not web reachable",
                explanation="DNS resolution succeeded, but HTTP metadata collection failed for both http and https.",
                evidence={"error": web.get("error", ""), "ip_count": int(row.get("ip_count") or 0)},
                remediation="Verify the service is intended to be web-facing; if so, check routing/firewall and origin health.",
                rule_key="web.unreachable",
            )

        if web_reachable:
            if scheme == "http" and not tls:
                add(
                    severity="investigate",
                    category="tls",
                    title="TLS not enabled (HTTP only)",
                    explanation="The observed final URL uses HTTP and TLS information was not collected.",
                    evidence={"final_url": final_url, "scheme": scheme},
                    remediation="Enable HTTPS and enforce redirect from HTTP to HTTPS where applicable.",
                    rule_key="tls.missing",
                )

            missing_security = []
            for header in (
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            ):
                if not security_headers.get(header):
                    missing_security.append(header)
            if missing_security:
                add(
                    severity="watch" if len(missing_security) < 3 else "investigate",
                    category="web",
                    title="Missing security headers",
                    explanation="One or more recommended security headers were not observed in the HTTP response.",
                    evidence={"missing": missing_security, "present": sorted([k for k, v in security_headers.items() if v])},
                    remediation="Add missing headers at the application/edge layer (start with CSP, X-Frame-Options, X-Content-Type-Options).",
                    rule_key="web.missing_security_headers",
                )

            if tls and not hsts:
                add(
                    severity="watch",
                    category="web",
                    title="HSTS not enabled",
                    explanation="Site appears to support TLS, but Strict-Transport-Security was not observed.",
                    evidence={"final_url": final_url},
                    remediation="Add a Strict-Transport-Security header (start with max-age) and validate includeSubDomains/preload policy if appropriate.",
                    rule_key="web.missing_hsts",
                )

            cert_days = _days_until(str(tls.get("not_after") or "")) if isinstance(tls, dict) else None
            if cert_days is not None and cert_days <= 30:
                add(
                    severity="investigate" if cert_days <= 14 else "watch",
                    category="tls",
                    title="Certificate expiring soon",
                    explanation="TLS certificate expiration is approaching.",
                    evidence={"not_after": tls.get("not_after"), "days_until": cert_days},
                    remediation="Renew/rotate the certificate and validate the full chain and SANs.",
                    rule_key="tls.cert_expiring_soon",
                )

            favicon = deep.get("favicon") if isinstance(deep, dict) else None
            if isinstance(favicon, dict):
                fingerprint = str(favicon.get("hash_fingerprint") or "").strip()
                if fingerprint:
                    add(
                        severity="investigate",
                        category="web",
                        title="Favicon matches known product fingerprint",
                        explanation="Favicon hash matched a known fingerprint; validate exposure is expected.",
                        evidence={
                            "final_url": favicon.get("final_url"),
                            "hash_mmh3": favicon.get("hash_mmh3"),
                            "hash_fingerprint": fingerprint,
                        },
                        remediation="Confirm the service is intended to be internet-facing; restrict access or harden auth if not.",
                        rule_key="web.favicon_fingerprint",
                    )

            robots = deep.get("robots") if isinstance(deep, dict) else None
            if isinstance(robots, dict) and deep.get("enabled") and not robots.get("present", True):
                add(
                    severity="info",
                    category="web",
                    title="robots.txt not present",
                    explanation="robots.txt was not observed during deep scan auxiliary checks.",
                    evidence={"status_code": robots.get("status_code"), "final_url": robots.get("final_url")},
                    remediation="If intended, add robots.txt to control crawling behavior; otherwise ignore.",
                    rule_key="web.robots_missing",
                )

            sitemap = deep.get("sitemap") if isinstance(deep, dict) else None
            if isinstance(sitemap, dict) and deep.get("enabled") and not sitemap.get("present", True):
                add(
                    severity="info",
                    category="web",
                    title="sitemap.xml not present",
                    explanation="sitemap.xml was not observed during deep scan auxiliary checks.",
                    evidence={"status_code": sitemap.get("status_code"), "final_url": sitemap.get("final_url")},
                    remediation="If intended, publish a sitemap.xml; otherwise ignore.",
                    rule_key="web.sitemap_missing",
                )

        if prev_intel_rows is not None:
            was_present = domain in prev_by_domain
            if not was_present:
                add(
                    severity="info",
                    category="change",
                    title="Newly discovered host",
                    explanation="Hostname was not present in the previous scan.",
                    evidence={"previous_scan_present": False},
                    remediation="Validate whether this is expected growth or an untracked deployment.",
                    rule_key="change.new_asset",
                )
            else:
                prev_reachable = bool(prev_web.get("reachable"))
                if prev_reachable and not web_reachable:
                    add(
                        severity="investigate",
                        category="change",
                        title="Newly unreachable web host",
                        explanation="Host was web reachable in the previous scan but is not reachable now.",
                        evidence={
                            "prev_final_url": prev_web.get("final_url", ""),
                            "curr_error": web.get("error", ""),
                        },
                        remediation="Check origin health and edge routing; validate planned maintenance vs. outage.",
                        rule_key="change.newly_unreachable",
                    )
                prev_final = str(prev_web.get("final_url") or "")
                if prev_final and final_url and prev_final != final_url:
                    add(
                        severity="watch",
                        category="change",
                        title="Final URL changed",
                        explanation="Observed redirect chain / final URL differs from the previous scan.",
                        evidence={"prev_final_url": prev_final, "curr_final_url": final_url},
                        remediation="Confirm redirects and canonical host configuration are expected.",
                        rule_key="change.final_url_changed",
                    )
                prev_title = str(prev_web.get("title") or "")
                if prev_title and title and prev_title != title:
                    add(
                        severity="info",
                        category="change",
                        title="Page title changed",
                        explanation="HTML title differs from the previous scan.",
                        evidence={"prev_title": prev_title, "curr_title": title},
                        remediation="Review if content changes are expected; investigate if indicative of defacement or misroute.",
                        rule_key="change.title_changed",
                    )
                prev_tech = _as_set(prev_web.get("technologies"))
                curr_tech = _as_set(web.get("technologies"))
                if prev_tech and curr_tech and prev_tech != curr_tech:
                    add(
                        severity="watch",
                        category="change",
                        title="Technology signals changed",
                        explanation="Detected technology indicators changed compared to the previous scan.",
                        evidence={"prev": sorted(prev_tech), "curr": sorted(curr_tech)},
                        remediation="Validate whether this indicates a deployment change or an unexpected platform drift.",
                        rule_key="change.technology_changed",
                    )

    results.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.asset_hostname, f.rule_key))
    return results


def persist_findings_for_scan(
    session: Session,
    *,
    company_id: uuid.UUID,
    scan_id: int,
    intel_rows: list[dict[str, Any]],
    prev_intel_rows: list[dict[str, Any]] | None = None,
) -> list[Finding]:
    session.execute(delete(Finding).where(Finding.scan_id == scan_id))
    drafts = generate_findings(
        company_id=company_id,
        scan_id=scan_id,
        intel_rows=intel_rows,
        prev_intel_rows=prev_intel_rows,
    )
    rows: list[Finding] = []
    for d in drafts:
        rows.append(
            Finding(
                company_id=d.company_id,
                scan_id=d.scan_id,
                asset_hostname=d.asset_hostname,
                root_domain=d.root_domain,
                severity=d.severity,
                category=d.category,
                title=d.title,
                explanation=d.explanation,
                evidence_json=_json(d.evidence),
                remediation=d.remediation,
                rule_key=d.rule_key,
                status=d.status,
            )
        )
    session.add_all(rows)
    return rows


def list_findings_for_scan(
    session: Session, *, scan_id: int, asset_hostname: str | None = None
) -> list[Finding]:
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if asset_hostname:
        stmt = stmt.where(Finding.asset_hostname == asset_hostname)
    return session.execute(stmt).scalars().all()

