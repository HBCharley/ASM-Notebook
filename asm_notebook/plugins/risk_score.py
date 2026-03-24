from __future__ import annotations

"""
Risk scoring engine — derives findings from collected scan artifacts.

All logic operates on the in-memory artifacts dict; no external calls are made.
Each finding has:
  severity  : critical | high | medium | low | info
  category  : the risk class
  domain    : the affected asset
  detail    : human-readable explanation
"""

from typing import TypedDict

# Cloud/hosting providers whose CNAMEs are classic subdomain-takeover targets
_TAKEOVER_PROVIDERS = {
    "amazonaws.com", "s3.amazonaws.com", "elasticbeanstalk.com",
    "azurewebsites.net", "cloudapp.net", "azureedge.net", "blob.core.windows.net",
    "herokuapp.com", "herokussl.com",
    "github.io", "githubusercontent.com",
    "netlify.app", "netlify.com",
    "vercel.app",
    "surge.sh",
    "readme.io", "readmessl.com",
    "ghost.io",
    "zendesk.com",
    "shopify.com",
    "wordpress.com", "wpengine.com",
    "fastly.net",
    "pantheonsite.io",
    "webflow.io",
    "fly.dev",
}

# Ports that warrant a flag when seen on a public IP
_SENSITIVE_PORTS: dict[int, str] = {
    21:    "FTP",
    22:    "SSH",
    23:    "Telnet",
    25:    "SMTP (open relay risk)",
    3389:  "RDP",
    5432:  "PostgreSQL",
    3306:  "MySQL",
    1433:  "MSSQL",
    6379:  "Redis",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch transport",
    5601:  "Kibana",
    8080:  "HTTP alt (admin panel?)",
    8443:  "HTTPS alt (admin panel?)",
    2375:  "Docker daemon (unauthenticated)",
    2376:  "Docker daemon (TLS)",
    4243:  "Docker daemon",
    11211: "Memcached",
    27017: "MongoDB",
    5000:  "Flask/dev server",
    8888:  "Jupyter Notebook",
    4444:  "Metasploit default listener",
    8983:  "Solr admin",
    7474:  "Neo4j browser",
}


class Finding(TypedDict):
    severity: str
    category: str
    domain: str
    detail: str


def compute_risk_score(artifacts: dict) -> dict:
    """
    Accepts the full artifacts dict for a single scan and returns:
    {
      "findings": [ {severity, category, domain, detail}, ... ],
      "summary": { "critical": N, "high": N, "medium": N, "low": N, "info": N }
    }
    """
    findings: list[Finding] = []

    dns_records: list[dict] = artifacts.get("dns", {}).get("records", [])
    shodan_data: dict[str, dict] = artifacts.get("shodan_idb", {})

    # Build lookup tables
    domain_dns: dict[str, dict] = {r["domain"]: r for r in dns_records}

    # ------------------------------------------------------------------ #
    # DNS-derived findings
    # ------------------------------------------------------------------ #
    for rec in dns_records:
        domain = rec.get("domain", "")
        cnames = rec.get("CNAME", [])
        a_records = rec.get("A", [])
        aaaa_records = rec.get("AAAA", [])
        mx_records = rec.get("MX", [])
        txt_records = rec.get("TXT", [])
        ns_records = rec.get("NS", [])

        has_ip = bool(a_records or aaaa_records)

        # --- Dangling CNAME (potential subdomain takeover) ---
        if cnames and not has_ip:
            for cname in cnames:
                for provider in _TAKEOVER_PROVIDERS:
                    if cname.rstrip(".").endswith(provider):
                        findings.append(Finding(
                            severity="high",
                            category="subdomain_takeover",
                            domain=domain,
                            detail=(
                                f"CNAME → {cname} (hosted on {provider}) but no A/AAAA record. "
                                "Service may be unclaimed — classic takeover vector."
                            ),
                        ))
                        break
                else:
                    # CNAME with no A/AAAA and not a known provider — still worth flagging
                    findings.append(Finding(
                        severity="low",
                        category="dangling_cname",
                        domain=domain,
                        detail=(
                            f"CNAME → {cnames[0]} but no A/AAAA record resolved. "
                            "Possible dead alias or misconfiguration."
                        ),
                    ))

        # --- Missing SPF (when MX records exist) ---
        if mx_records:
            has_spf = any("v=spf1" in t.lower() for t in txt_records)
            if not has_spf:
                findings.append(Finding(
                    severity="medium",
                    category="missing_email_security",
                    domain=domain,
                    detail="MX records present but no SPF TXT record found. Domain is spoofable.",
                ))

        # --- Missing DMARC (root domains only — heuristic: has NS records) ---
        if ns_records and not any("_dmarc" in d for d in domain_dns):
            dmarc_domain = f"_dmarc.{domain}"
            dmarc_rec = domain_dns.get(dmarc_domain)
            if dmarc_rec is None:
                # We didn't scan _dmarc. subdomain; flag if root has MX
                if mx_records:
                    findings.append(Finding(
                        severity="medium",
                        category="missing_email_security",
                        domain=domain,
                        detail=(
                            "No _dmarc TXT record detected. Without DMARC, spoofed email from "
                            "this domain cannot be rejected by receiving MTAs."
                        ),
                    ))

        # --- Wildcard DNS entry ---
        if domain.startswith("*."):
            findings.append(Finding(
                severity="info",
                category="wildcard_dns",
                domain=domain,
                detail="Wildcard DNS record exists. All subdomains resolve — increases attack surface.",
            ))

    # ------------------------------------------------------------------ #
    # Shodan InternetDB findings (per IP)
    # ------------------------------------------------------------------ #
    for ip, idb in shodan_data.items():
        vulns: list[str] = idb.get("vulns", [])
        ports: list[int] = idb.get("ports", [])
        tags: list[str] = idb.get("tags", [])

        # Known CVEs
        for cve in vulns:
            findings.append(Finding(
                severity="critical",
                category="known_cve",
                domain=ip,
                detail=f"{cve} reported by Shodan on this IP.",
            ))

        # Sensitive open ports
        for port in ports:
            if port in _SENSITIVE_PORTS:
                findings.append(Finding(
                    severity="high",
                    category="exposed_service",
                    domain=ip,
                    detail=f"Port {port} ({_SENSITIVE_PORTS[port]}) is open on a public IP.",
                ))

        # Shodan tags of interest
        if "self-signed" in tags:
            findings.append(Finding(
                severity="medium",
                category="tls_issue",
                domain=ip,
                detail="Shodan reports a self-signed TLS certificate on this IP.",
            ))
        if "honeypot" in tags:
            findings.append(Finding(
                severity="info",
                category="honeypot",
                domain=ip,
                detail="Shodan has flagged this IP as a possible honeypot.",
            ))

    # ------------------------------------------------------------------ #
    # Summary counts
    # ------------------------------------------------------------------ #
    summary: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    return {"findings": findings, "summary": summary}
