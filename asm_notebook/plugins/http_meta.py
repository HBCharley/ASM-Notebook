from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict

import httpx


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)


def _fingerprint_html(body: str, headers: dict[str, str]) -> list[str]:
    fingerprints: set[str] = set()
    lower = body.lower()
    server = headers.get("server", "").lower()
    powered = headers.get("x-powered-by", "").lower()

    gen = _GENERATOR_RE.search(body)
    if gen:
        fingerprints.add(f"generator:{gen.group(1).strip()}")

    if "wp-content" in lower or "wp-json" in lower or "wordpress" in lower:
        fingerprints.add("wordpress")
    if "drupal" in lower or "data-drupal-selector" in lower:
        fingerprints.add("drupal")
    if "shopify" in lower or "cdn.shopify.com" in lower:
        fingerprints.add("shopify")
    if "wix.com" in lower or "wix-static" in lower:
        fingerprints.add("wix")
    if "squarespace" in lower:
        fingerprints.add("squarespace")
    if "next.js" in lower or "__next" in lower:
        fingerprints.add("nextjs")
    if "nuxt" in lower or "__nuxt" in lower:
        fingerprints.add("nuxt")

    if "nginx" in server:
        fingerprints.add("nginx")
    if "apache" in server:
        fingerprints.add("apache")
    if "cloudflare" in server or "cloudflare" in headers.get("cf-ray", "").lower():
        fingerprints.add("cloudflare")
    if "express" in powered:
        fingerprints.add("express")
    if "asp.net" in powered or "asp.net" in server:
        fingerprints.add("aspnet")

    return sorted(fingerprints)


def _parse_hsts(header: str | None) -> dict[str, Any]:
    if not header:
        return {}
    directives = [d.strip() for d in header.split(";") if d.strip()]
    max_age = None
    include_subdomains = False
    preload = False
    for d in directives:
        if d.lower().startswith("max-age"):
            parts = d.split("=", 1)
            if len(parts) == 2:
                try:
                    max_age = int(parts[1].strip())
                except ValueError:
                    max_age = None
        if d.lower() == "includesubdomains":
            include_subdomains = True
        if d.lower() == "preload":
            preload = True
    preload_eligible = bool(max_age and max_age >= 31536000 and include_subdomains and preload)
    return {
        "header": header,
        "max_age": max_age,
        "include_subdomains": include_subdomains,
        "preload_directive": preload,
        "preload_eligible": preload_eligible,
    }


def _parse_cert_datetime(value: str | None) -> str:
    if not value:
        return ""
    try:
        dt = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return value


def _fetch_tls_info(host: str, port: int = 443) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=4) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            subject = cert.get("subject", [])
            issuer = cert.get("issuer", [])
            sans = [f"{t}:{v}" for t, v in cert.get("subjectAltName", [])]
            return {
                "protocol": ssock.version(),
                "cipher": ssock.cipher()[0] if ssock.cipher() else "",
                "cert": {
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": cert.get("serialNumber", ""),
                    "not_before": _parse_cert_datetime(cert.get("notBefore")),
                    "not_after": _parse_cert_datetime(cert.get("notAfter")),
                    "san": sans,
                },
            }


async def fetch_http_metadata(domain: str) -> Dict[str, Any]:
    last_error = ""
    timeout = httpx.Timeout(8.0, connect=5.0)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "asm-notebook/0.1"},
    ) as client:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                resp = await client.get(url)
                body = resp.text[:6000] if resp.text else ""
                m = _TITLE_RE.search(body)
                title = m.group(1).strip() if m else ""
                interesting = {}
                for k in (
                    "server",
                    "via",
                    "x-powered-by",
                    "x-cache",
                    "x-served-by",
                    "cf-ray",
                    "x-amz-cf-id",
                    "x-amz-cf-pop",
                ):
                    if k in resp.headers:
                        interesting[k] = resp.headers.get(k, "")
                security_headers = {}
                for k in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                    "permissions-policy",
                ):
                    if k in resp.headers:
                        security_headers[k] = resp.headers.get(k, "")
                fingerprints = _fingerprint_html(body, {k.lower(): v for k, v in resp.headers.items()})
                hsts = _parse_hsts(resp.headers.get("strict-transport-security"))
                tls_info: dict[str, Any] = {}
                if scheme == "https":
                    host = resp.url.host or domain
                    try:
                        tls_info = await asyncio.to_thread(_fetch_tls_info, host, resp.url.port or 443)
                    except Exception:
                        tls_info = {}
                return {
                    "domain": domain,
                    "reachable": True,
                    "scheme": scheme,
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                    "title": title,
                    "headers": interesting,
                    "security_headers": security_headers,
                    "fingerprints": fingerprints,
                    "hsts": hsts,
                    "tls": tls_info,
                }
            except Exception as e:
                last_error = str(e)
                continue

    return {
        "domain": domain,
        "reachable": False,
        "error": last_error[:250] if last_error else "request_failed",
    }
