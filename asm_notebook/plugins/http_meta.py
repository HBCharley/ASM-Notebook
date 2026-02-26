from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
import struct
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict

import httpx


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"(?P<name>[A-Za-z][A-Za-z0-9._+-]*)/(?P<ver>\d[^\s;,]*)")
_AUX_FETCH_LIMIT = 262144
_FAVICON_FETCH_LIMIT = 524288
_TECH_PATTERNS = [
    ("wordpress", r"wp-content|wp-json|wordpress"),
    ("drupal", r"drupal|data-drupal-selector"),
    ("joomla", r"joomla|/media/system/js/"),
    ("shopify", r"shopify|cdn\.shopify\.com"),
    ("wix", r"wix\.com|wix-static"),
    ("squarespace", r"squarespace"),
    ("nextjs", r"__next|next\.js"),
    ("nuxt", r"__nuxt|nuxt"),
    ("react", r"react(\.min)?\.js|data-reactroot"),
    ("angular", r"ng-version|angular(\.min)?\.js"),
    ("vue", r"vue(\.min)?\.js|data-v-"),
    ("svelte", r"svelte"),
    ("gatsby", r"gatsby"),
    ("hugo", r"hugo"),
    ("jekyll", r"jekyll"),
    ("ghost", r"ghost"),
    ("hubspot", r"hs-scripts\.com|hubspot"),
    ("salesforce", r"salesforce"),
    ("zendesk", r"zendesk"),
    ("okta", r"okta"),
]
_FAVICON_HASHES = {
    "-1231873279": "Jenkins",
    "-1379982221": "Kibana",
    "1953726032": "Grafana",
    "1469910324": "Elasticsearch",
    "1054341965": "WordPress",
    "833190513": "Jira",
    "-299287097": "Confluence",
}


def _mmh3_32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for block_start in range(0, nblocks * 4, 4):
        k1 = struct.unpack_from("<I", data, block_start)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    return struct.unpack("<i", struct.pack("<I", h1))[0]


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


def _extract_reported_versions(headers: dict[str, str], body: str) -> list[dict[str, str]]:
    versions: list[dict[str, str]] = []

    for header_key in ("server", "x-powered-by"):
        value = headers.get(header_key, "")
        if not value:
            continue
        for m in _VERSION_RE.finditer(value):
            versions.append(
                {
                    "name": m.group("name"),
                    "version": m.group("ver"),
                    "source": f"header:{header_key}",
                }
            )

    gen = _GENERATOR_RE.search(body)
    if gen:
        content = gen.group(1).strip()
        m = _VERSION_RE.search(content)
        if m:
            versions.append(
                {
                    "name": m.group("name"),
                    "version": m.group("ver"),
                    "source": "meta:generator",
                }
            )
        else:
            versions.append(
                {
                    "name": content,
                    "version": "",
                    "source": "meta:generator",
                }
            )

    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for entry in versions:
        key = (entry["name"], entry["version"], entry["source"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)

    return unique


def _detect_technologies(body: str, headers: dict[str, str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    lower_body = body.lower()
    header_blob = " ".join(
        [
            str(headers.get("server", "")),
            str(headers.get("x-powered-by", "")),
            str(headers.get("x-aspnet-version", "")),
            str(headers.get("x-generator", "")),
        ]
    ).lower()

    for name, pattern in _TECH_PATTERNS:
        if re.search(pattern, lower_body, re.IGNORECASE):
            findings.append({"name": name, "source": "html"})
        if re.search(pattern, header_blob, re.IGNORECASE):
            findings.append({"name": name, "source": "header"})

    powered = headers.get("x-powered-by", "")
    for m in _VERSION_RE.finditer(powered):
        findings.append({"name": m.group("name").lower(), "source": "header:x-powered-by"})

    server = headers.get("server", "")
    for m in _VERSION_RE.finditer(server):
        findings.append({"name": m.group("name").lower(), "source": "header:server"})

    gen = _GENERATOR_RE.search(body)
    if gen:
        findings.append({"name": gen.group(1).strip().lower(), "source": "meta:generator"})

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for entry in findings:
        key = (entry["name"], entry["source"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)

    return unique


def _detect_cloud_storage(body: str, url: httpx.URL, headers: dict[str, str]) -> dict[str, Any]:
    host = (url.host or "").lower()
    provider = ""
    if "s3.amazonaws.com" in host or host.endswith(".s3.amazonaws.com"):
        provider = "aws-s3"
    elif "s3-website" in host:
        provider = "aws-s3-website"
    elif "storage.googleapis.com" in host:
        provider = "gcp-gcs"
    elif "blob.core.windows.net" in host:
        provider = "azure-blob"
    elif "digitaloceanspaces.com" in host:
        provider = "do-spaces"

    if not provider:
        return {}

    lower_body = body.lower()
    listing = "listbucketresult" in lower_body
    error_hint = ""
    if "nosuchbucket" in lower_body or "the specified bucket does not exist" in lower_body:
        error_hint = "no_such_bucket"
    if "accessdenied" in lower_body:
        error_hint = "access_denied"
    return {
        "provider": provider,
        "endpoint_host": host,
        "listing_detected": listing,
        "error_hint": error_hint,
    }


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


async def _fetch_aux_resource(
    client: httpx.AsyncClient,
    base_url: httpx.URL,
    path: str,
    limit: int,
    collect_bytes: bool = False,
) -> dict[str, Any]:
    url = base_url.copy_with(path=path, query=None, fragment=None)
    try:
        start = time.monotonic()
        async with client.stream("GET", url) as resp:
            total = 0
            chunks: list[bytes] = []
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if collect_bytes:
                    chunks.append(chunk)
                if total >= limit:
                    break
            elapsed_ms = int((time.monotonic() - start) * 1000)
            payload = {
                "path": path,
                "status_code": resp.status_code,
                "final_url": str(resp.url),
                "content_type": resp.headers.get("content-type", ""),
                "content_length": resp.headers.get("content-length", ""),
                "bytes_read": total,
                "response_ms": elapsed_ms,
                "present": resp.status_code < 400,
            }
            if collect_bytes and chunks:
                data = b"".join(chunks)[:limit]
                mmh3 = _mmh3_32(data)
                payload["hash_mmh3"] = mmh3
                payload["hash_mmh3_unsigned"] = mmh3 & 0xFFFFFFFF
                payload["hash_fingerprint"] = _FAVICON_HASHES.get(str(mmh3), "")
            return {
                **payload,
            }
    except Exception as e:
        return {
            "path": path,
            "present": False,
            "error": str(e)[:200],
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
            cert = ssock.getpeercert() or {}
            subject = cert.get("subject", [])
            issuer = cert.get("issuer", [])
            sans = [f"{t}:{v}" for t, v in cert.get("subjectAltName", [])]
            not_before = _parse_cert_datetime(cert.get("notBefore"))
            not_after = _parse_cert_datetime(cert.get("notAfter"))
            serial_number = cert.get("serialNumber", "")

            if not not_before and not not_after:
                tmp_path = ""
                try:
                    pem = ssl.get_server_certificate((host, port))
                    with tempfile.NamedTemporaryFile("w+", delete=False) as fp:
                        fp.write(pem)
                        fp.flush()
                        tmp_path = fp.name
                    decoded = ssl._ssl._test_decode_cert(tmp_path)
                    subject = decoded.get("subject", subject)
                    issuer = decoded.get("issuer", issuer)
                    sans = [
                        f"{t}:{v}"
                        for t, v in (decoded.get("subjectAltName") or [])
                    ]
                    serial_number = decoded.get("serialNumber", serial_number)
                    not_before = _parse_cert_datetime(decoded.get("notBefore"))
                    not_after = _parse_cert_datetime(decoded.get("notAfter"))
                except Exception:
                    pass
                finally:
                    if tmp_path:
                        try:
                            os.unlink(tmp_path)
                        except Exception:
                            pass

            return {
                "protocol": ssock.version(),
                "cipher": ssock.cipher()[0] if ssock.cipher() else "",
                "cert": {
                    "subject": subject,
                    "issuer": issuer,
                    "serial_number": serial_number,
                    "not_before": not_before,
                    "not_after": not_after,
                    "san": sans,
                },
            }


async def fetch_http_metadata(domain: str, deep_scan: bool = False) -> Dict[str, Any]:
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
                lowered_headers = {k.lower(): v for k, v in resp.headers.items()}
                fingerprints = _fingerprint_html(body, lowered_headers)
                reported_versions = _extract_reported_versions(lowered_headers, body)
                technologies = _detect_technologies(body, lowered_headers)
                hsts = _parse_hsts(resp.headers.get("strict-transport-security"))
                cloud_storage = _detect_cloud_storage(body, resp.url, lowered_headers)
                tls_info: dict[str, Any] = {}
                if scheme == "https":
                    host = resp.url.host or domain
                    try:
                        tls_info = await asyncio.to_thread(_fetch_tls_info, host, resp.url.port or 443)
                    except Exception:
                        tls_info = {}
                deep_resources: dict[str, Any] = {"enabled": deep_scan}
                if deep_scan:
                    base_url = resp.url.copy_with(path="/", query=None, fragment=None)
                    deep_resources["favicon"] = await _fetch_aux_resource(
                        client, base_url, "/favicon.ico", _FAVICON_FETCH_LIMIT, collect_bytes=True
                    )
                    deep_resources["robots"] = await _fetch_aux_resource(
                        client, base_url, "/robots.txt", _AUX_FETCH_LIMIT
                    )
                    deep_resources["sitemap"] = await _fetch_aux_resource(
                        client, base_url, "/sitemap.xml", _AUX_FETCH_LIMIT
                    )
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
                    "reported_versions": reported_versions,
                    "technologies": technologies,
                    "hsts": hsts,
                    "tls": tls_info,
                    "cloud_storage": cloud_storage,
                    "deep_scan": deep_resources,
                }
            except Exception as e:
                last_error = str(e)
                continue

    return {
        "domain": domain,
        "reachable": False,
        "error": last_error[:250] if last_error else "request_failed",
    }
