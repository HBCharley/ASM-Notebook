from __future__ import annotations

import asyncio
import os
import re
import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict

import httpx
from cryptography import x509

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_GENERATOR_RE = re.compile(
    r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r"(?P<name>[A-Za-z][A-Za-z0-9._+-]*)/(?P<ver>\d[^\s;,]*)")
_JETTY_RE = re.compile(r"Jetty\((?P<ver>[^)]+)\)", re.IGNORECASE)
_WP_VER_RE = re.compile(r"wp-(?:content|includes)/[^\"' ]+\\?ver=(?P<ver>[0-9.]+)")
_JQUERY_RE = re.compile(r"jquery[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_BOOTSTRAP_RE = re.compile(r"bootstrap(?:\\.min)?(?:\\.bundle)?[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_JQUERY_UI_RE = re.compile(r"jquery-ui[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_REACT_RE = re.compile(r"react(?:\\.min)?[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_VUE_RE = re.compile(r"vue(?:\\.min)?[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_ANGULAR_RE = re.compile(r"angular(?:\\.min)?[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_MOMENT_RE = re.compile(r"moment(?:\\.min)?[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_LODASH_RE = re.compile(r"lodash(?:\\.min)?[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
_FONT_AWESOME_RE = re.compile(r"font-?awesome[-.](?P<ver>[0-9]+\.[0-9]+\.[0-9]+)", re.IGNORECASE)
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
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

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


def _extract_reported_versions(
    headers: dict[str, str], body: str
) -> list[dict[str, str]]:
    versions: list[dict[str, str]] = []

    for header_key in (
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-runtime",
        "x-mod-pagespeed",
        "x-drupal-cache",
        "x-joomla-cache",
    ):
        value = headers.get(header_key, "")
        if not value:
            continue
        for m in _VERSION_RE.finditer(value):
            versions.append(
                {
                    "name": m.group("name"),
                    "version": m.group("ver"),
                    "source": f"header:{header_key}",
                    "confidence": "high",
                    "evidence": {"type": "header", "key": header_key, "value": value},
                }
            )
        jetty = _JETTY_RE.search(value)
        if jetty:
            versions.append(
                {
                    "name": "jetty",
                    "version": jetty.group("ver"),
                    "source": f"header:{header_key}",
                    "confidence": "high",
                    "evidence": {"type": "header", "key": header_key, "value": value},
                }
            )

    if body:
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
                        "confidence": "medium",
                        "evidence": {"type": "meta", "key": "generator", "value": content},
                    }
                )
            else:
                versions.append(
                    {
                        "name": content,
                        "version": "",
                        "source": "meta:generator",
                        "confidence": "low",
                        "evidence": {"type": "meta", "key": "generator", "value": content},
                    }
                )

        for m in _WP_VER_RE.finditer(body):
            versions.append(
                {
                    "name": "wordpress",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "wp", "value": m.group(0)},
                }
            )
        for m in _JQUERY_RE.finditer(body):
            versions.append(
                {
                    "name": "jquery",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "jquery", "value": m.group(0)},
                }
            )
        for m in _BOOTSTRAP_RE.finditer(body):
            versions.append(
                {
                    "name": "bootstrap",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "bootstrap", "value": m.group(0)},
                }
            )
        for m in _JQUERY_UI_RE.finditer(body):
            versions.append(
                {
                    "name": "jquery-ui",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "jquery-ui", "value": m.group(0)},
                }
            )
        for m in _REACT_RE.finditer(body):
            versions.append(
                {
                    "name": "react",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "react", "value": m.group(0)},
                }
            )
        for m in _VUE_RE.finditer(body):
            versions.append(
                {
                    "name": "vue",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "vue", "value": m.group(0)},
                }
            )
        for m in _ANGULAR_RE.finditer(body):
            versions.append(
                {
                    "name": "angular",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "angular", "value": m.group(0)},
                }
            )
        for m in _MOMENT_RE.finditer(body):
            versions.append(
                {
                    "name": "moment",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "moment", "value": m.group(0)},
                }
            )
        for m in _LODASH_RE.finditer(body):
            versions.append(
                {
                    "name": "lodash",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "lodash", "value": m.group(0)},
                }
            )
        for m in _FONT_AWESOME_RE.finditer(body):
            versions.append(
                {
                    "name": "font-awesome",
                    "version": m.group("ver"),
                    "source": "html:asset",
                    "confidence": "medium",
                    "evidence": {"type": "asset", "key": "font-awesome", "value": m.group(0)},
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
            str(headers.get("x-aspnetmvc-version", "")),
            str(headers.get("x-generator", "")),
            str(headers.get("x-drupal-cache", "")),
            str(headers.get("x-joomla-cache", "")),
            str(headers.get("x-runtime", "")),
            str(headers.get("x-mod-pagespeed", "")),
        ]
    ).lower()

    for name, pattern in _TECH_PATTERNS:
        if re.search(pattern, lower_body, re.IGNORECASE):
            findings.append({"name": name, "source": "html"})
        if re.search(pattern, header_blob, re.IGNORECASE):
            findings.append({"name": name, "source": "header"})

    powered = headers.get("x-powered-by", "")
    for m in _VERSION_RE.finditer(powered):
        findings.append(
            {"name": m.group("name").lower(), "source": "header:x-powered-by"}
        )

    server = headers.get("server", "")
    for m in _VERSION_RE.finditer(server):
        findings.append({"name": m.group("name").lower(), "source": "header:server"})

    gen = _GENERATOR_RE.search(body)
    if gen:
        findings.append(
            {"name": gen.group(1).strip().lower(), "source": "meta:generator"}
        )

    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, str]] = []
    for entry in findings:
        key = (entry["name"], entry["source"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)

    return unique


def _detect_cloud_storage(
    body: str, url: httpx.URL, headers: dict[str, str]
) -> dict[str, Any]:
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
    if (
        "nosuchbucket" in lower_body
        or "the specified bucket does not exist" in lower_body
    ):
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
    preload_eligible = bool(
        max_age and max_age >= 31536000 and include_subdomains and preload
    )
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


def _format_x509_name(name: x509.Name) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    for attr in name:
        oid = attr.oid
        label = oid._name if hasattr(oid, "_name") and oid._name else oid.dotted_string
        result.append((label, attr.value))
    return result


def _parse_x509_pem(pem: str) -> dict[str, Any]:
    cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
    not_before = cert.not_valid_before
    not_after = cert.not_valid_after
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                sans.append(f"IP:{name.value}")
            else:
                sans.append(str(name.value))
    except Exception:
        sans = []
    return {
        "subject": _format_x509_name(cert.subject),
        "issuer": _format_x509_name(cert.issuer),
        "serial_number": format(cert.serial_number, "x"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "san": sans,
    }


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
                try:
                    pem = ssl.get_server_certificate((host, port))
                    parsed = _parse_x509_pem(pem)
                    subject = parsed.get("subject", subject)
                    issuer = parsed.get("issuer", issuer)
                    sans = parsed.get("san", sans)
                    serial_number = parsed.get("serial_number", serial_number)
                    not_before = parsed.get("not_before", not_before)
                    not_after = parsed.get("not_after", not_after)
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


async def fetch_http_metadata(
    domain: str, deep_scan: bool = False, timeout_seconds: float | None = None
) -> Dict[str, Any]:
    last_error = ""
    if timeout_seconds is None:
        try:
            timeout_seconds = float(os.getenv("ASM_HTTP_TIMEOUT_SECONDS", "5"))
        except Exception:
            timeout_seconds = 5.0
    timeout = httpx.Timeout(timeout_seconds, connect=min(5.0, timeout_seconds))

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "asm-notebook/0.1"},
    ) as client:
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                resp = await client.get(url)
                content_type = (resp.headers.get("content-type") or "").lower()
                body = ""
                title = ""
                if "text/" in content_type or "html" in content_type or not content_type:
                    body = resp.text[:6000] if resp.text else ""
                if body:
                    m = _TITLE_RE.search(body)
                    title = m.group(1).strip() if m else ""
                interesting = {}
                for k in (
                    "server",
                    "via",
                    "x-powered-by",
                    "x-aspnet-version",
                    "x-aspnetmvc-version",
                    "x-generator",
                    "x-runtime",
                    "x-drupal-cache",
                    "x-joomla-cache",
                    "x-mod-pagespeed",
                    "x-request-id",
                    "x-cdn",
                    "x-cache",
                    "x-cache-hits",
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
                fingerprints: list[str] = []
                reported_versions = _extract_reported_versions(lowered_headers, body)
                technologies = _detect_technologies(body, lowered_headers)
                if deep_scan and body:
                    fingerprints = _fingerprint_html(body, lowered_headers)
                hsts = _parse_hsts(resp.headers.get("strict-transport-security"))
                cloud_storage = _detect_cloud_storage(body, resp.url, lowered_headers)
                tls_info: dict[str, Any] = {}
                if scheme == "https":
                    host = resp.url.host or domain
                    try:
                        tls_info = await asyncio.to_thread(
                            _fetch_tls_info, host, resp.url.port or 443
                        )
                    except Exception:
                        tls_info = {}
                deep_resources: dict[str, Any] = {"enabled": deep_scan}
                if deep_scan:
                    base_url = resp.url.copy_with(path="/", query=None, fragment=None)
                    deep_resources["favicon"] = await _fetch_aux_resource(
                        client,
                        base_url,
                        "/favicon.ico",
                        _FAVICON_FETCH_LIMIT,
                        collect_bytes=True,
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
