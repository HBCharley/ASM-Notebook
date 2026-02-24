from __future__ import annotations

import re
from typing import Any, Dict

import httpx


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


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
                return {
                    "domain": domain,
                    "reachable": True,
                    "scheme": scheme,
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                    "title": title,
                    "headers": interesting,
                    "security_headers": security_headers,
                }
            except Exception as e:
                last_error = str(e)
                continue

    return {
        "domain": domain,
        "reachable": False,
        "error": last_error[:250] if last_error else "request_failed",
    }
