from __future__ import annotations

from urllib.parse import urlparse

import httpx

CDX_URL = "http://web.archive.org/cdx/search/cdx"


async def wayback_subdomains(root_domain: str) -> set[str]:
    """
    Discover historical subdomains via the Wayback Machine CDX API.

    Finds hostnames that appeared in archived URLs for *.root_domain even if
    they no longer exist in DNS — valuable for spotting ghost infrastructure
    and subdomain takeover candidates.

    Free, no API key required.  Returns empty set on any failure.
    """
    root = root_domain.strip(".").lower()
    params = {
        "url": f"*.{root}",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "5000",
    }

    try:
        async with httpx.AsyncClient(
            timeout=30,
            headers={"User-Agent": "asm-notebook/0.2"},
            follow_redirects=True,
        ) as client:
            r = await client.get(CDX_URL, params=params)
            r.raise_for_status()
            data = r.json()
    except Exception:
        return set()

    out: set[str] = set()
    # First row is the header ["original"], skip it
    for row in data[1:]:
        if not row:
            continue
        try:
            host = urlparse(row[0]).hostname
            if host:
                out.add(host.lower().strip("."))
        except Exception:
            continue

    return out
