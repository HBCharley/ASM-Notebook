from __future__ import annotations

import asyncio
import os
import random

import diskcache
import httpx

CRTSH_URL = "https://crt.sh/?q={query}&output=json"

_CACHE_DIR = os.environ.get("ASM_CACHE_DIR", ".asm_cache")
_CT_CACHE_TTL = int(os.environ.get("ASM_CT_CACHE_TTL", str(60 * 60 * 24)))  # 24 hours default
_cache = diskcache.Cache(_CACHE_DIR)


async def ct_subdomains(root_domain: str) -> set[str]:
    """
    Passive subdomain discovery via crt.sh Certificate Transparency logs.

    Results are cached on disk for ASM_CT_CACHE_TTL seconds (default 24 h) to
    avoid hammering crt.sh on repeated scans of the same domain.  Set
    ASM_CT_CACHE_TTL=0 to disable caching.
    """
    root = root_domain.strip(".").lower()

    # --- cache lookup ---
    cache_key = f"ct:{root}"
    if _CT_CACHE_TTL > 0:
        cached = _cache.get(cache_key)
        if cached is not None:
            return set(cached)

    result = await _fetch_ct(root)

    if _CT_CACHE_TTL > 0:
        _cache.set(cache_key, sorted(result), expire=_CT_CACHE_TTL)

    return result


async def _fetch_ct(root: str) -> set[str]:
    """Hit crt.sh with exponential-backoff retry.  Returns empty set on failure."""
    url = CRTSH_URL.format(query=f"%.{root}")

    # Polite jitter
    await asyncio.sleep(0.2 + random.random() * 0.5)

    last_err: Exception | None = None
    for delay in [0, 1, 2, 4, 8]:
        if delay:
            await asyncio.sleep(delay)
        try:
            async with httpx.AsyncClient(
                timeout=int(os.environ.get("ASM_CT_TIMEOUT_SECONDS", "30")),
                headers={"User-Agent": "asm-notebook/0.2"},
                follow_redirects=True,
            ) as client:
                r = await client.get(url)

            if r.status_code in (429, 500, 502, 503, 504):
                last_err = httpx.HTTPStatusError(
                    f"Transient HTTP {r.status_code}", request=r.request, response=r
                )
                continue

            r.raise_for_status()
            data = r.json()

            out: set[str] = set()
            for row in data:
                for name in (row.get("name_value") or "").split("\n"):
                    n = name.strip().lower().strip(".")
                    if n:
                        out.add(n)
            return out

        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as e:
            last_err = e
            continue

    # Best-effort: return empty rather than crashing the scan
    return set()
