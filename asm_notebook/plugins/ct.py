from __future__ import annotations

import asyncio
import os
import random
import httpx

CRTSH_URL = "https://crt.sh/?q={query}&output=json"

async def ct_subdomains(root_domain: str) -> set[str]:
    """
    Passive subdomain discovery via crt.sh (Certificate Transparency).
    Best-effort: retries on 429/5xx, and returns empty set if unavailable.
    """
    q = f"%.{root_domain.strip('.')}"
    url = CRTSH_URL.format(query=q)

    # Polite jitter to reduce burst/rate-limit issues
    await asyncio.sleep(0.2 + random.random() * 0.5)

    # Exponential backoff retries (tunable for local dev responsiveness)
    timeout_seconds = float(os.getenv("ASM_CT_TIMEOUT_SECONDS", "12"))
    retry_count = max(0, int(os.getenv("ASM_CT_RETRY_COUNT", "2")))
    delays = [1, 2, 4, 8][:retry_count]
    last_err: Exception | None = None

    for i, delay in enumerate([0] + delays):
        if delay:
            await asyncio.sleep(delay)

        try:
            async with httpx.AsyncClient(
                timeout=timeout_seconds,
                headers={"User-Agent": "asm-notebook/0.1"},
                follow_redirects=True,
            ) as client:
                r = await client.get(url)

            # Retry on rate limit / server errors
            if r.status_code in (429, 500, 502, 503, 504):
                last_err = httpx.HTTPStatusError(
                    f"Transient HTTP {r.status_code}", request=r.request, response=r
                )
                continue

            r.raise_for_status()
            data = r.json()

            out: set[str] = set()
            for row in data:
                names = (row.get("name_value") or "").split("\n")
                for n in names:
                    n = n.strip().lower().strip(".")
                    if n:
                        out.add(n)
            return out

        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPStatusError) as e:
            last_err = e
            continue

    # Best-effort fallback
    # You can log last_err later if you want; returning empty keeps scan running.
    return set()
