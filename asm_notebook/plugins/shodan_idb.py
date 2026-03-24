from __future__ import annotations

import asyncio

import httpx

# Shodan InternetDB — free, no API key.
# Returns open ports, CVEs, tags, CPEs, and hostnames per IP.
SHODAN_IDB_URL = "https://internetdb.shodan.io/{ip}"

# Concurrency cap: InternetDB is generous but we're polite
_SEM = asyncio.Semaphore(10)


async def shodan_idb(ips: list[str]) -> dict[str, dict]:
    """
    Look up every IP in the Shodan InternetDB (free, no key required).

    Returns a dict keyed by IP address:
    {
      "192.0.2.1": {
        "ports":     [22, 80, 443],
        "vulns":     ["CVE-2021-44228"],
        "tags":      ["self-signed"],
        "cpes":      ["cpe:/a:apache:http_server:2.4.51"],
        "hostnames": ["host.example.com"]
      },
      ...
    }
    IPs with no Shodan data are omitted from the result.
    """
    if not ips:
        return {}

    async with httpx.AsyncClient(
        timeout=10,
        headers={"User-Agent": "asm-notebook/0.2"},
        follow_redirects=False,
    ) as client:
        tasks = [_lookup(client, ip) for ip in ips]
        pairs = await asyncio.gather(*tasks)

    return {ip: data for ip, data in pairs if data}


async def _lookup(client: httpx.AsyncClient, ip: str) -> tuple[str, dict | None]:
    async with _SEM:
        try:
            r = await client.get(SHODAN_IDB_URL.format(ip=ip))
            if r.status_code == 404:
                return ip, None
            r.raise_for_status()
            d = r.json()
            return ip, {
                "ports":     d.get("ports", []),
                "vulns":     d.get("vulns", []),
                "tags":      d.get("tags", []),
                "cpes":      d.get("cpes", []),
                "hostnames": d.get("hostnames", []),
            }
        except Exception:
            return ip, None
