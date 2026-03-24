from __future__ import annotations

import asyncio
import json
import shutil


async def subfinder_subdomains(root_domain: str) -> set[str]:
    """
    Passive subdomain enumeration via the ProjectDiscovery Subfinder binary.

    Subfinder aggregates 50+ passive sources (VirusTotal, Shodan, Censys,
    SecurityTrails, etc.) behind a single CLI.  If the binary is not in PATH
    this function returns an empty set — the scan continues with CT + Wayback.

    Install: https://github.com/projectdiscovery/subfinder
      go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    """
    if not shutil.which("subfinder"):
        return set()

    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder",
            "-d", root_domain,
            "-silent",
            "-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except (asyncio.TimeoutError, OSError):
        return set()

    out: set[str] = set()
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "").strip().lower().strip(".")
            if host:
                out.add(host)
        except json.JSONDecodeError:
            # Some subfinder versions emit plain hostnames on stdout
            out.add(line.lower().strip("."))

    return out
