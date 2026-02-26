from __future__ import annotations
from datetime import datetime, timezone
import dns.resolver


def resolve_dns(domain: str, include_ptr: bool = True) -> dict:
    r = dns.resolver.Resolver()
    r.lifetime = 4

    def q(qtype: str) -> list[str]:
        try:
            ans = r.resolve(domain, qtype)
            return [str(x).rstrip(".") for x in ans]
        except Exception:
            return []

    def ptr_for_ip(ip: str) -> list[str]:
        try:
            ans = r.resolve_address(ip)
            return sorted({str(x).rstrip(".") for x in ans})
        except Exception:
            return []

    a = q("A")
    aaaa = q("AAAA")
    cname = q("CNAME")
    mx = q("MX")
    ns = q("NS")
    txt = q("TXT")
    soa = q("SOA")
    caa = q("CAA")

    ips = sorted({*a, *aaaa})
    ptr = {ip: ptr_for_ip(ip) for ip in ips} if include_ptr else {}

    return {
        "domain": domain,
        "resolved_at": datetime.now(timezone.utc).isoformat(),
        "A": a,
        "AAAA": aaaa,
        "CNAME": cname,
        "MX": mx,
        "NS": ns,
        "TXT": txt,
        "SOA": soa,
        "CAA": caa,
        "ips": ips,
        "PTR": ptr,
    }


def resolve_ips(domain: str) -> list[str]:
    r = dns.resolver.Resolver()
    r.lifetime = 3

    def q(qtype: str) -> list[str]:
        try:
            ans = r.resolve(domain, qtype)
            return [str(x).rstrip(".") for x in ans]
        except Exception:
            return []

    a = q("A")
    aaaa = q("AAAA")
    return sorted({*a, *aaaa})
