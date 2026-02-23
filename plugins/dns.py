from __future__ import annotations
import dns.resolver

def resolve_dns(domain: str) -> dict:
    r = dns.resolver.Resolver()
    r.lifetime = 4

    def q(qtype: str) -> list[str]:
        try:
            ans = r.resolve(domain, qtype)
            return [str(x).rstrip(".") for x in ans]
        except Exception:
            return []

    return {
        "domain": domain,
        "A": q("A"),
        "AAAA": q("AAAA"),
        "CNAME": q("CNAME"),
        "MX": q("MX"),
        "NS": q("NS"),
    }