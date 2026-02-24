from __future__ import annotations

import os
from typing import Any

try:
    from ipwhois import IPWhois
except Exception:  # pragma: no cover - optional dependency at runtime
    IPWhois = None


_ASN_CACHE: dict[str, dict[str, Any] | None] = {}


def _asn_enabled() -> bool:
    return os.getenv("ASM_ASN_LOOKUP", "1").strip() != "0"


def lookup_asn_for_ips(ips: list[str]) -> dict[str, dict[str, Any]]:
    if not _asn_enabled():
        return {}
    if IPWhois is None:
        return {}

    results: dict[str, dict[str, Any]] = {}
    for ip in ips:
        if ip in _ASN_CACHE:
            cached = _ASN_CACHE[ip]
            if cached:
                results[ip] = cached
            continue
        try:
            data = IPWhois(ip).lookup_rdap()
            record = {
                "ip": ip,
                "asn": data.get("asn"),
                "asn_cidr": data.get("asn_cidr"),
                "asn_country_code": data.get("asn_country_code"),
                "asn_registry": data.get("asn_registry"),
                "asn_description": data.get("asn_description"),
                "network_name": (data.get("network") or {}).get("name"),
                "network_type": (data.get("network") or {}).get("type"),
            }
            _ASN_CACHE[ip] = record
            results[ip] = record
        except Exception:
            _ASN_CACHE[ip] = None
            continue
    return results
