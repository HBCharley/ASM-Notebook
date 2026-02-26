from __future__ import annotations

import os
import socket
from typing import Any

try:
    from ipwhois import IPWhois
except Exception:  # pragma: no cover - optional dependency at runtime
    IPWhois = None


_ASN_CACHE: dict[str, dict[str, Any] | None] = {}


def _asn_enabled() -> bool:
    return os.getenv("ASM_ASN_LOOKUP", "1").strip() != "0"


def lookup_asn_for_ips(
    ips: list[str], timeout_seconds: float | None = None
) -> dict[str, dict[str, Any]]:
    if not _asn_enabled():
        return {}
    if IPWhois is None:
        return {}

    results: dict[str, dict[str, Any]] = {}
    if timeout_seconds is None:
        try:
            timeout_seconds = float(os.getenv("ASM_ASN_TIMEOUT_SECONDS", "5"))
        except Exception:
            timeout_seconds = 5.0
    for ip in ips:
        if ip in _ASN_CACHE:
            cached = _ASN_CACHE[ip]
            if cached:
                results[ip] = cached
            continue
        try:
            prev_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout_seconds)
            try:
                data = IPWhois(ip).lookup_rdap()
            finally:
                socket.setdefaulttimeout(prev_timeout)
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
