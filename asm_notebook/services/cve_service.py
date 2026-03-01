from __future__ import annotations

import gzip
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger(__name__)

_DEFAULT_FEED_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"
_FEED_TEMPLATE_V20 = "nvdcve-2.0-{year}.json.gz"
_FEED_TEMPLATE_V11 = "nvdcve-1.1-{year}.json.gz"

_PRODUCT_MAP = {
    "nginx": ("nginx", "nginx"),
    "apache": ("apache", "http_server"),
    "apache-http-server": ("apache", "http_server"),
    "apache-httpd": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "microsoft-iis": ("microsoft", "iis"),
    "iis": ("microsoft", "iis"),
    "wordpress": ("wordpress", "wordpress"),
    "jetty": ("eclipse", "jetty"),
    "openresty": ("openresty", "openresty"),
}


@dataclass(frozen=True)
class CveMatch:
    cve_id: str
    description: str
    severity: str
    score: float | None
    vector: str | None
    vendor: str
    product: str
    version: str


_index_cache: dict[str, Any] = {
    "loaded_years": None,
    "index_by_product": {},
    "index_by_vendor_product": {},
    "built": False,
    "built_at": None,
    "record_count": 0,
    "cve_count": 0,
}


def _data_dir() -> Path:
    base = Path(__file__).resolve().parents[1] / "data" / "nvd"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _feed_urls_for_year(year: int) -> list[str]:
    base = os.getenv("ASM_NVD_FEED_BASE", _DEFAULT_FEED_BASE).rstrip("/")
    return [
        f"{base}/{_FEED_TEMPLATE_V20.format(year=year)}",
        f"{base}/{_FEED_TEMPLATE_V11.format(year=year)}",
    ]


def _download_feed(urls: list[str], dest: Path) -> bool:
    for url in urls:
        try:
            with httpx.stream("GET", url, timeout=60) as resp:
                if resp.status_code != 200:
                    continue
                with open(dest, "wb") as fh:
                    for chunk in resp.iter_bytes():
                        fh.write(chunk)
                return True
        except Exception:
            continue
    return False


def _ensure_feeds(years: list[int]) -> list[Path]:
    if os.getenv("ASM_NVD_DISABLE", "").strip() == "1":
        return []
    refresh = os.getenv("ASM_NVD_REFRESH", "").strip() == "1"
    out: list[Path] = []
    for year in years:
        dest = _data_dir() / f"nvdcve-{year}.json.gz"
        if dest.exists() and not refresh:
            out.append(dest)
            continue
        if _download_feed(_feed_urls_for_year(year), dest):
            out.append(dest)
        else:
            log.warning("Failed to download NVD feed for %s", year)
    return out


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        log.exception("Failed to load NVD feed %s", path)
        return None


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _normalize_vendor_product(name: str) -> tuple[str | None, str | None]:
    key = _normalize_name(name)
    if key in _PRODUCT_MAP:
        return _PRODUCT_MAP[key]
    return None, key or None


def _parse_cpe(criteria: str) -> tuple[str, str, str]:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return "", "", ""
    part = parts[2]
    if part != "a":
        return "", "", ""
    vendor = parts[3]
    product = parts[4]
    version = parts[5]
    return vendor or "", product or "", version or ""


def _iter_cpe_matches(configs: Any) -> list[dict[str, Any]]:
    nodes = []
    if isinstance(configs, dict):
        nodes = configs.get("nodes") or configs.get("Nodes") or []
    elif isinstance(configs, list):
        nodes = configs
    matches: list[dict[str, Any]] = []

    def visit(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch") or node.get("cpe_match") or []:
            matches.append(match)
        for sub in node.get("nodes") or []:
            visit(sub)
        for child in node.get("children") or []:
            visit(child)

    for node in nodes:
        if isinstance(node, dict):
            visit(node)
    return matches


def _tokenize_version(value: str) -> list[Any]:
    tokens = re.findall(r"\d+|[a-zA-Z]+", value)
    out: list[Any] = []
    for token in tokens:
        if token.isdigit():
            out.append(int(token))
        else:
            out.append(token.lower())
    return out


def _cmp_versions(left: str, right: str) -> int:
    l_tokens = _tokenize_version(left)
    r_tokens = _tokenize_version(right)
    max_len = max(len(l_tokens), len(r_tokens))
    for idx in range(max_len):
        l_val = l_tokens[idx] if idx < len(l_tokens) else 0
        r_val = r_tokens[idx] if idx < len(r_tokens) else 0
        if l_val == r_val:
            continue
        if isinstance(l_val, int) and isinstance(r_val, int):
            return -1 if l_val < r_val else 1
        return -1 if str(l_val) < str(r_val) else 1
    return 0


def _version_in_range(version: str, match: dict[str, Any]) -> bool:
    if not version:
        return False
    v_start_inc = match.get("versionStartIncluding")
    v_start_exc = match.get("versionStartExcluding")
    v_end_inc = match.get("versionEndIncluding")
    v_end_exc = match.get("versionEndExcluding")
    if v_start_inc and _cmp_versions(version, v_start_inc) < 0:
        return False
    if v_start_exc and _cmp_versions(version, v_start_exc) <= 0:
        return False
    if v_end_inc and _cmp_versions(version, v_end_inc) > 0:
        return False
    if v_end_exc and _cmp_versions(version, v_end_exc) >= 0:
        return False
    return True


def _extract_metrics(entry: dict[str, Any]) -> tuple[str, float | None, str | None]:
    metrics = entry.get("metrics") or entry.get("impact") or {}
    candidates: list[tuple[float, str, str | None]] = []

    def add(score: Any, severity: Any, vector: Any) -> None:
        try:
            score_val = float(score)
        except Exception:
            score_val = 0.0
        candidates.append((score_val, str(severity or "Unknown"), vector))

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for row in metrics.get(key) or []:
            data = row.get("cvssData") or {}
            add(
                data.get("baseScore") or row.get("baseScore"),
                data.get("baseSeverity") or row.get("baseSeverity"),
                data.get("vectorString") or row.get("vectorString"),
            )

    for key in ("baseMetricV3", "baseMetricV2"):
        row = metrics.get(key) or {}
        data = row.get("cvssV3") or row.get("cvssV2") or row.get("cvssData") or {}
        add(
            row.get("baseScore") or data.get("baseScore"),
            row.get("baseSeverity") or data.get("baseSeverity"),
            data.get("vectorString"),
        )

    if not candidates:
        return "Unknown", None, None

    score, severity, vector = max(candidates, key=lambda item: item[0])
    if severity == "Unknown" and score:
        if score >= 9.0:
            severity = "Critical"
        elif score >= 7.0:
            severity = "High"
        elif score >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"
    return severity, score, vector


def _extract_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    if "vulnerabilities" in data:
        return data.get("vulnerabilities") or []
    return data.get("CVE_Items") or []


def _extract_cve_payload(entry: dict[str, Any]) -> tuple[str, str, dict[str, Any], Any]:
    if "cve" in entry and "id" in entry.get("cve", {}):
        cve = entry.get("cve") or {}
        cve_id = cve.get("id") or ""
        desc_list = cve.get("descriptions") or []
        description = ""
        for desc in desc_list:
            if desc.get("lang") == "en":
                description = desc.get("value") or ""
                break
        metrics = cve.get("metrics") or entry.get("metrics") or {}
        configs = entry.get("configurations") or cve.get("configurations") or {}
        return cve_id, description, metrics, configs

    cve = entry.get("cve") or {}
    cve_id = (cve.get("CVE_data_meta") or {}).get("ID") or ""
    description = ""
    desc_data = (cve.get("description") or {}).get("description_data") or []
    for desc in desc_data:
        if desc.get("lang") == "en":
            description = desc.get("value") or ""
            break
    metrics = entry.get("impact") or {}
    configs = entry.get("configurations") or {}
    return cve_id, description, metrics, configs


def _build_index(years: list[int]) -> None:
    feeds = _ensure_feeds(years)
    index_by_product: dict[str, list[dict[str, Any]]] = {}
    index_by_vendor_product: dict[str, list[dict[str, Any]]] = {}
    seen_cves: set[str] = set()
    record_count = 0
    for path in feeds:
        payload = _load_json(path)
        if not payload:
            continue
        for entry in _extract_entries(payload):
            cve_id, description, metrics, configs = _extract_cve_payload(entry)
            if not cve_id:
                continue
            matches = _iter_cpe_matches(configs)
            if not matches:
                continue
            severity, score, vector = _extract_metrics(
                {"metrics": metrics, "impact": metrics}
            )
            for match in matches:
                criteria = match.get("criteria") or match.get("cpe23Uri") or ""
                vendor, product, version = _parse_cpe(criteria)
                if not vendor or not product:
                    continue
                record = {
                    "cve_id": cve_id,
                    "description": description,
                    "severity": severity,
                    "score": score,
                    "vector": vector,
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                    "match": match,
                }
                index_by_vendor_product.setdefault(f"{vendor}:{product}", []).append(
                    record
                )
                index_by_product.setdefault(product, []).append(record)
                record_count += 1
                seen_cves.add(cve_id)
    _index_cache["loaded_years"] = years
    _index_cache["index_by_product"] = index_by_product
    _index_cache["index_by_vendor_product"] = index_by_vendor_product
    _index_cache["built"] = True
    _index_cache["built_at"] = datetime.utcnow().isoformat()
    _index_cache["record_count"] = record_count
    _index_cache["cve_count"] = len(seen_cves)


def _ensure_index() -> None:
    years_back = int(os.getenv("ASM_NVD_YEARS", "2"))
    now_year = datetime.utcnow().year
    years = [now_year - offset for offset in range(years_back)]
    cached = _index_cache.get("loaded_years")
    if cached == years and _index_cache.get("built"):
        return
    _build_index(years)


def _candidate_counts(name: str) -> dict[str, int]:
    vendor, product = _normalize_vendor_product(name)
    index_by_product: dict[str, list[dict[str, Any]]] = _index_cache.get(
        "index_by_product", {}
    )
    index_by_vendor_product: dict[str, list[dict[str, Any]]] = _index_cache.get(
        "index_by_vendor_product", {}
    )
    candidates: list[dict[str, Any]] = []
    if vendor and product:
        candidates.extend(index_by_vendor_product.get(f"{vendor}:{product}", []))
    if product:
        candidates.extend(index_by_product.get(product, []))
    unique_cves = {c.get("cve_id") for c in candidates if c.get("cve_id")}
    return {
        "candidates": len(candidates),
        "unique_cves": len(unique_cves),
    }


def get_cve_status(sample_products: list[str] | None = None) -> dict[str, Any]:
    _ensure_index()
    data_dir = _data_dir()
    files = sorted(data_dir.glob("nvdcve-*.json.gz"))
    file_rows: list[dict[str, Any]] = []
    latest_mtime = None
    for path in files:
        stat = path.stat()
        mtime = datetime.utcfromtimestamp(stat.st_mtime).isoformat()
        file_rows.append(
            {
                "name": path.name,
                "bytes": stat.st_size,
                "modified_utc": mtime,
            }
        )
        latest_mtime = max(latest_mtime or mtime, mtime)
    sample_products = sample_products or ["nginx", "apache", "wordpress"]
    sample_counts = {
        name: _candidate_counts(name) for name in sample_products if name
    }
    return {
        "cache_dir": str(data_dir),
        "cache_files": file_rows,
        "cache_last_updated_utc": latest_mtime,
        "loaded_years": _index_cache.get("loaded_years"),
        "loaded_cve_records": _index_cache.get("record_count", 0),
        "loaded_unique_cves": _index_cache.get("cve_count", 0),
        "index_products": len(_index_cache.get("index_by_product", {})),
        "built_at_utc": _index_cache.get("built_at"),
        "sample_query_counts": sample_counts,
    }


def find_cves(reported_versions: list[dict[str, str]]) -> list[dict[str, Any]]:
    _ensure_index()
    index_by_product: dict[str, list[dict[str, Any]]] = _index_cache.get(
        "index_by_product", {}
    )
    index_by_vendor_product: dict[str, list[dict[str, Any]]] = _index_cache.get(
        "index_by_vendor_product", {}
    )
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    possible_limit = int(os.getenv("ASM_CVE_POSSIBLE_LIMIT", "10"))

    for entry in reported_versions or []:
        confidence = entry.get("confidence")
        raw_name = entry.get("name") or ""
        version = entry.get("version") or ""
        vendor, product = _normalize_vendor_product(raw_name)
        candidates: list[dict[str, Any]] = []
        if vendor and product:
            candidates.extend(index_by_vendor_product.get(f"{vendor}:{product}", []))
        if product:
            candidates.extend(index_by_product.get(product, []))
        if not candidates:
            continue

        if version:
            if confidence not in (None, "high", "medium"):
                continue
            for cve in candidates:
                match = cve.get("match") or {}
                cpe_version = cve.get("version") or ""
                if cpe_version and cpe_version not in ("*", "-", "na"):
                    if _cmp_versions(version, cpe_version) != 0:
                        continue
                if any(
                    match.get(key)
                    for key in (
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    )
                ):
                    if not _version_in_range(version, match):
                        continue
                key = f"{cve.get('cve_id')}:{raw_name}:{version}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "cve": cve.get("cve_id"),
                        "component": raw_name,
                        "version": version,
                        "severity": cve.get("severity") or "Unknown",
                        "score": cve.get("score"),
                        "vector": cve.get("vector"),
                        "source": "nvd",
                        "match_tier": "probable",
                        "match_reason": "version_match",
                    }
                )
            continue

        if confidence not in (None, "high", "medium", "low"):
            continue
        sorted_candidates = sorted(
            candidates,
            key=lambda row: (row.get("score") or 0.0),
            reverse=True,
        )
        for cve in sorted_candidates[:possible_limit]:
            key = f"{cve.get('cve_id')}:{raw_name}:possible"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "cve": cve.get("cve_id"),
                    "component": raw_name,
                    "version": "",
                    "severity": cve.get("severity") or "Unknown",
                    "score": cve.get("score"),
                    "vector": cve.get("vector"),
                    "source": "nvd",
                    "match_tier": "possible",
                    "match_reason": "product_only",
                }
            )
    return findings
