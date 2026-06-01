"""EPSS score enrichment and CISA KEV feed integration."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from functools import lru_cache

import requests

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache: set[str] = set()
_kev_fetched_at: float = 0.0
_KEV_TTL = 3600  # refresh hourly


def fetch_epss(cve_ids: list[str], retries: int = 3) -> dict[str, dict]:
    """
    Fetch EPSS scores for a batch of CVE IDs.
    Returns {cve_id: {"epss": float, "percentile": float}}.
    EPSS API accepts up to 30 IDs per request.
    """
    if not cve_ids:
        return {}

    results: dict[str, dict] = {}
    batch_size = 30

    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i : i + batch_size]
        params = {"cve": ",".join(batch)}

        for attempt in range(1, retries + 1):
            try:
                resp = requests.get(EPSS_API, params=params, timeout=20)
                if resp.status_code == 429:
                    time.sleep(10 * attempt)
                    continue
                resp.raise_for_status()
                data = resp.json()
                for entry in data.get("data", []):
                    cve_id = entry.get("cve", "")
                    try:
                        results[cve_id] = {
                            "epss": float(entry.get("epss", 0)),
                            "percentile": float(entry.get("percentile", 0)),
                        }
                    except (TypeError, ValueError):
                        pass
                break
            except (requests.RequestException, ValueError):
                if attempt == retries:
                    break
                time.sleep(2 ** attempt)

        if i + batch_size < len(cve_ids):
            time.sleep(1)  # courtesy delay between batches

    return results


def get_kev_set() -> set[str]:
    """Return the set of CVE IDs in CISA's Known Exploited Vulnerabilities catalog."""
    global _kev_cache, _kev_fetched_at

    now = time.monotonic()
    if _kev_cache and (now - _kev_fetched_at) < _KEV_TTL:
        return _kev_cache

    try:
        resp = requests.get(KEV_URL, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        _kev_cache = {v["cveID"] for v in vulns if "cveID" in v}
        _kev_fetched_at = now
    except Exception:
        pass  # return stale cache on failure

    return _kev_cache


def is_kev(cve_id: str) -> bool:
    """Return True if CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    return cve_id in get_kev_set()


def enrich_cves(cves: list[dict], log=print) -> list[dict]:
    """
    Add epss_score, epss_percentile, and kev fields to each CVE dict in-place.
    Returns the same list.
    """
    if not cves:
        return cves

    cve_ids = [c["id"] for c in cves if c.get("id")]

    # Fetch EPSS scores
    log(f"  Fetching EPSS scores for {len(cve_ids)} CVE(s)...")
    epss_data = fetch_epss(cve_ids)

    # Refresh KEV set
    log("  Checking CISA KEV catalog...")
    kev = get_kev_set()

    for c in cves:
        cid = c.get("id", "")
        epss = epss_data.get(cid, {})
        c["epss_score"] = epss.get("epss")
        c["epss_percentile"] = epss.get("percentile")
        c["kev"] = cid in kev

    return cves
