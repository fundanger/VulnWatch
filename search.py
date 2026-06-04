"""CVE search, enrichment, filtering, and scheduling."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from threading import Event
from urllib.parse import quote_plus

import requests

import database
import epss as epss_mod
import integrations
import logger as _logger
import mail
import notify

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}

_CONFIG_PATH = Path(__file__).parent / "config.ini"

# Last successful NVD API contact — updated on every successful page fetch
_last_nvd_success: datetime | None = None
_last_nvd_error:   str | None      = None


def get_nvd_health() -> dict:
    """Return NVD API health info for the /api/scan/health endpoint."""
    return {
        "last_nvd_success": _last_nvd_success.isoformat() if _last_nvd_success else None,
        "last_nvd_error":   _last_nvd_error,
        "nvd_stale": (
            (datetime.now() - _last_nvd_success).total_seconds() > 7200
            if _last_nvd_success else None
        ),
    }


def _load_config():
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read(_CONFIG_PATH)
    return cfg


def _api_headers(cfg) -> dict:
    key = cfg["DEFAULT"].get("apiKey", "").strip()
    return {"apiKey": key} if key else {}


def _keyword_url(keyword: str, start: int = 0) -> str:
    return (
        f"{NVD_BASE}?keywordSearch={quote_plus(keyword.strip())}"
        f"&resultsPerPage={PAGE_SIZE}&startIndex={start}"
    )


def _cpe_url(cpe_name: str, start: int = 0) -> str:
    return (
        f"{NVD_BASE}?cpeName={quote_plus(cpe_name)}"
        f"&resultsPerPage={PAGE_SIZE}&startIndex={start}"
    )


# ── Per-keyword severity override ─────────────────────────────────────────────
# Syntax: "Apache Knox::HIGH" overrides the global min_severity for that keyword.

def parse_keyword(raw: str) -> tuple[str, str | None]:
    """Returns (keyword, override_severity_or_None)."""
    if "::" in raw:
        kw, _, sev = raw.partition("::")
        return kw.strip(), sev.strip().upper()
    return raw.strip(), None


# ── CVE data extraction ───────────────────────────────────────────────────────

def _get_severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []):
            try:
                return entry["cvssData"]["baseSeverity"].upper()
            except KeyError:
                pass
    return "UNKNOWN"


def _get_cvss_score(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for entry in metrics.get(key, []):
            try:
                return float(entry["cvssData"]["baseScore"])
            except (KeyError, TypeError, ValueError):
                pass
    for entry in metrics.get("cvssMetricV2", []):
        try:
            return float(entry["cvssData"]["baseScore"])
        except (KeyError, TypeError, ValueError):
            pass
    return None


def _get_cwe(cve: dict) -> str:
    cwes = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en":
                cwes.append(d["value"])
    return ", ".join(cwes) if cwes else ""


def _get_cpe(cve: dict) -> str:
    cpes = set()
    for cfg_node in cve.get("configurations", []):
        for node in cfg_node.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.add(match.get("criteria", ""))
    return ", ".join(sorted(cpes)[:10])


def _get_refs(cve: dict) -> list[dict]:
    """Return up to 10 reference objects with url and tags."""
    refs = []
    for r in cve.get("references", [])[:10]:
        if "url" not in r:
            continue
        refs.append({"url": r["url"], "tags": r.get("tags", [])})
    return refs


def _parse_dt(raw: str) -> str:
    # NVD timestamps are usually "%Y-%m-%dT%H:%M:%S.%f" but occasionally omit fractional seconds
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return datetime.fromisoformat(raw.rstrip("Z")).strftime("%Y-%m-%d %H:%M:%S")


# ── NVD fetch with pagination & retry ────────────────────────────────────────

def _fetch_page(keyword: str, start: int, headers: dict, retries: int = 4) -> dict:
    global _last_nvd_success, _last_nvd_error
    url = _keyword_url(keyword, start)
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code in (429, 403):
                # Rate limited — back off longer than the standard retry
                _last_nvd_error = f"HTTP {resp.status_code} rate-limited"
                time.sleep(30 * attempt)
                continue
            resp.raise_for_status()
            _last_nvd_success = datetime.now()
            _last_nvd_error   = None
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            _last_nvd_error = str(exc)
            if attempt == retries:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("NVD fetch failed after all retries")


def fetch_all_cves(keyword: str, headers: dict, log=print) -> list[dict]:
    first = _fetch_page(keyword, 0, headers)
    total = first.get("totalResults", 0)
    vulns = first.get("vulnerabilities", [])
    log(f"  {keyword.strip()}: {total} total result(s) from NVD")

    start = PAGE_SIZE
    while start < total:
        time.sleep(3)
        page = _fetch_page(keyword, start, headers)
        vulns.extend(page.get("vulnerabilities", []))
        start += PAGE_SIZE

    return vulns


def _fetch_page_by_cpe(cpe_name: str, start: int, headers: dict, retries: int = 4) -> dict:
    """Fetch NVD results by exact CPE name (version-aware)."""
    global _last_nvd_success, _last_nvd_error
    url = _cpe_url(cpe_name, start)
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code in (429, 403):
                _last_nvd_error = f"HTTP {resp.status_code} rate-limited"
                time.sleep(30 * attempt)
                continue
            resp.raise_for_status()
            _last_nvd_success = datetime.now()
            _last_nvd_error   = None
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            _last_nvd_error = str(exc)
            if attempt == retries:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("NVD CPE fetch failed after all retries")


def fetch_all_cves_by_cpe(cpe_name: str, headers: dict, log=print) -> list[dict]:
    first = _fetch_page_by_cpe(cpe_name, 0, headers)
    total = first.get("totalResults", 0)
    vulns = first.get("vulnerabilities", [])
    log(f"  CPE {cpe_name}: {total} CVE(s) from NVD")
    start = PAGE_SIZE
    while start < total:
        time.sleep(3)
        page = _fetch_page_by_cpe(cpe_name, start, headers)
        vulns.extend(page.get("vulnerabilities", []))
        start += PAGE_SIZE
    return vulns


# ── Processing ────────────────────────────────────────────────────────────────

def _passes_threshold(severity: str, min_severity: str) -> bool:
    rank = SEVERITY_ORDER.get(severity.upper(), 5)
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 5)
    return rank <= threshold


def process_keyword(
    keyword: str,
    cfg,
    log=print,
    min_severity: str = "NONE",
    enrich_epss: bool = True,
) -> tuple[list[dict], list[dict]]:
    """
    Fetch, enrich, filter, and store CVEs for one keyword.
    Returns (new_cves, upgraded_cves).
    """
    kw, override = parse_keyword(keyword)
    effective_min = override or min_severity

    table = re.sub(r"\W+", "_", kw)
    database.create_table(table)
    time.sleep(3)

    vulns = fetch_all_cves(kw, _api_headers(cfg), log=log)

    # Build candidate list before DB writes so we can batch-fetch EPSS
    candidates: list[dict] = []
    for v in vulns:
        cve = v["cve"]
        severity = _get_severity(cve)
        if not _passes_threshold(severity, effective_min):
            continue
        cvss_score = _get_cvss_score(cve)
        publish_date = _parse_dt(cve["published"])
        last_modified = _parse_dt(cve["lastModified"])
        descriptions = cve.get("descriptions", [])
        description = descriptions[0]["value"] if descriptions else "No description available."
        candidates.append({
            "keyword":       kw,
            "id":            cve["id"],
            "publish_date":  publish_date,
            "last_modified": last_modified,
            "description":   description,
            "severity":      severity,
            "cvss_score":    cvss_score,
            "cwe":           _get_cwe(cve),
            "cpe":           _get_cpe(cve),
            "refs":          _get_refs(cve),
            "epss_score":    None,
            "epss_percentile": None,
            "kev":           False,
        })

    # Batch EPSS + KEV enrichment
    if enrich_epss and candidates:
        try:
            epss_mod.enrich_cves(candidates, log=log)
        except Exception as exc:
            log(f"  [yellow]EPSS enrichment failed: {exc}[/yellow]")

    new_cves: list[dict] = []
    upgraded_cves: list[dict] = []

    for entry in candidates:
        is_new, is_upgraded = database.insert_cve(
            table,
            entry["id"],
            entry["publish_date"],
            entry["last_modified"],
            entry["description"],
            entry["severity"],
            entry["cvss_score"],
            entry["cwe"],
            entry["cpe"],
            json.dumps(entry["refs"]),
            kw,
            epss_score=entry.get("epss_score"),
            epss_percentile=entry.get("epss_percentile"),
            kev=entry.get("kev", False),
        )

        if is_new:
            new_cves.append(entry)
        elif is_upgraded:
            upgraded_cves.append({**entry, "upgraded": True})

    new_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    upgraded_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    log(f"  {kw}: {len(new_cves)} new, {len(upgraded_cves)} upgraded CVE(s)")

    _logger.event("keyword_processed", keyword=kw, new=len(new_cves), upgraded=len(upgraded_cves))
    return new_cves, upgraded_cves


def _versioned_cpe(cpe_template: str, version: str) -> str:
    """Replace the version component (index 5) of a CPE 2.3 string with the real version."""
    parts = cpe_template.split(":")
    if len(parts) >= 6:
        parts[5] = version
        return ":".join(parts)
    return cpe_template


# ── OSV.dev ecosystem mapping ─────────────────────────────────────────────────

# Maps (name_fragment_lower, category, source_fragment) → OSV ecosystem.
# OSV ecosystem strings: https://ossf.github.io/osv-schema/#affectedpackagename-field
_OSV_ECOSYSTEM_MAP: list[tuple[str, str, str, str]] = [
    # (name_substr, category, source_substr, ecosystem)
    # Python packages
    ("",        "python",    "pip",       "PyPI"),
    ("",        "",          "pip",       "PyPI"),
    ("",        "",          "pip3",      "PyPI"),
    # Node / npm
    ("",        "node",      "npm",       "npm"),
    ("",        "",          "npm",       "npm"),
    ("",        "",          "yarn",      "npm"),
    ("",        "",          "pnpm",      "npm"),
    # Java / Maven
    ("",        "java",      "maven",     "Maven"),
    ("",        "",          "mvn",       "Maven"),
    ("",        "",          "gradle",    "Maven"),
    # Ruby
    ("",        "ruby",      "gem",       "RubyGems"),
    ("",        "",          "gem",       "RubyGems"),
    # Go
    ("go",      "runtime",   "",          "Go"),
    ("",        "go",        "",          "Go"),
    # Rust / Cargo
    ("",        "",          "cargo",     "crates.io"),
    # PHP / Composer
    ("",        "php",       "composer",  "Packagist"),
    ("",        "",          "composer",  "Packagist"),
    # Linux distros — use distro-specific ecosystems for backpatch awareness
    ("",        "os",        "dpkg",      "Debian"),
    ("",        "os",        "apt",       "Debian"),
    ("",        "os",        "rpm",       "Red Hat"),
    ("",        "os",        "yum",       "Red Hat"),
    ("",        "os",        "dnf",       "Red Hat"),
    ("",        "os",        "apk",       "Alpine"),
    ("",        "os",        "brew",      "Homebrew"),
    # NuGet (.NET packages) — source set by PS1 scanner
    ("",        "nuget",     "nuget:",    "NuGet"),
    ("",        "",          "nuget:",    "NuGet"),
    # Java JARs — source is "jar:<filename>"; Maven is the best OSV ecosystem
    ("",        "",          "jar:",      "Maven"),
    # Catch-all runtimes by name
    ("python",  "",          "",          "PyPI"),
    ("node",    "",          "",          "npm"),
    ("nodejs",  "",          "",          "npm"),
    ("nginx",   "",          "",          "OSS-Fuzz"),
    ("linux",   "",          "",          "Linux"),
]

# Package name normalisation per ecosystem (OSV is case-sensitive in places)
_OSV_NAME_MAP: dict[str, str] = {
    # common NVD names → OSV package names
    "openssl":              "openssl",
    "openssh":              "openssh",
    "apache http server":   "httpd",
    "nginx":                "nginx",
    "python":               "python3",
    "node.js":              "node",
    "nodejs":               "node",
    "go":                   "stdlib",
    "linux kernel":         "linux",
}


def _osv_ecosystem(name: str, category: str, source: str) -> str:
    """Infer the OSV ecosystem string from inventory metadata."""
    nl = name.lower()
    cl = category.lower()
    sl = source.lower()
    for name_sub, cat_sub, src_sub, eco in _OSV_ECOSYSTEM_MAP:
        if name_sub and name_sub not in nl:
            continue
        if cat_sub and cat_sub not in cl:
            continue
        if src_sub and src_sub not in sl:
            continue
        return eco
    return ""


def _osv_package_name(name: str, ecosystem: str) -> str:
    """Normalise a product name to what OSV expects for the given ecosystem."""
    normalised = _OSV_NAME_MAP.get(name.lower(), name)
    # PyPI names are lowercase with hyphens
    if ecosystem == "PyPI":
        return normalised.lower().replace("_", "-")
    return normalised


OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"


def _osv_severity(vuln: dict) -> tuple[str, float | None]:
    """Extract severity label and CVSS score from an OSV vulnerability dict."""
    # OSV embeds CVSS in severity[] or database_specific
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        stype = sev.get("type", "")
        if "CVSS" in stype and score_str:
            try:
                score = float(score_str.split("/")[0]) if "/" not in score_str else None
                # CVSS vectors look like "CVSS:3.1/AV:N/..." — extract base score differently
                if score is None or score > 10:
                    # It's a vector string, skip score extraction here
                    score = None
            except (ValueError, AttributeError):
                score = None
            # Map severity from CVSS score buckets
            if score is not None:
                if score >= 9.0:   return "CRITICAL", score
                if score >= 7.0:   return "HIGH",     score
                if score >= 4.0:   return "MEDIUM",   score
                if score > 0:      return "LOW",      score
    # Fall back to aliases in the OSV record
    aliases = vuln.get("aliases", [])
    return "UNKNOWN", None


def process_osv(
    name: str,
    version: str,
    ecosystem: str,
    cfg,
    log=print,
    min_severity: str = "NONE",
) -> tuple[list[dict], list[dict]]:
    """
    Query OSV.dev for vulnerabilities affecting a specific package version.
    Handles ecosystem-aware version matching (including distro backpatches).
    Returns (new_cves, upgraded_cves).
    """
    osv_name = _osv_package_name(name, ecosystem)
    table_key = f"{name} {version}"
    table = re.sub(r"\W+", "_", table_key)
    database.create_table(table)

    payload = {
        "version": version,
        "package": {"name": osv_name, "ecosystem": ecosystem},
    }
    try:
        resp = requests.post(OSV_QUERY_URL, json=payload, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log(f"  [yellow]OSV query failed for {name} {version} ({ecosystem}): {exc}[/yellow]")
        return [], []

    vulns = data.get("vulns", [])
    if not vulns:
        return [], []

    # Enrich: fetch full details for each vuln to get CVE aliases + CVSS
    candidates: list[dict] = []
    now = datetime.utcnow().isoformat(timespec="seconds")

    for v in vulns:
        osv_id = v.get("id", "")
        aliases = v.get("aliases", [])
        # Find the CVE ID — prefer the canonical CVE alias
        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
        if not cve_id:
            # Use OSV ID if no CVE alias (GHSA- etc.)
            cve_id = osv_id

        severity, cvss_score = _osv_severity(v)
        if not _passes_threshold(severity, min_severity) and severity != "UNKNOWN":
            continue

        # Build a description from OSV summary/details
        description = v.get("summary") or v.get("details") or "No description available."
        description = description[:1000]

        published = (v.get("published") or now)[:19].replace("T", " ")
        modified  = (v.get("modified")  or now)[:19].replace("T", " ")

        # Extract reference URLs
        refs = [
            {"url": r["url"], "tags": r.get("type", "").split(",")}
            for r in v.get("references", [])[:10]
            if r.get("url")
        ]

        # CWE from database_specific or severity
        cwe = ""
        db_specific = v.get("database_specific", {})
        if isinstance(db_specific, dict):
            cwe = db_specific.get("cwe_ids", [""])[0] if db_specific.get("cwe_ids") else ""

        candidates.append({
            "keyword":         table_key,
            "id":              cve_id,
            "publish_date":    published,
            "last_modified":   modified,
            "description":     description,
            "severity":        severity,
            "cvss_score":      cvss_score,
            "cwe":             cwe,
            "cpe":             "",
            "refs":            refs,
            "epss_score":      None,
            "epss_percentile": None,
            "kev":             False,
            "osv_id":          osv_id,
        })

    if candidates:
        try:
            epss_mod.enrich_cves(candidates, log=log)
        except Exception as exc:
            log(f"  [yellow]EPSS enrichment failed: {exc}[/yellow]")

    new_cves: list[dict] = []
    upgraded_cves: list[dict] = []

    for entry in candidates:
        is_new, is_upgraded = database.insert_cve(
            table, entry["id"], entry["publish_date"], entry["last_modified"],
            entry["description"], entry["severity"], entry["cvss_score"],
            entry["cwe"], entry["cpe"], json.dumps(entry["refs"]), table_key,
            epss_score=entry.get("epss_score"),
            epss_percentile=entry.get("epss_percentile"),
            kev=entry.get("kev", False),
            scan_source="osv",
        )
        if is_new:
            new_cves.append(entry)
        elif is_upgraded:
            upgraded_cves.append({**entry, "upgraded": True})

    new_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    upgraded_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    if new_cves or upgraded_cves:
        log(f"  {table_key} [OSV/{ecosystem}]: {len(new_cves)} new, {len(upgraded_cves)} upgraded CVE(s)")
    return new_cves, upgraded_cves


def process_cpe(
    name: str,
    version: str,
    cpe_template: str,
    cfg,
    log=print,
    min_severity: str = "NONE",
    enrich_epss: bool = True,
) -> tuple[list[dict], list[dict]]:
    """
    Fetch CVEs from NVD using a versioned CPE name. NVD's cpeName parameter
    uses its own version-range data, so only CVEs where this exact version is
    in the vulnerable range are returned — no keyword false-positives.
    Returns (new_cves, upgraded_cves).
    """
    versioned = _versioned_cpe(cpe_template, version)
    # Table name: use product name + version, same sanitisation as keyword tables
    table_key = f"{name} {version}"
    table = re.sub(r"\W+", "_", table_key)
    database.create_table(table)
    time.sleep(3)

    vulns = fetch_all_cves_by_cpe(versioned, _api_headers(cfg), log=log)

    candidates: list[dict] = []
    for v in vulns:
        cve = v["cve"]
        severity = _get_severity(cve)
        if not _passes_threshold(severity, min_severity):
            continue
        cvss_score = _get_cvss_score(cve)
        descriptions = cve.get("descriptions", [])
        description = descriptions[0]["value"] if descriptions else "No description available."
        candidates.append({
            "keyword":       table_key,
            "id":            cve["id"],
            "publish_date":  _parse_dt(cve["published"]),
            "last_modified": _parse_dt(cve["lastModified"]),
            "description":   description,
            "severity":      severity,
            "cvss_score":    cvss_score,
            "cwe":           _get_cwe(cve),
            "cpe":           _get_cpe(cve),
            "refs":          _get_refs(cve),
            "epss_score":    None,
            "epss_percentile": None,
            "kev":           False,
        })

    if enrich_epss and candidates:
        try:
            epss_mod.enrich_cves(candidates, log=log)
        except Exception as exc:
            log(f"  [yellow]EPSS enrichment failed: {exc}[/yellow]")

    new_cves: list[dict] = []
    upgraded_cves: list[dict] = []
    current_cve_ids: set[str] = set()
    for entry in candidates:
        current_cve_ids.add(entry["id"])
        is_new, is_upgraded = database.insert_cve(
            table, entry["id"], entry["publish_date"], entry["last_modified"],
            entry["description"], entry["severity"], entry["cvss_score"],
            entry["cwe"], entry["cpe"], json.dumps(entry["refs"]), table_key,
            epss_score=entry.get("epss_score"),
            epss_percentile=entry.get("epss_percentile"),
            kev=entry.get("kev", False),
            scan_source="cpe",
        )
        if is_new:
            new_cves.append(entry)
        elif is_upgraded:
            upgraded_cves.append({**entry, "upgraded": True})

    # Auto-patch: find CVEs previously inserted by a CPE scan for this table
    # that NVD no longer returns — the installed version is no longer vulnerable.
    previously_cpe_scanned = database.get_cpe_scanned_cve_ids(table)
    no_longer_vulnerable = previously_cpe_scanned - current_cve_ids
    if no_longer_vulnerable:
        patched_count = database.triage_auto_patch(
            list(no_longer_vulnerable),
            patched_version=version,
            actor="inventory-scan",
        )
        if patched_count:
            log(f"  {table_key}: auto-patched {patched_count} CVE(s) no longer vulnerable in v{version}")

    new_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    upgraded_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    log(f"  {table_key}: {len(new_cves)} new, {len(upgraded_cves)} upgraded CVE(s) [CPE scan]")
    return new_cves, upgraded_cves


def run_inventory_scan(
    log=print,
    stop_event: Event | None = None,
    min_severity: str = "NONE",
) -> tuple[int, int]:
    """
    Scan CVEs for every software item in the inventory.
    Runs two complementary passes:
      1. NVD CPE scan — for items with a known CPE string
      2. OSV.dev scan — for items where an ecosystem can be inferred
    Returns (new_count, upgraded_count).
    """
    cfg = _load_config()
    all_new, all_upgraded = 0, 0

    # ── Pass 1: NVD CPE scan (unchanged) ─────────────────────────────────────
    cpe_items = database.inventory_get_cpe_items()
    seen_cpe: set[tuple[str, str]] = set()
    unique_cpe = []
    for item in cpe_items:
        key = (item["name"], item["version"])
        if key not in seen_cpe:
            seen_cpe.add(key)
            unique_cpe.append(item)

    if unique_cpe:
        log(f"NVD CPE inventory scan: {len(unique_cpe)} unique software version(s)...")
    for item in unique_cpe:
        if stop_event and stop_event.is_set():
            return all_new, all_upgraded
        try:
            new, upgraded = process_cpe(
                item["name"], item["version"], item["cpe"],
                cfg, log=log, min_severity=min_severity,
            )
            all_new += len(new)
            all_upgraded += len(upgraded)
        except Exception as exc:
            log(f"  [yellow]CPE scan failed for {item['name']} {item['version']}: {exc}[/yellow]")

    # ── Pass 2: OSV.dev scan ──────────────────────────────────────────────────
    osv_items = database.inventory_get_osv_items()
    seen_osv: set[tuple[str, str, str]] = set()
    unique_osv = []
    for item in osv_items:
        # Resolve ecosystem — use cached value if present
        eco = item.get("osv_ecosystem") or _osv_ecosystem(
            item["name"], item.get("category", ""), item.get("source", "")
        )
        if not eco:
            continue  # No ecosystem mapping — skip OSV for this item
        if item.get("id") and not item.get("osv_ecosystem"):
            database.inventory_set_osv_ecosystem(item["id"], eco)
        key = (item["name"], item["version"], eco)
        if key not in seen_osv:
            seen_osv.add(key)
            unique_osv.append({**item, "osv_ecosystem": eco})

    if unique_osv:
        log(f"OSV.dev inventory scan: {len(unique_osv)} unique package/ecosystem pair(s)...")
    for item in unique_osv:
        if stop_event and stop_event.is_set():
            return all_new, all_upgraded
        try:
            new, upgraded = process_osv(
                item["name"], item["version"], item["osv_ecosystem"],
                cfg, log=log, min_severity=min_severity,
            )
            all_new += len(new)
            all_upgraded += len(upgraded)
        except Exception as exc:
            log(f"  [yellow]OSV scan failed for {item['name']} {item['version']}: {exc}[/yellow]")

    return all_new, all_upgraded


def _build_email_body(cves: list[dict], label: str = "") -> str:
    lines = []
    if label:
        lines.append(label)
        lines.append("=" * len(label))
        lines.append("")
    for c in cves:
        score_str = f" ({c['cvss_score']:.1f})" if c.get("cvss_score") else ""
        upgraded_tag = "  [SEVERITY UPGRADED]" if c.get("upgraded") else ""
        lines.append(f"Service: {c['keyword']}")
        lines.append(f"{c['id']}  |  Severity: {c['severity']}{score_str}{upgraded_tag}")
        if c.get("cwe"):
            lines.append(f"CWE:         {c['cwe']}")
        if c.get("cpe"):
            lines.append(f"Affected:    {c['cpe']}")
        lines.append(f"Published:   {c['publish_date']}")
        lines.append(f"Modified:    {c['last_modified']}")
        lines.append(f"Description: {c['description']}")
        if c.get("refs"):
            urls = [r["url"] if isinstance(r, dict) else r for r in c["refs"]]
            lines.append("References:  " + " | ".join(urls))
        lines.append("")
    return "\n".join(lines)


# ── Dispatch helpers ──────────────────────────────────────────────────────────

def _dispatch(
    cves: list[dict],
    cfg,
    log=print,
    recipients: list[str] | None = None,
    webhook_url: str = "",
    slack_url: str = "",
    subject_suffix: str = "",
) -> None:
    base_subject = cfg["EMAIL"].get("subjectLine", "CVE Alert")
    subject = f"{base_subject}{subject_suffix}" if subject_suffix else base_subject
    body = _build_email_body(cves)

    import os as _os
    sender   = _os.environ.get("CVE_SENDER_EMAIL", "").strip() or cfg["EMAIL"].get("senderEmail", "").strip()
    password = _os.environ.get("CVE_SENDER_PASSWORD", "").strip() or cfg["EMAIL"].get("senderPassword", "").strip()
    rcpt_raw = _os.environ.get("CVE_RECIPIENT_EMAIL", "").strip() or cfg["EMAIL"].get("recipientEmail", "").strip()
    rcpts = recipients or [r.strip() for r in rcpt_raw.split(",") if r.strip()]

    if rcpts:
        if not sender or not password:
            log("[yellow]Email skipped — sender email or password not configured.[/yellow]")
        else:
            try:
                mail.send_email(sender=sender, password=password, recipients=rcpts, subject=subject, body=body)
                log(f"Email sent to {', '.join(rcpts)}.")
            except Exception as exc:
                log(f"[red]Email failed: {exc}[/red]")

    if webhook_url:
        notify.send_webhook(webhook_url, cves, subject)
        log("Webhook dispatched.")

    if slack_url:
        notify.send_slack(slack_url, cves, subject)
        log("Slack notification sent.")


def _dispatch_digest(profile: dict, cfg, log=print) -> None:
    """Send accumulated digest for a profile if due."""
    name = profile["name"]
    schedule = profile.get("digest_schedule") or "daily"
    if not database.digest_due(name, schedule):
        return
    pending = database.digest_get_pending(name)
    if not pending:
        return

    # Reconstruct minimal CVE dicts from queued rows
    cves = [
        {
            "keyword":     r["keyword"],
            "id":          r["cve_id"],
            "severity":    r["severity"],
            "cvss_score":  r["cvss_score"],
            "description": r["description"],
            "publish_date": r["queued_at"],
            "last_modified": r["queued_at"],
            "refs": [],
        }
        for r in pending
    ]

    rcpts = [r.strip() for r in (profile.get("recipients") or "").split(",") if r.strip()]
    _dispatch(
        cves, cfg, log=log,
        recipients=rcpts or None,
        webhook_url=profile.get("webhook_url", ""),
        slack_url=profile.get("slack_webhook", ""),
        subject_suffix=f" — {schedule.capitalize()} Digest ({len(cves)} CVEs)",
    )
    database.digest_mark_sent(name)
    log(f"Digest sent for profile '{name}' ({len(cves)} CVEs).")


# ── Public scan API ───────────────────────────────────────────────────────────

def run_once(
    log=print,
    stop_event: Event | None = None,
    keywords: list[str] | None = None,
    min_severity: str | None = None,
    recipients: list[str] | None = None,
    webhook_url: str = "",
    slack_url: str = "",
    digest_mode: bool = False,
    profile_name: str = "",
) -> tuple[bool, int, int]:
    """
    Run one full scan. Returns (emailed, new_cve_count, upgraded_cve_count).
    """
    cfg = _load_config()
    if keywords is None:
        from tui import load_keywords
        keywords = load_keywords()
    if min_severity is None:
        min_severity = cfg["DEFAULT"].get("minSeverity", "NONE").strip().upper()
    if not webhook_url:
        webhook_url = cfg["DEFAULT"].get("webhookUrl", "").strip()
    if not slack_url:
        slack_url = cfg["DEFAULT"].get("slackWebhook", "").strip()

    if not keywords:
        log("No keywords configured.")
        return False, 0, 0

    log(f"Scanning {len(keywords)} keyword(s) (min severity: {min_severity})...")
    history_id = database.history_start(keywords)

    all_new: list[dict] = []
    all_upgraded: list[dict] = []
    error_msg = ""
    try:
        for kw in keywords:
            if stop_event and stop_event.is_set():
                log("Scan stopped early.")
                database.history_finish(history_id, len(all_new), len(all_upgraded), False, "stopped")
                return False, len(all_new), len(all_upgraded)
            new, upgraded = process_keyword(kw, cfg, log=log, min_severity=min_severity)
            all_new.extend(new)
            all_upgraded.extend(upgraded)

        # CPE-based version scan using software inventory uploaded by scanners
        if not (stop_event and stop_event.is_set()):
            try:
                inv_new, inv_upg = run_inventory_scan(log=log, stop_event=stop_event, min_severity=min_severity)
                if inv_new or inv_upg:
                    log(f"CPE inventory scan: {inv_new} new, {inv_upg} upgraded CVE(s)")
            except Exception as exc:
                log(f"  [yellow]CPE inventory scan error: {exc}[/yellow]")
    except Exception as exc:
        error_msg = str(exc)
        log(f"[bold red]Error during scan:[/bold red] {exc}")

    emailed = False
    alert_cves = all_new + all_upgraded

    if digest_mode:
        if alert_cves:
            database.digest_enqueue(alert_cves, profile_name)
            log(f"Queued {len(alert_cves)} CVE(s) for digest.")
    elif alert_cves:
        suffix = ""
        if all_upgraded and not all_new:
            suffix = " — Severity Upgrades"
        elif all_upgraded:
            suffix = f" (+{len(all_upgraded)} upgraded)"
        log(f"Found {len(all_new)} new, {len(all_upgraded)} upgraded CVE(s) — dispatching notifications...")
        try:
            _dispatch(alert_cves, cfg, log=log,
                      recipients=recipients,
                      webhook_url=webhook_url,
                      slack_url=slack_url,
                      subject_suffix=suffix)
            emailed = True
        except Exception as exc:
            error_msg = str(exc)
            log(f"[bold red]Notification error:[/bold red] {exc}")

        # Create Jira / ServiceNow tickets for critical/high CVEs
        try:
            integrations.create_tickets(alert_cves, log=log)
        except Exception as exc:
            log(f"[yellow]Ticket creation error:[/yellow] {exc}")
    else:
        log("No new or upgraded CVEs found.")

    database.history_finish(history_id, len(all_new), len(all_upgraded), emailed, error_msg)
    _logger.event(
        "scan_complete",
        new=len(all_new),
        upgraded=len(all_upgraded),
        emailed=emailed,
        error=error_msg or None,
    )
    return emailed, len(all_new), len(all_upgraded)


def run_profiles(log=print, stop_event: Event | None = None) -> None:
    """Run each notification profile as a separate scan."""
    profiles = database.get_profiles()
    if not profiles:
        log("No notification profiles configured — running default scan.")
        run_once(log=log, stop_event=stop_event)
        return

    cfg = _load_config()
    for p in profiles:
        if stop_event and stop_event.is_set():
            return
        log(f"[bold]Profile:[/bold] {p['name']}")
        kws = [k.strip() for k in (p.get("keywords") or "").splitlines() if k.strip()]
        rcpts = [r.strip() for r in (p.get("recipients") or "").split(",") if r.strip()]
        digest = bool(p.get("digest_mode", 0))

        run_once(
            log=log,
            stop_event=stop_event,
            keywords=kws or None,
            min_severity=p.get("min_severity", "NONE"),
            recipients=rcpts or None,
            webhook_url=p.get("webhook_url", ""),
            slack_url=p.get("slack_webhook", ""),
            digest_mode=digest,
            profile_name=p["name"],
        )

        # Check if digest is due and send it
        if digest:
            try:
                _dispatch_digest(p, cfg, log=log)
            except Exception as exc:
                log(f"[bold red]Digest error:[/bold red] {exc}")


def timed_loop(log=print, stop_event: Event | None = None, on_sleep=None) -> None:
    while True:
        cfg = _load_config()
        interval = int(cfg["DEFAULT"].get("checkFrequency", "3600"))
        log(f"Starting scan cycle (interval: {interval}s)...")
        try:
            profiles = database.get_profiles()
            if profiles:
                run_profiles(log=log, stop_event=stop_event)
            else:
                run_once(log=log, stop_event=stop_event)
        except Exception as exc:
            log(f"[bold red]Scan error:[/bold red] {exc}")

        if stop_event and stop_event.is_set():
            log("Loop stopped.")
            return

        if on_sleep:
            on_sleep(interval)

        deadline = time.monotonic() + interval
        while time.monotonic() < deadline:
            if stop_event and stop_event.is_set():
                log("Loop stopped.")
                return
            time.sleep(1)
