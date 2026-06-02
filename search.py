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


def _get_refs(cve: dict) -> list[str]:
    return [r["url"] for r in cve.get("references", [])[:5] if "url" in r]


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
    for entry in candidates:
        is_new, is_upgraded = database.insert_cve(
            table, entry["id"], entry["publish_date"], entry["last_modified"],
            entry["description"], entry["severity"], entry["cvss_score"],
            entry["cwe"], entry["cpe"], json.dumps(entry["refs"]), table_key,
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
    log(f"  {table_key}: {len(new_cves)} new, {len(upgraded_cves)} upgraded CVE(s) [CPE scan]")
    return new_cves, upgraded_cves


def run_inventory_scan(
    log=print,
    stop_event: Event | None = None,
    min_severity: str = "NONE",
) -> tuple[int, int]:
    """
    Scan CVEs for every software item in the inventory that has a version and CPE.
    Runs after the normal keyword scan. Returns (new_count, upgraded_count).
    """
    cfg = _load_config()
    items = database.inventory_get_cpe_items()
    if not items:
        return 0, 0

    # Deduplicate by (name, version) — multiple assets may run the same software
    seen: set[tuple[str, str]] = set()
    unique = []
    for item in items:
        key = (item["name"], item["version"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    log(f"CPE inventory scan: {len(unique)} unique software version(s)...")
    all_new, all_upgraded = 0, 0
    for item in unique:
        if stop_event and stop_event.is_set():
            break
        try:
            new, upgraded = process_cpe(
                item["name"], item["version"], item["cpe"],
                cfg, log=log, min_severity=min_severity,
            )
            all_new += len(new)
            all_upgraded += len(upgraded)
        except Exception as exc:
            log(f"  [yellow]CPE scan failed for {item['name']} {item['version']}: {exc}[/yellow]")

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
            lines.append("References:  " + " | ".join(c["refs"]))
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
            mail.send_email(sender=sender, password=password, recipients=rcpts, subject=subject, body=body)
            log(f"Email sent to {', '.join(rcpts)}.")

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
