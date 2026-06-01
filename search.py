"""CVE search, enrichment, filtering, and scheduling."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime
from threading import Event
from urllib.parse import quote_plus

import requests

import database
import mail
import notify

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


def _load_config():
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read("config.ini")
    return cfg


def _api_headers(cfg) -> dict:
    key = cfg["DEFAULT"].get("apiKey", "").strip()
    return {"apiKey": key} if key else {}


def _keyword_url(keyword: str, start: int = 0) -> str:
    return (
        f"{NVD_BASE}?keywordSearch={quote_plus(keyword.strip())}"
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
    return ", ".join(sorted(cpes)[:10])  # cap at 10


def _get_refs(cve: dict) -> list[str]:
    return [r["url"] for r in cve.get("references", [])[:5] if "url" in r]


def _parse_dt(raw: str) -> str:
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S")


# ── NVD fetch with pagination & retry ────────────────────────────────────────

def _fetch_page(keyword: str, start: int, headers: dict, retries: int = 4) -> dict:
    url = _keyword_url(keyword, start)
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError):
            if attempt == retries:
                raise
            time.sleep(2 ** attempt)
    raise RuntimeError("unreachable")


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


# ── Processing ────────────────────────────────────────────────────────────────

def _passes_threshold(severity: str, cvss_score: float | None, min_severity: str) -> bool:
    rank = SEVERITY_ORDER.get(severity.upper(), 5)
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 5)
    return rank <= threshold


def process_keyword(
    keyword: str,
    cfg,
    log=print,
    min_severity: str = "NONE",
) -> list[dict]:
    """Fetch, enrich, filter, and store CVEs for one keyword. Returns new CVE dicts."""
    kw, override = parse_keyword(keyword)
    effective_min = override or min_severity

    table = re.sub(r"\W+", "_", kw)
    database.create_table(table)
    time.sleep(3)

    vulns = fetch_all_cves(kw, _api_headers(cfg), log=log)

    new_cves: list[dict] = []
    for v in vulns:
        cve = v["cve"]
        cve_id = cve["id"]
        severity = _get_severity(cve)
        cvss_score = _get_cvss_score(cve)

        if not _passes_threshold(severity, cvss_score, effective_min):
            continue

        publish_date = _parse_dt(cve["published"])
        last_modified = _parse_dt(cve["lastModified"])
        description = cve["descriptions"][0]["value"]
        cwe = _get_cwe(cve)
        cpe = _get_cpe(cve)
        refs = _get_refs(cve)
        numeric_id = re.sub(r"\D", "", cve_id)

        is_new = database.insert_cve(
            table, numeric_id, publish_date, last_modified, description,
            severity, cvss_score, cwe, cpe, json.dumps(refs), kw,
        )
        if is_new:
            new_cves.append({
                "keyword":      kw,
                "id":           cve_id,
                "publish_date": publish_date,
                "last_modified":last_modified,
                "description":  description,
                "severity":     severity,
                "cvss_score":   cvss_score,
                "cwe":          cwe,
                "cpe":          cpe,
                "refs":         refs,
            })

    new_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    log(f"  {kw}: {len(new_cves)} new CVE(s) after filtering")
    return new_cves


def _build_email_body(cves: list[dict]) -> str:
    lines = []
    for c in cves:
        score_str = f" ({c['cvss_score']:.1f})" if c.get("cvss_score") else ""
        lines.append(f"Service: {c['keyword']}")
        lines.append(f"{c['id']}  |  Severity: {c['severity']}{score_str}")
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

def _dispatch(cves: list[dict], cfg, log=print,
              recipients: list[str] | None = None,
              webhook_url: str = "",
              slack_url: str = "") -> None:
    subject = cfg["EMAIL"].get("subjectLine", "CVE Alert")
    body = _build_email_body(cves)

    rcpts = recipients or [r.strip() for r in cfg["EMAIL"]["recipientEmail"].split(",") if r.strip()]
    if rcpts:
        mail.send_email(
            sender=cfg["EMAIL"]["senderEmail"],
            password=cfg["EMAIL"]["senderPassword"],
            recipients=rcpts,
            subject=subject,
            body=body,
        )
        log(f"Email sent to {', '.join(rcpts)}.")

    if webhook_url:
        notify.send_webhook(webhook_url, cves, subject)
        log("Webhook dispatched.")

    if slack_url:
        notify.send_slack(slack_url, cves, subject)
        log("Slack notification sent.")


# ── Public scan API ───────────────────────────────────────────────────────────

def run_once(
    log=print,
    stop_event: Event | None = None,
    keywords: list[str] | None = None,
    min_severity: str | None = None,
    recipients: list[str] | None = None,
    webhook_url: str = "",
    slack_url: str = "",
) -> tuple[bool, int]:
    """
    Run one full scan. Returns (emailed, new_cve_count).
    If keywords/min_severity/recipients are None, reads from config.
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
        return False, 0

    log(f"Scanning {len(keywords)} keyword(s) (min severity: {min_severity})...")
    history_id = database.history_start(keywords)

    all_new: list[dict] = []
    error_msg = ""
    try:
        for kw in keywords:
            if stop_event and stop_event.is_set():
                log("Scan stopped early.")
                database.history_finish(history_id, len(all_new), False, "stopped")
                return False, len(all_new)
            all_new.extend(process_keyword(kw, cfg, log=log, min_severity=min_severity))
    except Exception as exc:
        error_msg = str(exc)
        log(f"[bold red]Error during scan:[/bold red] {exc}")

    emailed = False
    if all_new:
        log(f"Found {len(all_new)} new CVE(s) — dispatching notifications...")
        try:
            _dispatch(all_new, cfg, log=log,
                      recipients=recipients,
                      webhook_url=webhook_url,
                      slack_url=slack_url)
            emailed = True
        except Exception as exc:
            error_msg = str(exc)
            log(f"[bold red]Notification error:[/bold red] {exc}")
    else:
        log("No new CVEs found.")

    database.history_finish(history_id, len(all_new), emailed, error_msg)
    return emailed, len(all_new)


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
        run_once(
            log=log,
            stop_event=stop_event,
            keywords=kws or None,
            min_severity=p.get("min_severity", "NONE"),
            recipients=rcpts or None,
            webhook_url=p.get("webhook_url", ""),
            slack_url=p.get("slack_webhook", ""),
        )


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
