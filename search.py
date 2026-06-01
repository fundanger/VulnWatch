"""CVE search, processing, and scheduling."""

from __future__ import annotations

import re
import time
from datetime import datetime
from threading import Event
from urllib.parse import quote_plus

import requests

import database
import mail

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000  # NVD max results per request

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


def _get_severity(cve: dict) -> str:
    """Extract highest available CVSS severity label."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return entries[0]["cvssData"]["baseSeverity"].upper()
            except (KeyError, IndexError):
                pass
    return "UNKNOWN"


def _fetch_page(keyword: str, start: int, headers: dict, retries: int = 4) -> dict:
    url = _keyword_url(keyword, start)
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            if attempt == retries:
                raise
            wait = 2 ** attempt
            time.sleep(wait)
    raise RuntimeError("unreachable")


def fetch_all_cves(keyword: str, headers: dict, log=print) -> list[dict]:
    """Fetch every page from NVD for this keyword, handling pagination."""
    first = _fetch_page(keyword, 0, headers)
    total = first.get("totalResults", 0)
    vulns = first.get("vulnerabilities", [])
    log(f"  {keyword.strip()}: {total} total result(s)")

    start = PAGE_SIZE
    while start < total:
        time.sleep(3)  # NVD rate-limit between pages
        page = _fetch_page(keyword, start, headers)
        vulns.extend(page.get("vulnerabilities", []))
        start += PAGE_SIZE

    return vulns


def _parse_dt(raw: str) -> str:
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S")


def process_keyword(keyword: str, cfg, log=print) -> list[dict]:
    """
    Fetch all CVEs for keyword, insert new ones into DB.
    Returns list of new CVE dicts (with severity) sorted critical-first.
    """
    table = re.sub(r"\W+", "_", keyword.strip())
    database.create_table(table)
    time.sleep(3)  # courtesy delay before first request

    vulns = fetch_all_cves(keyword, _api_headers(cfg), log=log)

    new_cves = []
    for v in vulns:
        cve = v["cve"]
        cve_id = cve["id"]
        publish_date = _parse_dt(cve["published"])
        last_modified = _parse_dt(cve["lastModified"])
        description = cve["descriptions"][0]["value"]
        severity = _get_severity(cve)
        numeric_id = re.sub(r"\D", "", cve_id)

        is_new = database.insert_cve(table, numeric_id, publish_date, last_modified, description, severity)
        if is_new:
            new_cves.append({
                "keyword": keyword.strip(),
                "id": cve_id,
                "publish_date": publish_date,
                "last_modified": last_modified,
                "description": description,
                "severity": severity,
            })

    new_cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    log(f"  {keyword.strip()}: {len(new_cves)} new CVE(s)")
    return new_cves


def run_once(log=print, stop_event: Event | None = None) -> bool:
    """
    Run one full scan cycle. Reloads config fresh each call.
    Returns True if email was sent.
    """
    cfg = _load_config()

    keyword_file = cfg["DEFAULT"].get("txtList", "").strip()
    with open(keyword_file) as f:
        keywords = [ln.strip() for ln in f if ln.strip()]

    log(f"Scanning {len(keywords)} keyword(s)...")
    all_new: list[dict] = []
    for kw in keywords:
        if stop_event and stop_event.is_set():
            log("Scan stopped early.")
            return False
        all_new.extend(process_keyword(kw, cfg, log=log))

    if not all_new:
        log("No new CVEs found.")
        return False

    body = _build_email_body(all_new)
    log(f"Found {len(all_new)} new CVE(s) — sending email...")
    recipients = [r.strip() for r in cfg["EMAIL"]["recipientEmail"].split(",") if r.strip()]
    mail.send_email(
        sender=cfg["EMAIL"]["senderEmail"],
        password=cfg["EMAIL"]["senderPassword"],
        recipients=recipients,
        subject=cfg["EMAIL"]["subjectLine"],
        body=body,
    )
    log("Email sent.")
    return True


def _build_email_body(cves: list[dict]) -> str:
    lines = []
    for c in cves:
        lines.append(f"Service: {c['keyword']}")
        lines.append(f"{c['id']}  |  Severity: {c['severity']}")
        lines.append(f"Published:   {c['publish_date']}")
        lines.append(f"Modified:    {c['last_modified']}")
        lines.append(f"Description: {c['description']}")
        lines.append("")
    return "\n".join(lines)


def timed_loop(log=print, stop_event: Event | None = None) -> None:
    while True:
        cfg = _load_config()
        interval = int(cfg["DEFAULT"]["checkFrequency"])
        log(f"Starting scan (interval: {interval}s)...")
        try:
            run_once(log=log, stop_event=stop_event)
        except Exception as exc:
            log(f"[bold red]Scan error:[/bold red] {exc}")

        # Interruptible sleep — wakes immediately when stop_event fires
        deadline = time.monotonic() + interval
        while time.monotonic() < deadline:
            if stop_event and stop_event.is_set():
                log("Loop stopped.")
                return
            time.sleep(1)

        if stop_event and stop_event.is_set():
            log("Loop stopped.")
            return
