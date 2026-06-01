import configparser
import re
import time
from datetime import datetime
from urllib.parse import quote_plus

import requests

import database
import mail

CONFIG = configparser.ConfigParser()
CONFIG.read("config.ini")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _api_headers() -> dict:
    key = CONFIG["DEFAULT"].get("apiKey", "").strip()
    return {"apiKey": key} if key else {}


def _keyword_url(keyword: str) -> str:
    return f"{NVD_BASE}?keywordSearch={quote_plus(keyword.strip())}"


def fetch_cves(keyword: str) -> list[dict]:
    url = _keyword_url(keyword)
    resp = requests.get(url, headers=_api_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def _parse_dt(raw: str) -> str:
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%d %H:%M:%S")


def process_keyword(keyword: str, log=print) -> str:
    """Fetch CVEs for one keyword, insert new ones into DB, return email fragment."""
    table = re.sub(r"\W+", "_", keyword.strip())
    database.create_table(table)
    time.sleep(3)  # NVD rate-limit courtesy delay

    vulns = fetch_cves(keyword)
    log(f"  {keyword.strip()}: {len(vulns)} result(s) from NVD")

    fragment = ""
    for v in vulns:
        cve = v["cve"]
        cve_id = cve["id"]
        publish_date = _parse_dt(cve["published"])
        last_modified = _parse_dt(cve["lastModified"])
        description = cve["descriptions"][0]["value"]
        numeric_id = re.sub(r"\D", "", cve_id)

        is_new = database.insert_cve(table, numeric_id, publish_date, last_modified, description)
        if is_new:
            fragment += (
                f"Service: {keyword.strip()}\n"
                f"{cve_id}\n"
                f"Published:  {publish_date}\n"
                f"Modified:   {last_modified}\n"
                f"Description: {description}\n\n"
            )
    return fragment


def run_once(log=print) -> bool:
    """Run one full scan cycle. Returns True if any email was sent."""
    keyword_file = CONFIG["DEFAULT"]["txtList"].strip()
    with open(keyword_file) as f:
        keywords = [ln.strip() for ln in f if ln.strip()]

    log(f"Scanning {len(keywords)} keyword(s)...")
    body = ""
    for kw in keywords:
        body += process_keyword(kw, log=log)

    if body:
        log("New CVEs found — sending email...")
        mail.send_email(
            sender=CONFIG["EMAIL"]["senderEmail"],
            password=CONFIG["EMAIL"]["senderPassword"],
            recipient=CONFIG["EMAIL"]["recipientEmail"],
            subject=CONFIG["EMAIL"]["subjectLine"],
            body=body,
        )
        log("Email sent.")
        return True

    log("No new CVEs found.")
    return False


def timed_loop(log=print) -> None:
    interval = int(CONFIG["DEFAULT"]["checkFrequency"])
    log(f"Starting — will check every {interval}s.")
    while True:
        run_once(log=log)
        log(f"Sleeping {interval}s until next check...")
        time.sleep(interval)
