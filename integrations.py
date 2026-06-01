"""Third-party ticket integrations: Jira and ServiceNow."""

from __future__ import annotations

import configparser
from pathlib import Path

import requests

_CONFIG_PATH = Path(__file__).parent / "config.ini"


def _load() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(_CONFIG_PATH)
    return cfg


# ── Jira ──────────────────────────────────────────────────────────────────────

def create_jira_ticket(cve: dict) -> str | None:
    """
    Create a Jira issue for a CVE.
    Returns the issue key (e.g. 'SEC-123') or None if Jira is not configured.

    Required config.ini keys under [JIRA]:
        url          — e.g. https://myorg.atlassian.net
        user         — email address
        token        — API token
        project_key  — e.g. SEC
        issue_type   — e.g. Bug (default: Bug)
    """
    cfg = _load()
    if not cfg.has_section("JIRA"):
        return None

    url   = cfg["JIRA"].get("url", "").rstrip("/")
    user  = cfg["JIRA"].get("user", "")
    token = cfg["JIRA"].get("token", "")
    proj  = cfg["JIRA"].get("project_key", "")
    itype = cfg["JIRA"].get("issue_type", "Bug")

    if not all([url, user, token, proj]):
        return None

    severity = cve.get("severity", "UNKNOWN")
    score = cve.get("cvss_score")
    epss = cve.get("epss_score")
    kev = cve.get("kev", False)

    score_str = f"{score:.1f}" if score is not None else "N/A"
    epss_str = f"{epss:.4f}" if epss is not None else "N/A"
    kev_str = "YES — actively exploited per CISA KEV" if kev else "No"

    summary = f"[CVE] {cve['id']} — {severity} severity in {cve.get('keyword', 'Unknown')}"
    description = (
        f"h2. {cve['id']}\n\n"
        f"*Keyword:* {cve.get('keyword', '')}\n"
        f"*Severity:* {severity}\n"
        f"*CVSS Score:* {score_str}\n"
        f"*EPSS Score:* {epss_str} (exploitation probability)\n"
        f"*CISA KEV:* {kev_str}\n"
        f"*Published:* {cve.get('publish_date', '')}\n"
        f"*CWE:* {cve.get('cwe') or 'N/A'}\n\n"
        f"h3. Description\n{cve.get('description', '')}\n\n"
        f"h3. References\n"
        + "\n".join(f"* {r}" for r in (cve.get("refs") or []))
    )

    payload = {
        "fields": {
            "project":   {"key": proj},
            "issuetype": {"name": itype},
            "summary":   summary,
            "description": description,
            "priority": {"name": _jira_priority(severity)},
        }
    }

    resp = requests.post(
        f"{url}/rest/api/2/issue",
        json=payload,
        auth=(user, token),
        headers={"Content-Type": "application/json"},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json().get("key")


def _jira_priority(severity: str) -> str:
    return {
        "CRITICAL": "Highest",
        "HIGH":     "High",
        "MEDIUM":   "Medium",
        "LOW":      "Low",
    }.get(severity.upper(), "Medium")


# ── ServiceNow ────────────────────────────────────────────────────────────────

def create_snow_incident(cve: dict) -> str | None:
    """
    Create a ServiceNow incident for a CVE.
    Returns the incident sys_id or None if ServiceNow is not configured.

    Required config.ini keys under [SERVICENOW]:
        instance  — e.g. myorg.service-now.com
        user      — username
        password  — password or OAuth token
        category  — e.g. Security (default: Security)
    """
    cfg = _load()
    if not cfg.has_section("SERVICENOW"):
        return None

    instance = cfg["SERVICENOW"].get("instance", "").rstrip("/")
    user     = cfg["SERVICENOW"].get("user", "")
    password = cfg["SERVICENOW"].get("password", "")
    category = cfg["SERVICENOW"].get("category", "Security")

    if not all([instance, user, password]):
        return None

    severity = cve.get("severity", "UNKNOWN")
    score = cve.get("cvss_score")
    epss = cve.get("epss_score")
    kev = cve.get("kev", False)

    score_str = f"{score:.1f}" if score is not None else "N/A"
    epss_str = f"{epss:.4f}" if epss is not None else "N/A"
    kev_str = "YES — actively exploited (CISA KEV)" if kev else "No"

    short_desc = f"{cve['id']} — {severity} in {cve.get('keyword', 'Unknown')}"
    work_notes = (
        f"CVE ID: {cve['id']}\n"
        f"Severity: {severity}\n"
        f"CVSS Score: {score_str}\n"
        f"EPSS Score: {epss_str}\n"
        f"CISA KEV: {kev_str}\n"
        f"Published: {cve.get('publish_date', '')}\n"
        f"CWE: {cve.get('cwe') or 'N/A'}\n\n"
        f"Description:\n{cve.get('description', '')}\n\n"
        f"References:\n" + "\n".join(cve.get("refs") or [])
    )

    payload = {
        "short_description": short_desc,
        "description":       work_notes,
        "category":          category,
        "urgency":           _snow_urgency(severity),
        "impact":            _snow_impact(severity),
    }

    url = f"https://{instance}/api/now/table/incident"
    resp = requests.post(
        url,
        json=payload,
        auth=(user, password),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json().get("result", {}).get("sys_id")


def _snow_urgency(severity: str) -> str:
    return {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "3"}.get(severity.upper(), "3")


def _snow_impact(severity: str) -> str:
    return {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "3"}.get(severity.upper(), "3")


# ── Dispatch helper ───────────────────────────────────────────────────────────

def create_tickets(cves: list[dict], log=print) -> None:
    """
    Create Jira and/or ServiceNow tickets for CRITICAL and HIGH CVEs.
    Silently skips if neither integration is configured.
    """
    cfg = _load()
    has_jira = cfg.has_section("JIRA") and cfg["JIRA"].get("url")
    has_snow = cfg.has_section("SERVICENOW") and cfg["SERVICENOW"].get("instance")

    if not has_jira and not has_snow:
        return

    for cve in cves:
        severity = (cve.get("severity") or "").upper()
        if severity not in ("CRITICAL", "HIGH"):
            continue

        if has_jira:
            try:
                key = create_jira_ticket(cve)
                if key:
                    log(f"  Jira ticket created: {key} for {cve['id']}")
            except Exception as exc:
                log(f"  [yellow]Jira ticket failed for {cve['id']}: {exc}[/yellow]")

        if has_snow:
            try:
                sys_id = create_snow_incident(cve)
                if sys_id:
                    log(f"  ServiceNow incident created: {sys_id} for {cve['id']}")
            except Exception as exc:
                log(f"  [yellow]ServiceNow incident failed for {cve['id']}: {exc}[/yellow]")
