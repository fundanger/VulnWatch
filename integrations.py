"""
Third-party ticket integrations: Jira and ServiceNow.

Secrets are read from environment variables first, then config.ini fallback.

Jira env vars:
    JIRA_URL          — e.g. https://myorg.atlassian.net
    JIRA_USER         — email address
    JIRA_TOKEN        — API token
    JIRA_PROJECT_KEY  — e.g. SEC
    JIRA_ISSUE_TYPE   — e.g. Bug (default: Bug)

ServiceNow env vars:
    SNOW_INSTANCE     — e.g. myorg.service-now.com
    SNOW_USER         — username
    SNOW_PASSWORD     — password or OAuth token
    SNOW_CATEGORY     — e.g. Security (default: Security)
"""

from __future__ import annotations

import configparser
import os
from pathlib import Path

import requests

_CONFIG_PATH = Path(__file__).parent / "config.ini"


def _load_ini() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(_CONFIG_PATH)
    return cfg


def _get(env_key: str, section: str, ini_key: str, default: str = "") -> str:
    """Return env var if set, else config.ini value, else default."""
    val = os.environ.get(env_key, "").strip()
    if val:
        return val
    cfg = _load_ini()
    return cfg.get(section, ini_key, fallback=default).strip()


# ── Jira ──────────────────────────────────────────────────────────────────────

def _jira_config() -> dict:
    return {
        "url":          _get("JIRA_URL",         "JIRA", "url"),
        "user":         _get("JIRA_USER",        "JIRA", "user"),
        "token":        _get("JIRA_TOKEN",       "JIRA", "token"),
        "project_key":  _get("JIRA_PROJECT_KEY", "JIRA", "project_key"),
        "issue_type":   _get("JIRA_ISSUE_TYPE",  "JIRA", "issue_type", "Bug"),
    }


def create_jira_ticket(cve: dict) -> str | None:
    """
    Create a Jira issue for a CVE. Returns the issue key (e.g. 'SEC-123') or None.
    Returns None silently if Jira is not configured.
    """
    cfg = _jira_config()
    if not all([cfg["url"], cfg["user"], cfg["token"], cfg["project_key"]]):
        return None

    severity = cve.get("severity", "UNKNOWN")
    score    = cve.get("cvss_score")
    epss     = cve.get("epss_score")
    kev      = cve.get("kev", False)

    summary = f"[CVE] {cve['id']} — {severity} in {cve.get('keyword', 'Unknown')}"
    description = (
        f"h2. {cve['id']}\n\n"
        f"*Keyword:* {cve.get('keyword','')}\n"
        f"*Severity:* {severity}\n"
        f"*CVSS Score:* {f'{score:.1f}' if score is not None else 'N/A'}\n"
        f"*EPSS Score:* {f'{epss:.4f}' if epss is not None else 'N/A'} (exploitation probability)\n"
        f"*CISA KEV:* {'YES — actively exploited' if kev else 'No'}\n"
        f"*Published:* {cve.get('publish_date','')}\n"
        f"*CWE:* {cve.get('cwe') or 'N/A'}\n\n"
        f"h3. Description\n{cve.get('description','')}\n\n"
        f"h3. References\n" + "\n".join(f"* {r}" for r in (cve.get("refs") or []))
    )

    resp = requests.post(
        f"{cfg['url'].rstrip('/')}/rest/api/2/issue",
        json={
            "fields": {
                "project":    {"key": cfg["project_key"]},
                "issuetype":  {"name": cfg["issue_type"]},
                "summary":    summary,
                "description": description,
                "priority":   {"name": _jira_priority(severity)},
            }
        },
        auth=(cfg["user"], cfg["token"]),
        headers={"Content-Type": "application/json"},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json().get("key")


def _jira_priority(severity: str) -> str:
    return {"CRITICAL": "Highest", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get(
        severity.upper(), "Medium"
    )


# ── ServiceNow ────────────────────────────────────────────────────────────────

def _snow_config() -> dict:
    return {
        "instance": _get("SNOW_INSTANCE", "SERVICENOW", "instance"),
        "user":     _get("SNOW_USER",     "SERVICENOW", "user"),
        "password": _get("SNOW_PASSWORD", "SERVICENOW", "password"),
        "category": _get("SNOW_CATEGORY", "SERVICENOW", "category", "Security"),
    }


def create_snow_incident(cve: dict) -> str | None:
    """
    Create a ServiceNow incident. Returns sys_id or None if not configured.
    """
    cfg = _snow_config()
    if not all([cfg["instance"], cfg["user"], cfg["password"]]):
        return None

    severity = cve.get("severity", "UNKNOWN")
    score    = cve.get("cvss_score")
    epss     = cve.get("epss_score")
    kev      = cve.get("kev", False)

    short_desc = f"{cve['id']} — {severity} in {cve.get('keyword', 'Unknown')}"
    work_notes = (
        f"CVE ID: {cve['id']}\n"
        f"Severity: {severity}\n"
        f"CVSS Score: {f'{score:.1f}' if score is not None else 'N/A'}\n"
        f"EPSS Score: {f'{epss:.4f}' if epss is not None else 'N/A'}\n"
        f"CISA KEV: {'YES — actively exploited' if kev else 'No'}\n"
        f"Published: {cve.get('publish_date','')}\n"
        f"CWE: {cve.get('cwe') or 'N/A'}\n\n"
        f"Description:\n{cve.get('description','')}\n\n"
        f"References:\n" + "\n".join(cve.get("refs") or [])
    )

    resp = requests.post(
        f"https://{cfg['instance'].rstrip('/')}/api/now/table/incident",
        json={
            "short_description": short_desc,
            "description":       work_notes,
            "category":          cfg["category"],
            "urgency":           _snow_urgency(severity),
            "impact":            _snow_urgency(severity),
        },
        auth=(cfg["user"], cfg["password"]),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        timeout=20,
    )
    resp.raise_for_status()
    return resp.json().get("result", {}).get("sys_id")


def _snow_urgency(severity: str) -> str:
    return {"CRITICAL": "1", "HIGH": "2", "MEDIUM": "3"}.get(severity.upper(), "3")


# ── Dispatch helper ───────────────────────────────────────────────────────────

def create_tickets(cves: list[dict], log=print) -> None:
    """Create Jira and/or ServiceNow tickets for CRITICAL and HIGH CVEs."""
    jira_cfg = _jira_config()
    snow_cfg  = _snow_config()
    has_jira  = bool(jira_cfg["url"] and jira_cfg["token"])
    has_snow  = bool(snow_cfg["instance"] and snow_cfg["password"])

    if not has_jira and not has_snow:
        return

    for cve in cves:
        if (cve.get("severity") or "").upper() not in ("CRITICAL", "HIGH"):
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
