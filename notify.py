"""Webhook and Slack notification dispatch."""

from __future__ import annotations

import json

import requests

SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH":     ":orange_circle:",
    "MEDIUM":   ":yellow_circle:",
    "LOW":      ":large_green_circle:",
    "NONE":     ":white_circle:",
    "UNKNOWN":  ":white_circle:",
}


def send_slack(webhook_url: str, cves: list[dict], subject: str) -> None:
    """Post a Slack message via incoming webhook."""
    if not webhook_url or not cves:
        return

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": subject}},
        {"type": "divider"},
    ]
    for c in cves[:20]:  # Slack block limit
        emoji = SEVERITY_EMOJI.get(c.get("severity", "UNKNOWN"), ":white_circle:")
        score_str = f" ({c['cvss_score']:.1f})" if c.get("cvss_score") else ""
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *{c['id']}* — {c['severity']}{score_str}\n"
                    f"*Service:* {c['keyword']}\n"
                    f"{c['description'][:300]}{'...' if len(c['description']) > 300 else ''}"
                ),
            },
        })
        if c.get("refs"):
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": " | ".join(
                    f"<{r}|Ref {i+1}>" for i, r in enumerate(c["refs"][:3])
                )}],
            })
        blocks.append({"type": "divider"})

    if len(cves) > 20:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"_...and {len(cves) - 20} more CVEs._"},
        })

    resp = requests.post(
        webhook_url,
        json={"blocks": blocks},
        timeout=15,
    )
    resp.raise_for_status()


def send_webhook(webhook_url: str, cves: list[dict], subject: str) -> None:
    """POST a JSON payload to a generic webhook URL."""
    if not webhook_url or not cves:
        return
    payload = {
        "subject": subject,
        "count": len(cves),
        "cves": [
            {
                "id":           c["id"],
                "keyword":      c["keyword"],
                "severity":     c["severity"],
                "cvss_score":   c.get("cvss_score"),
                "cwe":          c.get("cwe"),
                "description":  c["description"],
                "published":    c["publish_date"],
                "modified":     c["last_modified"],
                "references":   c.get("refs", []),
            }
            for c in cves
        ],
    }
    resp = requests.post(webhook_url, json=payload, timeout=15)
    resp.raise_for_status()
