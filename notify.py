"""Webhook and Slack notification dispatch."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

import requests

_log = logging.getLogger("cve_emailer.notify")

SEVERITY_EMOJI = {
    "CRITICAL": ":red_circle:",
    "HIGH":     ":orange_circle:",
    "MEDIUM":   ":yellow_circle:",
    "LOW":      ":large_green_circle:",
    "NONE":     ":white_circle:",
    "UNKNOWN":  ":white_circle:",
}

# ── Retry queue ───────────────────────────────────────────────────────────────

@dataclass
class _RetryJob:
    fn:       Callable
    args:     tuple
    kwargs:   dict
    channel:  str
    attempts: int = 0
    next_try: float = field(default_factory=time.time)

_retry_queue: deque[_RetryJob] = deque()
_retry_lock  = threading.Lock()
_retry_thread: threading.Thread | None = None
_MAX_ATTEMPTS = 4
_BACKOFF = [30, 120, 300]  # seconds between attempt 1→2, 2→3, 3→4


def _retry_worker() -> None:
    while True:
        time.sleep(10)
        now = time.time()
        with _retry_lock:
            due = [j for j in _retry_queue if j.next_try <= now]
            for j in due:
                _retry_queue.remove(j)
        for job in due:
            try:
                job.fn(*job.args, **job.kwargs)
                _log.info("notify retry succeeded: %s (attempt %d)", job.channel, job.attempts + 1)
            except Exception as exc:
                job.attempts += 1
                if job.attempts < _MAX_ATTEMPTS:
                    delay = _BACKOFF[min(job.attempts - 1, len(_BACKOFF) - 1)]
                    job.next_try = time.time() + delay
                    with _retry_lock:
                        _retry_queue.append(job)
                    _log.warning(
                        "notify %s failed (attempt %d/%d), retrying in %ds: %s",
                        job.channel, job.attempts, _MAX_ATTEMPTS, delay, exc,
                    )
                else:
                    _log.error(
                        "notify %s permanently failed after %d attempts: %s",
                        job.channel, _MAX_ATTEMPTS, exc,
                    )


def _ensure_retry_thread() -> None:
    global _retry_thread
    if _retry_thread is None or not _retry_thread.is_alive():
        _retry_thread = threading.Thread(target=_retry_worker, daemon=True, name="notify-retry")
        _retry_thread.start()


def _dispatch(fn: Callable, args: tuple, kwargs: dict, channel: str) -> None:
    """Call fn; on failure enqueue for retry with exponential backoff."""
    _ensure_retry_thread()
    try:
        fn(*args, **kwargs)
    except Exception as exc:
        _log.warning("notify %s failed, enqueuing for retry: %s", channel, exc)
        job = _RetryJob(fn=fn, args=args, kwargs=kwargs, channel=channel,
                        attempts=1, next_try=time.time() + _BACKOFF[0])
        with _retry_lock:
            _retry_queue.append(job)


def retry_queue_status() -> list[dict]:
    """Return current retry queue contents (for /metrics or logging)."""
    with _retry_lock:
        return [
            {"channel": j.channel, "attempts": j.attempts,
             "next_try_in": max(0, int(j.next_try - time.time()))}
            for j in _retry_queue
        ]


# ── Slack ─────────────────────────────────────────────────────────────────────

def send_slack(webhook_url: str, cves: list[dict], subject: str) -> None:
    """Post a Slack message via incoming webhook."""
    if not webhook_url or not cves:
        return
    _dispatch(_send_slack_raw, (webhook_url, cves, subject), {}, "slack")


def _send_slack_raw(webhook_url: str, cves: list[dict], subject: str) -> None:
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

    resp = requests.post(webhook_url, json={"blocks": blocks}, timeout=15)
    resp.raise_for_status()


# ── Generic webhook ───────────────────────────────────────────────────────────

def send_webhook(webhook_url: str, cves: list[dict], subject: str) -> None:
    """POST a JSON payload to a generic webhook URL."""
    if not webhook_url or not cves:
        return
    _dispatch(_send_webhook_raw, (webhook_url, cves, subject), {}, "webhook")


def _send_webhook_raw(webhook_url: str, cves: list[dict], subject: str) -> None:
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
