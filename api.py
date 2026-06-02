"""
CVE Emailer — REST API + Web Dashboard server.

Run:
    python api.py                    # default port 5000
    python api.py --port 8080        # custom port
    python api.py --host 0.0.0.0     # bind all interfaces

Environment variables:
    API_SECRET   — Bearer token required for write endpoints (optional but recommended)
    DATABASE_URL — Postgres DSN (falls back to SQLite)
"""

from __future__ import annotations

import argparse
import configparser
import json
import os
from datetime import datetime
from functools import wraps
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.memory import MemoryJobStore
from flask import Flask, jsonify, request, send_from_directory, abort
from flask_cors import CORS

import database

_scheduler = BackgroundScheduler(jobstores={"default": MemoryJobStore()})
_scheduler.start()

_HERE = Path(__file__).parent
_DASHBOARD_DIR = _HERE / "dashboard"
_API_SECRET = os.environ.get("API_SECRET", "")

app = Flask(__name__, static_folder=None)
CORS(app)


# ── Auth ──────────────────────────────────────────────────────────────────────

def _require_auth(f):
    """Decorator: enforce Bearer token if API_SECRET is set."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if _API_SECRET:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth[7:] != _API_SECRET:
                abort(401)
        return f(*args, **kwargs)
    return wrapper


# ── Dashboard static files ────────────────────────────────────────────────────

@app.route("/")
@app.route("/dashboard")
def serve_dashboard():
    return send_from_directory(_DASHBOARD_DIR, "index.html")


@app.route("/docs")
def serve_docs():
    return send_from_directory(_DASHBOARD_DIR, "docs.html")


@app.route("/dashboard/<path:filename>")
def serve_static(filename):
    return send_from_directory(_DASHBOARD_DIR, filename)


# ── Health & metrics ──────────────────────────────────────────────────────────

@app.route("/health")
def health():
    try:
        database.list_cve_tables()
        return jsonify({"status": "ok", "ts": datetime.utcnow().isoformat()})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 500


@app.route("/metrics")
def metrics():
    """Prometheus-compatible text exposition + JSON."""
    data = database.get_metrics()
    fmt = request.args.get("format", "json")
    if fmt == "prometheus":
        lines = []
        for k, v in data.items():
            lines.append(f"# HELP cve_emailer_{k} CVE Emailer metric")
            lines.append(f"# TYPE cve_emailer_{k} gauge")
            lines.append(f"cve_emailer_{k} {v}")
        return "\n".join(lines) + "\n", 200, {"Content-Type": "text/plain; version=0.0.4"}
    return jsonify(data)


# ── Dashboard data API ────────────────────────────────────────────────────────

@app.route("/api/dashboard")
def api_dashboard():
    stats = database.get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/history")
def api_history():
    limit = min(int(request.args.get("limit", 100)), 500)
    rows = database.get_history(limit)
    return jsonify(rows)


@app.route("/api/tables")
def api_tables():
    return jsonify(database.list_cve_tables())


@app.route("/api/cves")
def api_cves():
    table = request.args.get("table", "")
    if not table or table not in database.list_cve_tables():
        return jsonify({"error": "invalid or missing table"}), 400

    search = request.args.get("search", "")
    min_sev = request.args.get("min_severity", "NONE")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    limit = min(int(request.args.get("limit", 200)), 1000)
    offset = int(request.args.get("offset", 0))

    rows = database.query_cves(
        table,
        search=search,
        min_severity=min_sev,
        limit=limit,
        offset=offset,
        date_from=date_from,
        date_to=date_to,
    )
    return jsonify(rows)


@app.route("/api/cve/<path:cve_id>")
def api_cve_detail(cve_id: str):
    table = request.args.get("table", "")
    if not table:
        return jsonify({"error": "table parameter required"}), 400
    row = database.get_cve(table, cve_id)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(row)


@app.route("/api/profiles")
def api_profiles():
    return jsonify(database.get_profiles())


@app.route("/api/profiles", methods=["POST"])
@_require_auth
def api_save_profile():
    data = request.get_json(force=True)
    required = ("name",)
    if not all(k in data for k in required):
        return jsonify({"error": "name is required"}), 400
    database.save_profile({
        "name":            data["name"],
        "keywords":        data.get("keywords", ""),
        "min_severity":    data.get("min_severity", "NONE"),
        "recipients":      data.get("recipients", ""),
        "webhook_url":     data.get("webhook_url", ""),
        "slack_webhook":   data.get("slack_webhook", ""),
        "digest_mode":     int(data.get("digest_mode", 0)),
        "digest_schedule": data.get("digest_schedule", "daily"),
    })
    return jsonify({"ok": True})


@app.route("/api/profiles/<name>", methods=["DELETE"])
@_require_auth
def api_delete_profile(name: str):
    database.delete_profile(name)
    return jsonify({"ok": True})


@app.route("/api/scan", methods=["POST"])
@_require_auth
def api_trigger_scan():
    """
    Trigger a one-shot scan via APScheduler. Returns immediately.
    Rejects the request if a scan is already queued or running.
    """
    import search, logger as _log_mod

    existing = _scheduler.get_jobs()
    if existing:
        return jsonify({"ok": False, "message": "A scan is already queued or running."}), 409

    def _run():
        _log_mod.setup()
        database.bootstrap()
        try:
            search.run_once(log=_broadcast_log)
        except Exception as exc:
            import logging
            logging.getLogger("cve_emailer.api").error("Triggered scan failed: %s", exc)
            _broadcast_log(f"[ERROR] Scan failed: {exc}")

    _scheduler.add_job(_run, id="triggered_scan", replace_existing=True)
    return jsonify({"ok": True, "message": "Scan queued."})


@app.route("/api/scan/status")
def api_scan_status():
    jobs = _scheduler.get_jobs()
    return jsonify({"running": bool(jobs), "queued": len(jobs)})


# ── Top CVEs ──────────────────────────────────────────────────────────────────

@app.route("/api/cves/top")
def api_top_cves():
    limit = min(int(request.args.get("limit", 20)), 100)
    return jsonify(database.get_top_cves(limit))


# ── Trend data ────────────────────────────────────────────────────────────────

@app.route("/api/history/trend")
def api_trend():
    limit = min(int(request.args.get("limit", 30)), 100)
    return jsonify(database.get_trend_data(limit))


# ── Digest queue ──────────────────────────────────────────────────────────────

@app.route("/api/digest")
def api_digest_queue():
    return jsonify(database.get_digest_queue_all())


@app.route("/api/digest/send", methods=["POST"])
@_require_auth
def api_digest_send():
    data = request.get_json(force=True) or {}
    profile_name = data.get("profile_name", "")
    count = database.digest_send_now(profile_name)
    return jsonify({"ok": True, "sent": count})


# ── Notification tests ────────────────────────────────────────────────────────

@app.route("/api/notify/test", methods=["POST"])
@_require_auth
def api_notify_test():
    data   = request.get_json(force=True) or {}
    channel = data.get("channel", "email")  # email | slack | webhook

    if channel == "email":
        import mail as _mail
        cfg = configparser.ConfigParser()
        cfg.read(_CONFIG_PATH)
        sender    = os.environ.get("CVE_SENDER_EMAIL",    "").strip() or cfg.get("EMAIL", "senderEmail",    fallback="")
        password  = os.environ.get("CVE_SENDER_PASSWORD", "").strip() or cfg.get("EMAIL", "senderPassword", fallback="")
        rcpt_raw  = os.environ.get("CVE_RECIPIENT_EMAIL", "").strip() or cfg.get("EMAIL", "recipientEmail", fallback="")
        recipients = [r.strip() for r in rcpt_raw.split(",") if r.strip()]
        if not sender or not password or not recipients:
            return jsonify({"ok": False, "error": "Email not configured"}), 400
        try:
            _mail.send_test_email(sender, password, recipients)
            database.notify_log_insert("email", cve_count=0, recipients=rcpt_raw, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("email", cve_count=0, recipients=rcpt_raw, success=False, error=str(exc))
            return jsonify({"ok": False, "error": str(exc)}), 500

    if channel == "slack":
        import notify as _notify
        cfg = configparser.ConfigParser()
        cfg.read(_CONFIG_PATH)
        webhook = os.environ.get("CVE_SLACK_WEBHOOK", "").strip() or cfg.get("DEFAULT", "slackWebhook", fallback="")
        if not webhook:
            return jsonify({"ok": False, "error": "Slack webhook not configured"}), 400
        try:
            _notify.send_slack(webhook, "CVE Emailer test message — Slack integration is working.")
            database.notify_log_insert("slack", cve_count=0, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("slack", cve_count=0, success=False, error=str(exc))
            return jsonify({"ok": False, "error": str(exc)}), 500

    if channel == "webhook":
        import notify as _notify
        cfg = configparser.ConfigParser()
        cfg.read(_CONFIG_PATH)
        webhook = os.environ.get("CVE_WEBHOOK_URL", "").strip() or cfg.get("DEFAULT", "webhookUrl", fallback="")
        if not webhook:
            return jsonify({"ok": False, "error": "Webhook URL not configured"}), 400
        try:
            _notify.send_webhook(webhook, [{"id": "TEST-0001", "description": "CVE Emailer test payload"}])
            database.notify_log_insert("webhook", cve_count=0, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("webhook", cve_count=0, success=False, error=str(exc))
            return jsonify({"ok": False, "error": str(exc)}), 500

    return jsonify({"ok": False, "error": f"Unknown channel: {channel}"}), 400


# ── Scan log (SSE) ────────────────────────────────────────────────────────────

import queue as _queue
import threading as _threading

_log_queue: _queue.Queue = _queue.Queue(maxsize=500)
_log_lock = _threading.Lock()
_log_subscribers: list[_queue.Queue] = []


def _broadcast_log(msg: str) -> None:
    """Push a log line to all active SSE subscribers and the ring buffer."""
    _log_queue.put_nowait(msg) if not _log_queue.full() else None
    with _log_lock:
        dead = []
        for q in _log_subscribers:
            try:
                q.put_nowait(msg)
            except _queue.Full:
                dead.append(q)
        for q in dead:
            _log_subscribers.remove(q)


@app.route("/api/scan/log")
def api_scan_log():
    """Server-Sent Events stream of live scan log lines."""
    sub: _queue.Queue = _queue.Queue(maxsize=200)
    with _log_lock:
        _log_subscribers.append(sub)

    def _stream():
        yield "retry: 2000\n\n"
        # Drain the recent ring buffer first so the client sees recent lines
        recent: list[str] = []
        tmp: _queue.Queue = _queue.Queue()
        while True:
            try:
                recent.append(_log_queue.get_nowait())
            except _queue.Empty:
                break
        for line in recent[-50:]:
            yield f"data: {line}\n\n"
            tmp.put_nowait(line)
        # Restore ring buffer
        while not tmp.empty():
            _log_queue.put_nowait(tmp.get_nowait())

        try:
            while True:
                try:
                    line = sub.get(timeout=25)
                    yield f"data: {line}\n\n"
                except _queue.Empty:
                    yield ": ping\n\n"
        finally:
            with _log_lock:
                if sub in _log_subscribers:
                    _log_subscribers.remove(sub)

    return app.response_class(_stream(), mimetype="text/event-stream",
                               headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── Config API ────────────────────────────────────────────────────────────────

_CONFIG_PATH = _HERE / "config.ini"

# Fields exposed to the dashboard: (section, key, sensitive?)
_CONFIG_FIELDS = [
    ("DEFAULT",     "apiKey",         False),
    ("DEFAULT",     "checkFrequency", False),
    ("DEFAULT",     "minSeverity",    False),
    ("DEFAULT",     "keywords",       False),
    ("DEFAULT",     "webhookUrl",     False),
    ("DEFAULT",     "slackWebhook",   False),
    ("EMAIL",       "senderEmail",    False),
    ("EMAIL",       "senderPassword", True),
    ("EMAIL",       "recipientEmail", False),
    ("EMAIL",       "subjectLine",    False),
    ("JIRA",        "url",            False),
    ("JIRA",        "user",           False),
    ("JIRA",        "token",          True),
    ("JIRA",        "project_key",    False),
    ("JIRA",        "issue_type",     False),
    ("SERVICENOW",  "instance",       False),
    ("SERVICENOW",  "user",           False),
    ("SERVICENOW",  "password",       True),
    ("SERVICENOW",  "category",       False),
]

# Env vars that override config.ini (values are read-only in the UI)
_ENV_OVERRIDES = {
    ("DEFAULT",    "apiKey"):         "NVD_API_KEY",
    ("DEFAULT",    "webhookUrl"):     "CVE_WEBHOOK_URL",
    ("DEFAULT",    "slackWebhook"):   "CVE_SLACK_WEBHOOK",
    ("EMAIL",      "senderEmail"):    "CVE_SENDER_EMAIL",
    ("EMAIL",      "senderPassword"): "CVE_SENDER_PASSWORD",
    ("EMAIL",      "recipientEmail"): "CVE_RECIPIENT_EMAIL",
    ("JIRA",       "url"):            "JIRA_URL",
    ("JIRA",       "user"):           "JIRA_USER",
    ("JIRA",       "token"):          "JIRA_TOKEN",
    ("JIRA",       "project_key"):    "JIRA_PROJECT_KEY",
    ("JIRA",       "issue_type"):     "JIRA_ISSUE_TYPE",
    ("SERVICENOW", "instance"):       "SNOW_INSTANCE",
    ("SERVICENOW", "user"):           "SNOW_USER",
    ("SERVICENOW", "password"):       "SNOW_PASSWORD",
    ("SERVICENOW", "category"):       "SNOW_CATEGORY",
}


def _read_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(_CONFIG_PATH)
    return cfg


@app.route("/api/config")
def api_get_config():
    cfg = _read_config()
    result = {}
    for section, key, sensitive in _CONFIG_FIELDS:
        env_key = _ENV_OVERRIDES.get((section, key))
        env_val = os.environ.get(env_key, "").strip() if env_key else ""
        if env_val:
            value = env_val if not sensitive else "••••••••"
            locked = True
        else:
            value = cfg.get(section, key, fallback="")
            if sensitive and value:
                value = "••••••••"
            locked = False
        result[f"{section}__{key}"] = {"value": value, "locked": locked, "sensitive": sensitive}
    return jsonify(result)


@app.route("/api/config", methods=["POST"])
@_require_auth
def api_save_config():
    data = request.get_json(force=True) or {}
    cfg = _read_config()
    for section, key, _sensitive in _CONFIG_FIELDS:
        field_id = f"{section}__{key}"
        if field_id not in data:
            continue
        env_key = _ENV_OVERRIDES.get((section, key))
        if env_key and os.environ.get(env_key, "").strip():
            continue  # env var takes precedence — don't overwrite ini
        value = str(data[field_id])
        if value == "••••••••":
            continue  # placeholder — user didn't change the password field
        if section != "DEFAULT" and not cfg.has_section(section):
            cfg.add_section(section)
        cfg[section][key] = value
    with open(_CONFIG_PATH, "w") as fh:
        cfg.write(fh)
    return jsonify({"ok": True})


# ── Entry point ───────────────────────────────────────────────────────────────

# ── Watchlist ─────────────────────────────────────────────────────────────────

@app.route("/api/watchlist")
def api_watchlist_get():
    return jsonify(database.watchlist_get())


@app.route("/api/watchlist", methods=["POST"])
@_require_auth
def api_watchlist_add():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    database.watchlist_add(cve_id, data.get("keyword", ""), data.get("notes", ""))
    return jsonify({"ok": True})


@app.route("/api/watchlist/<path:cve_id>", methods=["DELETE"])
@_require_auth
def api_watchlist_remove(cve_id: str):
    database.watchlist_remove(cve_id)
    return jsonify({"ok": True})


@app.route("/api/watchlist/<path:cve_id>/notes", methods=["POST"])
@_require_auth
def api_watchlist_notes(cve_id: str):
    data = request.get_json(force=True) or {}
    database.watchlist_update_notes(cve_id, data.get("notes", ""))
    return jsonify({"ok": True})


# ── CVE Reviews ───────────────────────────────────────────────────────────────

@app.route("/api/review", methods=["POST"])
@_require_auth
def api_review_set():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    database.review_set(cve_id, bool(data.get("reviewed", False)), data.get("notes", ""))
    return jsonify({"ok": True})


@app.route("/api/review/<path:cve_id>")
def api_review_get(cve_id: str):
    r = database.review_get(cve_id)
    return jsonify(r or {})


@app.route("/api/reviews")
def api_reviews_all():
    return jsonify(database.reviews_get_all())


# ── Keyword performance ───────────────────────────────────────────────────────

@app.route("/api/keywords/perf")
def api_keyword_perf():
    return jsonify(database.get_keyword_perf())


# ── Notification log ──────────────────────────────────────────────────────────

@app.route("/api/notify/log")
def api_notify_log():
    limit = min(int(request.args.get("limit", 200)), 500)
    return jsonify(database.notify_log_get(limit))


# ── Analytics ─────────────────────────────────────────────────────────────────

@app.route("/api/analytics/age")
def api_age_distribution():
    return jsonify(database.get_age_distribution())


@app.route("/api/analytics/scatter")
def api_scatter():
    limit = min(int(request.args.get("limit", 500)), 1000)
    return jsonify(database.get_scatter_data(limit))


@app.route("/api/analytics/heatmap")
def api_heatmap():
    days = min(int(request.args.get("days", 90)), 365)
    return jsonify(database.get_discovery_heatmap(days))


@app.route("/api/analytics/severity-over-time")
def api_severity_over_time():
    limit = min(int(request.args.get("limit", 30)), 100)
    return jsonify(database.get_severity_over_time(limit))


# ── Schedule info ─────────────────────────────────────────────────────────────

@app.route("/api/schedule/info")
def api_schedule_info():
    import configparser as _cp
    cfg = _cp.ConfigParser()
    cfg.read(_CONFIG_PATH)
    freq = int(os.environ.get("CVE_CHECK_FREQUENCY", "") or
               cfg.get("DEFAULT", "checkFrequency", fallback="3600") or 3600)
    info = database.get_schedule_info()
    info["check_frequency"] = freq
    return jsonify(info)


# ── Send single CVE to channel from detail panel ──────────────────────────────

@app.route("/api/cve/send", methods=["POST"])
@_require_auth
def api_cve_send():
    data    = request.get_json(force=True) or {}
    channel = data.get("channel", "slack")
    cve     = data.get("cve", {})
    if not cve.get("cve_id"):
        return jsonify({"error": "cve.cve_id required"}), 400

    cfg = _read_config()

    if channel == "slack":
        import notify as _notify
        webhook = os.environ.get("CVE_SLACK_WEBHOOK", "").strip() or cfg.get("DEFAULT", "slackWebhook", fallback="")
        if not webhook:
            return jsonify({"ok": False, "error": "Slack webhook not configured"}), 400
        try:
            _notify.send_slack(webhook, f"CVE Alert: {cve['cve_id']} — {cve.get('severity','?')} "
                               f"(CVSS {cve.get('cvss_score','?')}) — {cve.get('description','')[:200]}")
            database.notify_log_insert("slack", cve_count=1, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("slack", cve_count=1, success=False, error=str(exc))
            return jsonify({"ok": False, "error": str(exc)}), 500

    if channel == "webhook":
        import notify as _notify
        webhook = os.environ.get("CVE_WEBHOOK_URL", "").strip() or cfg.get("DEFAULT", "webhookUrl", fallback="")
        if not webhook:
            return jsonify({"ok": False, "error": "Webhook URL not configured"}), 400
        try:
            _notify.send_webhook(webhook, [cve])
            database.notify_log_insert("webhook", cve_count=1, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("webhook", cve_count=1, success=False, error=str(exc))
            return jsonify({"ok": False, "error": str(exc)}), 500

    if channel == "jira":
        import notify as _notify
        jira_url   = os.environ.get("JIRA_URL", "").strip()   or cfg.get("JIRA", "url",         fallback="")
        jira_user  = os.environ.get("JIRA_USER", "").strip()  or cfg.get("JIRA", "user",        fallback="")
        jira_token = os.environ.get("JIRA_TOKEN", "").strip() or cfg.get("JIRA", "token",       fallback="")
        jira_proj  = os.environ.get("JIRA_PROJECT_KEY", "").strip() or cfg.get("JIRA", "project_key", fallback="")
        jira_type  = os.environ.get("JIRA_ISSUE_TYPE", "").strip()  or cfg.get("JIRA", "issue_type",  fallback="Bug")
        if not all([jira_url, jira_user, jira_token, jira_proj]):
            return jsonify({"ok": False, "error": "Jira not fully configured"}), 400
        try:
            _notify.create_jira_issue(jira_url, jira_user, jira_token, jira_proj, jira_type, cve)
            database.notify_log_insert("jira", cve_count=1, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("jira", cve_count=1, success=False, error=str(exc))
            return jsonify({"ok": False, "error": str(exc)}), 500

    if channel == "servicenow":
        import notify as _notify
        snow_instance = os.environ.get("SNOW_INSTANCE", "").strip() or cfg.get("SERVICENOW", "instance", fallback="")
        snow_user     = os.environ.get("SNOW_USER", "").strip()     or cfg.get("SERVICENOW", "user",     fallback="")
        snow_pass     = os.environ.get("SNOW_PASSWORD", "").strip() or cfg.get("SERVICENOW", "password", fallback="")
        snow_cat      = os.environ.get("SNOW_CATEGORY", "").strip() or cfg.get("SERVICENOW", "category", fallback="Security")
        if not all([snow_instance, snow_user, snow_pass]):
            return jsonify({"ok": False, "error": "ServiceNow not fully configured"}), 400
        try:
            _notify.create_snow_incident(snow_instance, snow_user, snow_pass, snow_cat, cve)
            database.notify_log_insert("servicenow", cve_count=1, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("servicenow", cve_count=1, success=False, error=str(exc))
            return jsonify({"ok": False, "error": str(exc)}), 500

    return jsonify({"ok": False, "error": f"Unknown channel: {channel}"}), 400


# ── CVE Triage ────────────────────────────────────────────────────────────────

@app.route("/api/triage/<path:cve_id>")
def api_triage_get(cve_id: str):
    return jsonify(database.triage_get(cve_id) or {})


@app.route("/api/triage", methods=["POST"])
@_require_auth
def api_triage_set():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    database.triage_set(
        cve_id,
        status=data.get("status", "open"),
        assignee=data.get("assignee", ""),
        due_date=data.get("due_date", ""),
        severity=data.get("severity", ""),
    )
    return jsonify({"ok": True})


@app.route("/api/triage")
def api_triage_all():
    status = request.args.get("status", "")
    return jsonify(database.triage_get_all(status))


@app.route("/api/triage/sla/breached")
def api_triage_sla_breached():
    return jsonify(database.triage_sla_breached())


# ── Suppressions ──────────────────────────────────────────────────────────────

@app.route("/api/suppressions")
def api_suppressions_get():
    return jsonify(database.suppression_get_all())


@app.route("/api/suppressions", methods=["POST"])
@_require_auth
def api_suppression_add():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    database.suppression_add(
        cve_id,
        keyword=data.get("keyword", ""),
        reason=data.get("reason", ""),
        by=data.get("by", ""),
    )
    return jsonify({"ok": True})


@app.route("/api/suppressions/<path:cve_id>", methods=["DELETE"])
@_require_auth
def api_suppression_remove(cve_id: str):
    database.suppression_remove(cve_id)
    return jsonify({"ok": True})


# ── Saved views ───────────────────────────────────────────────────────────────

@app.route("/api/views")
def api_views_get():
    return jsonify(database.saved_views_get())


@app.route("/api/views", methods=["POST"])
@_require_auth
def api_view_set():
    data = request.get_json(force=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    database.saved_view_set(name, data.get("filters", {}))
    return jsonify({"ok": True})


@app.route("/api/views/<path:name>", methods=["DELETE"])
@_require_auth
def api_view_delete(name: str):
    database.saved_view_delete(name)
    return jsonify({"ok": True})


# ── Scan health ───────────────────────────────────────────────────────────────

@app.route("/api/scan/health")
def api_scan_health():
    limit = min(int(request.args.get("limit", 20)), 100)
    return jsonify(database.get_scan_health(limit))


# ── CVSS vector parse ─────────────────────────────────────────────────────────

@app.route("/api/cve/cvss-vector")
def api_cvss_vector():
    """Parse a CVSS v3 vector string into labeled components."""
    vector = request.args.get("v", "")
    result = _parse_cvss_vector(vector)
    return jsonify(result)


def _parse_cvss_vector(v: str) -> dict:
    """Parse CVSS v3 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H into readable labels."""
    LABELS = {
        "AV":  {"N": "Network", "A": "Adjacent", "L": "Local",        "P": "Physical"},
        "AC":  {"L": "Low",     "H": "High"},
        "PR":  {"N": "None",    "L": "Low",       "H": "High"},
        "UI":  {"N": "None",    "R": "Required"},
        "S":   {"U": "Unchanged","C": "Changed"},
        "C":   {"N": "None",    "L": "Low",       "H": "High"},
        "I":   {"N": "None",    "L": "Low",       "H": "High"},
        "A":   {"N": "None",    "L": "Low",       "H": "High"},
    }
    NAMES = {
        "AV": "Attack Vector", "AC": "Attack Complexity",
        "PR": "Privileges Required", "UI": "User Interaction",
        "S":  "Scope", "C": "Confidentiality",
        "I":  "Integrity", "A": "Availability",
    }
    if not v:
        return {}
    parts = v.lstrip("CVSS:3.0/").lstrip("CVSS:3.1/").split("/")
    result = {}
    for part in parts:
        if ":" not in part:
            continue
        key, val = part.split(":", 1)
        label_map = LABELS.get(key, {})
        result[key] = {
            "code":  val,
            "label": label_map.get(val, val),
            "name":  NAMES.get(key, key),
        }
    return result


# ── Config validation ─────────────────────────────────────────────────────────

@app.route("/api/config/validate", methods=["POST"])
@_require_auth
def api_config_validate():
    """Test-connect each configured channel and return status per channel."""
    cfg = _read_config()
    results = {}

    # SMTP
    sender   = os.environ.get("CVE_SENDER_EMAIL",    "").strip() or cfg.get("EMAIL", "senderEmail",    fallback="")
    password = os.environ.get("CVE_SENDER_PASSWORD", "").strip() or cfg.get("EMAIL", "senderPassword", fallback="")
    if sender and password:
        try:
            import smtplib, ssl
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx) as s:
                s.login(sender, password)
            results["email"] = {"ok": True}
        except Exception as exc:
            results["email"] = {"ok": False, "error": str(exc)}
    else:
        results["email"] = {"ok": None, "error": "Not configured"}

    # Slack
    slack = os.environ.get("CVE_SLACK_WEBHOOK", "").strip() or cfg.get("DEFAULT", "slackWebhook", fallback="")
    if slack:
        try:
            import urllib.request, urllib.error
            req = urllib.request.Request(slack, data=b'{"text":"CVE Emailer config test"}',
                                         headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                results["slack"] = {"ok": resp.status == 200}
        except Exception as exc:
            results["slack"] = {"ok": False, "error": str(exc)}
    else:
        results["slack"] = {"ok": None, "error": "Not configured"}

    # Webhook
    webhook = os.environ.get("CVE_WEBHOOK_URL", "").strip() or cfg.get("DEFAULT", "webhookUrl", fallback="")
    if webhook:
        try:
            import urllib.request
            req = urllib.request.Request(webhook, data=b'{"test":true}',
                                         headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                results["webhook"] = {"ok": resp.status < 400}
        except Exception as exc:
            results["webhook"] = {"ok": False, "error": str(exc)}
    else:
        results["webhook"] = {"ok": None, "error": "Not configured"}

    # Jira
    jira_url   = os.environ.get("JIRA_URL", "").strip()   or cfg.get("JIRA", "url",   fallback="")
    jira_user  = os.environ.get("JIRA_USER", "").strip()  or cfg.get("JIRA", "user",  fallback="")
    jira_token = os.environ.get("JIRA_TOKEN", "").strip() or cfg.get("JIRA", "token", fallback="")
    if jira_url and jira_user and jira_token:
        try:
            import urllib.request, base64
            creds = base64.b64encode(f"{jira_user}:{jira_token}".encode()).decode()
            req = urllib.request.Request(f"{jira_url.rstrip('/')}/rest/api/3/myself",
                                         headers={"Authorization": f"Basic {creds}"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                results["jira"] = {"ok": resp.status == 200}
        except Exception as exc:
            results["jira"] = {"ok": False, "error": str(exc)}
    else:
        results["jira"] = {"ok": None, "error": "Not configured"}

    return jsonify(results)


# ── Export all CVEs ───────────────────────────────────────────────────────────

@app.route("/api/cves/export-all")
def api_export_all():
    csv_str = database.export_all_cves_csv()
    return app.response_class(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=cve_export_all_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"},
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def _bootstrap_all():
    database.bootstrap()
    database.bootstrap_watchlist()
    database.bootstrap_reviews()
    database.bootstrap_notify_log()
    database.bootstrap_triage()
    database.bootstrap_suppressions()
    database.bootstrap_saved_views()


def create_app() -> Flask:
    _bootstrap_all()
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    _bootstrap_all()
    app.run(host=args.host, port=args.port, debug=args.debug)
