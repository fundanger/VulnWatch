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
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.memory import MemoryJobStore
from flask import Flask, jsonify, request, send_from_directory, abort, g
from flask_cors import CORS

import database

_scheduler = BackgroundScheduler(jobstores={"default": MemoryJobStore()})
_scheduler.start()

_HERE = Path(__file__).parent
_DASHBOARD_DIR = _HERE / "dashboard"
_API_SECRET = os.environ.get("API_SECRET", "").strip()

_log = logging.getLogger("cve_emailer.api")

# Warn loudly at startup if no secret is set — don't silently leave auth off
if not _API_SECRET:
    _log.warning(
        "API_SECRET is not set. All write endpoints are UNPROTECTED. "
        "Set the API_SECRET environment variable before exposing this server."
    )

app = Flask(__name__, static_folder=None)

# CORS: same-origin by default; set CVE_CORS_ORIGINS=* or a comma-list to widen
_cors_origins = os.environ.get("CVE_CORS_ORIGINS", "")
if _cors_origins:
    CORS(app, origins=[o.strip() for o in _cors_origins.split(",") if o.strip()])
else:
    # No cross-origin requests allowed by default
    CORS(app, origins=[])


# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Tight CSP: dashboard only needs its own scripts/styles + Chart.js CDN
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none';"
    )
    return response


# ── CSRF protection ───────────────────────────────────────────────────────────
# Double-submit cookie pattern. The dashboard JS reads the cookie and echoes
# it in the X-CSRF-Token header on every state-changing request.

_CSRF_COOKIE = "csrf_token"
_CSRF_HEADER = "X-CSRF-Token"

def _get_or_create_csrf_token() -> str:
    token = request.cookies.get(_CSRF_COOKIE, "")
    if not token:
        token = secrets.token_hex(32)
    return token

@app.before_request
def _csrf_check():
    """Enforce CSRF token on all state-changing requests."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    # Skip for machine-to-machine: requests that carry a valid Bearer token are
    # already authenticated and originate from code, not a browser form.
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return
    cookie_token = request.cookies.get(_CSRF_COOKIE, "")
    header_token = request.headers.get(_CSRF_HEADER, "")
    if not cookie_token or not header_token:
        abort(403)
    if not hmac.compare_digest(cookie_token, header_token):
        abort(403)

@app.after_request
def _set_csrf_cookie(response):
    """Ensure the CSRF cookie is always present for the dashboard to read."""
    if not request.cookies.get(_CSRF_COOKIE):
        token = secrets.token_hex(32)
        response.set_cookie(
            _CSRF_COOKIE, token,
            samesite="Strict", httponly=False,  # JS must read it
            secure=False,  # set True when behind HTTPS
        )
    return response


# ── Auth ──────────────────────────────────────────────────────────────────────

def _check_bearer() -> bool:
    """Return True if the request carries a valid global API_SECRET."""
    if not _API_SECRET:
        return False
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return hmac.compare_digest(auth[7:], _API_SECRET)

def _require_auth(f):
    """Decorator: require a valid Bearer token (global secret or per-user key).
    If API_SECRET is not configured AND no RBAC users exist, endpoints are open."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not _API_SECRET:
            # No global secret set — allow unless a per-user key was provided
            # but doesn't match any known user (bad token = reject).
            auth = request.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                user = _get_user_from_request()
                if not user:
                    abort(401)
                g.current_user = user
            return f(*args, **kwargs)
        if _check_bearer():
            return f(*args, **kwargs)
        user = _get_user_from_request()
        if user:
            g.current_user = user
            return f(*args, **kwargs)
        abort(401)
    return wrapper


# ── CVE ID validation ─────────────────────────────────────────────────────────

_CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

def _valid_cve_id(cve_id: str) -> bool:
    return bool(_CVE_RE.match(cve_id))

def _assert_cve_id(cve_id: str):
    if not _valid_cve_id(cve_id):
        abort(400, description="Invalid CVE ID format")


# ── Safe error helper ─────────────────────────────────────────────────────────

def _safe_error(exc: Exception, public_msg: str = "An internal error occurred") -> str:
    """Log the real exception, return only a generic message to the client."""
    _log.error("Internal error: %s", exc, exc_info=True)
    return public_msg


def _err(msg: str, status: int = 400):
    """Return a JSON error response tuple. Use as: return _err('reason', 400)"""
    return jsonify({"ok": False, "error": msg}), status


# ── Dashboard static files ────────────────────────────────────────────────────

@app.route("/")
@app.route("/dashboard")
def serve_dashboard():
    return send_from_directory(_DASHBOARD_DIR, "index.html")


@app.route("/docs")
def serve_docs():
    return send_from_directory(_DASHBOARD_DIR, "docs.html")


@app.route("/favicon.ico")
def favicon():
    return send_from_directory(_DASHBOARD_DIR, "favicon.svg",
                               mimetype="image/svg+xml")


@app.route("/dashboard/<path:filename>")
def serve_static(filename):
    return send_from_directory(_DASHBOARD_DIR, filename)


@app.route("/<path:filename>")
def serve_root_static(filename):
    return send_from_directory(_DASHBOARD_DIR, filename)


@app.route("/scanners/scan_environment.py")
def download_scanner_py():
    return send_from_directory(_HERE, "scan_environment.py",
                               as_attachment=True, mimetype="text/plain")


@app.route("/scanners/scan_environment.sh")
def download_scanner_sh():
    return send_from_directory(_HERE, "scan_environment.sh",
                               as_attachment=True, mimetype="text/plain")


@app.route("/scanners/Scan-Environment.ps1")
def download_scanner_ps1():
    return send_from_directory(_HERE, "Scan-Environment.ps1",
                               as_attachment=True, mimetype="text/plain")


# ── Health & metrics ──────────────────────────────────────────────────────────

@app.route("/health")
def health():
    try:
        database.list_cve_tables()
        return jsonify({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})
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
    search = request.args.get("search", "")
    min_sev = request.args.get("min_severity", "NONE")
    date_from = request.args.get("date_from", "")
    date_to = request.args.get("date_to", "")
    try:
        limit  = min(int(request.args.get("limit", 200)), 500)
        offset = max(int(request.args.get("offset", 0)), 0)
    except (TypeError, ValueError):
        return jsonify({"error": "limit and offset must be integers"}), 400

    all_tables = database.list_cve_tables()

    if table:
        if table not in all_tables:
            return jsonify({"error": "invalid table"}), 400
        tables_to_query = [table]
    else:
        tables_to_query = all_tables

    if not tables_to_query:
        return jsonify([])

    rows = database.query_cves_multi(
        tables_to_query,
        search=search,
        min_severity=min_sev,
        limit=limit,
        offset=offset,
        date_from=date_from,
        date_to=date_to,
    )
    return jsonify(rows)


@app.route("/api/cve/<string:cve_id>")
def api_cve_detail(cve_id: str):
    _assert_cve_id(cve_id)
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


@app.route("/api/digest/preview")
def api_digest_preview():
    return jsonify(database.get_digest_preview())


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
            return jsonify({"ok": False, "error": _safe_error(exc, "Email test failed — check sender credentials")}), 500

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
            return jsonify({"ok": False, "error": _safe_error(exc, "Slack test failed — check webhook URL")}), 500

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
            return jsonify({"ok": False, "error": _safe_error(exc, "Webhook test failed — check URL")}), 500

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
        # Restore all drained items (not just the 50 sent to client)
        for line in recent:
            try:
                _log_queue.put_nowait(line)
            except _queue.Full:
                break

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
    ("DEFAULT",     "apiKey",            False),
    ("DEFAULT",     "checkFrequency",    False),
    ("DEFAULT",     "minSeverity",       False),
    ("DEFAULT",     "keywords",          False),
    ("DEFAULT",     "webhookUrl",        False),
    ("DEFAULT",     "slackWebhook",      False),
    ("REPORT",      "reportSchedule",    False),
    ("REPORT",      "reportRecipients",  False),
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
    ("DEFAULT",     "teamsWebhook",   False),
    ("DEFAULT",     "pagerdutyKey",   True),
    ("DEFAULT",     "opsgenieKey",    True),
    ("LLM",         "provider",       False),
    ("LLM",         "apiKey",         True),
    ("LLM",         "baseUrl",        False),
    ("LLM",         "model",          False),
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
    ("DEFAULT",    "teamsWebhook"):   "TEAMS_WEBHOOK",
    ("DEFAULT",    "pagerdutyKey"):   "PAGERDUTY_ROUTING_KEY",
    ("DEFAULT",    "opsgenieKey"):    "OPSGENIE_API_KEY",
    ("LLM",        "apiKey"):         "LLM_API_KEY",
    ("LLM",        "baseUrl"):        "LLM_BASE_URL",
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
    _assert_cve_id(cve_id)
    database.watchlist_add(cve_id, data.get("keyword", ""), data.get("notes", ""))
    user = _get_user_from_request()
    database.audit_log_insert("watchlist_add", cve_id, "", actor=user["username"] if user else "")
    return jsonify({"ok": True})


@app.route("/api/watchlist/<string:cve_id>", methods=["DELETE"])
@_require_auth
def api_watchlist_remove(cve_id: str):
    _assert_cve_id(cve_id)
    database.watchlist_remove(cve_id)
    return jsonify({"ok": True})


@app.route("/api/watchlist/<string:cve_id>/notes", methods=["POST"])
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
    _assert_cve_id(cve_id)
    database.review_set(cve_id, bool(data.get("reviewed", False)), data.get("notes", ""))
    user = _get_user_from_request()
    database.audit_log_insert("review_set", cve_id,
        f"reviewed={data.get('reviewed', False)}", actor=user["username"] if user else "")
    return jsonify({"ok": True})


@app.route("/api/review/<string:cve_id>")
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
            return jsonify({"ok": False, "error": _safe_error(exc, "Slack delivery failed")}), 500

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
            return jsonify({"ok": False, "error": _safe_error(exc, "Webhook delivery failed")}), 500

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
            return jsonify({"ok": False, "error": _safe_error(exc, "Jira issue creation failed")}), 500

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
            return jsonify({"ok": False, "error": _safe_error(exc, "ServiceNow incident creation failed")}), 500

    if channel == "teams":
        webhook = os.environ.get("TEAMS_WEBHOOK", "").strip() or cfg.get("DEFAULT", "teamsWebhook", fallback="")
        if not webhook:
            return jsonify({"ok": False, "error": "Teams webhook not configured"}), 400
        try:
            _send_teams(webhook, cve)
            database.notify_log_insert("teams", cve_count=1, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("teams", cve_count=1, success=False, error=str(exc))
            return jsonify({"ok": False, "error": _safe_error(exc, "Teams delivery failed")}), 500

    if channel == "pagerduty":
        key = os.environ.get("PAGERDUTY_ROUTING_KEY", "").strip() or cfg.get("DEFAULT", "pagerdutyKey", fallback="")
        if not key:
            return jsonify({"ok": False, "error": "PagerDuty routing key not configured"}), 400
        try:
            _send_pagerduty(key, cve)
            database.notify_log_insert("pagerduty", cve_count=1, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("pagerduty", cve_count=1, success=False, error=str(exc))
            return jsonify({"ok": False, "error": _safe_error(exc, "PagerDuty delivery failed")}), 500

    if channel == "opsgenie":
        key = os.environ.get("OPSGENIE_API_KEY", "").strip() or cfg.get("DEFAULT", "opsgenieKey", fallback="")
        if not key:
            return jsonify({"ok": False, "error": "Opsgenie API key not configured"}), 400
        try:
            _send_opsgenie(key, cve)
            database.notify_log_insert("opsgenie", cve_count=1, success=True)
            return jsonify({"ok": True})
        except Exception as exc:
            database.notify_log_insert("opsgenie", cve_count=1, success=False, error=str(exc))
            return jsonify({"ok": False, "error": _safe_error(exc, "Opsgenie delivery failed")}), 500

    return jsonify({"ok": False, "error": f"Unknown channel: {channel}"}), 400


# ── CVE Triage ────────────────────────────────────────────────────────────────

@app.route("/api/triage/<string:cve_id>")
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
    user = _get_user_from_request()
    actor = user["username"] if user else ""
    database.audit_log_insert("triage_set", cve_id,
        f"status={data.get('status','open')} assignee={data.get('assignee','')}", actor=actor)
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
    _assert_cve_id(cve_id)
    database.suppression_add(
        cve_id,
        keyword=data.get("keyword", ""),
        reason=data.get("reason", ""),
        by=data.get("by", ""),
    )
    user = _get_user_from_request()
    actor = user["username"] if user else data.get("by", "")
    database.audit_log_insert("suppression_add", cve_id, data.get("reason", ""), actor=actor)
    return jsonify({"ok": True})


@app.route("/api/suppressions/<string:cve_id>", methods=["DELETE"])
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


@app.route("/api/views/<string:name>", methods=["DELETE"])
@_require_auth
def api_view_delete(name: str):
    database.saved_view_delete(name)
    return jsonify({"ok": True})


# ── Scan health ───────────────────────────────────────────────────────────────

@app.route("/api/scan/health")
def api_scan_health():
    import search as _search
    limit = min(int(request.args.get("limit", 20)), 100)
    data = database.get_scan_health(limit)
    data["nvd"] = _search.get_nvd_health()
    return jsonify(data)


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
    for prefix in ("CVSS:3.1/", "CVSS:3.0/"):
        if v.startswith(prefix):
            v = v[len(prefix):]
            break
    parts = v.split("/")
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
            _log.error("Email validation failed: %s", exc)
            results["email"] = {"ok": False, "error": "Connection failed — check credentials"}
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
            _log.error("Slack validation failed: %s", exc)
            results["slack"] = {"ok": False, "error": "Connection failed — check webhook URL"}
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
            _log.error("Webhook validation failed: %s", exc)
            results["webhook"] = {"ok": False, "error": "Connection failed — check URL"}
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
            _log.error("Jira validation failed: %s", exc)
            results["jira"] = {"ok": False, "error": "Connection failed — check URL and token"}
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
        headers={"Content-Disposition": f"attachment; filename=cve_export_all_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"},
    )


# ── Exploit intelligence ──────────────────────────────────────────────────────

@app.route("/api/exploit/<string:cve_id>")
def api_exploit_get(cve_id: str):
    return jsonify(database.exploit_get(cve_id) or {})


@app.route("/api/exploit", methods=["POST"])
@_require_auth
def api_exploit_set():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    _assert_cve_id(cve_id)
    database.exploit_upsert(
        cve_id,
        has_exploit=bool(data.get("has_exploit", False)),
        exploit_refs=data.get("exploit_refs", []),
        poc_url=data.get("poc_url", ""),
        source=data.get("source", "manual"),
    )
    return jsonify({"ok": True})


@app.route("/api/exploit")
def api_exploit_all():
    only = request.args.get("has_exploit", "") == "1"
    return jsonify(database.exploit_get_all(has_exploit_only=only))


@app.route("/api/exploit/enrich/<string:cve_id>", methods=["POST"])
@_require_auth
def api_exploit_enrich(cve_id: str):
    """Query GitHub search API for PoC repos mentioning the CVE ID."""
    results = _check_exploit_refs(cve_id)
    return jsonify(results)


def _check_exploit_refs(cve_id: str) -> dict:
    """
    Check public sources for known exploits/PoCs for a CVE:
    - GitHub search API (no auth required for limited queries)
    - NVD references already stored contain exploit-db and packetstorm links
    """
    import urllib.request, urllib.parse, urllib.error

    refs = []
    poc_url = ""
    source_parts = []

    # 1. Check stored NVD references for exploit-db / packetstorm / rapid7
    exploit_domains = ("exploit-db.com", "packetstormsecurity.com",
                       "rapid7.com/db", "sploitus.com", "vulhub.org")
    try:
        tables = database.list_cve_tables()
        for tbl in tables:
            row = database.get_cve(tbl, cve_id)
            if row:
                stored_refs = json.loads(row.get("references_json") or "[]")
                for ref in stored_refs:
                    if any(d in ref for d in exploit_domains):
                        refs.append(ref)
                        if not poc_url:
                            poc_url = ref
                if refs:
                    source_parts.append("nvd-refs")
                break
    except Exception:
        pass

    # 2. GitHub code search (unauthenticated, low rate limit — best effort)
    try:
        q = urllib.parse.quote(f"{cve_id} exploit OR poc OR proof-of-concept")
        gh_url = f"https://api.github.com/search/repositories?q={q}&sort=updated&per_page=5"
        req = urllib.request.Request(gh_url, headers={"Accept": "application/vnd.github+json",
                                                       "User-Agent": "CVE-Emailer/2"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            gh = json.loads(resp.read().decode())
            items = gh.get("items", [])
            for item in items[:5]:
                url = item.get("html_url", "")
                if url:
                    refs.append(url)
                    if not poc_url:
                        poc_url = url
            if items:
                source_parts.append("github")
    except Exception:
        pass

    has_exploit = bool(refs)
    source = ", ".join(source_parts) if source_parts else "auto"

    database.exploit_upsert(cve_id, has_exploit=has_exploit,
                            exploit_refs=refs, poc_url=poc_url, source=source)
    return {
        "cve_id":      cve_id,
        "has_exploit": has_exploit,
        "exploit_refs": refs,
        "poc_url":     poc_url,
        "source":      source,
    }


# ── Asset inventory ───────────────────────────────────────────────────────────

@app.route("/api/assets")
def api_assets_get():
    return jsonify(database.assets_get_all())


@app.route("/api/assets", methods=["POST"])
@_require_auth
def api_asset_save():
    data = request.get_json(force=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    asset_id = database.asset_save(
        name=name,
        cpe=data.get("cpe", ""),
        tags=data.get("tags", ""),
        owner=data.get("owner", ""),
        environment=data.get("environment", ""),
        asset_id=data.get("id"),
        last_scanned_at=data.get("last_scanned_at", ""),
        scan_source=data.get("scan_source", ""),
    )
    return jsonify({"ok": True, "id": asset_id})


@app.route("/api/assets/<int:asset_id>", methods=["DELETE"])
@_require_auth
def api_asset_delete(asset_id: int):
    database.asset_delete(asset_id)
    return jsonify({"ok": True})


@app.route("/api/assets/match")
def api_asset_match():
    """Return assets that match the CPE string of a CVE."""
    cpe = request.args.get("cpe", "")
    return jsonify(database.assets_match_cve(cpe))


@app.route("/api/assets/<int:asset_id>/inventory", methods=["POST"])
@_require_auth
def api_asset_inventory(asset_id: int):
    """Upload software inventory for an asset (list of {name, version, cpe, category, severity, source})."""
    data = request.get_json(force=True) or {}
    items = data.get("items", [])
    if not isinstance(items, list):
        return jsonify({"error": "items must be a list"}), 400
    database.inventory_save(asset_id, items)
    return jsonify({"ok": True, "count": len(items)})


@app.route("/api/assets/inventory")
def api_inventory_get():
    """Return full software inventory across all assets."""
    return jsonify(database.inventory_get_all())


# ── CVE chaining / related CVEs ───────────────────────────────────────────────

@app.route("/api/cve/related")
def api_cve_related():
    """Return CVEs sharing the same CWE or CPE vendor:product prefix."""
    cve_id = request.args.get("cve_id", "")
    cwe    = request.args.get("cwe", "")
    cpe    = request.args.get("cpe", "")
    limit  = min(int(request.args.get("limit", 10)), 50)

    if not cwe and not cpe:
        return jsonify([])

    results: list[dict] = []
    seen: set[str] = {cve_id}
    # Use validated whitelist — never interpolate caller-supplied table names
    valid_tables = set(database.list_cve_tables())
    rank_expr = database._severity_rank_expr()

    from sqlalchemy import text as _text
    with database._connect() as conn:
        for tbl in valid_tables:
            try:
                conditions = []
                params: dict = {"lim": limit, "self_id": cve_id}
                if cwe:
                    first_cwe = cwe.split(",")[0].strip()
                    conditions.append("cwe LIKE :cwe")
                    params["cwe"] = f"%{first_cwe}%"
                if cpe:
                    # Match on vendor:product (first 5 CPE segments)
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        prefix = ":".join(parts[:5])
                        conditions.append("cpe LIKE :cpe")
                        params["cpe"] = f"{prefix}%"

                if not conditions:
                    continue
                where = " AND ".join(conditions) + " AND cve_id != :self_id"
                # tbl is from our own database whitelist — safe to quote and interpolate
                tbl_quoted = f'"{tbl}"'
                rows = conn.execute(_text(
                    f"SELECT *, :tbl_name as _keyword FROM {tbl_quoted} WHERE {where} "
                    f'ORDER BY {rank_expr} LIMIT :lim'
                ), {**params, "tbl_name": tbl}).fetchall()
                for r in rows:
                    d = database._row_to_dict(r)
                    if d["cve_id"] not in seen:
                        seen.add(d["cve_id"])
                        results.append(d)
            except Exception:
                pass

    results.sort(key=lambda r: database.SEVERITY_RANK.get((r.get("severity") or "UNKNOWN").upper(), 5))
    return jsonify(results[:limit])


# ── Patch tracking ────────────────────────────────────────────────────────────
# Stored as extra columns on cve_triage via migration

def _ensure_patch_columns() -> None:
    engine = database._get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        for col, typedef in [
            ("patched_version", "TEXT DEFAULT ''"),
            ("patched_at",      "TEXT DEFAULT ''"),
            ("patched_by",      "TEXT DEFAULT ''"),
        ]:
            database._add_column_if_missing(conn, "cve_triage", col, typedef)
        trans.commit()


@app.route("/api/triage/<string:cve_id>/patch", methods=["POST"])
@_require_auth
def api_triage_patch(cve_id: str):
    _assert_cve_id(cve_id)
    data = request.get_json(force=True) or {}
    from sqlalchemy import text as _text
    now = datetime.now().isoformat(timespec="seconds")
    with database._connect() as conn:
        conn.execute(_text(
            "UPDATE cve_triage SET patched_version=:pv, patched_at=:pa, patched_by=:pb, "
            "updated_at=:now WHERE cve_id=:cid"
        ), {
            "pv": data.get("patched_version", ""),
            "pa": data.get("patched_at", now[:10]),
            "pb": data.get("patched_by", ""),
            "now": now,
            "cid": cve_id,
        })
    user = _get_user_from_request()
    database.audit_log_insert("patch_set", cve_id,
        f"version={data.get('patched_version','')} by={data.get('patched_by','')}",
        actor=user["username"] if user else "")
    return jsonify({"ok": True})


# ── Remediation ──────────────────────────────────────────────────────────────

# CPE vendor:product → (package_manager, package_name_template)
# {version} is replaced with the patched version when known.
_CPE_PATCH_TEMPLATES: list[tuple[str, str, str]] = [
    # (vendor_fragment, product_fragment, command_template)
    # Linux package managers
    ("apache", "http_server",     "sudo apt-get install --only-upgrade apache2\nsudo yum update httpd"),
    ("apache", "tomcat",          "sudo apt-get install --only-upgrade tomcat9\nsudo yum update tomcat"),
    ("nginx",  "nginx",           "sudo apt-get install --only-upgrade nginx\nsudo yum update nginx"),
    ("openssl","openssl",         "sudo apt-get install --only-upgrade openssl\nsudo yum update openssl"),
    ("openssh","openssh",         "sudo apt-get install --only-upgrade openssh-server\nsudo yum update openssh-server"),
    # Python
    ("python", "python",          "pip install --upgrade python\n# Or update via system package manager:\nsudo apt-get install --only-upgrade python3"),
    ("",       "requests",        "pip install --upgrade requests"),
    ("",       "django",          "pip install --upgrade django"),
    ("",       "flask",           "pip install --upgrade flask"),
    ("",       "cryptography",    "pip install --upgrade cryptography"),
    ("",       "pillow",          "pip install --upgrade pillow"),
    ("",       "paramiko",        "pip install --upgrade paramiko"),
    ("",       "urllib3",         "pip install --upgrade urllib3"),
    ("",       "setuptools",      "pip install --upgrade setuptools"),
    ("",       "werkzeug",        "pip install --upgrade werkzeug"),
    # Node / npm
    ("",       "express",         "npm install express@latest\n# or pin to patched version:\nnpm install express@{version}"),
    ("",       "lodash",          "npm install lodash@latest"),
    ("",       "axios",           "npm install axios@latest"),
    ("",       "node-fetch",      "npm install node-fetch@latest"),
    ("",       "jsonwebtoken",    "npm install jsonwebtoken@latest"),
    ("nodejs", "node.js",         "# Update Node.js via nvm:\nnvm install --lts\nnvm use --lts"),
    # Java / Maven
    ("",       "log4j",           "# Update log4j in pom.xml:\n# <log4j.version>{version}</log4j.version>\nmvn dependency:resolve"),
    ("",       "spring",          "# Update Spring Boot in pom.xml:\n# <parent><version>{version}</version></parent>\nmvn dependency:resolve"),
    # Databases
    ("mysql",  "mysql",           "sudo apt-get install --only-upgrade mysql-server\nsudo yum update mysql-server"),
    ("mariadb","mariadb",         "sudo apt-get install --only-upgrade mariadb-server\nsudo yum update mariadb-server"),
    ("postgresql","postgresql",   "sudo apt-get install --only-upgrade postgresql\nsudo yum update postgresql"),
    ("redis",  "redis",           "sudo apt-get install --only-upgrade redis-server\nsudo yum update redis"),
    # Containers / infra
    ("docker", "docker",          "# Update Docker Engine:\nsudo apt-get install --only-upgrade docker-ce docker-ce-cli\n# Or:\ncurl -fsSL https://get.docker.com | sh"),
    ("kubernetes","kubernetes",   "# Update kubectl:\ncurl -LO https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"),
    # Windows / .NET
    ("microsoft","dotnet",        "# Update .NET SDK/runtime:\nwinget upgrade Microsoft.DotNet.Runtime\n# Or download from https://dotnet.microsoft.com/download"),
    ("microsoft","windows",       "# Apply Windows Update:\nwuauclt /detectnow /updatenow\n# Or via PowerShell:\nInstall-Module PSWindowsUpdate; Get-WindowsUpdate -Install"),
    # Catch-all for common OS packages
    ("",       "",                "# Generic — check your package manager:\nsudo apt-get update && sudo apt-get upgrade {product}\nsudo yum update {product}\n# Windows: winget upgrade {product}"),
]


def _template_commands(cve_row: dict) -> str:
    """Generate patch commands from CPE data using static templates."""
    cpe_str = (cve_row.get("cpe") or "").lower()
    keyword = (cve_row.get("keyword") or "").lower()

    # Extract vendor and product from CPE 2.3: cpe:2.3:a:vendor:product:version:...
    vendor, product = "", ""
    parts = cpe_str.split(":")
    if len(parts) >= 5:
        vendor  = parts[3]
        product = parts[4]

    # Fall back to keyword if CPE is absent
    if not vendor and not product:
        product = keyword.replace(" ", "_")

    # Match against templates — most specific first
    for tmpl_vendor, tmpl_product, cmd in _CPE_PATCH_TEMPLATES[:-1]:  # skip catch-all
        v_match = not tmpl_vendor or tmpl_vendor in vendor or tmpl_vendor in product
        p_match = not tmpl_product or tmpl_product in product or tmpl_product in keyword
        if v_match and p_match:
            return cmd.replace("{version}", cve_row.get("cvss_score") and "" or "").replace("{product}", product or keyword)

    # Catch-all
    return _CPE_PATCH_TEMPLATES[-1][2].replace("{product}", product or keyword)


def _llm_config() -> dict:
    """Read LLM provider config from env vars then config.ini."""
    cfg = _read_config()
    provider = os.environ.get("LLM_PROVIDER", "").strip() or cfg.get("LLM", "provider", fallback="").strip()
    api_key  = os.environ.get("LLM_API_KEY",  "").strip() or cfg.get("LLM", "apiKey",   fallback="").strip()
    base_url = os.environ.get("LLM_BASE_URL", "").strip() or cfg.get("LLM", "baseUrl",  fallback="").strip()
    model    = cfg.get("LLM", "model", fallback="").strip()

    # Defaults per provider
    _defaults = {
        "openai":    ("https://api.openai.com/v1",              "gpt-4o-mini"),
        "deepseek":  ("https://api.deepseek.com/v1",            "deepseek-chat"),
        "anthropic": ("https://api.anthropic.com/v1",           "claude-haiku-4-5-20251001"),
        "ollama":    ("http://localhost:11434/v1",               "llama3"),
    }
    if provider in _defaults and not base_url:
        base_url = _defaults[provider][0]
    if provider in _defaults and not model:
        model = _defaults[provider][1]

    return {"provider": provider, "api_key": api_key, "base_url": base_url, "model": model}


def _llm_generate(cve_id: str, cve_row: dict, template_cmds: str) -> str:
    """
    Call the configured LLM to generate platform-specific patch/remediation commands.
    Uses the OpenAI-compatible chat completions API (works with OpenAI, DeepSeek,
    Anthropic-compatible proxies, Ollama, and any custom endpoint).
    """
    import urllib.request, urllib.error

    cfg = _llm_config()
    if not cfg["api_key"] and cfg["provider"] not in ("ollama",):
        raise ValueError("LLM API key not configured. Set LLM_API_KEY env var or configure via Settings.")
    if not cfg["base_url"]:
        raise ValueError("LLM base URL not configured.")

    cpe = cve_row.get("cpe") or ""
    desc = (cve_row.get("description") or "")[:600]
    severity = cve_row.get("severity") or ""
    cvss = cve_row.get("cvss_score") or ""

    prompt = (
        f"You are a security engineer. Generate concise, copy-paste-ready remediation commands "
        f"for the following CVE. Include commands for multiple platforms where applicable "
        f"(Linux apt/yum, Windows winget/PowerShell, pip, npm, etc.). "
        f"Be specific — include exact package names and version pins where known. "
        f"Do not include explanatory prose, only the commands with brief inline comments.\n\n"
        f"CVE: {cve_id}\n"
        f"Severity: {severity} (CVSS {cvss})\n"
        f"Affected CPE: {cpe}\n"
        f"Description: {desc}\n\n"
        f"Template commands already generated (improve/expand on these):\n{template_cmds}"
    )

    payload = json.dumps({
        "model": cfg["model"],
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 600,
        "temperature": 0.2,
    }).encode()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cfg['api_key']}",
    }
    # Anthropic requires a different auth header
    if cfg["provider"] == "anthropic":
        headers["x-api-key"] = cfg["api_key"]
        del headers["Authorization"]
        headers["anthropic-version"] = "2023-06-01"

    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:200]
        raise RuntimeError(f"LLM API error {exc.code}: {body}") from exc


@app.route("/api/remediation/<string:cve_id>")
def api_remediation_get(cve_id: str):
    _assert_cve_id(cve_id)
    table = request.args.get("table", "")
    if table not in database.list_cve_tables():
        return jsonify({"error": "table not found"}), 404
    row = database.get_cve(table, cve_id)
    if not row:
        return jsonify({"error": "CVE not found"}), 404

    # Parse refs to find patch/advisory links
    try:
        refs = json.loads(row.get("references_json") or "[]")
    except Exception:
        refs = []
    patch_refs = [r for r in refs if isinstance(r, dict) and
                  any(t in ("Patch", "Vendor Advisory", "Mitigation") for t in r.get("tags", []))]

    template_cmds = _template_commands(row)
    saved = database.remediation_get(table, cve_id)

    return jsonify({
        "template_commands": template_cmds,
        "ai_commands":       saved.get("remediation_cmds", ""),
        "notes":             saved.get("remediation_notes", ""),
        "patch_refs":        patch_refs,
        "llm_configured":    bool(_llm_config()["api_key"] or _llm_config()["provider"] == "ollama"),
    })


@app.route("/api/remediation/<string:cve_id>/generate", methods=["POST"])
@_require_auth
def api_remediation_generate(cve_id: str):
    _assert_cve_id(cve_id)
    data = request.get_json(force=True) or {}
    table = data.get("table", "")
    if table not in database.list_cve_tables():
        return _err("table not found", 404)
    row = database.get_cve(table, cve_id)
    if not row:
        return _err("CVE not found", 404)
    template_cmds = _template_commands(row)
    try:
        ai_cmds = _llm_generate(cve_id, row, template_cmds)
    except ValueError as exc:
        return _err(str(exc), 400)
    except RuntimeError as exc:
        return _err(str(exc), 502)
    except Exception as exc:
        _log.error("LLM generate error: %s", exc, exc_info=True)
        return _err(str(exc), 500)
    database.remediation_save(table, cve_id,
                              notes=database.remediation_get(table, cve_id).get("remediation_notes", ""),
                              cmds=ai_cmds)
    return jsonify({"ok": True, "ai_commands": ai_cmds})


@app.route("/api/remediation/<string:cve_id>/notes", methods=["POST"])
@_require_auth
def api_remediation_notes(cve_id: str):
    _assert_cve_id(cve_id)
    data = request.get_json(force=True) or {}
    table = data.get("table", "")
    if table not in database.list_cve_tables():
        return _err("table not found", 404)
    notes = str(data.get("notes", ""))[:4000]
    saved = database.remediation_get(table, cve_id)
    database.remediation_save(table, cve_id, notes=notes, cmds=saved.get("remediation_cmds", ""))
    user = _get_user_from_request()
    database.audit_log_insert("remediation_notes", cve_id, f"notes updated ({len(notes)} chars)",
                               actor=user["username"] if user else "")
    return jsonify({"ok": True})


# ── LLM intelligence endpoints ───────────────────────────────────────────────

def _llm_chat(prompt: str, max_tokens: int = 600, system: str = "") -> str:
    """Shared helper: call the configured LLM and return the assistant text."""
    import urllib.request, urllib.error
    cfg = _llm_config()
    if not cfg["api_key"] and cfg["provider"] not in ("ollama",):
        raise ValueError("LLM API key not configured — set LLM_API_KEY or configure in Settings.")
    if not cfg["base_url"]:
        raise ValueError("LLM base URL not configured.")

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = json.dumps({
        "model": cfg["model"],
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }).encode()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cfg['api_key']}",
    }
    if cfg["provider"] == "anthropic":
        headers["x-api-key"] = cfg["api_key"]
        del headers["Authorization"]
        headers["anthropic-version"] = "2023-06-01"

    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:300]
        raise RuntimeError(f"LLM API error {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM unreachable: {exc.reason}") from exc


@app.route("/api/llm/nl-search", methods=["POST"])
def api_llm_nl_search():
    """Translate a natural-language query into Browse CVEs filter params."""
    data = request.get_json(force=True) or {}
    query = str(data.get("query", "")).strip()[:500]
    if not query:
        return _err("query required", 400)

    system = (
        "You are a security data analyst assistant. Convert the user's natural language "
        "query into JSON filter parameters for a CVE database. "
        "Return ONLY valid JSON with these optional keys: "
        '{"search": "text", "severity": "CRITICAL|HIGH|MEDIUM|LOW|NONE", '
        '"date_from": "YYYY-MM-DD", "date_to": "YYYY-MM-DD", "kev": true/false}. '
        "No other text, no markdown, no explanation."
    )
    try:
        raw = _llm_chat(query, max_tokens=200, system=system)
        # Strip markdown fences if present
        raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
        raw = re.sub(r"\n?```$", "", raw.strip())
        filters = json.loads(raw)
        # Validate keys
        allowed = {"search", "severity", "date_from", "date_to", "kev"}
        filters = {k: v for k, v in filters.items() if k in allowed}
        return jsonify({"ok": True, "filters": filters, "interpreted": raw})
    except (ValueError, json.JSONDecodeError) as exc:
        return _err(str(exc), 400)
    except RuntimeError as exc:
        return _err(str(exc), 502)
    except Exception as exc:
        _log.error("nl-search error: %s", exc, exc_info=True)
        return _err(str(exc), 500)


@app.route("/api/llm/summarize/<string:cve_id>")
def api_llm_summarize(cve_id: str):
    """Generate an executive summary for a CVE."""
    _assert_cve_id(cve_id)
    table = request.args.get("table", "")
    if table not in database.list_cve_tables():
        return _err("table not found", 404)
    row = database.get_cve(table, cve_id)
    if not row:
        return _err("CVE not found", 404)

    assets = database.assets_match_cpe(row.get("cpe") or "")
    asset_names = ", ".join(a["name"] for a in assets[:5]) if assets else "none identified"
    triage = database.triage_get(cve_id)
    status = (triage or {}).get("status", "untriaged")

    prompt = (
        f"Write a 3-sentence executive summary of this vulnerability for a non-technical audience. "
        f"Include what it is, what the impact is, and what action is recommended. Be concise.\n\n"
        f"CVE: {cve_id}\n"
        f"Severity: {row.get('severity')} (CVSS {row.get('cvss_score')})\n"
        f"Affected software: {row.get('cpe') or row.get('keyword')}\n"
        f"Description: {(row.get('description') or '')[:500]}\n"
        f"Affected internal assets: {asset_names}\n"
        f"Current status: {status}"
    )
    try:
        summary = _llm_chat(prompt, max_tokens=300,
                            system="You are a security engineer writing for a CISO audience.")
        return jsonify({"ok": True, "summary": summary})
    except ValueError as exc:
        return _err(str(exc), 400)
    except RuntimeError as exc:
        return _err(str(exc), 502)
    except Exception as exc:
        _log.error("summarize error: %s", exc, exc_info=True)
        return _err(str(exc), 500)


@app.route("/api/llm/triage-suggest/<string:cve_id>")
def api_llm_triage_suggest(cve_id: str):
    """Suggest triage status, assignee bucket, and due date based on CVE data + history."""
    _assert_cve_id(cve_id)
    table = request.args.get("table", "")
    if table not in database.list_cve_tables():
        return _err("table not found", 404)
    row = database.get_cve(table, cve_id)
    if not row:
        return _err("CVE not found", 404)

    # Pull recent similar triage decisions (same CWE or same product) for context
    recent = database.triage_get_all()[:20]
    recent_summary = "; ".join(
        f"{t['cve_id']}→{t['status']}" for t in recent[:10]
    ) if recent else "none"

    assets = database.assets_match_cpe(row.get("cpe") or "")
    asset_env = ", ".join(set(a.get("environment", "") for a in assets if a.get("environment"))) or "unknown"

    system = (
        "You are a security triage analyst. Suggest triage fields for a CVE. "
        "Return ONLY JSON with keys: "
        '{"status": "open|investigating|mitigated|wont_fix|false_positive", '
        '"due_days": <integer days from today>, '
        '"rationale": "<one sentence>"}. '
        "No other text."
    )
    prompt = (
        f"CVE: {cve_id}\n"
        f"Severity: {row.get('severity')} CVSS {row.get('cvss_score')}\n"
        f"KEV: {bool(row.get('kev'))}\n"
        f"EPSS: {row.get('epss_score')}\n"
        f"Affected asset environments: {asset_env}\n"
        f"Description: {(row.get('description') or '')[:400]}\n"
        f"Recent triage history: {recent_summary}"
    )
    try:
        raw = _llm_chat(prompt, max_tokens=200, system=system)
        raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
        raw = re.sub(r"\n?```$", "", raw.strip())
        suggestion = json.loads(raw)
        allowed = {"status", "due_days", "rationale"}
        suggestion = {k: v for k, v in suggestion.items() if k in allowed}
        return jsonify({"ok": True, "suggestion": suggestion})
    except (ValueError, json.JSONDecodeError) as exc:
        return _err(str(exc), 400)
    except RuntimeError as exc:
        return _err(str(exc), 502)
    except Exception as exc:
        _log.error("triage-suggest error: %s", exc, exc_info=True)
        return _err(str(exc), 500)


@app.route("/api/llm/noise-rank", methods=["POST"])
@_require_auth
def api_llm_noise_rank():
    """Rank a list of CVEs by actual risk relevance to the environment."""
    data = request.get_json(force=True) or {}
    # Accept either a flat cve_ids list (single table) or a list of {cve_id, table} objects
    raw_ids  = (data.get("cve_ids") or [])[:30]
    table    = str(data.get("table", ""))
    valid_tables = set(database.list_cve_tables())

    if not raw_ids:
        return _err("cve_ids required", 400)

    rows = []
    for item in raw_ids:
        if isinstance(item, dict):
            cid = str(item.get("cve_id", ""))
            tbl = str(item.get("table", table))
        else:
            cid = str(item)
            tbl = table
        if tbl not in valid_tables:
            continue
        r = database.get_cve(tbl, cid)
        if r:
            rows.append(r)

    assets = database.inventory_get_all()
    asset_summary = ", ".join(
        f"{a['name']} {a.get('version','')}".strip() for a in assets[:20]
    ) if assets else "no inventory data"

    cve_lines = "\n".join(
        f"- {r['cve_id']}: {r.get('severity')} CVSS={r.get('cvss_score')} KEV={bool(r.get('kev'))} "
        f"EPSS={r.get('epss_score')} | {(r.get('description') or '')[:120]}"
        for r in rows
    )

    system = (
        "You are a security analyst. Rank the provided CVEs from most to least actionable "
        "given the asset inventory. Return ONLY a JSON array of CVE IDs in ranked order, "
        'e.g. ["CVE-2024-1234", "CVE-2024-5678", ...]. No other text.'
    )
    prompt = (
        f"Asset inventory: {asset_summary}\n\n"
        f"CVEs to rank:\n{cve_lines}"
    )
    try:
        raw = _llm_chat(prompt, max_tokens=400, system=system)
        raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
        raw = re.sub(r"\n?```$", "", raw.strip())
        ranked = json.loads(raw)
        if not isinstance(ranked, list):
            raise ValueError("Expected JSON array")
        # Only return IDs that were in the input
        valid = set(r["cve_id"] for r in rows)
        ranked = [c for c in ranked if c in valid]
        return jsonify({"ok": True, "ranked": ranked})
    except ValueError as exc:
        return _err(str(exc), 400)
    except RuntimeError as exc:
        return _err(str(exc), 502)
    except Exception as exc:
        _log.error("noise-rank error: %s", exc, exc_info=True)
        return _err(str(exc), 500)


@app.route("/api/llm/keyword-expand", methods=["POST"])
def api_llm_keyword_expand():
    """Suggest additional CVE search keywords based on current keyword list."""
    data = request.get_json(force=True) or {}
    current_keywords = (data.get("keywords") or [])[:50]
    if not current_keywords:
        return _err("keywords required", 400)

    assets = database.inventory_get_all()
    asset_products = list({a["name"] for a in assets[:30]})

    system = (
        "You are a threat intelligence analyst. Suggest additional CVE search keywords "
        "that the user is likely missing. Return ONLY a JSON array of keyword strings. "
        "Each keyword should be a product name, library name, or vendor name suitable "
        "for NVD keyword search. No duplicates of existing keywords. Max 15 suggestions. "
        "No other text, no explanation."
    )
    prompt = (
        f"Current keywords: {', '.join(current_keywords)}\n"
        f"Known installed software: {', '.join(asset_products)}\n\n"
        "Suggest related keywords that cover the same tech stack but may be missing."
    )
    try:
        raw = _llm_chat(prompt, max_tokens=300, system=system)
        raw = re.sub(r"^```[a-z]*\n?", "", raw.strip())
        raw = re.sub(r"\n?```$", "", raw.strip())
        suggestions = json.loads(raw)
        if not isinstance(suggestions, list):
            raise ValueError("Expected JSON array")
        # Strip any that already exist (case-insensitive)
        existing_lower = {k.lower() for k in current_keywords}
        suggestions = [s for s in suggestions if str(s).lower() not in existing_lower][:15]
        return jsonify({"ok": True, "suggestions": suggestions})
    except Exception as exc:
        _log.error("keyword-expand error: %s", exc)
        return _err(str(exc), 500)


@app.route("/api/llm/digest-narrative", methods=["POST"])
def api_llm_digest_narrative():
    """Generate a human-readable narrative summary of a scan digest batch."""
    data = request.get_json(force=True) or {}
    cve_list = (data.get("cves") or [])[:50]
    period   = str(data.get("period", "this scan"))
    if not cve_list:
        return _err("cves required", 400)

    by_severity: dict[str, int] = {}
    kev_count = 0
    top_lines = []
    for c in cve_list:
        sev = (c.get("severity") or "UNKNOWN").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        if c.get("kev"):
            kev_count += 1
        if len(top_lines) < 5:
            top_lines.append(
                f"  - {c.get('cve_id')}: {sev} CVSS={c.get('cvss_score')} — "
                f"{(c.get('description') or '')[:100]}"
            )

    sev_str = ", ".join(f"{k}: {v}" for k, v in by_severity.items())
    top_str = "\n".join(top_lines)

    prompt = (
        f"Write a 4-6 sentence security digest narrative for {period}. "
        f"Summarize the findings, highlight the most important CVEs, "
        f"and recommend priority actions. Write for a security team lead.\n\n"
        f"Total CVEs: {len(cve_list)}\n"
        f"Breakdown: {sev_str}\n"
        f"CISA KEV entries: {kev_count}\n"
        f"Top CVEs:\n{top_str}"
    )
    try:
        narrative = _llm_chat(prompt, max_tokens=500,
                              system="You are a security analyst writing a weekly digest for a security team.")
        return jsonify({"ok": True, "narrative": narrative})
    except Exception as exc:
        _log.error("digest-narrative error: %s", exc)
        return _err(str(exc), 500)


@app.route("/api/llm/chat", methods=["POST"])
@_require_auth
def api_llm_chat():
    """Free-form AI chat with optional dashboard context injected as system prompt."""
    data = request.get_json(force=True) or {}
    messages_in = data.get("messages", [])
    context = data.get("context", {})

    if not isinstance(messages_in, list) or not messages_in:
        return _err("messages required", 400)

    # Sanitise messages — only role/content, max 40 turns, content truncated to 2000 chars
    history = []
    for m in messages_in[-40:]:
        role = str(m.get("role", "")).strip()
        content = str(m.get("content", "")).strip()[:2000]
        if role in ("user", "assistant") and content:
            history.append({"role": role, "content": content})
    if not history:
        return _err("no valid messages", 400)

    # Build system prompt with dashboard context
    ctx_parts = [
        "You are a security analyst assistant embedded in CVE Emailer, a self-hosted CVE "
        "monitoring platform. You have access to the user's current dashboard context and can "
        "answer questions about vulnerabilities, triage decisions, remediation, threat intel, "
        "asset risk, and general security topics. Be concise and actionable."
    ]
    if context.get("section"):
        ctx_parts.append(f"Current dashboard section: {context['section']}")
    if context.get("activeCve"):
        ctx_parts.append(f"Currently open CVE: {context['activeCve']}")
    if context.get("stats"):
        s = context["stats"]
        ctx_parts.append(
            f"Dashboard stats — Total: {s.get('total','?')}, Critical: {s.get('critical','?')}, "
            f"High: {s.get('high','?')}, Medium: {s.get('medium','?')}, Low: {s.get('low','?')}"
        )
    if context.get("keywords"):
        kws = str(context["keywords"])[:300]
        ctx_parts.append(f"Monitored keywords: {kws}")
    if context.get("triageBreached"):
        ctx_parts.append(f"SLA-breached CVEs: {context['triageBreached']}")
    if context.get("topCves"):
        top = context["topCves"]
        if isinstance(top, list):
            lines = []
            for c in top[:10]:
                cid  = str(c.get("id", ""))[:20]
                sev  = str(c.get("severity", ""))[:10]
                score = c.get("score", "?")
                kev  = " [KEV]" if c.get("kev") else ""
                desc = str(c.get("desc", ""))[:120]
                lines.append(f"  {cid} | {sev} | CVSS {score}{kev} — {desc}")
            ctx_parts.append("Top CVEs by severity/score:\n" + "\n".join(lines))

    system = "\n".join(ctx_parts)

    cfg = _llm_config()
    if not cfg["api_key"] and cfg["provider"] not in ("ollama",):
        return _err("LLM not configured — add LLM_API_KEY in Settings.", 400)

    import urllib.request, urllib.error
    if not cfg["base_url"]:
        return _err("LLM base URL not configured.", 400)

    messages = [{"role": "system", "content": system}] + history
    payload = json.dumps({
        "model": cfg["model"],
        "messages": messages,
        "max_tokens": 800,
        "temperature": 0.3,
    }).encode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cfg['api_key']}",
    }
    if cfg["provider"] == "anthropic":
        headers["x-api-key"] = cfg["api_key"]
        del headers["Authorization"]
        headers["anthropic-version"] = "2023-06-01"

    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            body = json.loads(resp.read())
            reply = body["choices"][0]["message"]["content"].strip()
            return jsonify({"ok": True, "reply": reply})
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode(errors="replace")[:300]
        _log.error("llm/chat error %s: %s", exc.code, err_body)
        return _err(f"LLM API error {exc.code}", 500)
    except Exception as exc:
        _log.error("llm/chat error: %s", exc)
        return _err(str(exc), 500)


# ── Internal CVSS overrides ───────────────────────────────────────────────────

@app.route("/api/cvss-override/<string:cve_id>")
def api_cvss_override_get(cve_id: str):
    return jsonify(database.cvss_override_get(cve_id) or {})


@app.route("/api/cvss-override", methods=["POST"])
@_require_auth
def api_cvss_override_set():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    _assert_cve_id(cve_id)
    score = data.get("internal_score")
    if score is not None:
        try:
            score = float(score)
            import math
            if math.isnan(score) or math.isinf(score) or not (0.0 <= score <= 10.0):
                return jsonify({"error": "score must be 0.0–10.0"}), 400
        except (TypeError, ValueError):
            return jsonify({"error": "invalid score"}), 400
    database.cvss_override_set(
        cve_id,
        internal_score=score,
        internal_sev=data.get("internal_sev", ""),
        rationale=data.get("rationale", ""),
        overridden_by=data.get("overridden_by", ""),
    )
    return jsonify({"ok": True})


@app.route("/api/cvss-override/<string:cve_id>", methods=["DELETE"])
@_require_auth
def api_cvss_override_delete(cve_id: str):
    database.cvss_override_delete(cve_id)
    return jsonify({"ok": True})


@app.route("/api/cvss-overrides")
def api_cvss_overrides_all():
    return jsonify(database.cvss_overrides_get_all())


# ── MITRE ATT&CK CWE → Technique mapping ─────────────────────────────────────
# Static mapping of common CWEs to ATT&CK Enterprise technique IDs + names.
# Source: MITRE CWE → CAPEC → ATT&CK mappings (curated subset).

_CWE_TO_ATTACK: dict[str, list[dict]] = {
    "CWE-78":  [{"id": "T1059",  "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-79":  [{"id": "T1059.007", "name": "JavaScript (XSS)", "tactic": "Execution"}],
    "CWE-89":  [{"id": "T1190",  "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-94":  [{"id": "T1059",  "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-119": [{"id": "T1203",  "name": "Exploitation for Client Execution", "tactic": "Execution"},
                {"id": "T1499.004", "name": "Application or System Exploitation", "tactic": "Impact"}],
    "CWE-120": [{"id": "T1203",  "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-121": [{"id": "T1203",  "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-122": [{"id": "T1203",  "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-125": [{"id": "T1005",  "name": "Data from Local System", "tactic": "Collection"}],
    "CWE-190": [{"id": "T1499.004", "name": "Application or System Exploitation", "tactic": "Impact"}],
    "CWE-200": [{"id": "T1552",  "name": "Unsecured Credentials", "tactic": "Credential Access"},
                {"id": "T1005",  "name": "Data from Local System", "tactic": "Collection"}],
    "CWE-269": [{"id": "T1548",  "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],
    "CWE-276": [{"id": "T1548",  "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],
    "CWE-284": [{"id": "T1548",  "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],
    "CWE-285": [{"id": "T1548",  "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],
    "CWE-287": [{"id": "T1110",  "name": "Brute Force", "tactic": "Credential Access"},
                {"id": "T1078",  "name": "Valid Accounts", "tactic": "Defense Evasion"}],
    "CWE-295": [{"id": "T1552.004", "name": "Private Keys", "tactic": "Credential Access"}],
    "CWE-306": [{"id": "T1078",  "name": "Valid Accounts", "tactic": "Defense Evasion"}],
    "CWE-311": [{"id": "T1040",  "name": "Network Sniffing", "tactic": "Credential Access"}],
    "CWE-312": [{"id": "T1552",  "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-319": [{"id": "T1040",  "name": "Network Sniffing", "tactic": "Credential Access"}],
    "CWE-320": [{"id": "T1552.004", "name": "Private Keys", "tactic": "Credential Access"}],
    "CWE-326": [{"id": "T1600",  "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-327": [{"id": "T1600",  "name": "Weaken Encryption", "tactic": "Defense Evasion"}],
    "CWE-330": [{"id": "T1552",  "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-352": [{"id": "T1185",  "name": "Browser Session Hijacking", "tactic": "Collection"}],
    "CWE-362": [{"id": "T1499.004", "name": "Application or System Exploitation", "tactic": "Impact"}],
    "CWE-400": [{"id": "T1499",  "name": "Endpoint Denial of Service", "tactic": "Impact"}],
    "CWE-416": [{"id": "T1203",  "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-434": [{"id": "T1190",  "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
                {"id": "T1105",  "name": "Ingress Tool Transfer", "tactic": "Command and Control"}],
    "CWE-476": [{"id": "T1499.004", "name": "Application or System Exploitation", "tactic": "Impact"}],
    "CWE-502": [{"id": "T1059",  "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-601": [{"id": "T1598",  "name": "Phishing for Information", "tactic": "Reconnaissance"}],
    "CWE-611": [{"id": "T1005",  "name": "Data from Local System", "tactic": "Collection"},
                {"id": "T1083",  "name": "File and Directory Discovery", "tactic": "Discovery"}],
    "CWE-639": [{"id": "T1078",  "name": "Valid Accounts", "tactic": "Defense Evasion"}],
    "CWE-732": [{"id": "T1548",  "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],
    "CWE-787": [{"id": "T1203",  "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-798": [{"id": "T1552",  "name": "Unsecured Credentials", "tactic": "Credential Access"}],
    "CWE-918": [{"id": "T1090",  "name": "Proxy", "tactic": "Command and Control"},
                {"id": "T1105",  "name": "Ingress Tool Transfer", "tactic": "Command and Control"}],
}


@app.route("/api/attack/map")
def api_attack_map():
    """Map CWE strings to MITRE ATT&CK techniques."""
    cwe_str = request.args.get("cwe", "")
    if not cwe_str:
        return jsonify([])
    cwes = [c.strip() for c in cwe_str.split(",") if c.strip()]
    seen: set[str] = set()
    results: list[dict] = []
    for cwe in cwes:
        for tech in _CWE_TO_ATTACK.get(cwe, []):
            if tech["id"] not in seen:
                seen.add(tech["id"])
                results.append({**tech, "cwe": cwe})
    return jsonify(results)


# ── Users / RBAC ──────────────────────────────────────────────────────────────

def _get_user_from_request() -> dict | None:
    """Return user dict if a valid per-user API key is supplied."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    key = auth[7:]
    return database.user_get_by_key(key)


def _require_role(*roles):
    """Decorator: require the caller to be an authenticated user with one of the given roles.
    Falls back to the legacy API_SECRET check so existing single-key setups still work."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user = _get_user_from_request()
            if user:
                if user["role"] not in roles:
                    abort(403)
                return f(*args, **kwargs)
            # Legacy fallback: accept the global API_SECRET
            if _API_SECRET:
                auth = request.headers.get("Authorization", "")
                if not auth.startswith("Bearer ") or auth[7:] != _API_SECRET:
                    abort(401)
            return f(*args, **kwargs)
        return wrapper
    return decorator


@app.route("/api/users")
def api_users_list():
    """List users — requires lead role or legacy API_SECRET."""
    user = _get_user_from_request()
    if user and user["role"] != "lead":
        abort(403)
    elif not user and _API_SECRET:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != _API_SECRET:
            abort(401)
    return jsonify(database.users_get_all())


@app.route("/api/users", methods=["POST"])
def api_user_create():
    user = _get_user_from_request()
    if user and user["role"] != "lead":
        abort(403)
    elif not user and _API_SECRET:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != _API_SECRET:
            abort(401)
    data = request.get_json(force=True) or {}
    username = data.get("username", "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400
    try:
        result = database.user_create(
            username,
            role=data.get("role", "analyst"),
            email=data.get("email", ""),
        )
        return jsonify({"ok": True, **result})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/users/<username>", methods=["PATCH"])
def api_user_update(username: str):
    user = _get_user_from_request()
    if user and user["role"] != "lead":
        abort(403)
    elif not user and _API_SECRET:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != _API_SECRET:
            abort(401)
    data = request.get_json(force=True) or {}
    _VALID_ROLES = {"viewer", "analyst", "lead"}
    new_role = data.get("role")
    if new_role is not None and new_role not in _VALID_ROLES:
        return jsonify({"error": f"Invalid role. Must be one of: {', '.join(sorted(_VALID_ROLES))}"}), 400
    try:
        database.user_update(
            username,
            role=new_role,
            email=data.get("email"),
            active=data.get("active"),
        )
        return jsonify({"ok": True})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/users/<username>", methods=["DELETE"])
def api_user_delete(username: str):
    user = _get_user_from_request()
    if user and user["role"] != "lead":
        abort(403)
    elif not user and _API_SECRET:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:] != _API_SECRET:
            abort(401)
    database.user_delete(username)
    return jsonify({"ok": True})


@app.route("/api/users/me")
def api_user_me():
    """Return the currently authenticated user's profile."""
    user = _get_user_from_request()
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({k: v for k, v in user.items() if k != "api_key"})


# ── SLA escalation ────────────────────────────────────────────────────────────

@app.route("/api/sla/due-soon")
def api_sla_due_soon():
    hours = min(int(request.args.get("hours", 24)), 168)
    return jsonify(database.get_sla_due_soon(hours))


@app.route("/api/sla/escalate", methods=["POST"])
@_require_auth
def api_sla_escalate():
    """
    Send escalation emails for CVEs whose SLA is within 24h of breach
    or already breached. Reads assignee field and emails them directly.
    """
    data = request.get_json(force=True) or {}
    hours = int(data.get("hours", 24))
    cfg = _read_config()

    import os as _os
    sender   = _os.environ.get("CVE_SENDER_EMAIL",    "").strip() or cfg.get("EMAIL", "senderEmail",    fallback="")
    password = _os.environ.get("CVE_SENDER_PASSWORD", "").strip() or cfg.get("EMAIL", "senderPassword", fallback="")
    if not sender or not password:
        return jsonify({"ok": False, "error": "Email not configured"}), 400

    due_soon  = database.get_sla_due_soon(hours)
    breached  = database.triage_sla_breached()

    # Deduplicate — breached entries may also appear in due_soon
    breached_ids = {r["cve_id"] for r in breached}
    all_items = breached + [r for r in due_soon if r["cve_id"] not in breached_ids]

    if not all_items:
        return jsonify({"ok": True, "sent": 0, "message": "No SLA items requiring escalation."})

    import mail as _mail
    sent = 0
    errors = []
    for item in all_items:
        assignee = item.get("assignee", "").strip()
        cve_id   = item["cve_id"]
        due      = item.get("due_date", "unknown")
        status   = item.get("status", "open")
        is_breach = cve_id in breached_ids

        subject = f"[SLA {'BREACHED' if is_breach else 'DUE SOON'}] {cve_id} — action required"
        body = (
            f"SLA {'BREACH' if is_breach else 'WARNING'}: {cve_id}\n\n"
            f"Status:   {status}\n"
            f"Due date: {due}\n"
            f"Assignee: {assignee or '(unassigned)'}\n\n"
            f"{'This CVE has exceeded its SLA deadline.' if is_breach else f'This CVE SLA expires within {hours} hours.'}\n"
            f"Please update the triage status in CVE Emailer.\n"
        )

        # Determine recipients — use assignee if it looks like an email, else fall back to configured recipients
        import re as _re
        recipients = []
        if assignee and _re.match(r"[^@]+@[^@]+\.[^@]+", assignee):
            recipients = [assignee]
        else:
            rcpt_raw = _os.environ.get("CVE_RECIPIENT_EMAIL", "").strip() or cfg.get("EMAIL", "recipientEmail", fallback="")
            recipients = [r.strip() for r in rcpt_raw.split(",") if r.strip()]

        if not recipients:
            continue

        try:
            _mail.send_email(sender=sender, password=password,
                             recipients=recipients, subject=subject, body=body)
            database.escalation_log_insert(cve_id, assignee, due, "email", True)
            sent += 1
        except Exception as exc:
            err = str(exc)
            errors.append({"cve_id": cve_id, "error": err})
            database.escalation_log_insert(cve_id, assignee, due, "email", False, err)

    return jsonify({"ok": True, "sent": sent, "errors": errors,
                    "total_items": len(all_items)})


# ── Threat intelligence ───────────────────────────────────────────────────────

@app.route("/api/threat/<string:cve_id>")
def api_threat_get(cve_id: str):
    return jsonify(database.threat_intel_get(cve_id) or {})


@app.route("/api/threat", methods=["POST"])
@_require_auth
def api_threat_set():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    _assert_cve_id(cve_id)
    database.threat_intel_upsert(
        cve_id,
        in_wild=bool(data.get("in_wild", False)),
        threat_actors=data.get("threat_actors", []),
        malware_families=data.get("malware_families", []),
        campaigns=data.get("campaigns", []),
        source=data.get("source", "manual"),
        first_seen=data.get("first_seen", ""),
    )
    database.audit_log_insert("threat_intel_set", cve_id, f"in_wild={data.get('in_wild')}")
    return jsonify({"ok": True})


@app.route("/api/threat")
def api_threat_all():
    only = request.args.get("in_wild", "") == "1"
    return jsonify(database.threat_intel_get_all(in_wild_only=only))


@app.route("/api/threat/enrich/<string:cve_id>", methods=["POST"])
@_require_auth
def api_threat_enrich(cve_id: str):
    """
    Pull live threat data from:
    1. CISA KEV catalog (already stored in CVE row kev field)
    2. AlienVault OTX public API (no key required for basic queries)
    """
    result = _fetch_threat_intel(cve_id)
    return jsonify(result)


def _fetch_threat_intel(cve_id: str) -> dict:
    import urllib.request, urllib.error, urllib.parse

    in_wild = False
    threat_actors: list[str] = []
    malware_families: list[str] = []
    campaigns: list[str] = []
    sources: list[str] = []

    # 1. Check if already marked KEV
    tables = database.list_cve_tables()
    for tbl in tables:
        row = database.get_cve(tbl, cve_id)
        if row and row.get("kev"):
            in_wild = True
            sources.append("cisa-kev")
            break

    # 2. AlienVault OTX public pulse search (no API key for read-only)
    try:
        q = urllib.parse.quote(cve_id)
        url = f"https://otx.alienvault.com/api/v1/search/pulses?q={q}&page=1&limit=5"
        req = urllib.request.Request(url, headers={
            "User-Agent": "CVE-Emailer/2",
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=8) as resp:
            otx = json.loads(resp.read().decode())
            pulses = otx.get("results", [])
            if pulses:
                in_wild = True
                sources.append("otx")
                for p in pulses[:5]:
                    for tag in (p.get("tags") or []):
                        if tag and len(tag) < 80:
                            campaigns.append(tag)
                    for indicator in (p.get("indicators") or []):
                        m_type = indicator.get("type", "")
                        m_val  = indicator.get("indicator", "")
                        if m_type == "malware-family" and m_val:
                            malware_families.append(m_val)
    except Exception:
        pass

    # Deduplicate
    malware_families = list(dict.fromkeys(malware_families))[:10]
    campaigns        = list(dict.fromkeys(campaigns))[:10]

    database.threat_intel_upsert(
        cve_id,
        in_wild=in_wild,
        threat_actors=threat_actors,
        malware_families=malware_families,
        campaigns=campaigns,
        source=", ".join(sources) or "auto",
    )
    return {
        "cve_id": cve_id,
        "in_wild": in_wild,
        "threat_actors": threat_actors,
        "malware_families": malware_families,
        "campaigns": campaigns,
        "source": ", ".join(sources) or "auto",
    }


# ── Risk scoring ──────────────────────────────────────────────────────────────

@app.route("/api/risk/<string:cve_id>")
def api_risk_score(cve_id: str):
    _assert_cve_id(cve_id)
    table = request.args.get("table", "")
    if table and table not in database.list_cve_tables():
        table = ""  # fall back to all-tables search rather than crashing
    return jsonify(database.compute_risk_score(cve_id, table))


@app.route("/api/risk/top")
def api_risk_top():
    """Return top-N CVEs ranked by composite risk score across all tables."""
    limit = min(int(request.args.get("limit", 20)), 100)
    tables = database.list_cve_tables()
    results = []
    seen: set[str] = set()
    rank_expr = database._severity_rank_expr()
    from sqlalchemy import text as _text
    with database._connect() as conn:
        for tbl in tables:
            try:
                # tbl is from our own database whitelist — safe to use as identifier
                tbl_quoted = f'"{tbl}"'
                rows = conn.execute(_text(
                    f"SELECT *, :tbl_name as _table FROM {tbl_quoted} "
                    f"WHERE severity IN ('CRITICAL','HIGH','MEDIUM') "
                    f"ORDER BY {rank_expr}, cvss_score DESC NULLS LAST LIMIT 50"
                ), {"tbl_name": tbl}).fetchall()
                for r in rows:
                    d = database._row_to_dict(r)
                    if d["cve_id"] not in seen:
                        seen.add(d["cve_id"])
                        risk = database.compute_risk_score(d["cve_id"], tbl)
                        d["risk_score"]  = risk["score"]
                        d["risk_label"]  = risk["label"]
                        d["risk_factors"] = risk["factors"]
                        results.append(d)
            except Exception:
                pass
    results.sort(key=lambda r: r.get("risk_score", 0), reverse=True)
    return jsonify(results[:limit])


# ── Compliance mapping ────────────────────────────────────────────────────────

@app.route("/api/compliance/map")
def api_compliance_map():
    cwe = request.args.get("cwe", "")
    if not cwe:
        return jsonify({"nist_800_53": [], "cis_v8": [], "iso_27001": []})
    return jsonify(database.get_compliance_mapping(cwe))


# ── Comments ──────────────────────────────────────────────────────────────────

@app.route("/api/comments/<string:cve_id>")
def api_comments_get(cve_id: str):
    return jsonify(database.comments_get(cve_id))


@app.route("/api/comments", methods=["POST"])
@_require_auth
def api_comment_add():
    data = request.get_json(force=True) or {}
    cve_id = data.get("cve_id", "").strip()
    body   = data.get("body", "").strip()[:2000]  # cap at 2000 chars
    if not cve_id or not body:
        return jsonify({"error": "cve_id and body required"}), 400
    _assert_cve_id(cve_id)
    user = _get_user_from_request()
    author = user["username"] if user else data.get("author", "")
    comment_id = database.comment_add(cve_id, body, author)
    database.audit_log_insert("comment_add", cve_id, body[:100], actor=author)
    return jsonify({"ok": True, "id": comment_id})


@app.route("/api/comments/<int:comment_id>", methods=["DELETE"])
@_require_auth
def api_comment_delete(comment_id: int):
    database.comment_delete(comment_id)
    return jsonify({"ok": True})


# ── Audit log ─────────────────────────────────────────────────────────────────

@app.route("/api/audit")
def api_audit_log():
    limit = min(int(request.args.get("limit", 200)), 500)
    target = request.args.get("cve_id", "")
    return jsonify(database.audit_log_get(limit, target_id=target))


# ── MTTR / lifecycle metrics ──────────────────────────────────────────────────

@app.route("/api/metrics/mttr")
def api_mttr():
    return jsonify(database.get_mttr_stats())


# ── HTML report export ────────────────────────────────────────────────────────

@app.route("/api/report/html")
def api_report_html():
    """Generate an HTML security report covering current CVE posture."""
    stats   = database.get_dashboard_stats()
    top     = database.get_top_cves(20)
    breached = database.triage_sla_breached()
    mttr    = database.get_mttr_stats()
    kw_perf = database.get_keyword_perf()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def _sev_color(sev: str) -> str:
        return {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
                "LOW": "#65a30d"}.get((sev or "").upper(), "#6b7280")

    top_rows = "".join(
        "<tr><td><code>{}</code></td>"
        "<td style='color:{};font-weight:700'>{}</td>"
        "<td>{}</td><td>{}%</td><td>{}</td><td>{}…</td></tr>".format(
            r["cve_id"],
            _sev_color(r.get("severity", "")),
            r.get("severity", "—"),
            r.get("cvss_score") or "—",
            round((r.get("epss_score") or 0) * 100, 2),
            "✓ KEV" if r.get("kev") else "—",
            (r.get("description") or "")[:80],
        )
        for r in top
    )
    breach_rows = "".join(
        f"<tr><td><code>{r['cve_id']}</code></td><td>{r.get('assignee','—')}</td>"
        f"<td style='color:#dc2626'>{r.get('due_date','—')}</td></tr>"
        for r in breached
    )
    kw_rows = "".join(
        f"<tr><td>{k['keyword']}</td><td>{k['total']}</td>"
        f"<td>{k['avg_cvss'] or '—'}</td><td>{k['kev_count']}</td></tr>"
        for k in kw_perf
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CVE Security Report — {now_str}</title>
<style>
  body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;margin:0;padding:2rem;color:#1e293b;background:#f8fafc}}
  h1{{color:#7c3aed;border-bottom:2px solid #7c3aed;padding-bottom:.5rem}}
  h2{{color:#334155;margin-top:2rem}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1rem;margin:1rem 0}}
  .stat{{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:1rem;text-align:center}}
  .stat-label{{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:#64748b}}
  .stat-val{{font-size:28px;font-weight:700;margin-top:.3rem}}
  table{{width:100%;border-collapse:collapse;margin-top:.75rem;font-size:13px}}
  th{{background:#f1f5f9;padding:.5rem .75rem;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#64748b}}
  td{{padding:.45rem .75rem;border-top:1px solid #e2e8f0;vertical-align:top}}
  code{{background:#f1f5f9;padding:1px 5px;border-radius:4px;font-size:12px}}
  .muted{{color:#94a3b8;font-size:12px}}
  .footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:12px}}
</style>
</head>
<body>
<h1>CVE Security Report</h1>
<p class="muted">Generated: {now_str}</p>

<h2>Summary</h2>
<div class="stats">
  <div class="stat"><div class="stat-label">Total CVEs</div><div class="stat-val">{stats['total_cves']}</div></div>
  <div class="stat"><div class="stat-label">Critical</div><div class="stat-val" style="color:#dc2626">{stats['totals'].get('CRITICAL',0)}</div></div>
  <div class="stat"><div class="stat-label">High</div><div class="stat-val" style="color:#ea580c">{stats['totals'].get('HIGH',0)}</div></div>
  <div class="stat"><div class="stat-label">Medium</div><div class="stat-val" style="color:#d97706">{stats['totals'].get('MEDIUM',0)}</div></div>
  <div class="stat"><div class="stat-label">CISA KEV</div><div class="stat-val" style="color:#9333ea">{stats['kev_total']}</div></div>
  <div class="stat"><div class="stat-label">MTTR (days)</div><div class="stat-val">{mttr['mttr_days'] or '—'}</div></div>
  <div class="stat"><div class="stat-label">Open Triage</div><div class="stat-val">{mttr['open']}</div></div>
  <div class="stat"><div class="stat-label">SLA Breached</div><div class="stat-val" style="color:#dc2626">{len(breached)}</div></div>
</div>

<h2>Top 20 Risk CVEs</h2>
<table>
<thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Description</th></tr></thead>
<tbody>{top_rows or '<tr><td colspan=6 class="muted">No CVEs found.</td></tr>'}</tbody>
</table>

{'<h2>SLA Breaches</h2><table><thead><tr><th>CVE ID</th><th>Assignee</th><th>Due Date</th></tr></thead><tbody>' + breach_rows + '</tbody></table>' if breached else ''}

<h2>Keyword Performance</h2>
<table>
<thead><tr><th>Keyword</th><th>Total CVEs</th><th>Avg CVSS</th><th>KEV</th></tr></thead>
<tbody>{kw_rows or '<tr><td colspan=4 class="muted">No keywords.</td></tr>'}</tbody>
</table>

<div class="footer">CVE Emailer — Report auto-generated. Data sourced from NVD, CISA KEV, EPSS.</div>
</body>
</html>"""

    return app.response_class(
        html, mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename=cve_report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"},
    )


# ── Internet exposure / vendor advisory enrichment ───────────────────────────

@app.route("/api/exposure/<string:cve_id>", methods=["POST"])
@_require_auth
def api_exposure_check(cve_id: str):
    """
    Check internet exposure for a CVE's affected CPEs:
    1. Query Shodan's free CVE endpoint (no API key) for exploit/exposure count
    2. Fetch vendor advisories from known advisory feeds (Red Hat, Ubuntu)
    Returns exposure data + advisory snippets.
    """
    result = _check_exposure(cve_id)
    return jsonify(result)


def _check_exposure(cve_id: str) -> dict:
    import urllib.request, urllib.error, urllib.parse

    exposure: dict = {
        "cve_id": cve_id,
        "shodan_count": None,
        "shodan_url": None,
        "advisories": [],
    }

    # 1. Shodan CVE lookup (public, no key)
    try:
        url = f"https://cvedb.shodan.io/cve/{urllib.parse.quote(cve_id)}"
        req = urllib.request.Request(url, headers={"User-Agent": "CVE-Emailer/2", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode())
            exposure["shodan_count"] = data.get("epss")   # EPSS from Shodan (consistent field)
            exposure["shodan_hostcount"] = data.get("kev") or data.get("ransomware_campaign") or None
            exposure["shodan_url"] = f"https://www.shodan.io/search?query=vuln:{cve_id}"
    except Exception:
        pass

    # 2. Red Hat Security Data API
    try:
        url = f"https://access.redhat.com/labs/securitydataapi/cve/{urllib.parse.quote(cve_id)}.json"
        req = urllib.request.Request(url, headers={"User-Agent": "CVE-Emailer/2"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            rh = json.loads(resp.read().decode())
            packages = rh.get("affected_packages") or rh.get("fixed_packages") or []
            if packages or rh.get("severity"):
                exposure["advisories"].append({
                    "source":   "Red Hat",
                    "severity": rh.get("severity") or rh.get("threat_severity", ""),
                    "url":      f"https://access.redhat.com/security/cve/{cve_id}",
                    "packages": packages[:5],
                    "fix_states": [p.get("fix_state", "") for p in packages[:5] if isinstance(p, dict)],
                })
    except Exception:
        pass

    # 3. Ubuntu Security Notices (USN) via Ubuntu CVE tracker
    try:
        url = f"https://ubuntu.com/security/cves/{urllib.parse.quote(cve_id)}.json"
        req = urllib.request.Request(url, headers={"User-Agent": "CVE-Emailer/2"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            ub = json.loads(resp.read().decode())
            if ub.get("notices") or ub.get("packages"):
                exposure["advisories"].append({
                    "source":   "Ubuntu",
                    "severity": ub.get("priority", ""),
                    "url":      f"https://ubuntu.com/security/{cve_id}",
                    "packages": [p.get("name", "") for p in (ub.get("packages") or [])[:5]],
                    "fix_states": [p.get("statuses", {}) for p in (ub.get("packages") or [])[:3]],
                })
    except Exception:
        pass

    return exposure


# ── Routing rules ─────────────────────────────────────────────────────────────

@app.route("/api/routing")
def api_routing_get():
    return jsonify(database.routing_rules_get())


@app.route("/api/routing", methods=["POST"])
@_require_auth
def api_routing_save():
    data = request.get_json(force=True) or {}
    name = data.get("name", "").strip()
    channel = data.get("channel", "").strip()
    destination = data.get("destination", "").strip()
    if not name or not channel or not destination:
        return jsonify({"error": "name, channel, destination required"}), 400
    rule_id = database.routing_rule_save(
        name=name,
        min_severity=data.get("min_severity", "CRITICAL"),
        tag_filter=data.get("tag_filter", ""),
        channel=channel,
        destination=destination,
        rule_id=data.get("id"),
    )
    return jsonify({"ok": True, "id": rule_id})


@app.route("/api/routing/<int:rule_id>", methods=["DELETE"])
@_require_auth
def api_routing_delete(rule_id: int):
    database.routing_rule_delete(rule_id)
    return jsonify({"ok": True})


# ── Alert deduplication check ─────────────────────────────────────────────────

@app.route("/api/dedup/check")
def api_dedup_check():
    cve_id  = request.args.get("cve_id", "")
    channel = request.args.get("channel", "email")
    hours   = int(request.args.get("hours", 24))
    suppressed = database.alert_dedup_check(cve_id, channel, hours)
    return jsonify({"suppressed": suppressed})


@app.route("/api/dedup/record", methods=["POST"])
@_require_auth
def api_dedup_record():
    data = request.get_json(force=True) or {}
    cve_id  = data.get("cve_id", "").strip()
    channel = data.get("channel", "email")
    if not cve_id:
        return jsonify({"error": "cve_id required"}), 400
    database.alert_dedup_record(cve_id, channel)
    return jsonify({"ok": True})


# ── Webhook integrations: Teams, PagerDuty, Opsgenie ─────────────────────────

def _send_teams(webhook_url: str, cve: dict) -> None:
    """Send an Adaptive Card to Microsoft Teams via incoming webhook."""
    import urllib.request
    sev = (cve.get("severity") or "UNKNOWN").upper()
    color_map = {"CRITICAL": "Attention", "HIGH": "Warning", "MEDIUM": "Warning", "LOW": "Default"}
    card = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "contentUrl": None,
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                     "text": f"CVE Alert: {cve.get('cve_id','?')}",
                     "style": "heading", "color": color_map.get(sev, "Default")},
                    {"type": "FactSet", "facts": [
                        {"title": "Severity", "value": sev},
                        {"title": "CVSS",     "value": str(cve.get("cvss_score") or "—")},
                        {"title": "EPSS",     "value": f"{round((cve.get('epss_score') or 0)*100, 2)}%"},
                        {"title": "KEV",      "value": "Yes" if cve.get("kev") else "No"},
                    ]},
                    {"type": "TextBlock", "text": (cve.get("description") or "")[:300],
                     "wrap": True, "color": "Default"},
                ],
            },
        }],
    }
    body = json.dumps(card).encode()
    req = urllib.request.Request(webhook_url, data=body,
                                  headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=8):
        pass


def _send_pagerduty(routing_key: str, cve: dict) -> None:
    """Trigger a PagerDuty alert via Events v2 API."""
    import urllib.request
    sev = (cve.get("severity") or "UNKNOWN").upper()
    pd_sev = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning"}.get(sev, "info")
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": cve.get("cve_id", ""),
        "payload": {
            "summary":   f"[{sev}] {cve.get('cve_id','?')} — {(cve.get('description') or '')[:200]}",
            "severity":  pd_sev,
            "source":    "CVE Emailer",
            "component": cve.get("keyword") or "security",
            "custom_details": {
                "cvss":    cve.get("cvss_score"),
                "epss":    cve.get("epss_score"),
                "kev":     bool(cve.get("kev")),
                "cwe":     cve.get("cwe"),
            },
        },
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://events.pagerduty.com/v2/enqueue",
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/vnd.pagerduty+json;version=2"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8):
        pass


def _send_opsgenie(api_key: str, cve: dict) -> None:
    """Create an Opsgenie alert via REST API."""
    import urllib.request
    sev = (cve.get("severity") or "UNKNOWN").upper()
    prio_map = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3", "LOW": "P4"}
    payload = {
        "message":   f"[{sev}] {cve.get('cve_id','?')}",
        "alias":     cve.get("cve_id", ""),
        "description": (cve.get("description") or "")[:500],
        "priority":  prio_map.get(sev, "P3"),
        "tags":      ["cve-emailer", sev.lower()],
        "details": {
            "cvss":  str(cve.get("cvss_score") or ""),
            "epss":  str(cve.get("epss_score") or ""),
            "kev":   "yes" if cve.get("kev") else "no",
            "cwe":   cve.get("cwe") or "",
        },
    }
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        "https://api.opsgenie.com/v2/alerts",
        data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"GenieKey {api_key}"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8):
        pass




# ── Scheduled HTML report email ───────────────────────────────────────────────

def _send_scheduled_report() -> None:
    """Email the HTML security report on schedule. Called by APScheduler."""
    cfg = _read_config()
    schedule    = cfg.get("REPORT", "reportSchedule",   fallback="off").strip().lower()
    rcpt_raw    = cfg.get("REPORT", "reportRecipients", fallback="").strip()
    sender      = os.environ.get("CVE_SENDER_EMAIL",    "").strip() or cfg.get("EMAIL", "senderEmail",    fallback="").strip()
    password    = os.environ.get("CVE_SENDER_PASSWORD", "").strip() or cfg.get("EMAIL", "senderPassword", fallback="").strip()
    recipients  = [r.strip() for r in rcpt_raw.split(",") if r.strip()]

    if schedule == "off" or not recipients or not sender or not password:
        return

    try:
        import mail as _mail
        # Build the HTML report body inline (reuse api_report_html logic)
        from flask import Response
        with app.test_request_context():
            resp: Response = api_report_html()
        html_body = resp.get_data(as_text=True)

        subject = f"CVE Security Report — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        _mail.send_email(
            sender=sender, password=password,
            recipients=recipients, subject=subject,
            body=subject, html=html_body,
        )
        database.notify_log_insert("email", cve_count=0, recipients=rcpt_raw, success=True)
        _log.info("Scheduled report sent to %s", rcpt_raw)
    except Exception as exc:
        _log.error("Scheduled report failed: %s", exc)
        database.notify_log_insert("email", cve_count=0, recipients=rcpt_raw, success=False, error=str(exc))


def _schedule_report_job() -> None:
    """Add or replace the APScheduler job for the report based on current config."""
    cfg      = _read_config()
    schedule = cfg.get("REPORT", "reportSchedule", fallback="off").strip().lower()
    job_id   = "scheduled_report"

    # Remove old job if present
    if _scheduler.get_job(job_id):
        _scheduler.remove_job(job_id)

    if schedule == "daily":
        _scheduler.add_job(_send_scheduled_report, "cron", hour=7, minute=0, id=job_id)
        _log.info("Scheduled report job registered: daily at 07:00")
    elif schedule == "weekly":
        _scheduler.add_job(_send_scheduled_report, "cron", day_of_week="mon", hour=7, minute=0, id=job_id)
        _log.info("Scheduled report job registered: weekly Mon 07:00")


@app.route("/api/report/schedule", methods=["POST"])
@_require_auth
def api_report_schedule_update():
    """Re-register the report job after config changes."""
    _schedule_report_job()
    return jsonify({"ok": True})


# ── Entry point ───────────────────────────────────────────────────────────────

def _bootstrap_all():
    database.bootstrap()
    database.bootstrap_watchlist()
    database.bootstrap_reviews()
    database.bootstrap_notify_log()
    database.bootstrap_triage()
    database.bootstrap_suppressions()
    database.bootstrap_saved_views()
    database.bootstrap_exploit_intel()
    database.bootstrap_assets()
    database.bootstrap_cvss_overrides()
    database.bootstrap_users()
    database.bootstrap_threat_intel()
    database.bootstrap_comments()
    database.bootstrap_audit_log()
    database.bootstrap_routing_rules()
    database.bootstrap_alert_dedup()
    database.bootstrap_inventory()
    _ensure_patch_columns()


def create_app() -> Flask:
    _bootstrap_all()
    _schedule_report_job()
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    _bootstrap_all()
    _schedule_report_job()
    app.run(host=args.host, port=args.port, debug=args.debug)
