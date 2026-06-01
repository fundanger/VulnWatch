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
import json
import os
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory, abort
from flask_cors import CORS

import database

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
    """Trigger a one-shot scan in the background. Returns immediately."""
    import threading
    import search

    def _run():
        import logger
        logger.setup()
        database.bootstrap()
        search.run_once(log=lambda m: None)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return jsonify({"ok": True, "message": "Scan started in background."})


# ── Entry point ───────────────────────────────────────────────────────────────

def create_app() -> Flask:
    database.bootstrap()
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    database.bootstrap()
    app.run(host=args.host, port=args.port, debug=args.debug)
