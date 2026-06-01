"""
Database backend for CVE Emailer.

Defaults to SQLite.  Set DATABASE_URL to a Postgres connection string to use
PostgreSQL instead (requires psycopg2-binary):

    export DATABASE_URL="postgresql://user:pass@localhost:5432/cveemailer"
"""

from __future__ import annotations

import csv
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

_DB_PATH = Path(__file__).parent / "cve_emailer.db"
_DATABASE_URL = os.environ.get("DATABASE_URL", "")
_USE_POSTGRES = bool(_DATABASE_URL)

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}


@contextmanager
def _connect():
    if _USE_POSTGRES:
        import psycopg2
        import psycopg2.extras

        class _PGConn:
            """Thin wrapper making psycopg2 behave like sqlite3 for our query patterns."""
            def __init__(self, c):
                self._c = c
            def execute(self, sql, params=()):
                # Postgres uses %s placeholders; SQLite uses ?
                sql = sql.replace("?", "%s")
                cur = self._c.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
                cur.execute(sql, params)
                return cur
            def executescript(self, sql):
                cur = self._c.cursor()
                for stmt in sql.split(";"):
                    stmt = stmt.strip()
                    if stmt:
                        cur.execute(stmt)
            def commit(self):   self._c.commit()
            def rollback(self): self._c.rollback()
            def close(self):    self._c.close()
            def create_function(self, *a, **kw): pass  # no-op; Postgres uses SQL functions

        raw = psycopg2.connect(_DATABASE_URL)
        wrapped = _PGConn(raw)
        try:
            yield wrapped
            wrapped.commit()
        except Exception:
            wrapped.rollback()
            raise
        finally:
            wrapped.close()
    else:
        conn = sqlite3.connect(_DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


# ── Schema bootstrap ──────────────────────────────────────────────────────────

def bootstrap() -> None:
    """Create system tables if they don't exist. Called once at startup."""
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                keywords    TEXT,
                new_cves    INTEGER DEFAULT 0,
                updated_cves INTEGER DEFAULT 0,
                emailed     INTEGER DEFAULT 0,
                error       TEXT
            );

            CREATE TABLE IF NOT EXISTS notification_profiles (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL UNIQUE,
                keywords        TEXT,
                min_severity    TEXT DEFAULT 'LOW',
                recipients      TEXT,
                webhook_url     TEXT,
                slack_webhook   TEXT,
                digest_mode     INTEGER DEFAULT 0,
                digest_schedule TEXT DEFAULT 'daily'
            );

            CREATE TABLE IF NOT EXISTS digest_queue (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                queued_at   TEXT NOT NULL,
                cve_id      TEXT NOT NULL,
                keyword     TEXT,
                severity    TEXT,
                cvss_score  REAL,
                description TEXT,
                profile_name TEXT,
                sent        INTEGER DEFAULT 0,
                sent_at     TEXT
            );
        """)
        # Migrate: add updated_cves column to scan_history if it doesn't exist
        try:
            conn.execute("ALTER TABLE scan_history ADD COLUMN updated_cves INTEGER DEFAULT 0")
        except Exception:
            pass
        # Migrate: add digest columns to notification_profiles if missing
        for col, defval in [("digest_mode", "0"), ("digest_schedule", "'daily'")]:
            try:
                conn.execute(f"ALTER TABLE notification_profiles ADD COLUMN {col} INTEGER DEFAULT {defval}")
            except Exception:
                pass
        # Migrate: add sent_at to digest_queue if missing
        try:
            conn.execute("ALTER TABLE digest_queue ADD COLUMN sent_at TEXT")
        except Exception:
            pass


# ── CVE tables ────────────────────────────────────────────────────────────────

def create_table(service_name: str) -> None:
    with _connect() as conn:
        conn.execute(
            f'CREATE TABLE IF NOT EXISTS "{service_name}" ('
            "cve_id TEXT NOT NULL PRIMARY KEY,"
            "publish_date TEXT,"
            "last_modified TEXT,"
            "description TEXT,"
            "severity TEXT,"
            "cvss_score REAL,"
            "cwe TEXT,"
            "cpe TEXT,"
            "references_json TEXT,"
            "keyword TEXT,"
            "alerted_severity TEXT,"
            "alerted_score REAL,"
            "epss_score REAL,"
            "epss_percentile REAL,"
            "kev INTEGER DEFAULT 0"
            ");"
        )
        # Migrate: add columns to existing tables
        for col, typedef in [
            ("alerted_severity", "TEXT DEFAULT NULL"),
            ("alerted_score", "REAL DEFAULT NULL"),
            ("epss_score", "REAL DEFAULT NULL"),
            ("epss_percentile", "REAL DEFAULT NULL"),
            ("kev", "INTEGER DEFAULT 0"),
        ]:
            try:
                conn.execute(f'ALTER TABLE "{service_name}" ADD COLUMN {col} {typedef}')
            except Exception:
                pass


def insert_cve(
    table: str,
    cve_id: str,
    publish_date: str,
    last_modified: str,
    description: str,
    severity: str,
    cvss_score: float | None,
    cwe: str,
    cpe: str,
    references_json: str,
    keyword: str,
    epss_score: float | None = None,
    epss_percentile: float | None = None,
    kev: bool = False,
) -> tuple[bool, bool]:
    """
    Returns (is_new, is_upgraded).
    is_new: CVE was not in DB before.
    is_upgraded: CVE existed but severity/score increased since last alert.
    """
    fields = (
        "(cve_id, publish_date, last_modified, description, severity, cvss_score, "
        "cwe, cpe, references_json, keyword, alerted_severity, alerted_score, "
        "epss_score, epss_percentile, kev)"
    )
    vals = (
        cve_id, publish_date, last_modified, description, severity, cvss_score,
        cwe, cpe, references_json, keyword, severity, cvss_score,
        epss_score, epss_percentile, int(kev),
    )
    query = f'INSERT OR IGNORE INTO "{table}" {fields} VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);'

    with _connect() as conn:
        cur = conn.execute(query, vals)
        if cur.rowcount > 0:
            return True, False

        # CVE already exists — check if severity upgraded since last alert
        row = conn.execute(
            f'SELECT severity, cvss_score, alerted_severity, alerted_score FROM "{table}" WHERE cve_id=?',
            (cve_id,)
        ).fetchone()
        if not row:
            return False, False

        current_rank = SEVERITY_RANK.get((severity or "UNKNOWN").upper(), 5)
        alerted_rank = SEVERITY_RANK.get((row["alerted_severity"] or "UNKNOWN").upper(), 5)
        alerted_score = row["alerted_score"] or 0.0
        current_score = cvss_score or 0.0

        # Re-alert if severity category improved (lower rank = more severe) or score jumped by >= 1.0
        upgraded = (current_rank < alerted_rank) or (current_score >= alerted_score + 1.0)
        if upgraded:
            conn.execute(
                f'UPDATE "{table}" SET severity=?, cvss_score=?, last_modified=?, '
                f'alerted_severity=?, alerted_score=?, epss_score=?, epss_percentile=?, kev=? WHERE cve_id=?',
                (severity, cvss_score, last_modified, severity, cvss_score,
                 epss_score, epss_percentile, int(kev), cve_id)
            )
        else:
            # Still update metadata silently
            conn.execute(
                f'UPDATE "{table}" SET severity=?, cvss_score=?, last_modified=?, '
                f'epss_score=?, epss_percentile=?, kev=? WHERE cve_id=?',
                (severity, cvss_score, last_modified, epss_score, epss_percentile, int(kev), cve_id)
            )
        return False, upgraded


# ── Scan history ──────────────────────────────────────────────────────────────

def history_start(keywords: list[str]) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scan_history (started_at, keywords) VALUES (?, ?);",
            (datetime.now().isoformat(timespec="seconds"), ", ".join(keywords)),
        )
        return cur.lastrowid


def history_finish(row_id: int, new_cves: int, updated_cves: int, emailed: bool, error: str = "") -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE scan_history SET finished_at=?, new_cves=?, updated_cves=?, emailed=?, error=? WHERE id=?;",
            (datetime.now().isoformat(timespec="seconds"), new_cves, updated_cves, int(emailed), error, row_id),
        )


def get_history(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?;", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── CVE browser / export ──────────────────────────────────────────────────────

def list_cve_tables() -> list[str]:
    """Return all CVE keyword table names (excludes system tables)."""
    system = {"scan_history", "notification_profiles", "digest_queue", "sqlite_sequence"}
    with _connect() as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        ).fetchall()
        return [r["name"] for r in rows if r["name"] not in system]


def query_cves(
    table: str,
    search: str = "",
    min_severity: str = "NONE",
    limit: int = 200,
    offset: int = 0,
    date_from: str = "",
    date_to: str = "",
) -> list[dict]:
    min_rank = SEVERITY_RANK.get(min_severity.upper(), 5)

    with _connect() as conn:
        conn.create_function("SEVERITY_RANK", 1,
            lambda s: SEVERITY_RANK.get((s or "UNKNOWN").upper(), 5))

        where_parts = [f"SEVERITY_RANK(severity) <= {min_rank}"]
        params: list = []
        if search:
            where_parts.append("(cve_id LIKE ? OR description LIKE ?)")
            params += [f"%{search}%", f"%{search}%"]
        if date_from:
            where_parts.append("publish_date >= ?")
            params.append(date_from)
        if date_to:
            where_parts.append("publish_date <= ?")
            params.append(date_to + " 23:59:59")
        where = "WHERE " + " AND ".join(where_parts)

        rows = conn.execute(
            f'SELECT * FROM "{table}" {where} ORDER BY SEVERITY_RANK(severity), publish_date DESC LIMIT ? OFFSET ?;',
            params + [limit, offset],
        ).fetchall()
        return [dict(r) for r in rows]


def get_cve(table: str, cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            f'SELECT * FROM "{table}" WHERE cve_id=?', (cve_id,)
        ).fetchone()
        return dict(row) if row else None


def export_cves_csv(table: str, path: Path, **query_kwargs) -> int:
    rows = query_cves(table, **query_kwargs)
    if not rows:
        return 0
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def export_cves_json(table: str, path: Path, **query_kwargs) -> int:
    rows = query_cves(table, **query_kwargs)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    return len(rows)


# ── Dashboard stats ───────────────────────────────────────────────────────────

def get_dashboard_stats() -> dict:
    """Return per-table severity counts, EPSS/KEV stats, and recent scan summary."""
    tables = list_cve_tables()
    severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0, "UNKNOWN": 0}
    per_keyword: list[dict] = []
    kev_total = 0

    with _connect() as conn:
        for tbl in tables:
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0, "UNKNOWN": 0}
            kev_count = 0
            try:
                rows = conn.execute(
                    f'SELECT severity, COUNT(*) as n FROM "{tbl}" GROUP BY severity'
                ).fetchall()
                for r in rows:
                    sev = (r["severity"] or "UNKNOWN").upper()
                    n = r["n"]
                    counts[sev] = counts.get(sev, 0) + n
                    severity_totals[sev] = severity_totals.get(sev, 0) + n
                kev_row = conn.execute(
                    f'SELECT COUNT(*) as n FROM "{tbl}" WHERE kev=1'
                ).fetchone()
                kev_count = kev_row["n"] if kev_row else 0
                kev_total += kev_count
            except Exception:
                pass
            per_keyword.append({"keyword": tbl, "kev": kev_count, **counts})

        recent = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT 5"
        ).fetchall()

    return {
        "totals": severity_totals,
        "per_keyword": per_keyword,
        "recent_scans": [dict(r) for r in recent],
        "total_keywords": len(tables),
        "total_cves": sum(severity_totals.values()),
        "kev_total": kev_total,
    }


def get_metrics() -> dict:
    """Prometheus-style metrics dict for /metrics endpoint."""
    stats = get_dashboard_stats()
    with _connect() as conn:
        scan_row = conn.execute(
            "SELECT COUNT(*) as n FROM scan_history"
        ).fetchone()
        error_row = conn.execute(
            "SELECT COUNT(*) as n FROM scan_history WHERE error != '' AND error IS NOT NULL"
        ).fetchone()
    return {
        "cve_total":               stats["total_cves"],
        "cve_critical":            stats["totals"].get("CRITICAL", 0),
        "cve_high":                stats["totals"].get("HIGH", 0),
        "cve_medium":              stats["totals"].get("MEDIUM", 0),
        "cve_low":                 stats["totals"].get("LOW", 0),
        "cve_kev":                 stats["kev_total"],
        "keyword_count":           stats["total_keywords"],
        "scan_total":              scan_row["n"] if scan_row else 0,
        "scan_errors":             error_row["n"] if error_row else 0,
    }


# ── Digest queue ──────────────────────────────────────────────────────────────

def digest_enqueue(cves: list[dict], profile_name: str = "") -> None:
    """Add CVEs to the digest queue."""
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        for c in cves:
            conn.execute(
                "INSERT INTO digest_queue (queued_at, cve_id, keyword, severity, cvss_score, description, profile_name) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now, c["id"], c.get("keyword", ""), c.get("severity", ""), c.get("cvss_score"), c.get("description", ""), profile_name)
            )


def digest_get_pending(profile_name: str = "") -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM digest_queue WHERE sent=0 AND profile_name=? ORDER BY queued_at",
            (profile_name,)
        ).fetchall()
        return [dict(r) for r in rows]


def digest_mark_sent(profile_name: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            "UPDATE digest_queue SET sent=1, sent_at=? WHERE sent=0 AND profile_name=?",
            (now, profile_name)
        )


def digest_due(profile_name: str, schedule: str) -> bool:
    """Return True if enough time has passed since the last digest was dispatched."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT MAX(sent_at) as last FROM digest_queue WHERE sent=1 AND profile_name=?",
            (profile_name,)
        ).fetchone()
    last_str = row["last"] if row else None
    if not last_str:
        return True
    try:
        last = datetime.fromisoformat(last_str)
    except ValueError:
        return True
    elapsed = (datetime.now() - last).total_seconds()
    thresholds = {"daily": 86400, "weekly": 604800, "hourly": 3600}
    return elapsed >= thresholds.get(schedule, 86400)


# ── Notification profiles ─────────────────────────────────────────────────────

def get_profiles() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM notification_profiles ORDER BY name;").fetchall()
        return [dict(r) for r in rows]


def save_profile(profile: dict) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO notification_profiles "
            "(name, keywords, min_severity, recipients, webhook_url, slack_webhook, digest_mode, digest_schedule)"
            " VALUES (:name, :keywords, :min_severity, :recipients, :webhook_url, :slack_webhook, :digest_mode, :digest_schedule)"
            " ON CONFLICT(name) DO UPDATE SET"
            "   keywords=excluded.keywords,"
            "   min_severity=excluded.min_severity,"
            "   recipients=excluded.recipients,"
            "   webhook_url=excluded.webhook_url,"
            "   slack_webhook=excluded.slack_webhook,"
            "   digest_mode=excluded.digest_mode,"
            "   digest_schedule=excluded.digest_schedule;",
            profile,
        )


def delete_profile(name: str) -> None:
    with _connect() as conn:
        conn.execute("DELETE FROM notification_profiles WHERE name=?;", (name,))
