"""
Database backend — SQLite (default) or MySQL.

Set [DATABASE] backend = mysql in config.ini to use MySQL.
SQLite stores data in cve_emailer.db next to the script with zero server setup.
"""

from __future__ import annotations

import csv
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def _cfg():
    import configparser
    c = configparser.ConfigParser()
    c.read("config.ini")
    return c


def _backend() -> str:
    return _cfg().get("DATABASE", "backend", fallback="sqlite").strip().lower()


# ── SQLite ────────────────────────────────────────────────────────────────────

SQLITE_PATH = Path("cve_emailer.db")


@contextmanager
def _sqlite():
    conn = sqlite3.connect(SQLITE_PATH)
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


# ── MySQL ─────────────────────────────────────────────────────────────────────

def _mysql_connect(retries: int = 3, delay: float = 2.0):
    import mysql.connector
    cfg = _cfg()
    kwargs = dict(
        user=cfg["DATABASE"]["username"],
        password=cfg["DATABASE"]["password"],
        host=cfg["DATABASE"]["host"],
        database=cfg["DATABASE"]["database"],
    )
    for attempt in range(1, retries + 1):
        try:
            return mysql.connector.connect(**kwargs)
        except mysql.connector.Error:
            if attempt == retries:
                raise
            time.sleep(delay * attempt)


@contextmanager
def _mysql():
    conn = _mysql_connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def _connect():
    if _backend() == "mysql":
        with _mysql() as conn:
            yield conn
    else:
        with _sqlite() as conn:
            yield conn


# ── Schema bootstrap ──────────────────────────────────────────────────────────

def bootstrap() -> None:
    """Create all core tables if they don't exist. Called once at startup."""
    if _backend() != "sqlite":
        return  # MySQL tables created per-keyword as before
    with _sqlite() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                keywords    TEXT,
                new_cves    INTEGER DEFAULT 0,
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
                slack_webhook   TEXT
            );
        """)


# ── CVE tables ────────────────────────────────────────────────────────────────

def create_table(service_name: str) -> None:
    if _backend() == "mysql":
        query = (
            f"CREATE TABLE IF NOT EXISTS `{service_name}` ("
            "cve_id VARCHAR(255) NOT NULL PRIMARY KEY,"
            "publish_date DATETIME,"
            "last_modified DATETIME,"
            "description TEXT,"
            "severity VARCHAR(16),"
            "cvss_score FLOAT,"
            "cwe TEXT,"
            "cpe TEXT,"
            "references_json TEXT,"
            "keyword TEXT"
            ");"
        )
        with _connect() as conn:
            conn.cursor().execute(query)
    else:
        with _sqlite() as conn:
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
                "keyword TEXT"
                ");"
            )


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
) -> bool:
    """Returns True if the CVE was new."""
    fields = "(cve_id, publish_date, last_modified, description, severity, cvss_score, cwe, cpe, references_json, keyword)"
    vals = (cve_id, publish_date, last_modified, description, severity, cvss_score, cwe, cpe, references_json, keyword)

    if _backend() == "mysql":
        query = f"INSERT IGNORE INTO `{table}` {fields} VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);"
        with _connect() as conn:
            cur = conn.cursor()
            cur.execute(query, vals)
            return cur.rowcount > 0
    else:
        query = f'INSERT OR IGNORE INTO "{table}" {fields} VALUES (?,?,?,?,?,?,?,?,?,?);'
        with _sqlite() as conn:
            cur = conn.execute(query, vals)
            return cur.rowcount > 0


# ── Scan history ──────────────────────────────────────────────────────────────

def history_start(keywords: list[str]) -> int:
    """Record scan start. Returns the row id."""
    if _backend() != "sqlite":
        return -1
    from datetime import datetime
    with _sqlite() as conn:
        cur = conn.execute(
            "INSERT INTO scan_history (started_at, keywords) VALUES (?, ?);",
            (datetime.now().isoformat(timespec="seconds"), ", ".join(keywords)),
        )
        return cur.lastrowid


def history_finish(row_id: int, new_cves: int, emailed: bool, error: str = "") -> None:
    if _backend() != "sqlite" or row_id < 0:
        return
    from datetime import datetime
    with _sqlite() as conn:
        conn.execute(
            "UPDATE scan_history SET finished_at=?, new_cves=?, emailed=?, error=? WHERE id=?;",
            (datetime.now().isoformat(timespec="seconds"), new_cves, int(emailed), error, row_id),
        )


def get_history(limit: int = 50) -> list[dict]:
    if _backend() != "sqlite":
        return []
    with _sqlite() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?;", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── CVE browser / export ──────────────────────────────────────────────────────

def list_cve_tables() -> list[str]:
    """Return all CVE keyword table names (excludes system tables)."""
    if _backend() != "sqlite":
        return []
    system = {"scan_history", "notification_profiles"}
    with _sqlite() as conn:
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
) -> list[dict]:
    SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}
    min_rank = SEVERITY_RANK.get(min_severity.upper(), 5)

    if _backend() != "sqlite":
        return []
    with _sqlite() as conn:
        where_parts = [f"SEVERITY_RANK(severity) <= {min_rank}"]
        params: list = []
        if search:
            where_parts.append("(cve_id LIKE ? OR description LIKE ?)")
            params += [f"%{search}%", f"%{search}%"]
        where = "WHERE " + " AND ".join(where_parts) if where_parts else ""

        conn.create_function("SEVERITY_RANK", 1,
            lambda s: SEVERITY_RANK.get((s or "UNKNOWN").upper(), 5))
        rows = conn.execute(
            f'SELECT * FROM "{table}" {where} ORDER BY SEVERITY_RANK(severity), publish_date DESC LIMIT ? OFFSET ?;',
            params + [limit, offset],
        ).fetchall()
        return [dict(r) for r in rows]


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


# ── Notification profiles ─────────────────────────────────────────────────────

def get_profiles() -> list[dict]:
    if _backend() != "sqlite":
        return []
    with _sqlite() as conn:
        rows = conn.execute("SELECT * FROM notification_profiles ORDER BY name;").fetchall()
        return [dict(r) for r in rows]


def save_profile(profile: dict) -> None:
    if _backend() != "sqlite":
        return
    with _sqlite() as conn:
        conn.execute(
            "INSERT INTO notification_profiles (name, keywords, min_severity, recipients, webhook_url, slack_webhook)"
            " VALUES (:name, :keywords, :min_severity, :recipients, :webhook_url, :slack_webhook)"
            " ON CONFLICT(name) DO UPDATE SET"
            "   keywords=excluded.keywords,"
            "   min_severity=excluded.min_severity,"
            "   recipients=excluded.recipients,"
            "   webhook_url=excluded.webhook_url,"
            "   slack_webhook=excluded.slack_webhook;",
            profile,
        )


def delete_profile(name: str) -> None:
    if _backend() != "sqlite":
        return
    with _sqlite() as conn:
        conn.execute("DELETE FROM notification_profiles WHERE name=?;", (name,))
