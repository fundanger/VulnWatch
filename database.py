"""
Database backend for CVE Emailer — SQLAlchemy Core (SQLite default, Postgres optional).

Set DATABASE_URL to use Postgres:
    export DATABASE_URL="postgresql+psycopg2://user:pass@localhost:5432/cveemailer"

Omit DATABASE_URL to use SQLite (default, stored next to this script).
"""

from __future__ import annotations

import csv
import json
import os
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from sqlalchemy import (
    Boolean, Column, Float, Integer, MetaData, String, Table, Text,
    create_engine, event, inspect, text,
)
from sqlalchemy.engine import Connection, Engine

_DB_PATH = Path(__file__).parent / "cve_emailer.db"
_DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{_DB_PATH}")
_IS_SQLITE = _DATABASE_URL.startswith("sqlite")

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}

_engine: Engine | None = None


def _get_engine() -> Engine:
    global _engine
    if _engine is None:
        kwargs: dict = {}
        if _IS_SQLITE:
            kwargs["connect_args"] = {"check_same_thread": False}
        _engine = create_engine(_DATABASE_URL, **kwargs)
        if _IS_SQLITE:
            # Enable WAL mode and register SEVERITY_RANK as a scalar function
            @event.listens_for(_engine, "connect")
            def _on_connect(conn, _):
                conn.execute("PRAGMA journal_mode=WAL")
                conn.create_function(
                    "SEVERITY_RANK", 1,
                    lambda s: SEVERITY_RANK.get((s or "UNKNOWN").upper(), 5),
                )
    return _engine


@contextmanager
def _connect():
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        try:
            yield conn
            trans.commit()
        except Exception:
            trans.rollback()
            raise


def _row_to_dict(row) -> dict:
    """Convert a SQLAlchemy Row to a plain dict."""
    return dict(row._mapping)


# ── Schema bootstrap ──────────────────────────────────────────────────────────

_AUTOINCREMENT = "SERIAL" if not _IS_SQLITE else "INTEGER"


def bootstrap() -> None:
    """Create system tables if they don't exist. Safe to call on every startup."""
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        if _IS_SQLITE:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at  TEXT NOT NULL,
                    finished_at TEXT,
                    keywords    TEXT,
                    new_cves    INTEGER DEFAULT 0,
                    updated_cves INTEGER DEFAULT 0,
                    emailed     INTEGER DEFAULT 0,
                    error       TEXT
                )
            """))
            conn.execute(text("""
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
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS digest_queue (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    queued_at    TEXT NOT NULL,
                    cve_id       TEXT NOT NULL,
                    keyword      TEXT,
                    severity     TEXT,
                    cvss_score   REAL,
                    description  TEXT,
                    profile_name TEXT,
                    sent         INTEGER DEFAULT 0,
                    sent_at      TEXT
                )
            """))
        else:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id           SERIAL PRIMARY KEY,
                    started_at   TEXT NOT NULL,
                    finished_at  TEXT,
                    keywords     TEXT,
                    new_cves     INTEGER DEFAULT 0,
                    updated_cves INTEGER DEFAULT 0,
                    emailed      INTEGER DEFAULT 0,
                    error        TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS notification_profiles (
                    id              SERIAL PRIMARY KEY,
                    name            TEXT NOT NULL UNIQUE,
                    keywords        TEXT,
                    min_severity    TEXT DEFAULT 'LOW',
                    recipients      TEXT,
                    webhook_url     TEXT,
                    slack_webhook   TEXT,
                    digest_mode     INTEGER DEFAULT 0,
                    digest_schedule TEXT DEFAULT 'daily'
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS digest_queue (
                    id           SERIAL PRIMARY KEY,
                    queued_at    TEXT NOT NULL,
                    cve_id       TEXT NOT NULL,
                    keyword      TEXT,
                    severity     TEXT,
                    cvss_score   REAL,
                    description  TEXT,
                    profile_name TEXT,
                    sent         INTEGER DEFAULT 0,
                    sent_at      TEXT
                )
            """))

        # Safe column migrations — add any missing columns
        _add_column_if_missing(conn, "scan_history",           "updated_cves",   "INTEGER DEFAULT 0")
        _add_column_if_missing(conn, "notification_profiles",  "digest_mode",    "INTEGER DEFAULT 0")
        _add_column_if_missing(conn, "notification_profiles",  "digest_schedule","TEXT DEFAULT 'daily'")
        _add_column_if_missing(conn, "digest_queue",           "sent_at",        "TEXT")
        trans.commit()


def _add_column_if_missing(conn: Connection, table: str, column: str, typedef: str) -> None:
    """ALTER TABLE ... ADD COLUMN if it does not already exist."""
    try:
        conn.execute(text(f'ALTER TABLE {table} ADD COLUMN {column} {typedef}'))
    except Exception:
        pass  # column already exists


# ── CVE tables ────────────────────────────────────────────────────────────────

def _cve_columns_ddl() -> str:
    return (
        "cve_id          TEXT NOT NULL PRIMARY KEY,"
        "publish_date     TEXT,"
        "last_modified    TEXT,"
        "description      TEXT,"
        "severity         TEXT,"
        "cvss_score       REAL,"
        "cwe              TEXT,"
        "cpe              TEXT,"
        "references_json  TEXT,"
        "keyword          TEXT,"
        "alerted_severity TEXT,"
        "alerted_score    REAL,"
        "epss_score       REAL,"
        "epss_percentile  REAL,"
        "kev              INTEGER DEFAULT 0,"
        "scan_source      TEXT DEFAULT 'keyword',"
        "remediation_notes TEXT DEFAULT '',"
        "remediation_cmds  TEXT DEFAULT ''"
    )


def create_table(service_name: str) -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text(
            f'CREATE TABLE IF NOT EXISTS "{service_name}" ({_cve_columns_ddl()})'
        ))
        for col, typedef in [
            ("alerted_severity", "TEXT"),
            ("alerted_score",    "REAL"),
            ("epss_score",       "REAL"),
            ("epss_percentile",  "REAL"),
            ("kev",               "INTEGER DEFAULT 0"),
            ("scan_source",       "TEXT DEFAULT 'keyword'"),
            ("remediation_notes", "TEXT DEFAULT ''"),
            ("remediation_cmds",  "TEXT DEFAULT ''"),
        ]:
            _add_column_if_missing(conn, f'"{service_name}"', col, typedef)
        trans.commit()


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
    scan_source: str = "keyword",
) -> tuple[bool, bool]:
    """
    Returns (is_new, is_upgraded).
    is_new: CVE was not in DB before.
    is_upgraded: CVE existed but severity/score increased since last alert.
    """
    with _connect() as conn:
        # Try INSERT — use dialect-appropriate conflict clause
        if _IS_SQLITE:
            ins = text(
                f'INSERT OR IGNORE INTO "{table}" '
                "(cve_id, publish_date, last_modified, description, severity, cvss_score, "
                "cwe, cpe, references_json, keyword, alerted_severity, alerted_score, "
                "epss_score, epss_percentile, kev, scan_source) "
                "VALUES (:cve_id,:publish_date,:last_modified,:description,:severity,:cvss_score,"
                ":cwe,:cpe,:references_json,:keyword,:severity2,:cvss_score2,"
                ":epss_score,:epss_percentile,:kev,:scan_source)"
            )
        else:
            ins = text(
                f'INSERT INTO "{table}" '
                "(cve_id, publish_date, last_modified, description, severity, cvss_score, "
                "cwe, cpe, references_json, keyword, alerted_severity, alerted_score, "
                "epss_score, epss_percentile, kev, scan_source) "
                "VALUES (:cve_id,:publish_date,:last_modified,:description,:severity,:cvss_score,"
                ":cwe,:cpe,:references_json,:keyword,:severity2,:cvss_score2,"
                ":epss_score,:epss_percentile,:kev,:scan_source) "
                "ON CONFLICT (cve_id) DO NOTHING"
            )

        params = dict(
            cve_id=cve_id, publish_date=publish_date, last_modified=last_modified,
            description=description, severity=severity, cvss_score=cvss_score,
            cwe=cwe, cpe=cpe, references_json=references_json, keyword=keyword,
            severity2=severity, cvss_score2=cvss_score,
            epss_score=epss_score, epss_percentile=epss_percentile, kev=int(kev),
            scan_source=scan_source,
        )
        result = conn.execute(ins, params)
        if result.rowcount > 0:
            return True, False

        # CVE already exists — check upgrade
        row = conn.execute(
            text(f'SELECT alerted_severity, alerted_score FROM "{table}" WHERE cve_id=:cid'),
            {"cid": cve_id},
        ).fetchone()
        if not row:
            return False, False

        current_rank = SEVERITY_RANK.get((severity or "UNKNOWN").upper(), 5)
        alerted_rank = SEVERITY_RANK.get((row[0] or "UNKNOWN").upper(), 5)
        alerted_score = row[1] or 0.0
        current_score = cvss_score or 0.0

        upgraded = (current_rank < alerted_rank) or (current_score >= alerted_score + 1.0)
        if upgraded:
            conn.execute(
                text(f'UPDATE "{table}" SET severity=:sev, cvss_score=:score, last_modified=:lm, '
                     'alerted_severity=:asev, alerted_score=:ascore, '
                     'epss_score=:epss, epss_percentile=:epss_p, kev=:kev WHERE cve_id=:cid'),
                dict(sev=severity, score=cvss_score, lm=last_modified,
                     asev=severity, ascore=cvss_score,
                     epss=epss_score, epss_p=epss_percentile, kev=int(kev), cid=cve_id),
            )
        else:
            conn.execute(
                text(f'UPDATE "{table}" SET severity=:sev, cvss_score=:score, last_modified=:lm, '
                     'epss_score=:epss, epss_percentile=:epss_p, kev=:kev WHERE cve_id=:cid'),
                dict(sev=severity, score=cvss_score, lm=last_modified,
                     epss=epss_score, epss_p=epss_percentile, kev=int(kev), cid=cve_id),
            )
        return False, upgraded


# ── Scan history ──────────────────────────────────────────────────────────────

def history_start(keywords: list[str]) -> int:
    with _connect() as conn:
        result = conn.execute(
            text("INSERT INTO scan_history (started_at, keywords) VALUES (:ts, :kw)"),
            {"ts": datetime.now().isoformat(timespec="seconds"), "kw": ", ".join(keywords)},
        )
        if _IS_SQLITE:
            return result.lastrowid
        # Postgres: fetch the generated id
        row = conn.execute(text("SELECT lastval()")).fetchone()
        return row[0]


def history_finish(row_id: int, new_cves: int, updated_cves: int, emailed: bool, error: str = "") -> None:
    with _connect() as conn:
        conn.execute(
            text("UPDATE scan_history SET finished_at=:ft, new_cves=:n, updated_cves=:u, "
                 "emailed=:e, error=:err WHERE id=:id"),
            dict(ft=datetime.now().isoformat(timespec="seconds"),
                 n=new_cves, u=updated_cves, e=int(emailed), err=error, id=row_id),
        )


def get_history(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            text("SELECT * FROM scan_history ORDER BY id DESC LIMIT :lim"), {"lim": limit}
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── CVE browser / export ──────────────────────────────────────────────────────

def list_cve_tables() -> list[str]:
    """Return all CVE keyword table names (excludes system tables)."""
    system = {
        "scan_history", "notification_profiles", "digest_queue", "sqlite_sequence",
        "cve_watchlist", "cve_reviews", "cve_triage", "cve_suppressions",
        "saved_views", "notification_log", "exploit_intel", "assets",
        "cvss_overrides", "users", "threat_intel", "cve_comments",
        "audit_log", "routing_rules", "alert_dedup", "software_inventory",
    }
    engine = _get_engine()
    insp = inspect(engine)
    return sorted(t for t in insp.get_table_names() if t not in system)


def _severity_rank_expr(col: str = "severity") -> str:
    """Return a CASE expression that maps severity text to sort order, for both dialects."""
    return (
        f"CASE UPPER({col}) "
        "WHEN 'CRITICAL' THEN 0 "
        "WHEN 'HIGH' THEN 1 "
        "WHEN 'MEDIUM' THEN 2 "
        "WHEN 'LOW' THEN 3 "
        "WHEN 'NONE' THEN 4 "
        "ELSE 5 END"
    )


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
    rank_expr = _severity_rank_expr()

    where_parts = [f"({rank_expr}) <= :min_rank"]
    params: dict = {"min_rank": min_rank, "lim": limit, "off": offset}

    if search:
        where_parts.append("(cve_id LIKE :search OR description LIKE :search)")
        params["search"] = f"%{search}%"
    if date_from:
        where_parts.append("publish_date >= :date_from")
        params["date_from"] = date_from
    if date_to:
        where_parts.append("publish_date <= :date_to")
        params["date_to"] = date_to + " 23:59:59"

    where = "WHERE " + " AND ".join(where_parts)
    order = f"ORDER BY {rank_expr}, publish_date DESC"

    with _connect() as conn:
        rows = conn.execute(
            text(f'SELECT * FROM "{table}" {where} {order} LIMIT :lim OFFSET :off'),
            params,
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def query_cves_multi(
    tables: list[str],
    search: str = "",
    min_severity: str = "NONE",
    limit: int = 200,
    offset: int = 0,
    date_from: str = "",
    date_to: str = "",
) -> list[dict]:
    """Query across multiple CVE tables, merge, sort, and paginate."""
    seen: set[str] = set()
    all_rows: list[dict] = []
    for table in tables:
        rows = query_cves(
            table,
            search=search,
            min_severity=min_severity,
            limit=limit,  # per-table cap; final slice applied below
            offset=0,
            date_from=date_from,
            date_to=date_to,
        )
        for r in rows:
            cve_id = r.get("cve_id", "")
            if cve_id not in seen:
                seen.add(cve_id)
                r["_table"] = table
                all_rows.append(r)

    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    # Two-pass stable sort: date descending first, then severity ascending.
    # Python's sort is stable, so equal-severity rows keep date-descending order.
    all_rows.sort(key=lambda r: r.get("publish_date") or "", reverse=True)
    all_rows.sort(key=lambda r: sev_order.get((r.get("severity") or "NONE").upper(), 5))
    return all_rows[offset: offset + limit]


def get_cve(table: str, cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            text(f'SELECT * FROM "{table}" WHERE cve_id=:cid'), {"cid": cve_id}
        ).fetchone()
        return _row_to_dict(row) if row else None


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
    severity_totals: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0, "UNKNOWN": 0}
    per_keyword: list[dict] = []
    kev_total = 0

    with _connect() as conn:
        for tbl in tables:
            counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0, "UNKNOWN": 0}
            kev_count = 0
            try:
                for r in conn.execute(
                    text(f'SELECT severity, COUNT(*) as n FROM "{tbl}" GROUP BY severity')
                ).fetchall():
                    sev = (r[0] or "UNKNOWN").upper()
                    n = r[1]
                    counts[sev] = counts.get(sev, 0) + n
                    severity_totals[sev] = severity_totals.get(sev, 0) + n
                kev_row = conn.execute(
                    text(f'SELECT COUNT(*) FROM "{tbl}" WHERE kev=1')
                ).fetchone()
                kev_count = kev_row[0] if kev_row else 0
                kev_total += kev_count
            except Exception:
                pass
            per_keyword.append({"keyword": tbl, "kev": kev_count, **counts})

        recent = conn.execute(
            text("SELECT * FROM scan_history ORDER BY id DESC LIMIT 5")
        ).fetchall()

    with _connect() as conn2:
        asset_count = conn2.execute(text("SELECT COUNT(*) FROM assets")).fetchone()[0]
        open_triage = conn2.execute(
            text("SELECT COUNT(*) FROM cve_triage WHERE status NOT IN ('closed','wont_fix','false_positive')")
        ).fetchone()[0]
        overdue_count = conn2.execute(
            text("SELECT COUNT(*) FROM cve_triage WHERE due_date != '' AND due_date < date('now') "
                 "AND status NOT IN ('closed','wont_fix','false_positive')")
        ).fetchone()[0]

    return {
        "totals":          severity_totals,
        "per_keyword":     per_keyword,
        "recent_scans":    [_row_to_dict(r) for r in recent],
        "total_keywords":  len(tables),
        "total_cves":      sum(severity_totals.values()),
        "kev_total":       kev_total,
        "asset_count":     asset_count,
        "open_triage":     open_triage,
        "overdue_count":   overdue_count,
    }


def get_metrics() -> dict:
    """Prometheus-style metrics dict for /metrics endpoint."""
    stats = get_dashboard_stats()
    with _connect() as conn:
        scan_n = conn.execute(text("SELECT COUNT(*) FROM scan_history")).fetchone()[0]
        err_n  = conn.execute(
            text("SELECT COUNT(*) FROM scan_history WHERE error IS NOT NULL AND error != ''")
        ).fetchone()[0]
    return {
        "cve_total":    stats["total_cves"],
        "cve_critical": stats["totals"].get("CRITICAL", 0),
        "cve_high":     stats["totals"].get("HIGH", 0),
        "cve_medium":   stats["totals"].get("MEDIUM", 0),
        "cve_low":      stats["totals"].get("LOW", 0),
        "cve_kev":      stats["kev_total"],
        "keyword_count":stats["total_keywords"],
        "scan_total":   scan_n,
        "scan_errors":  err_n,
    }


# ── Digest queue ──────────────────────────────────────────────────────────────

def digest_enqueue(cves: list[dict], profile_name: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        for c in cves:
            conn.execute(
                text("INSERT INTO digest_queue "
                     "(queued_at, cve_id, keyword, severity, cvss_score, description, profile_name) "
                     "VALUES (:qa,:cid,:kw,:sev,:score,:desc,:pn)"),
                dict(qa=now, cid=c["id"], kw=c.get("keyword",""),
                     sev=c.get("severity",""), score=c.get("cvss_score"),
                     desc=c.get("description",""), pn=profile_name),
            )


def digest_get_pending(profile_name: str = "") -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            text("SELECT * FROM digest_queue WHERE sent=0 AND profile_name=:pn ORDER BY queued_at"),
            {"pn": profile_name},
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def digest_mark_sent(profile_name: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(
            text("UPDATE digest_queue SET sent=1, sent_at=:now WHERE sent=0 AND profile_name=:pn"),
            {"now": now, "pn": profile_name},
        )


def digest_due(profile_name: str, schedule: str) -> bool:
    """Return True if enough time has passed since the last digest was dispatched."""
    with _connect() as conn:
        row = conn.execute(
            text("SELECT MAX(sent_at) FROM digest_queue WHERE sent=1 AND profile_name=:pn"),
            {"pn": profile_name},
        ).fetchone()
    last_str = row[0] if row else None
    if not last_str:
        return True
    try:
        last = datetime.fromisoformat(last_str)
    except ValueError:
        return True
    elapsed = (datetime.now() - last).total_seconds()
    return elapsed >= {"daily": 86400, "weekly": 604800, "hourly": 3600}.get(schedule, 86400)


# ── Notification profiles ─────────────────────────────────────────────────────

def get_profiles() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            text("SELECT * FROM notification_profiles ORDER BY name")
        ).fetchall()
        return [_row_to_dict(r) for r in rows]


def save_profile(profile: dict) -> None:
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(
                text(
                    "INSERT INTO notification_profiles "
                    "(name,keywords,min_severity,recipients,webhook_url,slack_webhook,digest_mode,digest_schedule) "
                    "VALUES (:name,:keywords,:min_severity,:recipients,:webhook_url,:slack_webhook,:digest_mode,:digest_schedule) "
                    "ON CONFLICT(name) DO UPDATE SET "
                    "keywords=excluded.keywords, min_severity=excluded.min_severity, "
                    "recipients=excluded.recipients, webhook_url=excluded.webhook_url, "
                    "slack_webhook=excluded.slack_webhook, digest_mode=excluded.digest_mode, "
                    "digest_schedule=excluded.digest_schedule"
                ),
                profile,
            )
        else:
            conn.execute(
                text(
                    "INSERT INTO notification_profiles "
                    "(name,keywords,min_severity,recipients,webhook_url,slack_webhook,digest_mode,digest_schedule) "
                    "VALUES (:name,:keywords,:min_severity,:recipients,:webhook_url,:slack_webhook,:digest_mode,:digest_schedule) "
                    "ON CONFLICT(name) DO UPDATE SET "
                    "keywords=EXCLUDED.keywords, min_severity=EXCLUDED.min_severity, "
                    "recipients=EXCLUDED.recipients, webhook_url=EXCLUDED.webhook_url, "
                    "slack_webhook=EXCLUDED.slack_webhook, digest_mode=EXCLUDED.digest_mode, "
                    "digest_schedule=EXCLUDED.digest_schedule"
                ),
                profile,
            )


def delete_profile(name: str) -> None:
    with _connect() as conn:
        conn.execute(
            text("DELETE FROM notification_profiles WHERE name=:name"), {"name": name}
        )


# ── Top CVEs ──────────────────────────────────────────────────────────────────

def get_top_cves(limit: int = 20) -> list[dict]:
    """Return highest-risk CVEs across all tables, scored by CVSS × (1 + EPSS), KEV boosted."""
    tables = list_cve_tables()
    rows: list[dict] = []
    rank_expr = _severity_rank_expr()
    with _connect() as conn:
        for tbl in tables:
            try:
                res = conn.execute(text(
                    f"SELECT *, '{tbl.replace(chr(39), chr(39)+chr(39))}' as _table FROM \"{tbl}\" "
                    f"WHERE severity IN ('CRITICAL','HIGH','MEDIUM') "
                    f"ORDER BY {rank_expr}, cvss_score DESC NULLS LAST LIMIT 100"
                )).fetchall()
                rows.extend(_row_to_dict(r) for r in res)
            except Exception:
                pass

    def _risk(r: dict) -> float:
        score = r.get("cvss_score") or 0.0
        epss  = r.get("epss_score") or 0.0
        kev   = 2.0 if r.get("kev") else 1.0
        return score * (1 + epss) * kev

    rows.sort(key=_risk, reverse=True)
    return rows[:limit]


# ── Trend data ────────────────────────────────────────────────────────────────

def get_trend_data(limit: int = 30) -> list[dict]:
    """Return per-scan new/updated CVE counts for the last `limit` scans, oldest first."""
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT started_at, new_cves, updated_cves, error "
            "FROM scan_history ORDER BY id DESC LIMIT :lim"
        ), {"lim": limit}).fetchall()
    return list(reversed([_row_to_dict(r) for r in rows]))


# ── Digest queue viewer ───────────────────────────────────────────────────────

def get_digest_queue_all() -> list[dict]:
    """Return all unsent digest queue entries across all profiles."""
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM digest_queue WHERE sent=0 ORDER BY profile_name, queued_at DESC"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


def get_digest_preview() -> list[dict]:
    """Return per-profile digest status: pending count, last sent, next fire time."""
    with _connect() as conn:
        profiles = conn.execute(
            text("SELECT name, digest_mode, digest_schedule FROM notification_profiles WHERE digest_mode=1")
        ).fetchall()
        result = []
        intervals = {"hourly": 3600, "daily": 86400, "weekly": 604800}
        for p in profiles:
            name, _, schedule = p[0], p[1], p[2] or "daily"
            pending = conn.execute(
                text("SELECT COUNT(*) FROM digest_queue WHERE sent=0 AND profile_name=:pn"),
                {"pn": name},
            ).fetchone()[0]
            last_row = conn.execute(
                text("SELECT MAX(sent_at) FROM digest_queue WHERE sent=1 AND profile_name=:pn"),
                {"pn": name},
            ).fetchone()
            last_sent = last_row[0] if last_row else None
            next_fire = None
            if last_sent:
                try:
                    from datetime import datetime as _dt
                    last_dt = _dt.fromisoformat(last_sent)
                    interval = intervals.get(schedule, 86400)
                    next_dt  = last_dt.fromtimestamp(last_dt.timestamp() + interval)
                    next_fire = next_dt.isoformat()
                except Exception:
                    pass
            result.append({
                "profile": name,
                "schedule": schedule,
                "pending": pending,
                "last_sent": last_sent,
                "next_fire": next_fire,
            })
        return result


def digest_send_now(profile_name: str) -> int:
    """Force-flush the digest queue for a profile. Returns count sent."""
    pending = digest_get_pending(profile_name)
    if not pending:
        return 0
    digest_mark_sent(profile_name)
    return len(pending)


# ── CVE Watchlist ─────────────────────────────────────────────────────────────

def bootstrap_watchlist() -> None:
    """Create cve_watchlist table if it doesn't exist."""
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cve_watchlist (
                cve_id    TEXT NOT NULL PRIMARY KEY,
                keyword   TEXT,
                added_at  TEXT NOT NULL,
                notes     TEXT DEFAULT ''
            )
        """))
        trans.commit()


def watchlist_add(cve_id: str, keyword: str = "", notes: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT OR IGNORE INTO cve_watchlist (cve_id, keyword, added_at, notes) "
                "VALUES (:cid, :kw, :ts, :notes)"
            ), {"cid": cve_id, "kw": keyword, "ts": now, "notes": notes})
        else:
            conn.execute(text(
                "INSERT INTO cve_watchlist (cve_id, keyword, added_at, notes) "
                "VALUES (:cid, :kw, :ts, :notes) ON CONFLICT (cve_id) DO NOTHING"
            ), {"cid": cve_id, "kw": keyword, "ts": now, "notes": notes})


def watchlist_remove(cve_id: str) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM cve_watchlist WHERE cve_id=:cid"), {"cid": cve_id})


def watchlist_update_notes(cve_id: str, notes: str) -> None:
    with _connect() as conn:
        conn.execute(text("UPDATE cve_watchlist SET notes=:notes WHERE cve_id=:cid"),
                     {"notes": notes, "cid": cve_id})


def watchlist_get() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT w.cve_id, w.keyword, w.added_at, w.notes FROM cve_watchlist w ORDER BY w.added_at DESC"
        )).fetchall()
        result = []
        tables = list_cve_tables()
        for row in rows:
            d = _row_to_dict(row)
            # Try to fetch live CVE data from the matching keyword table
            kw = d.get("keyword", "")
            if kw and kw in tables:
                live = conn.execute(text(
                    f'SELECT severity, cvss_score, epss_score, kev, description FROM "{kw}" WHERE cve_id=:cid'
                ), {"cid": d["cve_id"]}).fetchone()
                if live:
                    d.update(_row_to_dict(live))
            result.append(d)
        return result


# ── CVE review / notes ────────────────────────────────────────────────────────

def bootstrap_reviews() -> None:
    """Create cve_reviews table if it doesn't exist."""
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cve_reviews (
                cve_id      TEXT NOT NULL PRIMARY KEY,
                reviewed    INTEGER DEFAULT 0,
                notes       TEXT DEFAULT '',
                reviewed_at TEXT
            )
        """))
        trans.commit()


def review_set(cve_id: str, reviewed: bool, notes: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds") if reviewed else None
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT INTO cve_reviews (cve_id, reviewed, notes, reviewed_at) "
                "VALUES (:cid, :rev, :notes, :ts) "
                "ON CONFLICT(cve_id) DO UPDATE SET reviewed=excluded.reviewed, "
                "notes=excluded.notes, reviewed_at=excluded.reviewed_at"
            ), {"cid": cve_id, "rev": int(reviewed), "notes": notes, "ts": now})
        else:
            conn.execute(text(
                "INSERT INTO cve_reviews (cve_id, reviewed, notes, reviewed_at) "
                "VALUES (:cid, :rev, :notes, :ts) "
                "ON CONFLICT(cve_id) DO UPDATE SET reviewed=EXCLUDED.reviewed, "
                "notes=EXCLUDED.notes, reviewed_at=EXCLUDED.reviewed_at"
            ), {"cid": cve_id, "rev": int(reviewed), "notes": notes, "ts": now})


def review_get(cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT * FROM cve_reviews WHERE cve_id=:cid"
        ), {"cid": cve_id}).fetchone()
        return _row_to_dict(row) if row else None


def reviews_get_all() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM cve_reviews ORDER BY reviewed_at DESC"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── Keyword performance stats ─────────────────────────────────────────────────

def get_keyword_perf() -> list[dict]:
    """Per-keyword: last scan time, total CVEs, avg CVSS, avg EPSS, KEV count."""
    tables = list_cve_tables()
    result = []
    with _connect() as conn:
        for tbl in tables:
            try:
                row = conn.execute(text(
                    f'SELECT COUNT(*) as total, '
                    f'AVG(cvss_score) as avg_cvss, '
                    f'AVG(epss_score) as avg_epss, '
                    f'SUM(kev) as kev_count '
                    f'FROM "{tbl}"'
                )).fetchone()
                d = _row_to_dict(row)

                # Last scan that touched this keyword — match whole token to avoid
                # "apache" matching "apache tomcat" scans.
                last_row = conn.execute(text(
                    "SELECT MAX(started_at) as last_scan FROM scan_history "
                    "WHERE ',' || keywords || ',' LIKE :kw"
                ), {"kw": f"%,{tbl},%"}).fetchone()

                result.append({
                    "keyword":   tbl,
                    "total":     d["total"] or 0,
                    "avg_cvss":  round(d["avg_cvss"], 2) if d["avg_cvss"] else None,
                    "avg_epss":  round(d["avg_epss"] * 100, 2) if d["avg_epss"] else None,
                    "kev_count": int(d["kev_count"] or 0),
                    "last_scan": (last_row[0] or "")[:16] if last_row else "",
                })
            except Exception:
                pass
    return result


# ── All-tables CSV export ─────────────────────────────────────────────────────

def export_all_cves_csv() -> str:
    """Return a CSV string of every CVE across all keyword tables."""
    import io
    tables = list_cve_tables()
    buf = io.StringIO()
    writer = None
    rank_expr = _severity_rank_expr()
    with _connect() as conn:
        for tbl in tables:
            try:
                rows = conn.execute(text(
                    f"SELECT *, '{tbl.replace(chr(39), chr(39)+chr(39))}' as keyword_table FROM \"{tbl}\" "
                    f"ORDER BY {rank_expr}, publish_date DESC"
                )).fetchall()
                for row in rows:
                    d = _row_to_dict(row)
                    if writer is None:
                        writer = csv.DictWriter(buf, fieldnames=list(d.keys()))
                        writer.writeheader()
                    writer.writerow(d)
            except Exception:
                pass
    return buf.getvalue()


# ── Notification log ──────────────────────────────────────────────────────────

def bootstrap_notify_log() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS notification_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sent_at     TEXT NOT NULL,
                channel     TEXT NOT NULL,
                profile     TEXT DEFAULT '',
                cve_count   INTEGER DEFAULT 0,
                recipients  TEXT DEFAULT '',
                success     INTEGER DEFAULT 1,
                error       TEXT DEFAULT ''
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS notification_log (
                id          SERIAL PRIMARY KEY,
                sent_at     TEXT NOT NULL,
                channel     TEXT NOT NULL,
                profile     TEXT DEFAULT '',
                cve_count   INTEGER DEFAULT 0,
                recipients  TEXT DEFAULT '',
                success     INTEGER DEFAULT 1,
                error       TEXT DEFAULT ''
            )
        """))
        trans.commit()


def notify_log_insert(channel: str, profile: str = "", cve_count: int = 0,
                      recipients: str = "", success: bool = True, error: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(text(
            "INSERT INTO notification_log (sent_at, channel, profile, cve_count, recipients, success, error) "
            "VALUES (:ts, :ch, :pr, :cnt, :rcpt, :ok, :err)"
        ), dict(ts=now, ch=channel, pr=profile, cnt=cve_count, rcpt=recipients,
                ok=int(success), err=error))


def notify_log_get(limit: int = 200) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM notification_log ORDER BY id DESC LIMIT :lim"
        ), {"lim": limit}).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── Severity-over-time data ───────────────────────────────────────────────────

def get_severity_over_time(limit: int = 30) -> list[dict]:
    """
    Return per-scan cumulative severity snapshot by joining scan_history with
    a count of CVEs published up to that scan's started_at across all tables.
    Because we don't snapshot severity counts per scan, we approximate by
    returning the current total broken down by severity alongside each scan timestamp.
    For a real trend we return the existing scan new/updated counts with a severity
    breakdown of all CVEs published up to each scan date.
    """
    with _connect() as conn:
        scans = conn.execute(text(
            "SELECT id, started_at, new_cves, updated_cves FROM scan_history ORDER BY id DESC LIMIT :lim"
        ), {"lim": limit}).fetchall()
    return list(reversed([_row_to_dict(r) for r in scans]))


# ── CVE age distribution ──────────────────────────────────────────────────────

def get_age_distribution() -> list[dict]:
    """Return CVE counts bucketed by age: <30d, 30-90d, 90-180d, 180d+."""
    tables = list_cve_tables()
    buckets = {"lt30": 0, "30_90": 0, "90_180": 0, "gt180": 0}
    with _connect() as conn:
        for tbl in tables:
            try:
                rows = conn.execute(text(
                    f'SELECT publish_date FROM "{tbl}" WHERE publish_date IS NOT NULL'
                )).fetchall()
                for row in rows:
                    try:
                        pub = datetime.fromisoformat(row[0][:10])
                        age = (datetime.utcnow() - pub).days
                        if age < 30:
                            buckets["lt30"] += 1
                        elif age < 90:
                            buckets["30_90"] += 1
                        elif age < 180:
                            buckets["90_180"] += 1
                        else:
                            buckets["gt180"] += 1
                    except Exception:
                        pass
            except Exception:
                pass
    return [
        {"label": "<30 days",   "count": buckets["lt30"]},
        {"label": "30–90 days", "count": buckets["30_90"]},
        {"label": "90–180 days","count": buckets["90_180"]},
        {"label": "180d+",      "count": buckets["gt180"]},
    ]


# ── EPSS vs CVSS scatter data ─────────────────────────────────────────────────

def get_scatter_data(limit: int = 500) -> list[dict]:
    """Return CVSS+EPSS+KEV+severity for all CVEs for scatter plot, capped."""
    tables = list_cve_tables()
    rows: list[dict] = []
    rank_expr = _severity_rank_expr()
    with _connect() as conn:
        for tbl in tables:
            try:
                res = conn.execute(text(
                    f"SELECT cve_id, severity, cvss_score, epss_score, kev, '{tbl.replace(chr(39), chr(39)+chr(39))}' as keyword "
                    f"FROM \"{tbl}\" WHERE cvss_score IS NOT NULL AND epss_score IS NOT NULL "
                    f"ORDER BY {rank_expr} LIMIT 200"
                )).fetchall()
                rows.extend(_row_to_dict(r) for r in res)
            except Exception:
                pass
    rows.sort(key=lambda r: (r.get("kev") or 0), reverse=True)
    return rows[:limit]


# ── CVE age heatmap ───────────────────────────────────────────────────────────

def get_discovery_heatmap(days: int = 90) -> list[dict]:
    """Return per-day new CVE counts for the last N days based on scan_history."""
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT started_at, new_cves FROM scan_history "
            "WHERE started_at >= date('now', :offset) ORDER BY started_at"
        ), {"offset": f"-{days} days"}).fetchall()
    result: dict[str, int] = {}
    for row in rows:
        day = (row[0] or "")[:10]
        if day:
            result[day] = result.get(day, 0) + (row[1] or 0)
    return [{"date": d, "count": c} for d, c in sorted(result.items())]


# ── Schedule info ─────────────────────────────────────────────────────────────

def get_schedule_info() -> dict:
    """Return last scan time and check frequency for schedule countdown."""
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT started_at, finished_at FROM scan_history ORDER BY id DESC LIMIT 1"
        )).fetchone()
    return {
        "last_scan": row[0] if row else None,
        "last_finished": row[1] if row else None,
    }


# ── CVE Triage (assignment, status, SLA) ──────────────────────────────────────

_TRIAGE_STATUSES = {"open", "investigating", "mitigated", "wont_fix", "false_positive", "closed"}
_SLA_DEFAULTS = {"CRITICAL": 3, "HIGH": 7, "MEDIUM": 30, "LOW": 90}  # days


def bootstrap_triage() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cve_triage (
                cve_id      TEXT NOT NULL PRIMARY KEY,
                status      TEXT DEFAULT 'open',
                assignee    TEXT DEFAULT '',
                due_date    TEXT DEFAULT '',
                created_at  TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """))
        _add_column_if_missing(conn, "cve_triage", "status",          "TEXT DEFAULT 'open'")
        _add_column_if_missing(conn, "cve_triage", "assignee",        "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "cve_triage", "due_date",        "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "cve_triage", "created_at",      "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(conn, "cve_triage", "updated_at",      "TEXT NOT NULL DEFAULT ''")
        _add_column_if_missing(conn, "cve_triage", "patched_version", "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "cve_triage", "patched_at",      "TEXT DEFAULT ''")
        _add_column_if_missing(conn, "cve_triage", "patched_by",      "TEXT DEFAULT ''")
        trans.commit()


def triage_set(cve_id: str, status: str = "open", assignee: str = "",
               due_date: str = "", severity: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    if not due_date and severity:
        days = _SLA_DEFAULTS.get(severity.upper(), 30)
        due = datetime.now()
        due = due.replace(hour=0, minute=0, second=0, microsecond=0)
        from datetime import timedelta
        due_date = (due + timedelta(days=days)).isoformat()[:10]
    if _IS_SQLITE:
        upsert = text(
            "INSERT INTO cve_triage (cve_id, status, assignee, due_date, created_at, updated_at) "
            "VALUES (:cid, :st, :asg, :due, :now, :now) "
            "ON CONFLICT(cve_id) DO UPDATE SET status=excluded.status, "
            "assignee=excluded.assignee, due_date=excluded.due_date, updated_at=excluded.updated_at"
        )
    else:
        upsert = text(
            "INSERT INTO cve_triage (cve_id, status, assignee, due_date, created_at, updated_at) "
            "VALUES (:cid, :st, :asg, :due, :now, :now) "
            "ON CONFLICT(cve_id) DO UPDATE SET status=EXCLUDED.status, "
            "assignee=EXCLUDED.assignee, due_date=EXCLUDED.due_date, updated_at=EXCLUDED.updated_at"
        )
    with _connect() as conn:
        conn.execute(upsert, {"cid": cve_id, "st": status, "asg": assignee, "due": due_date, "now": now})


def triage_get(cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT * FROM cve_triage WHERE cve_id=:cid"
        ), {"cid": cve_id}).fetchone()
        return _row_to_dict(row) if row else None


def triage_get_all(status: str = "") -> list[dict]:
    with _connect() as conn:
        if status:
            rows = conn.execute(text(
                "SELECT * FROM cve_triage WHERE status=:st ORDER BY updated_at DESC"
            ), {"st": status}).fetchall()
        else:
            rows = conn.execute(text(
                "SELECT * FROM cve_triage ORDER BY updated_at DESC"
            )).fetchall()
        return [_row_to_dict(r) for r in rows]


def triage_sla_breached() -> list[dict]:
    """Return triage entries whose due_date has passed and aren't closed/mitigated."""
    today = datetime.now().isoformat()[:10]
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM cve_triage WHERE due_date != '' AND due_date < :today "
            "AND status NOT IN ('closed','mitigated','wont_fix','false_positive') "
            "ORDER BY due_date"
        ), {"today": today}).fetchall()
        return [_row_to_dict(r) for r in rows]


def remediation_save(table: str, cve_id: str, notes: str = "", cmds: str = "") -> None:
    """Persist analyst remediation notes and/or AI-generated commands for a CVE."""
    with _connect() as conn:
        conn.execute(text(
            f'UPDATE "{table}" SET remediation_notes=:notes, remediation_cmds=:cmds WHERE cve_id=:cid'
        ), {"notes": notes, "cmds": cmds, "cid": cve_id})


def remediation_get(table: str, cve_id: str) -> dict:
    """Return remediation_notes and remediation_cmds for a CVE row."""
    with _connect() as conn:
        try:
            row = conn.execute(text(
                f'SELECT remediation_notes, remediation_cmds FROM "{table}" WHERE cve_id=:cid'
            ), {"cid": cve_id}).fetchone()
            if row:
                return {"remediation_notes": row[0] or "", "remediation_cmds": row[1] or ""}
        except Exception:
            pass
    return {"remediation_notes": "", "remediation_cmds": ""}


def get_cpe_scanned_cve_ids(table: str) -> set[str]:
    """Return all CVE IDs in a table that were inserted by a CPE (inventory) scan."""
    with _connect() as conn:
        try:
            rows = conn.execute(
                text(f'SELECT cve_id FROM "{table}" WHERE scan_source=\'cpe\'')
            ).fetchall()
            return {r[0] for r in rows}
        except Exception:
            return set()


def triage_auto_patch(cve_ids: list[str], patched_version: str = "", actor: str = "inventory-scan") -> int:
    """
    Mark CVEs as patched=True in triage when a CPE rescan shows they are no longer
    vulnerable for the installed version. Only updates rows that aren't already in a
    terminal state (closed/patched/wont_fix/false_positive).

    Returns the number of rows actually updated.
    """
    if not cve_ids:
        return 0
    now = datetime.now().isoformat(timespec="seconds")
    today = now[:10]
    updated = 0
    with _connect() as conn:
        for cve_id in cve_ids:
            # Upsert: create triage row if none exists, otherwise update only non-terminal rows
            existing = conn.execute(
                text("SELECT status FROM cve_triage WHERE cve_id=:cid"), {"cid": cve_id}
            ).fetchone()
            if existing:
                if existing[0] in ("closed", "patched", "wont_fix", "false_positive"):
                    continue
                conn.execute(text(
                    "UPDATE cve_triage SET status='patched', patched_at=:pa, patched_version=:pv, "
                    "patched_by=:pb, updated_at=:now WHERE cve_id=:cid"
                ), {"pa": today, "pv": patched_version, "pb": actor, "now": now, "cid": cve_id})
            else:
                if _IS_SQLITE:
                    conn.execute(text(
                        "INSERT OR IGNORE INTO cve_triage "
                        "(cve_id, status, assignee, due_date, patched_at, patched_version, patched_by, created_at, updated_at) "
                        "VALUES (:cid,'patched','','', :pa,:pv,:pb,:now,:now)"
                    ), {"cid": cve_id, "pa": today, "pv": patched_version, "pb": actor, "now": now})
                else:
                    conn.execute(text(
                        "INSERT INTO cve_triage "
                        "(cve_id, status, assignee, due_date, patched_at, patched_version, patched_by, created_at, updated_at) "
                        "VALUES (:cid,'patched','','', :pa,:pv,:pb,:now,:now) ON CONFLICT (cve_id) DO NOTHING"
                    ), {"cid": cve_id, "pa": today, "pv": patched_version, "pb": actor, "now": now})
            updated += 1
            audit_log_insert(
                "auto_patched", cve_id,
                f"version={patched_version} no longer vulnerable per CPE rescan",
                actor=actor,
            )
    return updated


# ── False-positive suppression ────────────────────────────────────────────────

def bootstrap_suppressions() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cve_suppressions (
                cve_id      TEXT NOT NULL PRIMARY KEY,
                keyword     TEXT DEFAULT '',
                reason      TEXT DEFAULT '',
                suppressed_at TEXT NOT NULL,
                suppressed_by TEXT DEFAULT ''
            )
        """))
        trans.commit()


def suppression_add(cve_id: str, keyword: str = "", reason: str = "", by: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT OR IGNORE INTO cve_suppressions (cve_id, keyword, reason, suppressed_at, suppressed_by) "
                "VALUES (:cid, :kw, :reason, :ts, :by)"
            ), {"cid": cve_id, "kw": keyword, "reason": reason, "ts": now, "by": by})
        else:
            conn.execute(text(
                "INSERT INTO cve_suppressions (cve_id, keyword, reason, suppressed_at, suppressed_by) "
                "VALUES (:cid, :kw, :reason, :ts, :by) ON CONFLICT (cve_id) DO NOTHING"
            ), {"cid": cve_id, "kw": keyword, "reason": reason, "ts": now, "by": by})


def suppression_remove(cve_id: str) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM cve_suppressions WHERE cve_id=:cid"), {"cid": cve_id})


def suppression_get_all() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM cve_suppressions ORDER BY suppressed_at DESC"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


def is_suppressed(cve_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT 1 FROM cve_suppressions WHERE cve_id=:cid"
        ), {"cid": cve_id}).fetchone()
        return row is not None


# ── Saved views ───────────────────────────────────────────────────────────────

def bootstrap_saved_views() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS saved_views (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL UNIQUE,
                filters    TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS saved_views (
                id         SERIAL PRIMARY KEY,
                name       TEXT NOT NULL UNIQUE,
                filters    TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """))
        trans.commit()


def saved_view_set(name: str, filters: dict) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    filters_json = json.dumps(filters)
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT INTO saved_views (name, filters, created_at) VALUES (:n, :f, :ts) "
                "ON CONFLICT(name) DO UPDATE SET filters=excluded.filters, created_at=excluded.created_at"
            ), {"n": name, "f": filters_json, "ts": now})
        else:
            conn.execute(text(
                "INSERT INTO saved_views (name, filters, created_at) VALUES (:n, :f, :ts) "
                "ON CONFLICT(name) DO UPDATE SET filters=EXCLUDED.filters, created_at=EXCLUDED.created_at"
            ), {"n": name, "f": filters_json, "ts": now})


def saved_view_delete(name: str) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM saved_views WHERE name=:n"), {"n": name})


def saved_views_get() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM saved_views ORDER BY name"
        )).fetchall()
        result = []
        for r in rows:
            d = _row_to_dict(r)
            try:
                d["filters"] = json.loads(d["filters"])
            except Exception:
                d["filters"] = {}
            result.append(d)
        return result


# ── Exploit intelligence ──────────────────────────────────────────────────────
# Stores known exploit / PoC references per CVE, enriched from public sources.

def bootstrap_exploit_intel() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS exploit_intel (
                cve_id        TEXT NOT NULL PRIMARY KEY,
                has_exploit   INTEGER DEFAULT 0,
                exploit_refs  TEXT DEFAULT '',
                poc_url       TEXT DEFAULT '',
                source        TEXT DEFAULT '',
                checked_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS exploit_intel (
                cve_id        TEXT NOT NULL PRIMARY KEY,
                has_exploit   INTEGER DEFAULT 0,
                exploit_refs  TEXT DEFAULT '',
                poc_url       TEXT DEFAULT '',
                source        TEXT DEFAULT '',
                checked_at    TEXT NOT NULL,
                updated_at    TEXT NOT NULL
            )
        """))
        trans.commit()


def exploit_upsert(cve_id: str, has_exploit: bool, exploit_refs: list,
                   poc_url: str = "", source: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    refs_json = json.dumps(exploit_refs)
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT INTO exploit_intel (cve_id, has_exploit, exploit_refs, poc_url, source, checked_at, updated_at) "
                "VALUES (:cid, :he, :refs, :poc, :src, :now, :now) "
                "ON CONFLICT(cve_id) DO UPDATE SET has_exploit=excluded.has_exploit, "
                "exploit_refs=excluded.exploit_refs, poc_url=excluded.poc_url, "
                "source=excluded.source, updated_at=excluded.updated_at"
            ), {"cid": cve_id, "he": int(has_exploit), "refs": refs_json,
                "poc": poc_url, "src": source, "now": now})
        else:
            conn.execute(text(
                "INSERT INTO exploit_intel (cve_id, has_exploit, exploit_refs, poc_url, source, checked_at, updated_at) "
                "VALUES (:cid, :he, :refs, :poc, :src, :now, :now) "
                "ON CONFLICT(cve_id) DO UPDATE SET has_exploit=EXCLUDED.has_exploit, "
                "exploit_refs=EXCLUDED.exploit_refs, poc_url=EXCLUDED.poc_url, "
                "source=EXCLUDED.source, updated_at=EXCLUDED.updated_at"
            ), {"cid": cve_id, "he": int(has_exploit), "refs": refs_json,
                "poc": poc_url, "src": source, "now": now})


def exploit_get(cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT * FROM exploit_intel WHERE cve_id=:cid"
        ), {"cid": cve_id}).fetchone()
        if not row:
            return None
        d = _row_to_dict(row)
        try:
            d["exploit_refs"] = json.loads(d["exploit_refs"] or "[]")
        except Exception:
            d["exploit_refs"] = []
        return d


def exploit_get_all(has_exploit_only: bool = False) -> list[dict]:
    with _connect() as conn:
        if has_exploit_only:
            rows = conn.execute(text(
                "SELECT * FROM exploit_intel WHERE has_exploit=1 ORDER BY updated_at DESC"
            )).fetchall()
        else:
            rows = conn.execute(text(
                "SELECT * FROM exploit_intel ORDER BY updated_at DESC"
            )).fetchall()
        result = []
        for r in rows:
            d = _row_to_dict(r)
            try:
                d["exploit_refs"] = json.loads(d["exploit_refs"] or "[]")
            except Exception:
                d["exploit_refs"] = []
            result.append(d)
        return result


# ── Asset inventory ───────────────────────────────────────────────────────────

def bootstrap_assets() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT NOT NULL,
                cpe             TEXT DEFAULT '',
                tags            TEXT DEFAULT '',
                owner           TEXT DEFAULT '',
                environment     TEXT DEFAULT '',
                last_scanned_at TEXT DEFAULT '',
                scan_source     TEXT DEFAULT '',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS assets (
                id              SERIAL PRIMARY KEY,
                name            TEXT NOT NULL,
                cpe             TEXT DEFAULT '',
                tags            TEXT DEFAULT '',
                owner           TEXT DEFAULT '',
                environment     TEXT DEFAULT '',
                last_scanned_at TEXT DEFAULT '',
                scan_source     TEXT DEFAULT '',
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            )
        """))
        # Migrations for existing databases
        for col, default in [("last_scanned_at", "''"), ("scan_source", "''")]:
            try:
                conn.execute(text(f"ALTER TABLE assets ADD COLUMN {col} TEXT DEFAULT {default}"))
            except Exception:
                pass
        trans.commit()


def asset_save(name: str, cpe: str = "", tags: str = "",
               owner: str = "", environment: str = "",
               asset_id: int | None = None,
               last_scanned_at: str = "", scan_source: str = "") -> int:
    now = datetime.now().isoformat(timespec="seconds")
    scanned = last_scanned_at or now
    with _connect() as conn:
        if asset_id:
            conn.execute(text(
                "UPDATE assets SET name=:name, cpe=:cpe, tags=:tags, owner=:owner, "
                "environment=:env, last_scanned_at=:scanned, scan_source=:src, "
                "updated_at=:now WHERE id=:id"
            ), {"name": name, "cpe": cpe, "tags": tags, "owner": owner,
                "env": environment, "scanned": scanned, "src": scan_source,
                "now": now, "id": asset_id})
            return asset_id
        result = conn.execute(text(
            "INSERT INTO assets (name, cpe, tags, owner, environment, "
            "last_scanned_at, scan_source, created_at, updated_at) "
            "VALUES (:name, :cpe, :tags, :owner, :env, :scanned, :src, :now, :now)"
        ), {"name": name, "cpe": cpe, "tags": tags, "owner": owner,
            "env": environment, "scanned": scanned, "src": scan_source, "now": now})
        return result.lastrowid if _IS_SQLITE else conn.execute(text("SELECT lastval()")).fetchone()[0]


def asset_delete(asset_id: int) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM assets WHERE id=:id"), {"id": asset_id})


def assets_get_all() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM assets ORDER BY name"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


def assets_match_cve(cpe_string: str) -> list[dict]:
    """Return assets whose CPE pattern overlaps with the given CVE CPE string."""
    if not cpe_string:
        return []
    assets = assets_get_all()
    matches = []
    cve_cpes = [c.strip().lower() for c in cpe_string.split(",") if c.strip()]
    for asset in assets:
        asset_cpes = [c.strip().lower() for c in (asset.get("cpe") or "").split(",") if c.strip()]
        for ac in asset_cpes:
            # Wildcard-style: match on vendor:product prefix (first 4 CPE components)
            ac_parts = ac.split(":")
            for cc in cve_cpes:
                cc_parts = cc.split(":")
                # Match if first 5 parts align (cpe:2.3:type:vendor:product)
                if len(ac_parts) >= 5 and len(cc_parts) >= 5 and ac_parts[:5] == cc_parts[:5]:
                    matches.append(asset)
                    break
            else:
                continue
            break
    return matches


# ── Software inventory (per-asset, version-specific) ─────────────────────────

def bootstrap_inventory() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS software_inventory (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id    INTEGER NOT NULL,
                name        TEXT NOT NULL,
                version     TEXT DEFAULT '',
                cpe         TEXT DEFAULT '',
                category    TEXT DEFAULT '',
                severity    TEXT DEFAULT '',
                source      TEXT DEFAULT '',
                updated_at  TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS software_inventory (
                id          SERIAL PRIMARY KEY,
                asset_id    INTEGER NOT NULL,
                name        TEXT NOT NULL,
                version     TEXT DEFAULT '',
                cpe         TEXT DEFAULT '',
                category    TEXT DEFAULT '',
                severity    TEXT DEFAULT '',
                source      TEXT DEFAULT '',
                updated_at  TEXT NOT NULL
            )
        """))
        trans.commit()


def inventory_save(asset_id: int, items: list[dict]) -> None:
    """Replace software inventory for an asset (upsert by name)."""
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        for item in items:
            name = (item.get("name") or "").strip()
            if not name:
                continue
            existing = conn.execute(
                text("SELECT id FROM software_inventory WHERE asset_id=:a AND name=:n"),
                {"a": asset_id, "n": name},
            ).fetchone()
            if existing:
                conn.execute(text(
                    "UPDATE software_inventory SET version=:v, cpe=:c, category=:cat, "
                    "severity=:sev, source=:src, updated_at=:t "
                    "WHERE id=:id"
                ), {
                    "v": item.get("version", ""), "c": item.get("cpe", ""),
                    "cat": item.get("category", ""), "sev": item.get("severity", ""),
                    "src": item.get("source", ""), "t": now, "id": existing[0],
                })
            else:
                conn.execute(text(
                    "INSERT INTO software_inventory "
                    "(asset_id, name, version, cpe, category, severity, source, updated_at) "
                    "VALUES (:a, :n, :v, :c, :cat, :sev, :src, :t)"
                ), {
                    "a": asset_id, "n": name, "v": item.get("version", ""),
                    "c": item.get("cpe", ""), "cat": item.get("category", ""),
                    "sev": item.get("severity", ""), "src": item.get("source", ""),
                    "t": now,
                })


def inventory_get_all() -> list[dict]:
    """Return all software inventory rows joined with asset names."""
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT si.*, a.name AS asset_name "
            "FROM software_inventory si "
            "LEFT JOIN assets a ON a.id = si.asset_id "
            "ORDER BY a.name, si.name"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


def inventory_get_cpe_items() -> list[dict]:
    """Return inventory items that have a versioned CPE (for CPE-based NVD scan)."""
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT si.name, si.version, si.cpe, si.severity, a.name AS asset_name "
            "FROM software_inventory si "
            "LEFT JOIN assets a ON a.id = si.asset_id "
            "WHERE si.version != '' AND si.cpe != ''"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── Internal CVSS override ────────────────────────────────────────────────────

def bootstrap_cvss_overrides() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cvss_overrides (
                cve_id          TEXT NOT NULL PRIMARY KEY,
                internal_score  REAL,
                internal_sev    TEXT DEFAULT '',
                rationale       TEXT DEFAULT '',
                overridden_by   TEXT DEFAULT '',
                overridden_at   TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS cvss_overrides (
                cve_id          TEXT NOT NULL PRIMARY KEY,
                internal_score  REAL,
                internal_sev    TEXT DEFAULT '',
                rationale       TEXT DEFAULT '',
                overridden_by   TEXT DEFAULT '',
                overridden_at   TEXT NOT NULL
            )
        """))
        trans.commit()


def cvss_override_set(cve_id: str, internal_score: float | None,
                      internal_sev: str = "", rationale: str = "",
                      overridden_by: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT INTO cvss_overrides (cve_id, internal_score, internal_sev, rationale, overridden_by, overridden_at) "
                "VALUES (:cid, :sc, :sev, :rat, :by, :now) "
                "ON CONFLICT(cve_id) DO UPDATE SET internal_score=excluded.internal_score, "
                "internal_sev=excluded.internal_sev, rationale=excluded.rationale, "
                "overridden_by=excluded.overridden_by, overridden_at=excluded.overridden_at"
            ), {"cid": cve_id, "sc": internal_score, "sev": internal_sev,
                "rat": rationale, "by": overridden_by, "now": now})
        else:
            conn.execute(text(
                "INSERT INTO cvss_overrides (cve_id, internal_score, internal_sev, rationale, overridden_by, overridden_at) "
                "VALUES (:cid, :sc, :sev, :rat, :by, :now) "
                "ON CONFLICT(cve_id) DO UPDATE SET internal_score=EXCLUDED.internal_score, "
                "internal_sev=EXCLUDED.internal_sev, rationale=EXCLUDED.rationale, "
                "overridden_by=EXCLUDED.overridden_by, overridden_at=EXCLUDED.overridden_at"
            ), {"cid": cve_id, "sc": internal_score, "sev": internal_sev,
                "rat": rationale, "by": overridden_by, "now": now})


def cvss_override_get(cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT * FROM cvss_overrides WHERE cve_id=:cid"
        ), {"cid": cve_id}).fetchone()
        return _row_to_dict(row) if row else None


def cvss_override_delete(cve_id: str) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM cvss_overrides WHERE cve_id=:cid"), {"cid": cve_id})


def cvss_overrides_get_all() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM cvss_overrides ORDER BY overridden_at DESC"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── Users / RBAC ──────────────────────────────────────────────────────────────
# Roles: viewer (read-only), analyst (read + triage/review), lead (full access)

_VALID_ROLES = {"viewer", "analyst", "lead"}


def bootstrap_users() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT NOT NULL UNIQUE,
                api_key    TEXT NOT NULL UNIQUE,
                role       TEXT NOT NULL DEFAULT 'analyst',
                email      TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                active     INTEGER DEFAULT 1
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS users (
                id         SERIAL PRIMARY KEY,
                username   TEXT NOT NULL UNIQUE,
                api_key    TEXT NOT NULL UNIQUE,
                role       TEXT NOT NULL DEFAULT 'analyst',
                email      TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                active     INTEGER DEFAULT 1
            )
        """))
        trans.commit()


def user_create(username: str, role: str = "analyst", email: str = "") -> dict:
    import secrets
    if role not in _VALID_ROLES:
        raise ValueError(f"Invalid role: {role}")
    api_key = secrets.token_hex(32)
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        if _IS_SQLITE:
            result = conn.execute(text(
                "INSERT OR IGNORE INTO users (username, api_key, role, email, created_at) "
                "VALUES (:u, :k, :r, :e, :now)"
            ), {"u": username, "k": api_key, "r": role, "e": email, "now": now})
        else:
            result = conn.execute(text(
                "INSERT INTO users (username, api_key, role, email, created_at) "
                "VALUES (:u, :k, :r, :e, :now) ON CONFLICT (username) DO NOTHING"
            ), {"u": username, "k": api_key, "r": role, "e": email, "now": now})
        if result.rowcount == 0:
            raise ValueError(f"Username '{username}' already exists")
    return {"username": username, "api_key": api_key, "role": role}


def user_update(username: str, role: str | None = None,
                email: str | None = None, active: bool | None = None) -> None:
    parts, params = [], {"u": username}
    if role is not None:
        if role not in _VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")
        parts.append("role=:role"); params["role"] = role
    if email is not None:
        parts.append("email=:email"); params["email"] = email
    if active is not None:
        parts.append("active=:active"); params["active"] = int(active)
    if not parts:
        return
    with _connect() as conn:
        conn.execute(text(f"UPDATE users SET {', '.join(parts)} WHERE username=:u"), params)


def user_delete(username: str) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM users WHERE username=:u"), {"u": username})


def user_get_by_key(api_key: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT * FROM users WHERE api_key=:k AND active=1"
        ), {"k": api_key}).fetchone()
        return _row_to_dict(row) if row else None


def users_get_all() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT id, username, role, email, created_at, active FROM users ORDER BY username"
        )).fetchall()  # NOTE: api_key intentionally excluded from list
        return [_row_to_dict(r) for r in rows]


# ── SLA escalation tracking ───────────────────────────────────────────────────

def get_sla_due_soon(hours: int = 24) -> list[dict]:
    """Return triage entries whose due_date is within `hours` hours from now (not yet breached)."""
    from datetime import timedelta
    now = datetime.now()
    window_end = (now + timedelta(hours=hours)).isoformat()[:10]
    today = now.isoformat()[:10]
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM cve_triage WHERE due_date != '' AND due_date >= :today AND due_date <= :end "
            "AND status NOT IN ('closed','mitigated','wont_fix','false_positive') "
            "ORDER BY due_date"
        ), {"today": today, "end": window_end}).fetchall()
        return [_row_to_dict(r) for r in rows]


def escalation_log_insert(cve_id: str, assignee: str, due_date: str,
                           channel: str, success: bool, error: str = "") -> None:
    """Record that an SLA escalation alert was sent."""
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(text(
            "INSERT INTO notification_log (sent_at, channel, profile, cve_count, recipients, success, error) "
            "VALUES (:ts, :ch, :pr, 1, :rcpt, :ok, :err)"
        ), dict(ts=now, ch=f"sla-escalation/{channel}", pr="",
                rcpt=assignee, ok=int(success), err=error))


# ── Threat intelligence: CISA KEV + in-the-wild ──────────────────────────────

def bootstrap_threat_intel() -> None:
    """Create threat_intel table storing per-CVE in-the-wild exploitation data."""
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS threat_intel (
                cve_id          TEXT NOT NULL PRIMARY KEY,
                in_wild         INTEGER DEFAULT 0,
                threat_actors   TEXT DEFAULT '',
                malware_families TEXT DEFAULT '',
                campaigns       TEXT DEFAULT '',
                source          TEXT DEFAULT '',
                first_seen      TEXT DEFAULT '',
                updated_at      TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS threat_intel (
                cve_id          TEXT NOT NULL PRIMARY KEY,
                in_wild         INTEGER DEFAULT 0,
                threat_actors   TEXT DEFAULT '',
                malware_families TEXT DEFAULT '',
                campaigns       TEXT DEFAULT '',
                source          TEXT DEFAULT '',
                first_seen      TEXT DEFAULT '',
                updated_at      TEXT NOT NULL
            )
        """))
        trans.commit()


def threat_intel_upsert(cve_id: str, in_wild: bool = False,
                        threat_actors: list | None = None,
                        malware_families: list | None = None,
                        campaigns: list | None = None,
                        source: str = "", first_seen: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT INTO threat_intel (cve_id, in_wild, threat_actors, malware_families, campaigns, source, first_seen, updated_at) "
                "VALUES (:cid, :iw, :ta, :mf, :cp, :src, :fs, :now) "
                "ON CONFLICT(cve_id) DO UPDATE SET in_wild=excluded.in_wild, threat_actors=excluded.threat_actors, "
                "malware_families=excluded.malware_families, campaigns=excluded.campaigns, "
                "source=excluded.source, first_seen=excluded.first_seen, updated_at=excluded.updated_at"
            ), {"cid": cve_id, "iw": int(in_wild),
                "ta": json.dumps(threat_actors or []),
                "mf": json.dumps(malware_families or []),
                "cp": json.dumps(campaigns or []),
                "src": source, "fs": first_seen, "now": now})
        else:
            conn.execute(text(
                "INSERT INTO threat_intel (cve_id, in_wild, threat_actors, malware_families, campaigns, source, first_seen, updated_at) "
                "VALUES (:cid, :iw, :ta, :mf, :cp, :src, :fs, :now) "
                "ON CONFLICT(cve_id) DO UPDATE SET in_wild=EXCLUDED.in_wild, threat_actors=EXCLUDED.threat_actors, "
                "malware_families=EXCLUDED.malware_families, campaigns=EXCLUDED.campaigns, "
                "source=EXCLUDED.source, first_seen=EXCLUDED.first_seen, updated_at=EXCLUDED.updated_at"
            ), {"cid": cve_id, "iw": int(in_wild),
                "ta": json.dumps(threat_actors or []),
                "mf": json.dumps(malware_families or []),
                "cp": json.dumps(campaigns or []),
                "src": source, "fs": first_seen, "now": now})


def _parse_threat_intel(d: dict) -> dict:
    for field in ("threat_actors", "malware_families", "campaigns"):
        try:
            d[field] = json.loads(d.get(field) or "[]")
        except Exception:
            d[field] = []
    return d


def threat_intel_get(cve_id: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT * FROM threat_intel WHERE cve_id=:cid"
        ), {"cid": cve_id}).fetchone()
        if not row:
            return None
        return _parse_threat_intel(_row_to_dict(row))


def threat_intel_get_all(in_wild_only: bool = False) -> list[dict]:
    with _connect() as conn:
        if in_wild_only:
            rows = conn.execute(text(
                "SELECT * FROM threat_intel WHERE in_wild=1 ORDER BY updated_at DESC"
            )).fetchall()
        else:
            rows = conn.execute(text(
                "SELECT * FROM threat_intel ORDER BY updated_at DESC"
            )).fetchall()
        return [_parse_threat_intel(_row_to_dict(r)) for r in rows]


# ── Risk scoring ──────────────────────────────────────────────────────────────

def compute_risk_score(cve_id: str, table: str = "") -> dict:
    """
    Composite risk score (0–100) combining:
      - Base CVSS (0–10) × 5           → max 50 pts
      - EPSS probability × 20          → max 20 pts
      - KEV / in-the-wild × 15         → max 15 pts (KEV=12, in_wild=10, both=15)
      - Exploit available × 8          → max 8 pts
      - Asset criticality × 7          → max 7 pts (production = 7, staging = 4, other = 1)
    Returns dict with score (int), factors (dict), label (str).
    """
    factors: dict = {"cvss": 0, "epss": 0, "threat": 0, "exploit": 0, "asset": 0}
    row = None

    if table:
        row = get_cve(table, cve_id)
    else:
        tables = list_cve_tables()
        with _connect() as conn:
            for tbl in tables:
                r = conn.execute(text(
                    f'SELECT * FROM "{tbl}" WHERE cve_id=:cid'
                ), {"cid": cve_id}).fetchone()
                if r:
                    row = _row_to_dict(r)
                    break

    if row:
        cvss = row.get("cvss_score") or 0.0
        factors["cvss"] = min(50, round(cvss * 5, 1))
        epss = row.get("epss_score") or 0.0
        factors["epss"] = min(20, round(epss * 20, 1))
        kev = bool(row.get("kev"))
    else:
        kev = False

    # Threat intel
    ti = threat_intel_get(cve_id)
    in_wild = bool(ti and ti.get("in_wild"))
    if kev and in_wild:
        factors["threat"] = 15
    elif kev:
        factors["threat"] = 12
    elif in_wild:
        factors["threat"] = 10

    # Exploit intel
    ei = exploit_get(cve_id)
    if ei and ei.get("has_exploit"):
        factors["exploit"] = 8

    # Asset criticality — highest-criticality asset affected
    asset_score = 0
    if row and row.get("cpe"):
        matched = assets_match_cve(row["cpe"])
        for a in matched:
            env = (a.get("environment") or "").lower()
            if env == "production":
                asset_score = max(asset_score, 7)
            elif env in ("staging", "dmz"):
                asset_score = max(asset_score, 4)
            else:
                asset_score = max(asset_score, 1)
    factors["asset"] = asset_score

    total = round(sum(factors.values()))
    total = min(100, total)

    if total >= 80:
        label = "CRITICAL RISK"
    elif total >= 60:
        label = "HIGH RISK"
    elif total >= 40:
        label = "MEDIUM RISK"
    elif total >= 20:
        label = "LOW RISK"
    else:
        label = "MINIMAL RISK"

    return {"cve_id": cve_id, "score": total, "label": label, "factors": factors}


# ── CVE comments / audit log ──────────────────────────────────────────────────

def bootstrap_comments() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS cve_comments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id     TEXT NOT NULL,
                author     TEXT DEFAULT '',
                body       TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS cve_comments (
                id         SERIAL PRIMARY KEY,
                cve_id     TEXT NOT NULL,
                author     TEXT DEFAULT '',
                body       TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """))
        trans.commit()


def comment_add(cve_id: str, body: str, author: str = "") -> int:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        result = conn.execute(text(
            "INSERT INTO cve_comments (cve_id, author, body, created_at) VALUES (:cid, :au, :body, :now)"
        ), {"cid": cve_id, "au": author, "body": body, "now": now})
        if _IS_SQLITE:
            return result.lastrowid
        return conn.execute(text("SELECT lastval()")).fetchone()[0]


def comment_delete(comment_id: int) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM cve_comments WHERE id=:id"), {"id": comment_id})


def comments_get(cve_id: str) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM cve_comments WHERE cve_id=:cid ORDER BY created_at"
        ), {"cid": cve_id}).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── Audit log ─────────────────────────────────────────────────────────────────

def bootstrap_audit_log() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                actor      TEXT DEFAULT '',
                action     TEXT NOT NULL,
                target_id  TEXT DEFAULT '',
                detail     TEXT DEFAULT ''
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS audit_log (
                id         SERIAL PRIMARY KEY,
                ts         TEXT NOT NULL,
                actor      TEXT DEFAULT '',
                action     TEXT NOT NULL,
                target_id  TEXT DEFAULT '',
                detail     TEXT DEFAULT ''
            )
        """))
        trans.commit()


def audit_log_insert(action: str, target_id: str = "", detail: str = "", actor: str = "") -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        conn.execute(text(
            "INSERT INTO audit_log (ts, actor, action, target_id, detail) VALUES (:ts, :ac, :act, :tid, :det)"
        ), {"ts": now, "ac": actor, "act": action, "tid": target_id, "det": detail})


def audit_log_get(limit: int = 200, target_id: str = "") -> list[dict]:
    with _connect() as conn:
        if target_id:
            rows = conn.execute(text(
                "SELECT * FROM audit_log WHERE target_id=:tid ORDER BY id DESC LIMIT :lim"
            ), {"tid": target_id, "lim": limit}).fetchall()
        else:
            rows = conn.execute(text(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT :lim"
            ), {"lim": limit}).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── Lifecycle / MTTR ──────────────────────────────────────────────────────────

def get_mttr_stats() -> dict:
    """
    Mean Time To Remediate — average days from triage created_at to
    status entering a terminal state (closed/mitigated).
    Also returns open count, overdue count, and per-severity averages.
    """
    terminal = ("closed", "mitigated", "wont_fix", "false_positive")
    today = datetime.now().isoformat()[:10]
    with _connect() as conn:
        all_rows = conn.execute(text(
            "SELECT cve_id, status, created_at, updated_at, due_date FROM cve_triage"
        )).fetchall()

    durations = []
    open_count = 0
    overdue_count = 0

    for row in all_rows:
        d = _row_to_dict(row)
        if d["status"] in terminal and d["created_at"] and d["updated_at"]:
            try:
                start = datetime.fromisoformat(d["created_at"][:19])
                end   = datetime.fromisoformat(d["updated_at"][:19])
                days  = max(0, (end - start).days)
                durations.append(days)
            except Exception:
                pass
        elif d["status"] not in terminal:
            open_count += 1
            if d.get("due_date") and d["due_date"] < today:
                overdue_count += 1

    mttr = round(sum(durations) / len(durations), 1) if durations else None

    # Time-in-state distribution
    state_counts = {}
    for row in all_rows:
        d = _row_to_dict(row)
        state_counts[d["status"]] = state_counts.get(d["status"], 0) + 1

    return {
        "mttr_days":     mttr,
        "remediated":    len(durations),
        "open":          open_count,
        "overdue":       overdue_count,
        "state_counts":  state_counts,
    }


# ── Notification routing rules ────────────────────────────────────────────────

def bootstrap_routing_rules() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS routing_rules (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                min_severity TEXT DEFAULT 'CRITICAL',
                tag_filter   TEXT DEFAULT '',
                channel      TEXT NOT NULL,
                destination  TEXT NOT NULL,
                active       INTEGER DEFAULT 1,
                created_at   TEXT NOT NULL
            )
        """ if _IS_SQLITE else """
            CREATE TABLE IF NOT EXISTS routing_rules (
                id           SERIAL PRIMARY KEY,
                name         TEXT NOT NULL,
                min_severity TEXT DEFAULT 'CRITICAL',
                tag_filter   TEXT DEFAULT '',
                channel      TEXT NOT NULL,
                destination  TEXT NOT NULL,
                active       INTEGER DEFAULT 1,
                created_at   TEXT NOT NULL
            )
        """))
        trans.commit()


def routing_rule_save(name: str, min_severity: str, tag_filter: str,
                      channel: str, destination: str, rule_id: int | None = None) -> int:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        if rule_id:
            conn.execute(text(
                "UPDATE routing_rules SET name=:name, min_severity=:ms, tag_filter=:tf, "
                "channel=:ch, destination=:dest WHERE id=:id"
            ), {"name": name, "ms": min_severity, "tf": tag_filter,
                "ch": channel, "dest": destination, "id": rule_id})
            return rule_id
        result = conn.execute(text(
            "INSERT INTO routing_rules (name, min_severity, tag_filter, channel, destination, created_at) "
            "VALUES (:name, :ms, :tf, :ch, :dest, :now)"
        ), {"name": name, "ms": min_severity, "tf": tag_filter,
            "ch": channel, "dest": destination, "now": now})
        if _IS_SQLITE:
            return result.lastrowid
        return conn.execute(text("SELECT lastval()")).fetchone()[0]


def routing_rule_delete(rule_id: int) -> None:
    with _connect() as conn:
        conn.execute(text("DELETE FROM routing_rules WHERE id=:id"), {"id": rule_id})


def routing_rules_get() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT * FROM routing_rules WHERE active=1 ORDER BY id"
        )).fetchall()
        return [_row_to_dict(r) for r in rows]


# ── Alert deduplication ───────────────────────────────────────────────────────

def bootstrap_alert_dedup() -> None:
    engine = _get_engine()
    with engine.connect() as conn:
        trans = conn.begin()
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS alert_dedup (
                cve_id     TEXT NOT NULL,
                channel    TEXT NOT NULL,
                alerted_at TEXT NOT NULL,
                PRIMARY KEY (cve_id, channel)
            )
        """))
        trans.commit()


def alert_dedup_check(cve_id: str, channel: str, cooldown_hours: int = 24) -> bool:
    """Return True if alert was already sent within cooldown_hours and should be suppressed."""
    from datetime import timedelta
    cutoff = (datetime.now() - timedelta(hours=cooldown_hours)).isoformat(timespec="seconds")
    with _connect() as conn:
        row = conn.execute(text(
            "SELECT alerted_at FROM alert_dedup WHERE cve_id=:cid AND channel=:ch AND alerted_at > :cutoff"
        ), {"cid": cve_id, "ch": channel, "cutoff": cutoff}).fetchone()
        return row is not None


def alert_dedup_record(cve_id: str, channel: str) -> None:
    now = datetime.now().isoformat(timespec="seconds")
    with _connect() as conn:
        if _IS_SQLITE:
            conn.execute(text(
                "INSERT INTO alert_dedup (cve_id, channel, alerted_at) VALUES (:cid, :ch, :now) "
                "ON CONFLICT(cve_id, channel) DO UPDATE SET alerted_at=excluded.alerted_at"
            ), {"cid": cve_id, "ch": channel, "now": now})
        else:
            conn.execute(text(
                "INSERT INTO alert_dedup (cve_id, channel, alerted_at) VALUES (:cid, :ch, :now) "
                "ON CONFLICT(cve_id, channel) DO UPDATE SET alerted_at=EXCLUDED.alerted_at"
            ), {"cid": cve_id, "ch": channel, "now": now})


# ── Compliance mapping ────────────────────────────────────────────────────────
# Static CWE → control framework mapping (NIST 800-53, CIS Controls v8, ISO 27001)

_COMPLIANCE_MAP: dict[str, dict] = {
    "CWE-78":  {"nist": ["SI-10", "SI-3"],        "cis": ["8.2", "8.5"],      "iso": ["A.12.6.1"]},
    "CWE-79":  {"nist": ["SI-10", "SC-28"],        "cis": ["4.1"],             "iso": ["A.12.6.1"]},
    "CWE-89":  {"nist": ["SI-10", "AC-3"],         "cis": ["4.1", "4.2"],      "iso": ["A.12.6.1", "A.9.4.1"]},
    "CWE-94":  {"nist": ["SI-3", "SI-10"],         "cis": ["10.1"],            "iso": ["A.12.6.1"]},
    "CWE-119": {"nist": ["SI-10", "SI-16"],        "cis": ["10.2"],            "iso": ["A.12.6.1"]},
    "CWE-120": {"nist": ["SI-16"],                 "cis": ["10.2"],            "iso": ["A.12.6.1"]},
    "CWE-200": {"nist": ["AC-3", "AC-6", "SC-28"], "cis": ["3.1", "3.2"],      "iso": ["A.9.4.1", "A.10.1.1"]},
    "CWE-269": {"nist": ["AC-6", "AC-2"],          "cis": ["5.1", "5.4"],      "iso": ["A.9.2.3"]},
    "CWE-276": {"nist": ["AC-6", "CM-6"],          "cis": ["5.1"],             "iso": ["A.9.4.1"]},
    "CWE-284": {"nist": ["AC-3", "AC-6"],          "cis": ["5.1", "5.2"],      "iso": ["A.9.4.1"]},
    "CWE-285": {"nist": ["AC-3"],                  "cis": ["5.3"],             "iso": ["A.9.4.1"]},
    "CWE-287": {"nist": ["IA-2", "IA-5"],          "cis": ["6.1", "6.3"],      "iso": ["A.9.4.2"]},
    "CWE-295": {"nist": ["SC-17", "SI-7"],         "cis": ["12.1"],            "iso": ["A.10.1.1"]},
    "CWE-306": {"nist": ["IA-2", "AC-3"],          "cis": ["6.1"],             "iso": ["A.9.4.2"]},
    "CWE-311": {"nist": ["SC-28", "SC-8"],         "cis": ["3.1", "12.4"],     "iso": ["A.10.1.1"]},
    "CWE-312": {"nist": ["SC-28"],                 "cis": ["3.1"],             "iso": ["A.10.1.1"]},
    "CWE-319": {"nist": ["SC-8"],                  "cis": ["12.4"],            "iso": ["A.10.1.1"]},
    "CWE-326": {"nist": ["SC-13"],                 "cis": ["12.4"],            "iso": ["A.10.1.1"]},
    "CWE-327": {"nist": ["SC-13"],                 "cis": ["12.4"],            "iso": ["A.10.1.1"]},
    "CWE-330": {"nist": ["SC-13"],                 "cis": ["12.4"],            "iso": ["A.10.1.1"]},
    "CWE-352": {"nist": ["SC-23", "SI-10"],        "cis": ["4.1"],             "iso": ["A.12.6.1"]},
    "CWE-362": {"nist": ["SI-16", "SC-39"],        "cis": ["10.2"],            "iso": ["A.12.6.1"]},
    "CWE-400": {"nist": ["SC-5", "SI-17"],         "cis": ["12.1"],            "iso": ["A.12.6.1"]},
    "CWE-416": {"nist": ["SI-16"],                 "cis": ["10.2"],            "iso": ["A.12.6.1"]},
    "CWE-434": {"nist": ["SI-3", "CM-7"],          "cis": ["10.1"],            "iso": ["A.12.6.1"]},
    "CWE-476": {"nist": ["SI-16"],                 "cis": ["10.2"],            "iso": ["A.12.6.1"]},
    "CWE-502": {"nist": ["SI-10", "CM-7"],         "cis": ["4.1"],             "iso": ["A.12.6.1"]},
    "CWE-601": {"nist": ["SI-10"],                 "cis": ["4.1"],             "iso": ["A.12.6.1"]},
    "CWE-611": {"nist": ["SI-10", "CM-7"],         "cis": ["4.1"],             "iso": ["A.12.6.1"]},
    "CWE-639": {"nist": ["AC-3"],                  "cis": ["5.3"],             "iso": ["A.9.4.1"]},
    "CWE-732": {"nist": ["AC-6", "CM-6"],          "cis": ["5.1"],             "iso": ["A.9.4.1"]},
    "CWE-787": {"nist": ["SI-16"],                 "cis": ["10.2"],            "iso": ["A.12.6.1"]},
    "CWE-798": {"nist": ["IA-5", "SC-28"],         "cis": ["6.3"],             "iso": ["A.9.4.3"]},
    "CWE-918": {"nist": ["SC-7", "AC-4"],          "cis": ["12.2"],            "iso": ["A.13.1.3"]},
}


def get_compliance_mapping(cwe_str: str) -> dict:
    """Return NIST 800-53, CIS Controls v8, and ISO 27001 controls for the given CWE(s)."""
    cwes = [c.strip() for c in cwe_str.split(",") if c.strip()]
    nist: set[str] = set()
    cis:  set[str] = set()
    iso:  set[str] = set()
    for cwe in cwes:
        mapping = _COMPLIANCE_MAP.get(cwe, {})
        nist.update(mapping.get("nist", []))
        cis.update(mapping.get("cis", []))
        iso.update(mapping.get("iso", []))
    return {
        "nist_800_53": sorted(nist),
        "cis_v8":      sorted(cis),
        "iso_27001":   sorted(iso),
    }


# ── Scan health stats ─────────────────────────────────────────────────────────

def get_scan_health(limit: int = 20) -> dict:
    """Return scan success rate, avg duration, error rate for last N scans."""
    with _connect() as conn:
        rows = conn.execute(text(
            "SELECT started_at, finished_at, new_cves, updated_cves, error "
            "FROM scan_history ORDER BY id DESC LIMIT :lim"
        ), {"lim": limit}).fetchall()

    scans = [_row_to_dict(r) for r in rows]
    total = len(scans)
    if not total:
        return {"total": 0, "success_rate": 0, "avg_duration_sec": 0, "error_rate": 0, "scans": []}

    errors = sum(1 for s in scans if s.get("error"))
    durations = []
    for s in scans:
        if s.get("started_at") and s.get("finished_at"):
            try:
                dur = (datetime.fromisoformat(s["finished_at"]) - datetime.fromisoformat(s["started_at"])).total_seconds()
                durations.append(dur)
            except Exception:
                pass

    return {
        "total":           total,
        "success_rate":    round((total - errors) / total * 100, 1),
        "avg_duration_sec": round(sum(durations) / len(durations), 1) if durations else 0,
        "error_rate":      round(errors / total * 100, 1),
        "scans":           list(reversed(scans)),
    }
