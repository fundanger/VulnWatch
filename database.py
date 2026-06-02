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
        "kev              INTEGER DEFAULT 0"
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
            ("kev",              "INTEGER DEFAULT 0"),
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
                "epss_score, epss_percentile, kev) "
                "VALUES (:cve_id,:publish_date,:last_modified,:description,:severity,:cvss_score,"
                ":cwe,:cpe,:references_json,:keyword,:severity2,:cvss_score2,"
                ":epss_score,:epss_percentile,:kev)"
            )
        else:
            ins = text(
                f'INSERT INTO "{table}" '
                "(cve_id, publish_date, last_modified, description, severity, cvss_score, "
                "cwe, cpe, references_json, keyword, alerted_severity, alerted_score, "
                "epss_score, epss_percentile, kev) "
                "VALUES (:cve_id,:publish_date,:last_modified,:description,:severity,:cvss_score,"
                ":cwe,:cpe,:references_json,:keyword,:severity2,:cvss_score2,"
                ":epss_score,:epss_percentile,:kev) "
                "ON CONFLICT (cve_id) DO NOTHING"
            )

        params = dict(
            cve_id=cve_id, publish_date=publish_date, last_modified=last_modified,
            description=description, severity=severity, cvss_score=cvss_score,
            cwe=cwe, cpe=cpe, references_json=references_json, keyword=keyword,
            severity2=severity, cvss_score2=cvss_score,
            epss_score=epss_score, epss_percentile=epss_percentile, kev=int(kev),
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
    system = {"scan_history", "notification_profiles", "digest_queue", "sqlite_sequence"}
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

    return {
        "totals":          severity_totals,
        "per_keyword":     per_keyword,
        "recent_scans":    [_row_to_dict(r) for r in recent],
        "total_keywords":  len(tables),
        "total_cves":      sum(severity_totals.values()),
        "kev_total":       kev_total,
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
                    f'SELECT *, "{tbl}" as _table FROM "{tbl}" '
                    f'WHERE severity IN (\'CRITICAL\',\'HIGH\',\'MEDIUM\') '
                    f'ORDER BY {rank_expr}, cvss_score DESC NULLS LAST LIMIT 100'
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

                # Last scan that touched this keyword
                last_row = conn.execute(text(
                    "SELECT MAX(started_at) as last_scan FROM scan_history "
                    "WHERE keywords LIKE :kw"
                ), {"kw": f"%{tbl}%"}).fetchone()

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
                    f'SELECT *, "{tbl}" as keyword_table FROM "{tbl}" '
                    f'ORDER BY {rank_expr}, publish_date DESC'
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
