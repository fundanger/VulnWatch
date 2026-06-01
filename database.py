"""
Database backend — SQLite (default) or MySQL.

Set [DATABASE] backend = mysql in config.ini to use MySQL.
SQLite stores data in cve_emailer.db next to the script with zero server setup.
"""

from __future__ import annotations

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


# ── Unified context manager ───────────────────────────────────────────────────

@contextmanager
def _connect():
    if _backend() == "mysql":
        with _mysql() as conn:
            yield conn
    else:
        with _sqlite() as conn:
            yield conn


# ── Public API ────────────────────────────────────────────────────────────────

def create_table(service_name: str) -> None:
    if _backend() == "mysql":
        query = (
            f"CREATE TABLE IF NOT EXISTS `{service_name}` ("
            "cve_id VARCHAR(255) NOT NULL PRIMARY KEY,"
            "publish_date DATETIME,"
            "last_modified DATETIME,"
            "description TEXT,"
            "severity VARCHAR(16)"
            ");"
        )
    else:
        query = (
            f'CREATE TABLE IF NOT EXISTS "{service_name}" ('
            "cve_id TEXT NOT NULL PRIMARY KEY,"
            "publish_date TEXT,"
            "last_modified TEXT,"
            "description TEXT,"
            "severity TEXT"
            ");"
        )
    with _connect() as conn:
        conn.execute(query) if _backend() != "mysql" else conn.cursor().execute(query)


def insert_cve(
    table: str,
    cve_id: str,
    publish_date: str,
    last_modified: str,
    description: str,
    severity: str,
) -> bool:
    """Insert a CVE row. Returns True if it was new (not already seen)."""
    if _backend() == "mysql":
        query = (
            f"INSERT IGNORE INTO `{table}` "
            "(cve_id, publish_date, last_modified, description, severity)"
            " VALUES (%s, %s, %s, %s, %s);"
        )
        with _connect() as conn:
            cur = conn.cursor()
            cur.execute(query, (cve_id, publish_date, last_modified, description, severity))
            return cur.rowcount > 0
    else:
        query = (
            f'INSERT OR IGNORE INTO "{table}" '
            "(cve_id, publish_date, last_modified, description, severity)"
            " VALUES (?, ?, ?, ?, ?);"
        )
        with _connect() as conn:
            cur = conn.execute(query, (cve_id, publish_date, last_modified, description, severity))
            return cur.rowcount > 0
