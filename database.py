import configparser
from contextlib import contextmanager

import mysql.connector

CONFIG = configparser.ConfigParser()
CONFIG.read("config.ini")


@contextmanager
def _connect():
    conn = mysql.connector.connect(
        user=CONFIG["DATABASE"]["username"],
        password=CONFIG["DATABASE"]["password"],
        host=CONFIG["DATABASE"]["host"],
        database=CONFIG["DATABASE"]["database"],
    )
    try:
        yield conn
    finally:
        conn.close()


def create_table(service_name: str) -> None:
    query = (
        f"CREATE TABLE IF NOT EXISTS `{service_name}` ("
        "cve_id VARCHAR(255) NOT NULL PRIMARY KEY,"
        "publish_date DATETIME,"
        "last_modified DATETIME,"
        "description TEXT"
        ");"
    )
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        conn.commit()


def insert_cve(table: str, cve_id: str, publish_date: str, last_modified: str, description: str) -> bool:
    """Insert a CVE row. Returns True if it was new (not already present)."""
    query = (
        f"INSERT IGNORE INTO `{table}` (cve_id, publish_date, last_modified, description)"
        " VALUES (%s, %s, %s, %s);"
    )
    with _connect() as conn:
        cursor = conn.cursor()
        cursor.execute(query, (cve_id, publish_date, last_modified, description))
        conn.commit()
        return cursor.rowcount > 0
