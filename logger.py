"""Structured JSON logging for SIEM ingest."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

_LOG_PATH = Path(__file__).parent / "cve_emailer.log"

_initialized = False


def _json_formatter(record: logging.LogRecord) -> str:
    payload = {
        "ts":      datetime.now(timezone.utc).isoformat(),
        "level":   record.levelname,
        "logger":  record.name,
        "message": record.getMessage(),
    }
    if record.exc_info:
        payload["exception"] = logging.Formatter().formatException(record.exc_info)
    if hasattr(record, "extra"):
        payload.update(record.extra)
    return json.dumps(payload)


class _JsonHandler(logging.StreamHandler):
    def format(self, record: logging.LogRecord) -> str:
        return _json_formatter(record)


def setup(also_stderr: bool = False) -> None:
    global _initialized
    if _initialized:
        return
    _initialized = True

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # File handler — JSON, always
    fh = logging.FileHandler(_LOG_PATH, encoding="utf-8")
    fh.setFormatter(logging.Formatter())
    fh.emit = lambda r: fh.stream.write(_json_formatter(r) + "\n") or fh.stream.flush()  # type: ignore[method-assign]
    root.addHandler(fh)

    if also_stderr:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        root.addHandler(sh)


def get(name: str) -> logging.Logger:
    """Return a named logger. Call setup() first."""
    return logging.getLogger(name)


def event(name: str, **kwargs) -> None:
    """Log a structured event at INFO level."""
    logger = logging.getLogger("cve_emailer.events")
    record = logging.LogRecord(
        name="cve_emailer.events",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg=name,
        args=(),
        exc_info=None,
    )
    record.extra = kwargs  # type: ignore[attr-defined]
    logger.handle(record)
