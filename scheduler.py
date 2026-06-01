"""
Windows Task Scheduler integration for headless / background operation.

Usage:
    python scheduler.py install   — register a Task Scheduler job
    python scheduler.py remove    — delete the job
    python scheduler.py run       — run one scan cycle (called by the scheduler)
    python scheduler.py status    — show whether the job is registered
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

TASK_NAME = "CVEEmailer"
PYTHON = sys.executable
SCRIPT = str(Path(__file__).resolve())


def _run_cmd(args: list[str]) -> tuple[int, str]:
    result = subprocess.run(args, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def install(interval_minutes: int = 60) -> str:
    """Register a repeating Task Scheduler job."""
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).parent / "config.ini")
    freq_sec = int(cfg["DEFAULT"].get("checkFrequency", "3600"))
    interval_minutes = max(1, freq_sec // 60)

    # Build schtasks command
    cmd = [
        "schtasks", "/create", "/f",
        "/tn", TASK_NAME,
        "/tr", f'"{PYTHON}" "{SCRIPT}" run',
        "/sc", "minute",
        "/mo", str(interval_minutes),
        "/rl", "HIGHEST",
    ]
    code, out = _run_cmd(cmd)
    if code != 0:
        raise RuntimeError(f"schtasks /create failed:\n{out}")
    return f"Task '{TASK_NAME}' registered — runs every {interval_minutes} minute(s)."


def remove() -> str:
    code, out = _run_cmd(["schtasks", "/delete", "/f", "/tn", TASK_NAME])
    if code != 0:
        raise RuntimeError(f"schtasks /delete failed:\n{out}")
    return f"Task '{TASK_NAME}' removed."


def status() -> str:
    code, out = _run_cmd(["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST"])
    if code != 0:
        return f"Task '{TASK_NAME}' is NOT registered."
    return out.strip()


def run_headless() -> None:
    """Single scan cycle — intended to be called by Task Scheduler."""
    import logging
    from pathlib import Path as P
    logging.basicConfig(
        filename=str(P(__file__).parent / "cve_emailer.log"),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    log = lambda msg: logging.info(msg)  # noqa: E731

    import database
    database.bootstrap()

    from tui import _run_once_patched
    try:
        _run_once_patched(log=log)
    except Exception as exc:
        logging.error(f"Headless scan failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    try:
        if cmd == "install":
            print(install())
        elif cmd == "remove":
            print(remove())
        elif cmd == "status":
            print(status())
        elif cmd == "run":
            run_headless()
        else:
            print(__doc__)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
