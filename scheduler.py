"""
Cross-platform background scheduler for CVE Emailer.

Usage:
    python scheduler.py install   — register a background job for this OS
    python scheduler.py remove    — unregister the job
    python scheduler.py status    — check if the job is registered
    python scheduler.py run       — run one scan cycle (called by the scheduler)

Supported platforms:
    Windows  — Windows Task Scheduler (schtasks)
    macOS    — launchd user agent (~/Library/LaunchAgents)
    Linux    — systemd user service  (~/.config/systemd/user)
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
from pathlib import Path

TASK_NAME = "CVEEmailer"
PYTHON = sys.executable
SCRIPT = str(Path(__file__).resolve())
_CONFIG_PATH = Path(__file__).parent / "config.ini"
_LOG_PATH = Path(__file__).parent / "cve_emailer.log"

OS = platform.system()  # "Windows", "Darwin", "Linux"


def _freq_minutes() -> int:
    import configparser
    cfg = configparser.ConfigParser()
    cfg.read(_CONFIG_PATH)
    freq_sec = int(cfg["DEFAULT"].get("checkFrequency", "3600"))
    return max(1, freq_sec // 60)


def _run_cmd(args: list[str]) -> tuple[int, str]:
    result = subprocess.run(args, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


# ── Windows ───────────────────────────────────────────────────────────────────

def _win_install() -> str:
    interval = _freq_minutes()
    cmd = [
        "schtasks", "/create", "/f",
        "/tn", TASK_NAME,
        "/tr", f'"{PYTHON}" "{SCRIPT}" run',
        "/sc", "minute",
        "/mo", str(interval),
        "/rl", "HIGHEST",
    ]
    code, out = _run_cmd(cmd)
    if code != 0:
        raise RuntimeError(f"schtasks /create failed:\n{out}")
    return f"Task '{TASK_NAME}' registered — runs every {interval} minute(s)."


def _win_remove() -> str:
    code, out = _run_cmd(["schtasks", "/delete", "/f", "/tn", TASK_NAME])
    if code != 0:
        raise RuntimeError(f"schtasks /delete failed:\n{out}")
    return f"Task '{TASK_NAME}' removed."


def _win_status() -> str:
    code, out = _run_cmd(["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST"])
    if code != 0:
        return f"Task '{TASK_NAME}' is NOT registered."
    return out.strip()


# ── macOS (launchd) ───────────────────────────────────────────────────────────

_LAUNCH_AGENTS = Path.home() / "Library" / "LaunchAgents"
_PLIST_PATH = _LAUNCH_AGENTS / f"com.{TASK_NAME.lower()}.plist"


def _mac_install() -> str:
    interval_sec = _freq_minutes() * 60
    _LAUNCH_AGENTS.mkdir(parents=True, exist_ok=True)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.{TASK_NAME.lower()}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{PYTHON}</string>
        <string>{SCRIPT}</string>
        <string>run</string>
    </array>
    <key>StartInterval</key>
    <integer>{interval_sec}</integer>
    <key>StandardOutPath</key>
    <string>{_LOG_PATH}</string>
    <key>StandardErrorPath</key>
    <string>{_LOG_PATH}</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
"""
    _PLIST_PATH.write_text(plist)
    code, out = _run_cmd(["launchctl", "load", str(_PLIST_PATH)])
    if code != 0:
        raise RuntimeError(f"launchctl load failed:\n{out}")
    return f"launchd agent loaded — runs every {interval_sec}s.\nPlist: {_PLIST_PATH}"


def _mac_remove() -> str:
    if _PLIST_PATH.exists():
        _run_cmd(["launchctl", "unload", str(_PLIST_PATH)])
        _PLIST_PATH.unlink()
        return f"launchd agent removed ({_PLIST_PATH.name})."
    return "No launchd agent found."


def _mac_status() -> str:
    if not _PLIST_PATH.exists():
        return f"launchd agent NOT installed ({_PLIST_PATH.name})."
    code, out = _run_cmd(["launchctl", "list", f"com.{TASK_NAME.lower()}"])
    if code != 0:
        return f"Plist exists but agent is not loaded: {_PLIST_PATH}"
    return f"launchd agent running.\n{out.strip()}"


# ── Linux (systemd user service) ──────────────────────────────────────────────

_SYSTEMD_DIR = Path.home() / ".config" / "systemd" / "user"
_SERVICE_PATH = _SYSTEMD_DIR / f"{TASK_NAME.lower()}.service"
_TIMER_PATH = _SYSTEMD_DIR / f"{TASK_NAME.lower()}.timer"


def _linux_install() -> str:
    interval_sec = _freq_minutes() * 60
    _SYSTEMD_DIR.mkdir(parents=True, exist_ok=True)

    service = f"""[Unit]
Description=CVE Emailer scheduled scan

[Service]
Type=oneshot
ExecStart={PYTHON} {SCRIPT} run
StandardOutput=append:{_LOG_PATH}
StandardError=append:{_LOG_PATH}
"""
    timer = f"""[Unit]
Description=CVE Emailer scan timer

[Timer]
OnBootSec=60
OnUnitActiveSec={interval_sec}
Persistent=true

[Install]
WantedBy=timers.target
"""
    _SERVICE_PATH.write_text(service)
    _TIMER_PATH.write_text(timer)

    _run_cmd(["systemctl", "--user", "daemon-reload"])
    code, out = _run_cmd(["systemctl", "--user", "enable", "--now", f"{TASK_NAME.lower()}.timer"])
    if code != 0:
        raise RuntimeError(f"systemctl enable failed:\n{out}")
    return f"systemd timer enabled — runs every {interval_sec}s.\nService: {_SERVICE_PATH}"


def _linux_remove() -> str:
    _run_cmd(["systemctl", "--user", "disable", "--now", f"{TASK_NAME.lower()}.timer"])
    for p in (_SERVICE_PATH, _TIMER_PATH):
        if p.exists():
            p.unlink()
    _run_cmd(["systemctl", "--user", "daemon-reload"])
    return "systemd timer and service removed."


def _linux_status() -> str:
    if not _TIMER_PATH.exists():
        return "systemd timer NOT installed."
    code, out = _run_cmd(["systemctl", "--user", "status", f"{TASK_NAME.lower()}.timer"])
    return out.strip() if out.strip() else "Timer exists but status unknown."


# ── Public API ────────────────────────────────────────────────────────────────

def install() -> str:
    if OS == "Windows":
        return _win_install()
    elif OS == "Darwin":
        return _mac_install()
    else:
        return _linux_install()


def remove() -> str:
    if OS == "Windows":
        return _win_remove()
    elif OS == "Darwin":
        return _mac_remove()
    else:
        return _linux_remove()


def status() -> str:
    if OS == "Windows":
        return _win_status()
    elif OS == "Darwin":
        return _mac_status()
    else:
        return _linux_status()


def run_headless() -> None:
    """Single scan cycle — intended to be called by the background scheduler."""
    logging.basicConfig(
        filename=str(_LOG_PATH),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    import database
    database.bootstrap()

    from tui import _run_once_patched
    try:
        _run_once_patched(log=lambda msg: logging.info(msg))
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
