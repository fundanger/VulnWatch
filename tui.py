"""CVE Emailer v2 — Textual TUI"""

from __future__ import annotations

import configparser
import threading
from pathlib import Path

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

CONFIG_PATH = Path("config.ini")

# ──────────────────────────────────────────────────────────────────────────────
# Settings screen
# ──────────────────────────────────────────────────────────────────────────────

FIELDS = [
    # (section, key, label, placeholder, password?)
    ("DEFAULT", "apiKey",         "NVD API Key",          "your-nvd-api-key",       False),
    ("DEFAULT", "txtList",        "Keywords file path",   "keywords.txt",            False),
    ("DEFAULT", "checkFrequency", "Check interval (sec)", "3600",                    False),
    ("EMAIL",   "senderEmail",    "Sender Gmail",         "you@gmail.com",           False),
    ("EMAIL",   "senderPassword", "Gmail App Password",   "xxxx xxxx xxxx xxxx",     True),
    ("EMAIL",   "recipientEmail", "Recipient email",      "recipient@example.com",   False),
    ("EMAIL",   "subjectLine",    "Email subject",        "CVE Alert",               False),
    ("DATABASE","username",       "DB username",          "root",                    False),
    ("DATABASE","password",       "DB password",          "••••",                    True),
    ("DATABASE","host",           "DB host",              "127.0.0.1",               False),
    ("DATABASE","database",       "DB name",              "cve_emailer",             False),
]


def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_PATH)
    return cfg


def save_config(values: dict[tuple[str, str], str]) -> None:
    cfg = load_config()
    for (section, key), value in values.items():
        if not cfg.has_section(section) and section != "DEFAULT":
            cfg.add_section(section)
        cfg[section][key] = value
    with open(CONFIG_PATH, "w") as f:
        cfg.write(f)


class SettingsScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        cfg = load_config()
        yield Header(show_clock=True)
        yield Label("Settings", id="settings-title")
        with ScrollableContainer(id="settings-form"):
            for section, key, label, placeholder, is_password in FIELDS:
                current = cfg.get(section, key, fallback="").strip()
                yield Label(label)
                yield Input(
                    value=current,
                    placeholder=placeholder,
                    password=is_password,
                    id=f"input-{section}-{key}",
                )
            yield Button("Save", variant="success", id="btn-save")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-save":
            return
        values = {}
        for section, key, *_ in FIELDS:
            widget = self.query_one(f"#input-{section}-{key}", Input)
            values[(section, key)] = widget.value.strip()
        save_config(values)
        self.notify("Settings saved.", severity="information")
        self.app.pop_screen()


# ──────────────────────────────────────────────────────────────────────────────
# Setup wizard (shown on first run when required config values are missing)
# ──────────────────────────────────────────────────────────────────────────────

class SetupWizard(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label("Welcome to CVE Emailer v2\nLet's get you configured.", id="wizard-title")
        with ScrollableContainer(id="wizard-form"):
            for section, key, label, placeholder, is_password in FIELDS:
                yield Label(label)
                yield Input(
                    placeholder=placeholder,
                    password=is_password,
                    id=f"wizard-{section}-{key}",
                )
            yield Button("Save & Continue", variant="success", id="wizard-save")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "wizard-save":
            return
        values = {}
        for section, key, *_ in FIELDS:
            widget = self.query_one(f"#wizard-{section}-{key}", Input)
            values[(section, key)] = widget.value.strip()
        save_config(values)
        self.notify("Configuration saved!", severity="information")
        self.app.pop_screen()


# ──────────────────────────────────────────────────────────────────────────────
# Main screen
# ──────────────────────────────────────────────────────────────────────────────

class MainScreen(Screen):
    BINDINGS = [
        Binding("s", "push_screen('settings')", "Settings"),
        Binding("q", "app.quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self._running = False
        self._thread: threading.Thread | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield Static("CVE Emailer v2", id="sidebar-title")
                yield Button("Run Once", variant="primary", id="btn-run-once")
                yield Button("Start Loop", variant="success", id="btn-start")
                yield Button("Stop", variant="error", id="btn-stop", disabled=True)
                yield Button("Settings", variant="default", id="btn-settings")
                yield Button("Quit", variant="default", id="btn-quit")
                yield Static("", id="status-label")
            with Container(id="log-container"):
                yield RichLog(id="log", highlight=True, markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#log", RichLog).write("[bold cyan]CVE Emailer v2 ready.[/bold cyan]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        handlers = {
            "btn-run-once": self._run_once,
            "btn-start":    self._start_loop,
            "btn-stop":     self._stop_loop,
            "btn-settings": lambda: self.app.push_screen("settings"),
            "btn-quit":     self.app.exit,
        }
        handler = handlers.get(event.button.id)
        if handler:
            handler()

    def _log(self, msg: str) -> None:
        self.call_from_thread(self._write_log, msg)

    def _write_log(self, msg: str) -> None:
        self.query_one("#log", RichLog).write(msg)

    def _set_status(self, text: str) -> None:
        self.call_from_thread(self._update_status, text)

    def _update_status(self, text: str) -> None:
        self.query_one("#status-label", Static).update(text)

    def _run_once(self) -> None:
        if self._running:
            self.notify("Already running.", severity="warning")
            return

        def task():
            import search
            self._running = True
            self._set_status("[yellow]Running...[/yellow]")
            try:
                search.run_once(log=self._log)
            except Exception as exc:
                self._log(f"[bold red]Error:[/bold red] {exc}")
            finally:
                self._running = False
                self._set_status("")

        self._thread = threading.Thread(target=task, daemon=True)
        self._thread.start()

    def _start_loop(self) -> None:
        if self._running:
            self.notify("Already running.", severity="warning")
            return

        self._running = True
        self.query_one("#btn-start", Button).disabled = True
        self.query_one("#btn-stop", Button).disabled = False
        self._set_status("[green]Loop running[/green]")

        def task():
            import search
            try:
                search.timed_loop(log=self._log)
            except Exception as exc:
                self._log(f"[bold red]Error:[/bold red] {exc}")
            finally:
                self._running = False
                self.call_from_thread(self._reset_loop_buttons)

        self._thread = threading.Thread(target=task, daemon=True)
        self._thread.start()

    def _stop_loop(self) -> None:
        self._log("[yellow]Stop requested — will halt after current sleep.[/yellow]")
        self._running = False
        self._reset_loop_buttons()

    def _reset_loop_buttons(self) -> None:
        self.query_one("#btn-start", Button).disabled = False
        self.query_one("#btn-stop", Button).disabled = True
        self._set_status("")


# ──────────────────────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────────────────────

class CVEEmailerApp(App):
    CSS = """
    #main-layout {
        height: 1fr;
    }

    #sidebar {
        width: 22;
        background: $panel;
        border-right: solid $primary;
        padding: 1 1;
    }

    #sidebar-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 1;
    }

    #sidebar Button {
        width: 100%;
        margin-bottom: 1;
    }

    #status-label {
        text-align: center;
        margin-top: 1;
    }

    #log-container {
        width: 1fr;
        padding: 1 2;
    }

    #log {
        height: 1fr;
    }

    #settings-title, #wizard-title {
        text-style: bold;
        text-align: center;
        color: $accent;
        margin: 1 0;
        padding: 0 2;
    }

    #settings-form, #wizard-form {
        padding: 1 4;
    }

    #settings-form Label, #wizard-form Label {
        margin-top: 1;
        color: $text-muted;
    }

    #settings-form Button, #wizard-form Button {
        margin-top: 2;
        width: 20;
    }
    """

    SCREENS = {
        "main":     MainScreen,
        "settings": SettingsScreen,
    }

    BINDINGS = [Binding("ctrl+c", "quit", "Quit", show=False)]

    def on_mount(self) -> None:
        if _needs_setup():
            self.push_screen(SetupWizard())
        else:
            self.push_screen("main")


def _needs_setup() -> bool:
    cfg = load_config()
    required = [
        ("DEFAULT", "txtList"),
        ("EMAIL",   "senderEmail"),
        ("EMAIL",   "senderPassword"),
        ("EMAIL",   "recipientEmail"),
        ("DATABASE","host"),
        ("DATABASE","database"),
    ]
    return any(not cfg.get(s, k, fallback="").strip() for s, k in required)


def run():
    CVEEmailerApp().run()
