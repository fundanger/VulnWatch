"""CVE Emailer v2 — Textual TUI"""

from __future__ import annotations

import configparser
import threading
import time
from pathlib import Path
from threading import Event

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, ScrollableContainer, Vertical
from textual.screen import Screen
from textual.timer import Timer
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Static,
)

CONFIG_PATH = Path("config.ini")

# ── Config helpers ─────────────────────────────────────────────────────────────

FIELDS = [
    # (section, key, label, placeholder, password?)
    ("DEFAULT", "apiKey",         "NVD API Key",          "your-nvd-api-key (optional)", False),
    ("DEFAULT", "checkFrequency", "Check interval (sec)", "3600",                         False),
    ("EMAIL",   "senderEmail",    "Sender Gmail",         "you@gmail.com",                False),
    ("EMAIL",   "senderPassword", "Gmail App Password",   "xxxx xxxx xxxx xxxx",          True),
    ("EMAIL",   "recipientEmail", "Recipient email(s)",   "a@x.com, b@x.com",             False),
    ("EMAIL",   "subjectLine",    "Email subject",        "CVE Alert",                    False),
    ("DATABASE","backend",        "DB backend",           "sqlite  (or mysql)",           False),
    ("DATABASE","username",       "DB username (MySQL)",  "root",                         False),
    ("DATABASE","password",       "DB password (MySQL)",  "••••",                         True),
    ("DATABASE","host",           "DB host (MySQL)",      "127.0.0.1",                    False),
    ("DATABASE","database",       "DB name (MySQL)",      "cve_emailer",                  False),
]

REQUIRED = [
    ("EMAIL",   "senderEmail"),
    ("EMAIL",   "senderPassword"),
    ("EMAIL",   "recipientEmail"),
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


def _needs_setup() -> bool:
    cfg = load_config()
    return any(not cfg.get(s, k, fallback="").strip() for s, k in REQUIRED)


# Keywords are stored in config.ini as a newline-separated list under
# [DEFAULT] keywords, removing the need for a separate .txt file.

def load_keywords() -> list[str]:
    cfg = load_config()
    raw = cfg.get("DEFAULT", "keywords", fallback="")
    return [k.strip() for k in raw.splitlines() if k.strip()]


def save_keywords(keywords: list[str]) -> None:
    cfg = load_config()
    cfg["DEFAULT"]["keywords"] = "\n".join(keywords)
    with open(CONFIG_PATH, "w") as f:
        cfg.write(f)


# ── Settings screen ────────────────────────────────────────────────────────────

class SettingsScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        cfg = load_config()
        yield Header(show_clock=True)
        yield Label("Settings", id="settings-title")
        with ScrollableContainer(id="settings-form"):
            yield Static(
                "[bold yellow]Warning:[/bold yellow] Gmail app password is stored in "
                "plain text in config.ini. Keep this file private.",
                id="security-warning",
            )
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


# ── Keyword editor screen ──────────────────────────────────────────────────────

class KeywordsScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("Keywords", id="kw-title")
        with Vertical(id="kw-layout"):
            yield ListView(
                *[ListItem(Label(kw), id=f"kw-{i}") for i, kw in enumerate(load_keywords())],
                id="kw-list",
            )
            with Horizontal(id="kw-input-row"):
                yield Input(placeholder="New keyword (e.g. Apache Knox)", id="kw-input")
                yield Button("Add", variant="primary", id="btn-kw-add")
            yield Button("Remove selected", variant="error", id="btn-kw-remove")
            yield Button("Save & Back", variant="success", id="btn-kw-save")
        yield Footer()

    # track keywords in memory while editing
    def on_mount(self) -> None:
        self._keywords = load_keywords()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-kw-add":
            self._add_keyword()
        elif event.button.id == "btn-kw-remove":
            self._remove_selected()
        elif event.button.id == "btn-kw-save":
            save_keywords(self._keywords)
            self.notify("Keywords saved.", severity="information")
            self.app.pop_screen()

    def _add_keyword(self) -> None:
        inp = self.query_one("#kw-input", Input)
        kw = inp.value.strip()
        if not kw:
            return
        if kw in self._keywords:
            self.notify(f'"{kw}" already in list.', severity="warning")
            return
        self._keywords.append(kw)
        lv = self.query_one("#kw-list", ListView)
        lv.append(ListItem(Label(kw), id=f"kw-{len(self._keywords)-1}"))
        inp.value = ""

    def _remove_selected(self) -> None:
        lv = self.query_one("#kw-list", ListView)
        if lv.highlighted_child is None:
            self.notify("Select a keyword first.", severity="warning")
            return
        idx = lv.index
        if idx is not None and 0 <= idx < len(self._keywords):
            removed = self._keywords.pop(idx)
            lv.highlighted_child.remove()
            self.notify(f'Removed "{removed}".', severity="information")


# ── Setup wizard ───────────────────────────────────────────────────────────────

class SetupWizard(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label("Welcome to CVE Emailer v2\nLet's get you configured.", id="wizard-title")
        with ScrollableContainer(id="wizard-form"):
            yield Static(
                "[bold yellow]Note:[/bold yellow] Credentials are stored in plain text "
                "in config.ini. Keep that file private and out of version control.",
                id="security-warning",
            )
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


# ── Main screen ────────────────────────────────────────────────────────────────

class MainScreen(Screen):
    BINDINGS = [
        Binding("s", "push_screen('settings')", "Settings"),
        Binding("k", "push_screen('keywords')", "Keywords"),
        Binding("r", "run_once", "Run Once"),
        Binding("q", "app.quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self._stop_event = Event()
        self._thread: threading.Thread | None = None
        self._countdown_end: float = 0.0
        self._ticker: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main-layout"):
            with Vertical(id="sidebar"):
                yield Static("CVE Emailer v2", id="sidebar-title")
                yield Button("Run Once  [r]", variant="primary",  id="btn-run-once")
                yield Button("Start Loop",    variant="success",  id="btn-start")
                yield Button("Stop",          variant="error",    id="btn-stop",  disabled=True)
                yield Button("Keywords  [k]", variant="default",  id="btn-keywords")
                yield Button("Settings  [s]", variant="default",  id="btn-settings")
                yield Button("Quit      [q]", variant="default",  id="btn-quit")
                yield Static("", id="status-label")
                yield Static("", id="countdown-label")
            with Container(id="log-container"):
                yield RichLog(id="log", highlight=True, markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#log", RichLog).write(
            "[bold cyan]CVE Emailer v2 ready.[/bold cyan]\n"
            "Press [bold]R[/bold] to run once, or [bold]Start Loop[/bold] to run on a schedule."
        )

    # ── button routing ─────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        handlers = {
            "btn-run-once":  self.action_run_once,
            "btn-start":     self._start_loop,
            "btn-stop":      self._stop_loop,
            "btn-keywords":  lambda: self.app.push_screen("keywords"),
            "btn-settings":  lambda: self.app.push_screen("settings"),
            "btn-quit":      self.app.exit,
        }
        handler = handlers.get(event.button.id)
        if handler:
            handler()

    # ── log / status helpers ───────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        self.call_from_thread(self._write_log, msg)

    def _write_log(self, msg: str) -> None:
        self.query_one("#log", RichLog).write(msg)

    def _set_status(self, text: str) -> None:
        self.call_from_thread(lambda: self.query_one("#status-label", Static).update(text))

    def _set_countdown(self, text: str) -> None:
        self.query_one("#countdown-label", Static).update(text)

    # ── countdown timer ────────────────────────────────────────────────────────

    def _start_countdown(self, seconds: int) -> None:
        self._countdown_end = time.monotonic() + seconds
        if self._ticker:
            self._ticker.stop()
        self._ticker = self.set_interval(1, self._tick_countdown)

    def _tick_countdown(self) -> None:
        remaining = int(self._countdown_end - time.monotonic())
        if remaining <= 0:
            self._set_countdown("")
            if self._ticker:
                self._ticker.stop()
                self._ticker = None
        else:
            mins, secs = divmod(remaining, 60)
            self._set_countdown(f"Next check in\n[bold]{mins:02d}:{secs:02d}[/bold]")

    def _stop_countdown(self) -> None:
        if self._ticker:
            self._ticker.stop()
            self._ticker = None
        self._set_countdown("")

    # ── run once ───────────────────────────────────────────────────────────────

    def action_run_once(self) -> None:
        if self._thread and self._thread.is_alive():
            self.notify("Already running.", severity="warning")
            return
        self._stop_event.clear()

        def task():
            import search
            self._set_status("[yellow]Running...[/yellow]")
            try:
                # patch search to use keywords from config instead of txtList file
                _run_once_patched(log=self._log, stop_event=self._stop_event)
            except Exception as exc:
                self._log(f"[bold red]Error:[/bold red] {exc}")
            finally:
                self._set_status("")

        self._thread = threading.Thread(target=task, daemon=True)
        self._thread.start()

    # ── timed loop ─────────────────────────────────────────────────────────────

    def _start_loop(self) -> None:
        if self._thread and self._thread.is_alive():
            self.notify("Already running.", severity="warning")
            return
        self._stop_event.clear()
        self.query_one("#btn-start", Button).disabled = True
        self.query_one("#btn-stop",  Button).disabled = False
        self._set_status("[green]Loop running[/green]")

        def task():
            _timed_loop_patched(log=self._log, stop_event=self._stop_event,
                                on_sleep=self._start_countdown)
            self.call_from_thread(self._on_loop_done)

        self._thread = threading.Thread(target=task, daemon=True)
        self._thread.start()

    def _stop_loop(self) -> None:
        self._stop_event.set()
        self._stop_countdown()
        self._log("[yellow]Stop signal sent — halting after current operation.[/yellow]")

    def _on_loop_done(self) -> None:
        self.query_one("#btn-start", Button).disabled = False
        self.query_one("#btn-stop",  Button).disabled = True
        self._set_status("")
        self._stop_countdown()

    # ── screen actions ─────────────────────────────────────────────────────────

    def action_push_screen(self, screen: str) -> None:
        self.app.push_screen(screen)


# ── Patched scan functions that read keywords from config ──────────────────────

def _run_once_patched(log=print, stop_event: Event | None = None) -> bool:
    """Like search.run_once but reads keywords from config instead of a file."""
    import search

    cfg = search._load_config()
    keywords = load_keywords()

    if not keywords:
        log("[yellow]No keywords configured. Go to Keywords screen to add some.[/yellow]")
        return False

    log(f"Scanning {len(keywords)} keyword(s)...")
    all_new: list[dict] = []
    for kw in keywords:
        if stop_event and stop_event.is_set():
            log("Scan stopped early.")
            return False
        all_new.extend(search.process_keyword(kw, cfg, log=log))

    if not all_new:
        log("No new CVEs found.")
        return False

    body = search._build_email_body(all_new)
    log(f"Found {len(all_new)} new CVE(s) — sending email...")
    import mail
    recipients = [r.strip() for r in cfg["EMAIL"]["recipientEmail"].split(",") if r.strip()]
    mail.send_email(
        sender=cfg["EMAIL"]["senderEmail"],
        password=cfg["EMAIL"]["senderPassword"],
        recipients=recipients,
        subject=cfg["EMAIL"]["subjectLine"],
        body=body,
    )
    log("Email sent.")
    return True


def _timed_loop_patched(log=print, stop_event: Event | None = None, on_sleep=None) -> None:
    import search
    while True:
        cfg = search._load_config()
        interval = int(cfg["DEFAULT"].get("checkFrequency", "3600"))
        log(f"Starting scan (interval: {interval}s)...")
        try:
            _run_once_patched(log=log, stop_event=stop_event)
        except Exception as exc:
            log(f"[bold red]Scan error:[/bold red] {exc}")

        if stop_event and stop_event.is_set():
            log("Loop stopped.")
            return

        if on_sleep:
            on_sleep(interval)

        deadline = time.monotonic() + interval
        while time.monotonic() < deadline:
            if stop_event and stop_event.is_set():
                log("Loop stopped.")
                return
            time.sleep(1)


# ── App ────────────────────────────────────────────────────────────────────────

class CVEEmailerApp(App):
    CSS = """
    #main-layout {
        height: 1fr;
    }

    #sidebar {
        width: 24;
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

    #countdown-label {
        text-align: center;
        margin-top: 1;
        color: $text-muted;
    }

    #log-container {
        width: 1fr;
        padding: 1 2;
    }

    #log {
        height: 1fr;
    }

    /* Settings / wizard */
    #settings-title, #wizard-title, #kw-title {
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

    #security-warning {
        background: $warning 15%;
        border: solid $warning;
        padding: 1 2;
        margin-bottom: 1;
    }

    /* Keywords */
    #kw-layout {
        padding: 1 4;
        height: 1fr;
    }

    #kw-list {
        height: 1fr;
        border: solid $primary;
        margin-bottom: 1;
    }

    #kw-input-row {
        height: auto;
        margin-bottom: 1;
    }

    #kw-input {
        width: 1fr;
    }

    #btn-kw-add {
        width: 10;
        margin-left: 1;
    }
    """

    SCREENS = {
        "main":     MainScreen,
        "settings": SettingsScreen,
        "keywords": KeywordsScreen,
    }

    BINDINGS = [Binding("ctrl+c", "quit", "Quit", show=False)]

    def on_mount(self) -> None:
        if _needs_setup():
            self.push_screen(SetupWizard())
        else:
            self.push_screen("main")


def run():
    CVEEmailerApp().run()
