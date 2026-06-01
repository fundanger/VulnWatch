"""CVE Emailer v2 — Textual TUI"""

from __future__ import annotations

import configparser
import json
import platform
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
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    RichLog,
    Select,
    Static,
    TextArea,
)

CONFIG_PATH = Path(__file__).parent / "config.ini"

# ── Config helpers ─────────────────────────────────────────────────────────────

FIELDS = [
    # (section, key, label, placeholder, password?)
    ("DEFAULT", "apiKey",         "NVD API Key",            "optional",                     False),
    ("DEFAULT", "checkFrequency", "Check interval (sec)",   "3600",                          False),
    ("DEFAULT", "minSeverity",    "Global min severity",    "NONE / LOW / MEDIUM / HIGH / CRITICAL", False),
    ("DEFAULT", "webhookUrl",     "Webhook URL",            "https://...",                   False),
    ("DEFAULT", "slackWebhook",   "Slack webhook URL",      "https://hooks.slack.com/...",   False),
    ("EMAIL",   "senderEmail",    "Sender Gmail",           "you@gmail.com",                 False),
    ("EMAIL",   "senderPassword", "Gmail App Password",     "xxxx xxxx xxxx xxxx",           True),
    ("EMAIL",   "recipientEmail", "Recipient email(s)",     "a@x.com, b@x.com",              False),
    ("EMAIL",   "subjectLine",    "Email subject",          "CVE Alert",                     False),
]

REQUIRED = [
    ("EMAIL", "senderEmail"),
    ("EMAIL", "senderPassword"),
    ("EMAIL", "recipientEmail"),
]

SEVERITY_OPTS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "NONE":     "dim",
    "UNKNOWN":  "dim",
}


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
                "[bold yellow]Warning:[/bold yellow] Credentials are stored in plain text "
                "in config.ini — keep that file private and out of version control.",
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
            with Horizontal(id="settings-buttons"):
                yield Button("Save", variant="success", id="btn-save")
                yield Button("Send Test Email", variant="primary", id="btn-test-email")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-save":
            self._save()
        elif event.button.id == "btn-test-email":
            self._test_email()

    def _save(self) -> None:
        values = {}
        for section, key, *_ in FIELDS:
            widget = self.query_one(f"#input-{section}-{key}", Input)
            values[(section, key)] = widget.value.strip()
        save_config(values)
        self.notify("Settings saved.", severity="information")

    def _test_email(self) -> None:
        sender = self.query_one("#input-EMAIL-senderEmail", Input).value.strip()
        password = self.query_one("#input-EMAIL-senderPassword", Input).value.strip()
        recipient_raw = self.query_one("#input-EMAIL-recipientEmail", Input).value.strip()
        recipients = [r.strip() for r in recipient_raw.split(",") if r.strip()]
        if not sender or not password or not recipients:
            self.notify("Fill in sender email, password, and recipient first.", severity="warning")
            return

        def task():
            import mail
            try:
                mail.send_test_email(sender, password, recipients)
                self.call_from_thread(
                    lambda: self.notify("Test email sent!", severity="information")
                )
            except Exception as exc:
                self.call_from_thread(
                    lambda: self.notify(f"Failed: {exc}", severity="error")
                )

        threading.Thread(target=task, daemon=True).start()
        self.notify("Sending test email...", severity="information")


# ── Keyword editor ─────────────────────────────────────────────────────────────

class KeywordsScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("Keywords", id="kw-title")
        yield Static(
            'Syntax: "Apache Knox" — or "Apache Knox::HIGH" to override min severity for that keyword.',
            id="kw-hint",
        )
        with Vertical(id="kw-layout"):
            yield ListView(id="kw-list")
            with Horizontal(id="kw-input-row"):
                yield Input(placeholder="e.g.  Apache Knox  or  Apache Knox::HIGH", id="kw-input")
                yield Button("Add", variant="primary", id="btn-kw-add")
            with Horizontal(id="kw-buttons"):
                yield Button("Remove selected", variant="error",   id="btn-kw-remove")
                yield Button("Save & Back",     variant="success",  id="btn-kw-save")
        yield Footer()

    def on_mount(self) -> None:
        self._keywords = load_keywords()
        lv = self.query_one("#kw-list", ListView)
        for kw in self._keywords:
            lv.append(ListItem(Label(kw)))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-kw-add":
            self._add()
        elif event.button.id == "btn-kw-remove":
            self._remove()
        elif event.button.id == "btn-kw-save":
            save_keywords(self._keywords)
            self.notify("Keywords saved.", severity="information")
            self.app.pop_screen()

    def _add(self) -> None:
        inp = self.query_one("#kw-input", Input)
        kw = inp.value.strip()
        if not kw:
            return
        if kw in self._keywords:
            self.notify(f'"{kw}" already in list.', severity="warning")
            return
        self._keywords.append(kw)
        self.query_one("#kw-list", ListView).append(ListItem(Label(kw)))
        inp.value = ""

    def _remove(self) -> None:
        lv = self.query_one("#kw-list", ListView)
        idx = lv.index
        if idx is not None and 0 <= idx < len(self._keywords):
            removed = self._keywords.pop(idx)
            lv.highlighted_child.remove()
            self.notify(f'Removed "{removed}".', severity="information")
        else:
            self.notify("Select a keyword first.", severity="warning")


# ── Notification profiles ──────────────────────────────────────────────────────

class ProfilesScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("Notification Profiles", id="profiles-title")
        yield Static(
            "Each profile scans its own keyword set and routes to its own recipients/webhooks.",
            id="profiles-hint",
        )
        with Vertical(id="profiles-layout"):
            yield DataTable(id="profiles-table")
            with Horizontal(id="profiles-form-row"):
                with Vertical(id="profiles-form"):
                    yield Input(placeholder="Profile name", id="pf-name")
                    yield Label("Keywords (one per line)", id="pf-keywords-label")
                    yield TextArea(id="pf-keywords")
                    yield Input(placeholder="Min severity: NONE/LOW/MEDIUM/HIGH/CRITICAL", id="pf-severity")
                    yield Input(placeholder="Recipients (comma-separated)", id="pf-recipients")
                    yield Input(placeholder="Webhook URL (optional)", id="pf-webhook")
                    yield Input(placeholder="Slack webhook URL (optional)", id="pf-slack")
                    yield Static("─" * 30, id="pf-sep")
                    yield Label("Digest mode", id="pf-digest-label")
                    yield Select(
                        options=[("Off (immediate)", "off"), ("Hourly", "hourly"), ("Daily", "daily"), ("Weekly", "weekly")],
                        value="off",
                        id="pf-digest",
                    )
                with Vertical(id="profiles-actions"):
                    yield Button("Save profile",    variant="success", id="btn-pf-save")
                    yield Button("Load selected",   variant="primary",  id="btn-pf-load")
                    yield Button("Delete selected", variant="error",    id="btn-pf-delete")
        yield Footer()

    def on_mount(self) -> None:
        import database
        database.bootstrap()
        table = self.query_one("#profiles-table", DataTable)
        table.add_columns("Name", "Min Severity", "Recipients", "Digest", "Webhook")
        self._refresh_table()

    def _refresh_table(self) -> None:
        import database
        table = self.query_one("#profiles-table", DataTable)
        table.clear()
        for p in database.get_profiles():
            digest_val = ""
            if p.get("digest_mode"):
                digest_val = p.get("digest_schedule", "daily").capitalize()
            table.add_row(
                p["name"],
                p.get("min_severity", "NONE"),
                (p.get("recipients") or "")[:30],
                digest_val or "Immediate",
                "Yes" if p.get("webhook_url") or p.get("slack_webhook") else "No",
                key=p["name"],
            )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        import database
        if event.button.id == "btn-pf-save":
            name = self.query_one("#pf-name", Input).value.strip()
            if not name:
                self.notify("Profile name required.", severity="warning")
                return
            digest_sel = self.query_one("#pf-digest", Select)
            digest_val = str(digest_sel.value) if digest_sel.value is not Select.BLANK else "off"
            digest_mode = 1 if digest_val != "off" else 0
            digest_schedule = digest_val if digest_val != "off" else "daily"
            database.save_profile({
                "name":            name,
                "keywords":        self.query_one("#pf-keywords",   TextArea).text.strip(),
                "min_severity":    self.query_one("#pf-severity",   Input).value.strip().upper() or "NONE",
                "recipients":      self.query_one("#pf-recipients", Input).value.strip(),
                "webhook_url":     self.query_one("#pf-webhook",    Input).value.strip(),
                "slack_webhook":   self.query_one("#pf-slack",      Input).value.strip(),
                "digest_mode":     digest_mode,
                "digest_schedule": digest_schedule,
            })
            self._refresh_table()
            self.notify(f'Profile "{name}" saved.', severity="information")

        elif event.button.id == "btn-pf-load":
            table = self.query_one("#profiles-table", DataTable)
            if table.cursor_row < 0:
                self.notify("Select a profile row first.", severity="warning")
                return
            profiles = database.get_profiles()
            if table.cursor_row < len(profiles):
                p = profiles[table.cursor_row]
                self.query_one("#pf-name",       Input).value = p["name"]
                self.query_one("#pf-keywords",   TextArea).load_text(p.get("keywords") or "")
                self.query_one("#pf-severity",   Input).value = p.get("min_severity") or "NONE"
                self.query_one("#pf-recipients", Input).value = p.get("recipients") or ""
                self.query_one("#pf-webhook",    Input).value = p.get("webhook_url") or ""
                self.query_one("#pf-slack",      Input).value = p.get("slack_webhook") or ""
                schedule = p.get("digest_schedule", "daily") if p.get("digest_mode") else "off"
                digest_sel = self.query_one("#pf-digest", Select)
                digest_sel.value = schedule

        elif event.button.id == "btn-pf-delete":
            table = self.query_one("#profiles-table", DataTable)
            profiles = database.get_profiles()
            if table.cursor_row < 0 or table.cursor_row >= len(profiles):
                self.notify("Select a profile row first.", severity="warning")
                return
            name = profiles[table.cursor_row]["name"]
            database.delete_profile(name)
            self._refresh_table()
            self.notify(f'Profile "{name}" deleted.', severity="information")


# ── Scan history ───────────────────────────────────────────────────────────────

class HistoryScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back"), Binding("r", "refresh", "Refresh")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("Scan History", id="history-title")
        yield DataTable(id="history-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#history-table", DataTable)
        table.add_columns("Started", "Finished", "Keywords", "New", "Upgraded", "Emailed", "Error")
        self.action_refresh()

    def action_refresh(self) -> None:
        import database
        table = self.query_one("#history-table", DataTable)
        table.clear()
        for row in database.get_history(100):
            table.add_row(
                row.get("started_at", "")[:19],
                (row.get("finished_at") or "")[:19],
                (row.get("keywords") or "")[:35],
                str(row.get("new_cves", 0)),
                str(row.get("updated_cves", 0)),
                "Yes" if row.get("emailed") else "No",
                (row.get("error") or "")[:25],
            )


# ── Dashboard screen ───────────────────────────────────────────────────────────

class DashboardScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back"), Binding("r", "refresh", "Refresh")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("Dashboard", id="dashboard-title")
        with Horizontal(id="dash-top"):
            yield Static("", id="dash-summary")
            yield Static("", id="dash-recent")
        yield DataTable(id="dash-keyword-table")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#dash-keyword-table", DataTable)
        table.add_columns("Keyword", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE/UNKNOWN", "Total")
        self.action_refresh()

    def action_refresh(self) -> None:
        import database
        stats = database.get_dashboard_stats()

        totals = stats["totals"]
        total_cves = stats["total_cves"]
        kw_count = stats["total_keywords"]

        summary_lines = [
            f"[bold cyan]Total CVEs:[/bold cyan]  {total_cves}",
            f"[bold cyan]Keywords:[/bold cyan]    {kw_count}",
            "",
            f"[bold red]CRITICAL:[/bold red]  {totals.get('CRITICAL', 0)}",
            f"[red]HIGH:[/red]      {totals.get('HIGH', 0)}",
            f"[yellow]MEDIUM:[/yellow]    {totals.get('MEDIUM', 0)}",
            f"[green]LOW:[/green]       {totals.get('LOW', 0)}",
            f"[dim]NONE/UNK:[/dim]  {totals.get('NONE', 0) + totals.get('UNKNOWN', 0)}",
        ]
        self.query_one("#dash-summary", Static).update("\n".join(summary_lines))

        recent = stats["recent_scans"]
        recent_lines = ["[bold]Recent Scans[/bold]", ""]
        for r in recent:
            ts = (r.get("started_at") or "")[:16]
            new = r.get("new_cves", 0)
            upd = r.get("updated_cves", 0)
            err = " [red]ERR[/red]" if r.get("error") else ""
            recent_lines.append(f"{ts}  +{new} new  ~{upd} upd{err}")
        self.query_one("#dash-recent", Static).update("\n".join(recent_lines))

        table = self.query_one("#dash-keyword-table", DataTable)
        table.clear()
        for kw_stat in stats["per_keyword"]:
            none_unk = kw_stat.get("NONE", 0) + kw_stat.get("UNKNOWN", 0)
            row_total = sum(kw_stat.get(s, 0) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"))
            table.add_row(
                kw_stat["keyword"],
                str(kw_stat.get("CRITICAL", 0)),
                str(kw_stat.get("HIGH", 0)),
                str(kw_stat.get("MEDIUM", 0)),
                str(kw_stat.get("LOW", 0)),
                str(none_unk),
                str(row_total),
            )


# ── CVE detail view ────────────────────────────────────────────────────────────

class CVEDetailScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def __init__(self, table: str, cve_id: str):
        super().__init__()
        self._table = table
        self._cve_id = cve_id

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label(f"CVE Detail — {self._cve_id}", id="detail-title")
        yield ScrollableContainer(Static("Loading...", id="detail-body"))
        yield Footer()

    def on_mount(self) -> None:
        import database
        row = database.get_cve(self._table, self._cve_id)
        if not row:
            self.query_one("#detail-body", Static).update("[red]CVE not found.[/red]")
            return

        sev = row.get("severity", "UNKNOWN")
        score = f"{row['cvss_score']:.1f}" if row.get("cvss_score") else "N/A"
        color = SEVERITY_COLORS.get(sev, "dim")

        try:
            refs = json.loads(row.get("references_json") or "[]")
        except (ValueError, TypeError):
            refs = []

        ref_lines = "\n".join(f"  • [link={u}]{u}[/link]" for u in refs) if refs else "  None"

        body = (
            f"[{color}]Severity:[/{color}]  [{color}]{sev}[/{color}]   "
            f"[bold]CVSS Score:[/bold] {score}\n\n"
            f"[bold]CVE ID:[/bold]       {self._cve_id}\n"
            f"[bold]Keyword:[/bold]      {row.get('keyword', '')}\n"
            f"[bold]Published:[/bold]    {row.get('publish_date', '')}\n"
            f"[bold]Modified:[/bold]     {row.get('last_modified', '')}\n"
            f"[bold]CWE:[/bold]          {row.get('cwe') or 'N/A'}\n\n"
            f"[bold]Affected (CPE):[/bold]\n  {(row.get('cpe') or 'N/A').replace(', ', chr(10)+'  ')}\n\n"
            f"[bold]Description:[/bold]\n  {row.get('description', '')}\n\n"
            f"[bold]References:[/bold]\n{ref_lines}\n"
        )
        self.query_one("#detail-body", Static).update(body)


# ── CVE browser ────────────────────────────────────────────────────────────────

class BrowserScreen(Screen):
    BINDINGS = [
        Binding("escape", "app.pop_screen", "Back"),
        Binding("e", "export_csv", "Export CSV"),
        Binding("j", "export_json", "Export JSON"),
        Binding("enter", "open_detail", "Detail", show=True),
    ]

    def __init__(self):
        super().__init__()
        self._current_table: str = ""
        self._current_rows: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("CVE Browser", id="browser-title")
        with Horizontal(id="browser-controls"):
            yield Select(options=[], prompt="Select keyword table...", id="browser-table-select")
            yield Input(placeholder="Search CVE ID or description...", id="browser-search")
            yield Select(
                options=[(s, s) for s in SEVERITY_OPTS],
                value="NONE",
                prompt="Min severity",
                id="browser-severity",
            )
        with Horizontal(id="browser-date-row"):
            yield Input(placeholder="Published from (YYYY-MM-DD)", id="browser-date-from")
            yield Input(placeholder="Published to   (YYYY-MM-DD)", id="browser-date-to")
            yield Button("Search", variant="primary", id="btn-browser-search")
        yield DataTable(id="browser-results", cursor_type="row")
        yield Static("", id="browser-status")
        yield Footer()

    def on_mount(self) -> None:
        import database
        database.bootstrap()
        tables = database.list_cve_tables()
        sel = self.query_one("#browser-table-select", Select)
        sel.set_options([(t, t) for t in tables])

        results = self.query_one("#browser-results", DataTable)
        results.add_columns("CVE ID", "Severity", "Score", "CWE", "Keyword", "Published", "Description")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-browser-search":
            self._do_search()

    def _do_search(self) -> None:
        import database
        table_sel = self.query_one("#browser-table-select", Select)
        if table_sel.value is Select.BLANK:
            self.notify("Select a keyword table first.", severity="warning")
            return

        search = self.query_one("#browser-search", Input).value.strip()
        sev_sel = self.query_one("#browser-severity", Select)
        min_sev = sev_sel.value if sev_sel.value is not Select.BLANK else "NONE"
        date_from = self.query_one("#browser-date-from", Input).value.strip()
        date_to = self.query_one("#browser-date-to", Input).value.strip()

        self._current_table = str(table_sel.value)
        self._current_rows = database.query_cves(
            self._current_table,
            search=search,
            min_severity=str(min_sev),
            date_from=date_from,
            date_to=date_to,
        )

        results = self.query_one("#browser-results", DataTable)
        results.clear()
        for r in self._current_rows:
            score = f"{r['cvss_score']:.1f}" if r.get("cvss_score") else ""
            desc = (r.get("description") or "")[:80]
            results.add_row(
                r.get("cve_id", ""),
                r.get("severity", ""),
                score,
                (r.get("cwe") or "")[:20],
                (r.get("keyword") or "")[:20],
                (r.get("publish_date") or "")[:10],
                desc,
            )
        self.query_one("#browser-status", Static).update(f"{len(self._current_rows)} result(s) — Enter to view detail")

    def action_open_detail(self) -> None:
        results = self.query_one("#browser-results", DataTable)
        if not self._current_table or not self._current_rows:
            return
        row_idx = results.cursor_row
        if 0 <= row_idx < len(self._current_rows):
            cve_id = self._current_rows[row_idx].get("cve_id", "")
            self.app.push_screen(CVEDetailScreen(self._current_table, cve_id))

    def action_export_csv(self) -> None:
        self._export("csv")

    def action_export_json(self) -> None:
        self._export("json")

    def _export(self, fmt: str) -> None:
        import database
        table_sel = self.query_one("#browser-table-select", Select)
        if table_sel.value is Select.BLANK:
            self.notify("Select a keyword table first.", severity="warning")
            return

        tbl = str(table_sel.value)
        search = self.query_one("#browser-search", Input).value.strip()
        sev_sel = self.query_one("#browser-severity", Select)
        min_sev = sev_sel.value if sev_sel.value is not Select.BLANK else "NONE"
        date_from = self.query_one("#browser-date-from", Input).value.strip()
        date_to = self.query_one("#browser-date-to", Input).value.strip()

        from datetime import datetime as _dt
        stamp = _dt.now().strftime("%Y%m%d_%H%M%S")
        out_path = Path(__file__).parent / f"export_{tbl}_{stamp}.{fmt}"
        if fmt == "csv":
            n = database.export_cves_csv(tbl, out_path, search=search, min_severity=str(min_sev),
                                         date_from=date_from, date_to=date_to)
        else:
            n = database.export_cves_json(tbl, out_path, search=search, min_severity=str(min_sev),
                                          date_from=date_from, date_to=date_to)
        self.notify(f"Exported {n} rows to {out_path.name}", severity="information")


# ── Setup wizard ───────────────────────────────────────────────────────────────

class SetupWizard(Screen):
    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Label("Welcome to CVE Emailer v2\nLet's get you configured.", id="wizard-title")
        with ScrollableContainer(id="wizard-form"):
            yield Static(
                "[bold yellow]Note:[/bold yellow] Credentials are stored in plain text "
                "in config.ini — keep that file private and out of version control.",
                id="security-warning",
            )
            for section, key, label, placeholder, is_password in FIELDS:
                yield Label(label)
                yield Input(placeholder=placeholder, password=is_password,
                            id=f"wizard-{section}-{key}")
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
        Binding("r", "run_once",               "Run Once"),
        Binding("s", "push_screen('settings')", "Settings"),
        Binding("k", "push_screen('keywords')", "Keywords"),
        Binding("d", "push_screen('dashboard')","Dashboard"),
        Binding("h", "push_screen('history')",  "History"),
        Binding("b", "push_screen('browser')",  "Browse CVEs"),
        Binding("p", "push_screen('profiles')", "Profiles"),
        Binding("q", "app.quit",                "Quit"),
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
                yield Button("Run Once   [r]",   variant="primary",  id="btn-run-once")
                yield Button("Start Loop",        variant="success",  id="btn-start")
                yield Button("Stop",              variant="error",    id="btn-stop",     disabled=True)
                yield Static("─" * 18,            id="sidebar-sep1")
                yield Button("Dashboard [d]",     variant="default",  id="btn-dashboard")
                yield Button("Keywords  [k]",     variant="default",  id="btn-keywords")
                yield Button("Profiles  [p]",     variant="default",  id="btn-profiles")
                yield Button("History   [h]",     variant="default",  id="btn-history")
                yield Button("Browse    [b]",     variant="default",  id="btn-browser")
                yield Button("Settings  [s]",     variant="default",  id="btn-settings")
                yield Static("─" * 18,            id="sidebar-sep2")
                yield Button("Scheduler",         variant="default",  id="btn-scheduler")
                yield Button("Quit      [q]",     variant="default",  id="btn-quit")
                yield Static("", id="status-label")
                yield Static("", id="countdown-label")
            with Container(id="log-container"):
                yield RichLog(id="log", highlight=True, markup=True, wrap=True)
        yield Footer()

    def on_mount(self) -> None:
        import database
        database.bootstrap()
        self.query_one("#log", RichLog).write(
            "[bold cyan]CVE Emailer v2 ready.[/bold cyan]\n"
            "Press [bold]R[/bold] to run once or [bold]Start Loop[/bold] for a scheduled scan.\n"
            "Use [bold]K[/bold] to manage keywords, [bold]D[/bold] for dashboard, "
            "[bold]H[/bold] for history, [bold]B[/bold] to browse CVEs."
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        routes = {
            "btn-run-once":  self.action_run_once,
            "btn-start":     self._start_loop,
            "btn-stop":      self._stop_loop,
            "btn-dashboard": lambda: self.app.push_screen("dashboard"),
            "btn-keywords":  lambda: self.app.push_screen("keywords"),
            "btn-profiles":  lambda: self.app.push_screen("profiles"),
            "btn-history":   lambda: self.app.push_screen("history"),
            "btn-browser":   lambda: self.app.push_screen("browser"),
            "btn-settings":  lambda: self.app.push_screen("settings"),
            "btn-scheduler": self._open_scheduler,
            "btn-quit":      self.app.exit,
        }
        handler = routes.get(event.button.id)
        if handler:
            handler()

    # ── log / status ───────────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        self.call_from_thread(lambda: self.query_one("#log", RichLog).write(msg))

    def _set_status(self, text: str) -> None:
        self.call_from_thread(lambda: self.query_one("#status-label", Static).update(text))

    # ── countdown ──────────────────────────────────────────────────────────────

    def _start_countdown(self, seconds: int) -> None:
        self._countdown_end = time.monotonic() + seconds
        if self._ticker:
            self._ticker.stop()
        self._ticker = self.set_interval(1, self._tick_countdown)

    def _tick_countdown(self) -> None:
        remaining = int(self._countdown_end - time.monotonic())
        if remaining <= 0:
            self.query_one("#countdown-label", Static).update("")
            if self._ticker:
                self._ticker.stop()
                self._ticker = None
        else:
            mins, secs = divmod(remaining, 60)
            self.query_one("#countdown-label", Static).update(
                f"Next check in\n[bold]{mins:02d}:{secs:02d}[/bold]"
            )

    def _stop_countdown(self) -> None:
        if self._ticker:
            self._ticker.stop()
            self._ticker = None
        self.query_one("#countdown-label", Static).update("")

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
                search.run_once(log=self._log, stop_event=self._stop_event)
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
            import search
            try:
                search.timed_loop(
                    log=self._log,
                    stop_event=self._stop_event,
                    on_sleep=lambda s: self.call_from_thread(self._start_countdown, s),
                )
            except Exception as exc:
                self._log(f"[bold red]Error:[/bold red] {exc}")
            finally:
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

    # ── scheduler dialog ───────────────────────────────────────────────────────

    def _open_scheduler(self) -> None:
        self.app.push_screen(SchedulerScreen())


# ── Scheduler screen ───────────────────────────────────────────────────────────

class SchedulerScreen(Screen):
    BINDINGS = [Binding("escape", "app.pop_screen", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("Background Scheduler", id="sched-title")

        os_name = platform.system()
        if os_name == "Windows":
            hint = (
                "Register CVE Emailer as a Windows Task Scheduler job. "
                "Uses checkFrequency from config.ini as the repeat interval."
            )
        elif os_name == "Darwin":
            hint = "Install a launchd plist to run CVE Emailer on a schedule (macOS)."
        else:
            hint = "Install a systemd user service to run CVE Emailer on a schedule (Linux)."

        yield Static(hint, id="sched-hint")
        with Vertical(id="sched-layout"):
            yield Static("", id="sched-status")
            with Horizontal(id="sched-buttons"):
                yield Button("Check status",    variant="default",  id="btn-sched-status")
                yield Button("Install job",     variant="success",  id="btn-sched-install")
                yield Button("Remove job",      variant="error",    id="btn-sched-remove")
        yield Footer()

    def on_mount(self) -> None:
        self._refresh_status()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        import scheduler
        try:
            if event.button.id == "btn-sched-status":
                self._refresh_status()
            elif event.button.id == "btn-sched-install":
                msg = scheduler.install()
                self.query_one("#sched-status", Static).update(f"[green]{msg}[/green]")
            elif event.button.id == "btn-sched-remove":
                msg = scheduler.remove()
                self.query_one("#sched-status", Static).update(f"[yellow]{msg}[/yellow]")
        except RuntimeError as exc:
            self.query_one("#sched-status", Static).update(f"[red]{exc}[/red]")

    def _refresh_status(self) -> None:
        import scheduler
        status = scheduler.status()
        self.query_one("#sched-status", Static).update(status)


# ── App ────────────────────────────────────────────────────────────────────────

class CVEEmailerApp(App):
    CSS = """
    #main-layout { height: 1fr; }

    #sidebar {
        width: 26;
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
    #sidebar Button { width: 100%; margin-bottom: 1; }
    #sidebar-sep1, #sidebar-sep2 { color: $primary; margin: 1 0; }
    #status-label { text-align: center; margin-top: 1; }
    #countdown-label { text-align: center; color: $text-muted; }

    #log-container { width: 1fr; padding: 1 2; }
    #log { height: 1fr; }

    /* Shared form title styles */
    #settings-title, #wizard-title, #kw-title, #profiles-title,
    #history-title, #browser-title, #sched-title, #dashboard-title, #detail-title {
        text-style: bold;
        text-align: center;
        color: $accent;
        margin: 1 0;
        padding: 0 2;
    }

    #settings-form { padding: 1 4; }
    #settings-form Label { margin-top: 1; color: $text-muted; }
    #settings-buttons { margin-top: 2; }
    #settings-buttons Button { margin-right: 1; }

    #security-warning {
        background: $warning 15%;
        border: solid $warning;
        padding: 1 2;
        margin-bottom: 1;
    }

    /* Keywords */
    #kw-hint { color: $text-muted; padding: 0 4; margin-bottom: 1; }
    #kw-layout { padding: 1 4; height: 1fr; }
    #kw-list { height: 1fr; border: solid $primary; margin-bottom: 1; }
    #kw-input-row { height: auto; margin-bottom: 1; }
    #kw-input { width: 1fr; }
    #btn-kw-add { width: 10; margin-left: 1; }
    #kw-buttons Button { margin-right: 1; }

    /* Profiles */
    #profiles-hint { color: $text-muted; padding: 0 4; margin-bottom: 1; }
    #profiles-layout { padding: 1 4; height: 1fr; }
    #profiles-table { height: 10; border: solid $primary; margin-bottom: 1; }
    #profiles-form-row { height: 1fr; }
    #profiles-form { width: 1fr; margin-right: 2; }
    #profiles-form Input { margin-bottom: 1; }
    #pf-keywords-label { color: $text-muted; margin-top: 1; margin-bottom: 0; }
    #pf-keywords { height: 5; margin-bottom: 1; }
    #pf-sep { color: $primary; margin: 1 0; }
    #pf-digest-label { color: $text-muted; margin-bottom: 0; }
    #pf-digest { margin-bottom: 1; }
    #profiles-actions { width: 22; }
    #profiles-actions Button { width: 100%; margin-bottom: 1; }

    /* History */
    #history-table { height: 1fr; margin: 0 4; }

    /* Dashboard */
    #dash-top { height: 12; padding: 0 4; margin-bottom: 1; }
    #dash-summary { width: 1fr; border: solid $primary; padding: 1 2; margin-right: 2; }
    #dash-recent { width: 1fr; border: solid $primary; padding: 1 2; }
    #dash-keyword-table { height: 1fr; margin: 0 4; }

    /* Browser */
    #browser-controls { height: auto; padding: 0 4; margin-bottom: 0; }
    #browser-controls Input { width: 1fr; margin-right: 1; }
    #browser-controls Select { width: 26; margin-right: 1; }
    #browser-date-row { height: auto; padding: 0 4; margin-bottom: 1; }
    #browser-date-row Input { width: 1fr; margin-right: 1; }
    #browser-date-row Button { width: 12; }
    #browser-results { height: 1fr; margin: 0 4; }
    #browser-status { color: $text-muted; padding: 0 4; }

    /* Detail */
    #detail-body { padding: 1 4; }

    /* Scheduler */
    #sched-hint { color: $text-muted; padding: 0 4; margin-bottom: 1; }
    #sched-layout { padding: 1 4; }
    #sched-status { margin-bottom: 2; }
    #sched-buttons Button { margin-right: 1; }

    /* Wizard */
    #wizard-form { padding: 1 4; }
    #wizard-form Label { margin-top: 1; color: $text-muted; }
    #wizard-form Button { margin-top: 2; width: 20; }
    """

    SCREENS = {
        "main":      MainScreen,
        "settings":  SettingsScreen,
        "keywords":  KeywordsScreen,
        "profiles":  ProfilesScreen,
        "history":   HistoryScreen,
        "browser":   BrowserScreen,
        "dashboard": DashboardScreen,
    }

    BINDINGS = [Binding("ctrl+c", "quit", "Quit", show=False)]

    def on_mount(self) -> None:
        if _needs_setup():
            self.push_screen(SetupWizard())
        else:
            self.push_screen("main")


def run():
    CVEEmailerApp().run()


# ── Headless helpers (used by scheduler.py) ────────────────────────────────────

def _run_once_patched(log=print) -> None:
    import search
    search.run_once(log=log, keywords=load_keywords())
