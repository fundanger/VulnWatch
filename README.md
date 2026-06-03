# CVE Emailer v2

A self-hosted CVE monitoring platform that tracks the [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities) for vulnerabilities matching your tech stack and delivers alerts across email, Slack, Microsoft Teams, PagerDuty, Opsgenie, Jira, and ServiceNow.

Runs as a full web dashboard, an interactive terminal UI, or a headless background service. Built for security teams who want passive, noise-filtered CVE coverage without manual checking.

> This product uses the NVD API but is not endorsed or certified by the NVD.

---

## Features

### Monitoring & Alerting
- **Keyword-based CVE scanning** — monitor any product, vendor, or library by name
- **Per-keyword severity overrides** — `Apache Knox::HIGH` ignores LOW/MEDIUM for that keyword only
- **CPE-based version scanning** — after an environment scan, NVD is queried by exact installed version so only CVEs where your version is in the vulnerable range are returned
- **EPSS enrichment** — exploit prediction scores fetched automatically for every CVE
- **CISA KEV tracking** — Known Exploited Vulnerabilities flagged on every result
- **Severity upgrade re-alerting** — re-notifies when a CVE's severity or CVSS score increases significantly
- **Alert deduplication** — configurable per-channel cooldown prevents repeat noise

### Notification Channels
- Email (Gmail SMTP)
- Slack (incoming webhook)
- Microsoft Teams (Adaptive Card)
- Generic JSON webhook
- PagerDuty (Events v2)
- Opsgenie (Alerts API)
- Jira (creates issues for critical/high CVEs)
- ServiceNow (creates incidents)

### Notification Profiles & Digest Mode
- **Profiles** — route different keyword sets to different recipients, channels, and severity floors
- **Digest mode** — batch CVEs and send on hourly/daily/weekly schedules instead of immediately

### Web Dashboard
A full-featured single-page app served at `http://localhost:5000`:

- **Overview** — stat cards, CVE trend chart, severity doughnut, EPSS chart, top risk CVEs, MTTR panel, scan health
- **Browse CVEs** — full-text search with severity/date/keyword filters, bulk triage actions, CVE detail overlay
- **Watchlist** — pin CVEs for ongoing monitoring
- **Analytics** — age distribution, severity-over-time, EPSS vs CVSS scatter, discovery heatmap
- **Scan History** — per-run new/upgraded CVE counts
- **Triage** — assign, set status/SLA, track patched versions, suppress false positives
- **Assets** — CPE-based asset inventory with CVE correlation
- **Threat Intel** — in-the-wild exploitation data from CISA KEV and OTX
- **Exploit Intel** — known PoC/exploit references from GitHub and NVD
- **Routing Rules** — route alerts by severity/tag to specific channels
- **Profiles** — create and manage notification profiles
- **Digest Queue** — view and manually send pending digest batches
- **Users (RBAC)** — viewer / analyst / lead roles with per-user API keys
- **Audit Log** — immutable record of every triage, comment, suppression, and override
- **Notify Log** — history of every notification sent
- **Settings** — full config editor with connection tests

### CVE Detail Overlay
Every CVE opens a rich detail panel with:
- Severity, EPSS, KEV status, CVSS vector breakdown
- Exploit intelligence (PoC/exploit refs)
- MITRE ATT&CK technique mapping (CWE → T-number)
- Affected assets (CPE-based matching)
- Related CVEs (same CWE or product)
- Threat intelligence (in-the-wild badge, malware families, campaigns)
- Composite risk score (CVSS + EPSS + threat + exploit + asset criticality)
- Compliance mapping (NIST 800-53, CIS Controls v8, ISO 27001)
- Vendor advisories (Red Hat, Ubuntu)
- **Remediation panel** — NVD patch/advisory links, template patch commands, AI-generated commands, analyst notes
- Internal risk override (never overwrites NVD data)
- Patch tracking (patched version, date, by)
- Threaded comments
- Triage fields

### AI / LLM Intelligence
Provider-agnostic — works with OpenAI, DeepSeek, Anthropic, Ollama, or any OpenAI-compatible API. Configure via Settings or environment variables.

- **Natural-language search** — plain English query bar in Browse CVEs translates to filter params
- **Executive summary** — auto-generated 3-sentence plain-language CVE summary in the detail overlay
- **Triage suggestions** — AI recommends status, due date, and rationale based on CVE data and triage history
- **Noise ranking** — re-sorts current browse results by relevance to your installed asset inventory
- **Digest narrative** — generates a human-readable security digest paragraph for team leads
- **Keyword expansion** — suggests missing coverage based on current keywords and asset inventory

### Remediation & Patch Guidance
- NVD reference tags surfaced as Patch / Vendor Advisory / Mitigation badges with direct links
- Template-based patch commands generated from CPE data (apt, yum, pip, npm, Maven, winget, PowerShell, and more)
- AI-generated platform-specific commands (cached per CVE)
- Analyst remediation notes field (saved per CVE)
- **Auto-patching** — when a rescan shows an installed version is no longer vulnerable per NVD, the CVE is automatically marked `patched` in triage

### Environment Scanners
Three scanners fingerprint installed software, running services, and listening ports on target machines, then upload asset records and software inventory to the dashboard. CVEs are then automatically correlated to specific hosts.

### Security
- Bearer token auth (`API_SECRET` env var or per-user RBAC keys)
- CSRF double-submit protection on all write endpoints
- Content Security Policy, X-Frame-Options, X-Content-Type-Options headers
- SQL injection prevention (table names from server-side whitelist only, always quoted)
- CVE ID validation on all route params
- Audit log for all state-changing actions

---

## Quick Start

**Requirements:** Python 3.10+

```bash
git clone https://github.com/fundanger/CVE-Emailer-v2.git
cd CVE-Emailer-v2
pip install -r requirements.txt
```

### Terminal UI
```bash
python main.py
```
A setup wizard runs automatically on first launch if required fields are missing.

### Web Dashboard
```bash
python api.py              # serves at http://localhost:5000
python api.py --port 8080  # custom port
python api.py --host 0.0.0.0  # bind all interfaces
```

### Headless / Scheduled Mode
```bash
python scheduler.py install   # register background job (Windows / macOS / Linux)
python scheduler.py run       # run one scan cycle now
python scheduler.py status    # check if registered
python scheduler.py remove    # unregister
```

---

## Configuration

All settings are managed via the web Settings page or directly in `config.ini` (gitignored — never committed). Sensitive values can be set as environment variables, which take precedence and appear read-only in the UI.

### Key environment variables

| Variable | Purpose |
|---|---|
| `API_SECRET` | Bearer token for all write endpoints. Required for production use. |
| `NVD_API_KEY` | NVD API key — optional but raises rate limit to 50 req/30s |
| `CVE_SENDER_EMAIL` | Gmail address to send alerts from |
| `CVE_SENDER_PASSWORD` | Google App Password |
| `CVE_RECIPIENT_EMAIL` | Comma-separated alert recipients |
| `CVE_SLACK_WEBHOOK` | Slack incoming webhook URL |
| `CVE_WEBHOOK_URL` | Generic JSON webhook URL |
| `TEAMS_WEBHOOK` | Microsoft Teams incoming webhook URL |
| `PAGERDUTY_ROUTING_KEY` | PagerDuty Events v2 routing key |
| `OPSGENIE_API_KEY` | Opsgenie API key |
| `JIRA_URL` / `JIRA_USER` / `JIRA_TOKEN` / `JIRA_PROJECT_KEY` | Jira integration |
| `SNOW_INSTANCE` / `SNOW_USER` / `SNOW_PASSWORD` | ServiceNow integration |
| `LLM_API_KEY` | API key for the configured LLM provider |
| `LLM_BASE_URL` | LLM API base URL (defaults per provider) |
| `LLM_PROVIDER` | `openai`, `deepseek`, `anthropic`, `ollama`, or `custom` |
| `CVE_CORS_ORIGINS` | Comma-separated allowed CORS origins (default: same-origin only) |

### Keyword syntax

```
Apache Knox
log4j::CRITICAL
OpenSSL::MEDIUM
nginx
```

The `::SEVERITY` suffix overrides the global minimum severity floor for that keyword only.

---

## Environment Scanners

Run on any machine you want to monitor. Each scanner fingerprints installed software, running services, OS/kernel, listening ports, and package libraries, then uploads the data to the dashboard — creating an Asset record and a versioned software inventory for CPE-based vulnerability matching.

**Python** (Windows / Linux / macOS):
```bash
python scan_environment.py

python scan_environment.py --upload http://your-dashboard:5000 \
    --token YOUR_API_SECRET --asset-name PROD-WEB-01 \
    --environment production --owner infra-team --append
```

**Bash** (Linux / macOS — no Python required):
```bash
bash scan_environment.sh

bash scan_environment.sh --upload http://your-dashboard:5000 \
    --token YOUR_API_SECRET --asset-name PROD-LNX-01 \
    --environment production --append
```

**PowerShell** (Windows):
```powershell
.\Scan-Environment.ps1

.\Scan-Environment.ps1 -DashboardUrl http://your-dashboard:5000 -Token YOUR_API_SECRET `
    -AssetName PROD-WIN-01 -Environment production -Owner infra-team -Append

# Preview without uploading
.\Scan-Environment.ps1 -DashboardUrl http://your-dashboard:5000 -Token SECRET -DryRun
```

All scanners:
- Require no root/admin rights (most checks degrade gracefully if unprivileged)
- Use `--append` to merge discovered keywords — version entries are updated in-place
- Filter generic noise names and use a Docker image whitelist
- Store `last_scanned_at` and `scan_source` on the Asset record

After uploading, the next scan cycle will query NVD by versioned CPE for each software item. CVEs where the exact installed version is no longer in the vulnerable range are automatically marked `patched` in triage.

---

## AI / LLM Setup

Configure any OpenAI-compatible LLM provider in Settings → AI / LLM Integration:

| Provider | Base URL | Example model |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Anthropic | `https://api.anthropic.com/v1` | `claude-haiku-4-5-20251001` |
| Ollama (local) | `http://localhost:11434/v1` | `llama3` |
| Custom | any OpenAI-compatible URL | any |

Base URLs default automatically when a known provider is selected. Set `LLM_API_KEY` as an environment variable to avoid storing it in `config.ini`.

---

## RBAC

Three roles:

| Role | Permissions |
|---|---|
| `viewer` | Read-only access |
| `analyst` | Triage, review, suppress, comment |
| `lead` | Full access including user management |

Manage users via the dashboard Users section or `POST /api/users`. Per-user API keys are 64-character hex strings shown only at creation time. The global `API_SECRET` env var continues to work as a superuser key.

---

## Project Structure

```
CVE-Emailer-v2/
├── main.py               # Entry point — calls tui.run()
├── tui.py                # Textual TUI: all screens, setup wizard, config helpers
├── search.py             # NVD fetch, CVE enrichment, CPE scanning, dispatch, scan loop
├── database.py           # SQLite backend: all tables, migrations, risk scoring
├── api.py                # Flask REST API + web dashboard + LLM endpoints
├── mail.py               # Gmail SMTP: plain-text + styled HTML email
├── notify.py             # Slack, webhook, Jira, ServiceNow dispatch
├── epss.py               # EPSS + CISA KEV enrichment
├── integrations.py       # Jira / ServiceNow ticket creation
├── scheduler.py          # Cross-platform background job installer
├── logger.py             # Structured event logging
├── scan_environment.py   # Cross-platform environment scanner (Python)
├── scan_environment.sh   # Linux/macOS environment scanner (Bash)
├── Scan-Environment.ps1  # Windows environment scanner (PowerShell)
├── dashboard/
│   ├── index.html        # Single-page web dashboard
│   ├── app.js            # Dashboard frontend logic
│   └── style.css         # Dashboard styles
├── config.ini            # Credentials and settings (gitignored)
└── requirements.txt
```

---

## Notes

- `config.ini` contains credentials. It is gitignored and must never be committed.
- The database (`cve_emailer.db`) contains your software inventory and scan data. It is also gitignored.
- CVE deduplication uses SQLite `INSERT OR IGNORE` on the CVE ID — already-seen CVEs are silently skipped and only re-alerted if severity upgrades.
- The NVD API returns up to 2000 results per page; pagination is automatic with a 3-second courtesy delay. HTTP 429/403 responses trigger extended backoff before retrying.
- Each keyword gets its own SQLite table named after the keyword (non-word characters replaced with `_`).
- All database migrations use `ALTER TABLE ... ADD COLUMN` in try/except blocks — upgrading from older versions is safe.

---

## License

MIT
