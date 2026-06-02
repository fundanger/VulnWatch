# CVE Emailer v2

Monitors the [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities) for new CVEs matching your tech stack and sends alerts via email, Slack, or webhook. Runs as an interactive terminal UI or as a headless Windows Task Scheduler job.

Built to keep a security team passively informed — no manual checking, no noise from CVEs you've already seen.

> This product uses the NVD API but is not endorsed or certified by the NVD.

---

## Features

- **Terminal UI** built with [Textual](https://textual.textualize.io/) — run scans, manage keywords, browse results, all from the terminal
- **Per-keyword severity overrides** — e.g. `Apache Knox::HIGH` ignores LOW/MEDIUM for that keyword only
- **Email, Slack, and webhook notifications** — send to multiple destinations simultaneously
- **Notification profiles** — route different keyword sets to different recipients or webhooks
- **CVE browser** — search and filter collected CVEs, export to CSV or JSON
- **Scan history** — view past scan results with timestamps and CVE counts
- **Windows Task Scheduler integration** — run headless in the background, scheduled automatically
- **SQLite storage** — zero server setup, everything in a single local file

---

## Requirements

- Python 3.10+
- Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) (for email alerts)
- NVD API key — free at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) (optional but recommended for higher rate limits)

```bash
pip install -r requirements.txt
```

---

## Setup

**1. Clone the repo**

```bash
git clone https://github.com/fundanger/CVE-Emailer-v2.git
cd CVE-Emailer-v2
```

**2. Run the app**

```bash
python main.py
```

On first launch, a setup wizard walks you through the required configuration (sender email, app password, recipient). Everything is stored in `config.ini` (gitignored — never committed).

**3. Add keywords**

Open the Keywords screen (`K`) and add the vendors or products you want to monitor:

```
Apache Knox
Microsoft Exchange
Cisco IOS XE
Palo Alto PAN-OS::CRITICAL
```

The `::SEVERITY` suffix overrides the global minimum severity for that keyword only.

---

## Configuration

All settings live in `config.ini`. The most important ones:

| Setting | Description |
|---|---|
| `apiKey` | NVD API key (optional, raises rate limit to 50 req/30s) |
| `checkFrequency` | Scan interval in seconds (default: 3600) |
| `minSeverity` | Global severity floor: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `senderEmail` | Gmail address to send alerts from |
| `senderPassword` | Google App Password (not your login password) |
| `recipientEmail` | Comma-separated list of alert recipients |
| `slackWebhook` | Slack incoming webhook URL |
| `webhookUrl` | Generic JSON webhook URL |

---

## Keyboard shortcuts

| Key | Action |
|---|---|
| `R` | Run one scan immediately |
| `S` | Settings |
| `K` | Keywords |
| `H` | Scan history |
| `B` | CVE browser |
| `P` | Notification profiles |
| `Q` | Quit |

---

## Headless / scheduled mode

Run without the TUI using Windows Task Scheduler:

```bash
python scheduler.py install   # register job (uses checkFrequency from config)
python scheduler.py status    # check if registered
python scheduler.py run       # run one cycle now (logs to cve_emailer.log)
python scheduler.py remove    # unregister job
```

You can also manage the Task Scheduler job from inside the TUI via the Scheduler button in the sidebar.

---

## Notification profiles

Profiles let you run separate scans for different audiences — e.g. send `Apache*` CVEs to the infrastructure team and `Salesforce*` CVEs to the app team.

Each profile has its own keyword list, severity floor, recipient list, and optional webhook/Slack URLs. Create and manage profiles on the Profiles screen (`P`).

When any profiles exist, the scan loop runs profiles instead of the default config-based scan.

---

## Environment scanners

Run one of these on any machine you want to monitor. Each script fingerprints installed software, running services, OS/kernel, listening ports, and package-manager libraries, then either prints a keyword list or uploads it directly to CVE Emailer — creating an Asset record so CVEs are automatically correlated to the host.

**Python** (Windows / Linux / macOS — recommended):

```bash
# Print keyword list
python scan_environment.py

# Upload to dashboard with full asset metadata
python scan_environment.py --upload http://your-dashboard:5000 --token YOUR_API_SECRET \
    --asset-name PROD-WEB-01 --environment production --owner infra-team --append
```

**Bash** (Linux / macOS — no Python required):

```bash
chmod +x scan_environment.sh

# Print keyword list
./scan_environment.sh

# Upload to dashboard
./scan_environment.sh --upload http://your-dashboard:5000 --token YOUR_API_SECRET \
    --asset-name PROD-LNX-01 --environment production --append
```

**PowerShell** (Windows):

```powershell
# Print keyword list
.\Scan-Environment.ps1

# Upload to dashboard with full asset metadata
.\Scan-Environment.ps1 -DashboardUrl http://your-dashboard:5000 -Token YOUR_API_SECRET `
    -AssetName PROD-WIN-01 -Environment production -Owner infra-team -Append

# Preview what would be uploaded (no changes made)
.\Scan-Environment.ps1 -DashboardUrl http://your-dashboard:5000 -Token SECRET -DryRun
```

All three scanners:
- Require no root / admin rights (most checks; some WMI queries on Windows work better elevated but degrade gracefully)
- Use `--append` / `-Append` to merge discovered keywords into the existing list — version entries are updated in-place (scanner always wins)
- Filter generic port-only names (`HTTP server`, `HTTPS server`, etc.) that produce NVD noise
- Use a Docker image whitelist — unknown container names are silently dropped
- Store `last_scanned_at` and `scan_source` on the Asset record

---

## Project structure

```
CVE-Emailer-v2/
├── main.py               # Entry point — calls tui.run()
├── tui.py                # Textual TUI: all screens, setup wizard, config helpers
├── search.py             # NVD fetch, CVE enrichment, dispatch, scan loop
├── database.py           # SQLite backend: CVE tables, scan history, profiles
├── mail.py               # Gmail SMTP: plain-text + styled HTML email
├── notify.py             # Slack block-kit and generic webhook dispatch
├── scheduler.py          # Cross-platform background job installer
├── api.py                # Flask REST API + web dashboard
├── scan_environment.py   # Cross-platform environment scanner (Python)
├── scan_environment.sh   # Linux/macOS environment scanner (Bash)
├── Scan-Environment.ps1  # Windows environment scanner (PowerShell)
├── config.ini            # Credentials and settings (gitignored)
└── requirements.txt
```

---

## Notes

- `config.ini` contains credentials. It is gitignored and must never be committed.
- CVE deduplication is handled by SQLite `INSERT OR IGNORE` on the CVE ID — already-seen CVEs are skipped silently.
- The NVD API returns up to 2000 results per page; the app paginates automatically with a 3-second courtesy delay between pages. HTTP 429/403 rate-limit responses trigger an extended backoff before retrying.
- Each keyword gets its own SQLite table named after the keyword (non-word characters replaced with `_`).

---

## License

MIT
