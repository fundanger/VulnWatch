# CVE Emailer

Polls the [NIST National Vulnerability Database (NVD) API](https://nvd.nist.gov/developers/vulnerabilities) for new CVEs matching a list of vendors and services, stores results in MySQL to avoid duplicates, and sends an email digest whenever new vulnerabilities are found.

Built to keep a security team passively informed on CVE activity for their specific tech stack — no manual checking, no noise from CVEs you've already seen.

> This product uses the NVD API but is not endorsed or certified by the NVD.

---

## How it works

1. Reads a list of vendor/service keywords from a text file (one per line)
2. Queries the NVD API for each keyword on a configurable interval
3. Checks results against a MySQL database — only new CVEs (not previously seen) are included
4. Sends a plain-text email digest via Gmail SMTP if any new CVEs were found

Each keyword gets its own table in MySQL. `INSERT IGNORE` handles deduplication — if a CVE ID already exists in the table, it's skipped silently.

---

## Requirements

- Python 3.8+
- MySQL database (local or remote)
- Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) configured (required if 2FA is enabled)
- NIST NVD API key — free, get one at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Setup

**1. Clone the repo**

```bash
git clone https://github.com/fundanger/CVE-Emailer.git
cd CVE-Emailer
```

**2. Create your keyword list**

Create a `.txt` file with one vendor/service per line. Format is `Vendor Product` with a space between them.

```
Apache Knox
Microsoft Exchange
Cisco IOS
Palo Alto PAN-OS
```

**3. Set up the MySQL database**

Create a database (the tool will create tables automatically):

```sql
CREATE DATABASE cve_emailer;
```

**4. Fill out `config.ini`**

```ini
[DEFAULT]
apiKey = your_nvd_api_key_here
txtList = keywords.txt
checkFrequency = 3600

[EMAIL]
senderEmail = youremail@gmail.com
senderPassword = your_app_password_here
recipientEmail = recipient@example.com
subjectLine = CVE Alert

[DATABASE]
username = root
password = your_db_password
host = 127.0.0.1
database = cve_emailer
```

- `checkFrequency` is in **seconds** — `3600` = every hour, `86400` = once a day
- `senderPassword` should be a [Google App Password](https://support.google.com/accounts/answer/185833), not your Gmail login password

**5. Run it**

```bash
python main.py
```

The script runs continuously, checking the API on the interval set in `checkFrequency`. Keep it running in a terminal, screen session, or scheduled task.

---

## Email output format

When new CVEs are found, you'll get one email per check cycle containing all new findings:

```
Service: MicrosoftExchange
CVE-20241234
publish_date: 2024-03-15 12:00:00
last_modified: 2024-03-16 08:30:00
description: A remote code execution vulnerability exists in Microsoft Exchange Server...

Service: CiscoIOS
CVE-20245678
publish_date: 2024-03-14 09:00:00
...
```

If nothing new is found, no email is sent.

---

## Project structure

```
CVE-Emailer/
├── main.py         # Entry point
├── search.py       # NVD API queries, scheduling loop, email assembly
├── database.py     # MySQL table creation and CVE insertion
├── mail.py         # Gmail SMTP email sending
├── config.ini      # Configuration (not committed — add your own)
└── requirements.txt
```

---

## Notes

- The NVD API has rate limits. The tool includes a short sleep between requests per keyword to stay within limits. With an API key, the limit is 50 requests per 30 seconds.
- Keyword formatting: spaces in keywords become `%20` in the URL query. The same string (spaces stripped) is used as the MySQL table name, so keep keywords alphanumeric.
- Gmail SMTP requires either an App Password or "less secure app access" — App Passwords are the right way to do this.
- `config.ini` contains credentials. Never commit it. It's in `.gitignore`.

---

## License

MIT
