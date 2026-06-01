"""Email composition and delivery."""

from __future__ import annotations

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SEVERITY_COLORS = {
    "CRITICAL": "#b91c1c",
    "HIGH":     "#c2410c",
    "MEDIUM":   "#b45309",
    "LOW":      "#4d7c0f",
    "NONE":     "#6b7280",
    "UNKNOWN":  "#6b7280",
}


def send_email(
    sender: str,
    password: str,
    recipients: list[str],
    subject: str,
    body: str,
) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(_to_html(body), "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.sendmail(sender, recipients, msg.as_string())


def send_test_email(sender: str, password: str, recipients: list[str]) -> None:
    """Send a dummy alert to verify SMTP config is working."""
    dummy = [{
        "keyword":      "Test Service",
        "id":           "CVE-2024-99999",
        "severity":     "HIGH",
        "cvss_score":   7.5,
        "cwe":          "CWE-79",
        "cpe":          "cpe:2.3:a:test:service:1.0:*:*:*:*:*:*:*",
        "publish_date": "2024-01-01 00:00:00",
        "last_modified":"2024-01-02 00:00:00",
        "description":  "This is a test alert from CVE Emailer v2. If you received this, your email configuration is working correctly.",
        "refs":         ["https://nvd.nist.gov/"],
    }]
    body = _build_plain(dummy)
    send_email(sender, password, recipients, "CVE Emailer — Test Alert", body)


def _build_plain(cves: list[dict]) -> str:
    lines = []
    for c in cves:
        score_str = f" ({c['cvss_score']:.1f})" if c.get("cvss_score") else ""
        lines.append(f"Service: {c['keyword']}")
        lines.append(f"{c['id']}  |  Severity: {c['severity']}{score_str}")
        if c.get("cwe"):
            lines.append(f"CWE:         {c['cwe']}")
        if c.get("cpe"):
            lines.append(f"Affected:    {c['cpe']}")
        lines.append(f"Published:   {c['publish_date']}")
        lines.append(f"Modified:    {c['last_modified']}")
        lines.append(f"Description: {c['description']}")
        if c.get("refs"):
            lines.append("References:  " + " | ".join(c["refs"]))
        lines.append("")
    return "\n".join(lines)


def _to_html(plain: str) -> str:
    """Convert plain-text email body to styled HTML."""
    blocks: list[str] = []
    current: list[str] = []

    def flush():
        if current:
            blocks.append("<br>".join(current))
            current.clear()

    for line in plain.splitlines():
        line = line.strip()
        if not line:
            flush()
        else:
            current.append(_format_line(line))
    flush()

    cards = "".join(
        f'<div style="background:#1e1e2e;border-left:4px solid #7c3aed;'
        f'border-radius:6px;padding:12px 16px;margin-bottom:12px;'
        f'font-family:monospace;font-size:13px;color:#cdd6f4">{b}</div>'
        for b in blocks
    )
    return (
        '<html><body style="background:#11111b;padding:24px;color:#cdd6f4;font-family:sans-serif">'
        '<h2 style="color:#cba6f7">CVE Emailer Alert</h2>'
        f"{cards}"
        "</body></html>"
    )


def _format_line(line: str) -> str:
    if line.startswith("Service:"):
        return f'<strong style="color:#89dceb">{line}</strong>'

    if "|" in line and "Severity:" in line:
        parts = line.split("|")
        if len(parts) == 2:
            cve_part = parts[0].strip()
            sev_part = parts[1].strip()
            sev_label = sev_part.replace("Severity:", "").strip()
            # strip score from label if present
            if "(" in sev_label:
                sev_label, _, score = sev_label.partition("(")
                score = score.rstrip(")")
                score_html = f' <span style="color:#a6adc8">({score})</span>'
            else:
                score_html = ""
            color = SEVERITY_COLORS.get(sev_label.strip(), "#6b7280")
            return (
                f'<strong style="color:#f38ba8">{cve_part}</strong>'
                f'&nbsp;<span style="background:{color};color:#fff;'
                f'padding:1px 7px;border-radius:4px;font-size:11px">{sev_label.strip()}</span>'
                f'{score_html}'
            )
        return f'<strong style="color:#f38ba8">{line}</strong>'

    if line.startswith("CWE:"):
        label, _, rest = line.partition(":")
        return f'<span style="color:#fab387">{label}:</span> {rest.strip()}'

    if line.startswith("Affected:"):
        label, _, rest = line.partition(":")
        return f'<span style="color:#a6adc8">{label}:</span> <code style="font-size:11px">{rest.strip()}</code>'

    if line.startswith("References:"):
        _, _, rest = line.partition(":")
        links = " &nbsp;|&nbsp; ".join(
            f'<a href="{u.strip()}" style="color:#89b4fa">{u.strip()}</a>'
            for u in rest.split("|")
        )
        return f'<span style="color:#a6adc8">References:</span> {links}'

    if line.startswith("Description:"):
        label, _, rest = line.partition(":")
        return f'<span style="color:#a6adc8">{label}:</span> {rest.strip()}'

    if line.startswith(("Published:", "Modified:")):
        label, _, rest = line.partition(":")
        return f'<span style="color:#585b70">{label}:</span> {rest.strip()}'

    return line
