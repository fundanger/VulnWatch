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


def _to_html(plain: str) -> str:
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
        '<html><body style="background:#11111b;padding:24px;color:#cdd6f4">'
        f'<h2 style="color:#cba6f7;font-family:sans-serif">CVE Emailer Alert</h2>'
        f"{cards}"
        "</body></html>"
    )


def _format_line(line: str) -> str:
    if line.startswith("Service:"):
        return f'<strong style="color:#89dceb">{line}</strong>'
    if line.startswith("CVE-") or ("|" in line and "Severity:" in line):
        parts = line.split("|")
        if len(parts) == 2:
            cve_part = parts[0].strip()
            sev_part = parts[1].strip()
            sev_label = sev_part.replace("Severity:", "").strip()
            color = SEVERITY_COLORS.get(sev_label, "#6b7280")
            return (
                f'<strong style="color:#f38ba8">{cve_part}</strong>'
                f' &nbsp;<span style="background:{color};color:#fff;'
                f'padding:1px 6px;border-radius:4px;font-size:11px">{sev_label}</span>'
            )
        return f'<strong style="color:#f38ba8">{line}</strong>'
    if line.startswith("Description:"):
        label, _, rest = line.partition(":")
        return f'<span style="color:#a6adc8">{label}:</span> {rest.strip()}'
    if line.startswith(("Published:", "Modified:")):
        label, _, rest = line.partition(":")
        return f'<span style="color:#585b70">{label}:</span> {rest.strip()}'
    return line
