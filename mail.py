import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_email(sender: str, password: str, recipient: str, subject: str, body: str) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(_to_html(body), "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.send_message(msg)


def _to_html(plain: str) -> str:
    rows = []
    for line in plain.splitlines():
        line = line.strip()
        if line.startswith("CVE-"):
            rows.append(f"<h3>{line}</h3>")
        elif line.startswith("Service:"):
            rows.append(f"<h2>{line}</h2>")
        elif line:
            rows.append(f"<p>{line}</p>")
    return "<html><body>" + "\n".join(rows) + "</body></html>"
