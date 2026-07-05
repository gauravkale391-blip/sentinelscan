"""
notifier.py
-----------
Sends alerts when malicious files are detected -- by email and/or
Slack -- so a scan doesn't just sit quietly in a log file. This
mirrors how real detection tools page/notify an analyst instead of
requiring someone to go looking for trouble.

Both notification channels are optional and fail gracefully: if they
aren't configured, or the network call fails, the scan itself is never
interrupted.
"""

import json
import smtplib
from email.mime.text import MIMEText

import requests


def build_alert_message(matches, target_dir):
    """Build a plain-text summary of detections, shared by both channels."""
    lines = [
        f"Antivirus Simulation Alert",
        f"Target scanned: {target_dir}",
        f"Total detections: {len(matches)}",
        "",
    ]
    for m in matches:
        lines.append(f"- File: {m['file']}")
        lines.append(f"  Hash: {m['hash']}")
        lines.append(f"  Source: {m['source']}")
        lines.append(f"  Label: {m['label']}")
        lines.append("")
    return "\n".join(lines)


def send_email_alert(matches, target_dir, email_config):
    """
    Send an email alert via SMTP.

    email_config expects:
        {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "you@gmail.com",
            "sender_password": "app_password_here",
            "recipient_email": "you@gmail.com"
        }

    For Gmail, sender_password must be an "App Password", not your
    normal login password (Google requires this for SMTP access).
    """
    required = ["smtp_server", "smtp_port", "sender_email",
                "sender_password", "recipient_email"]
    if not email_config or not all(email_config.get(k) for k in required):
        return False, "Email not configured -- skipped."

    body = build_alert_message(matches, target_dir)
    msg = MIMEText(body)
    msg["Subject"] = f"[AV Simulation] {len(matches)} detection(s) found"
    msg["From"] = email_config["sender_email"]
    msg["To"] = email_config["recipient_email"]

    try:
        with smtplib.SMTP(email_config["smtp_server"], int(email_config["smtp_port"])) as server:
            server.starttls()
            server.login(email_config["sender_email"], email_config["sender_password"])
            server.sendmail(
                email_config["sender_email"],
                [email_config["recipient_email"]],
                msg.as_string(),
            )
        return True, "Email alert sent."
    except Exception as e:
        return False, f"Email alert failed: {e}"


def send_slack_alert(matches, target_dir, slack_webhook_url):
    """
    Send an alert to a Slack channel via an Incoming Webhook URL.
    Get one at: https://api.slack.com/messaging/webhooks
    """
    if not slack_webhook_url:
        return False, "Slack webhook not configured -- skipped."

    text = build_alert_message(matches, target_dir)
    payload = {"text": f"```{text}```"}

    try:
        response = requests.post(
            slack_webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if response.status_code == 200:
            return True, "Slack alert sent."
        return False, f"Slack alert failed: HTTP {response.status_code}"
    except requests.exceptions.RequestException as e:
        return False, f"Slack alert failed: {e}"
