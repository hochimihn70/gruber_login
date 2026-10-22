"""E-Mail-Versand über SMTP.

Ohne konfigurierten SMTP läuft die App im Dev-Modus: Der Code wird nur ins Log
geschrieben und von der API an den Browser zurückgegeben, damit die Demo auch
ohne Mailserver funktioniert.
"""

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import OTP_PURPOSES, smtp_config, smtp_is_configured, smtp_missing_keys

logger = logging.getLogger(__name__)


def send_otp_email(to_email: str, otp_code: str, purpose: str = "2fa") -> bool:
    """Schickt den Code per E-Mail.

    True  = verschickt
    False = nicht verschickt (Dev-Modus oder Versandfehler)
    """
    cfg = smtp_config()
    title = "Dein Verifizierungscode" if purpose == "2fa" else "Passwort zurücksetzen"
    validity_minutes = OTP_PURPOSES[purpose]

    if not smtp_is_configured():
        # Bewusst nur im Dev-Modus: mit echtem SMTP gehört der Code nicht ins Log.
        logger.info("[DEV] %s für %s: %s", title, to_email, otp_code)
        return False

    message = _build_message(cfg["from"], to_email, title, otp_code, validity_minutes)

    try:
        if cfg["port"] == 465:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=10) as server:
                _login_and_send(server, cfg, to_email, message)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=10) as server:
                server.starttls()
                _login_and_send(server, cfg, to_email, message)
    except Exception as exc:
        logger.error("Mail-Fehler: %s", exc)
        return False

    return True


def _login_and_send(server, cfg: dict, to_email: str, message: MIMEMultipart) -> None:
    if cfg["user"] and cfg["password"]:
        server.login(cfg["user"], cfg["password"])
    server.sendmail(cfg["from"], [to_email], message.as_string())


def _build_message(sender: str, to_email: str, title: str, otp_code: str, validity_minutes: int) -> MIMEMultipart:
    message = MIMEMultipart("alternative")
    message["Subject"] = title  # Code nicht im Betreff (sonst im Sperrbildschirm sichtbar)
    message["From"] = sender
    message["To"] = to_email

    text_content = f"Hallo!\n\nDein Code lautet: {otp_code}\nEr ist {validity_minutes} Minuten gültig.\n"

    box_style = (
        "font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px; "
        "border: 1px solid #e0e0e0; border-radius: 8px;"
    )
    code_style = (
        "font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #111827; "
        "background: #f3f4f6; padding: 15px; text-align: center; border-radius: 6px; margin: 20px 0;"
    )
    html_content = f"""
    <div style="{box_style}">
      <h2 style="color: #333;">{title}</h2>
      <p>Gib den folgenden 6-stelligen Code ein:</p>
      <div style="{code_style}">
        {otp_code}
      </div>
      <p style="color: #666; font-size: 14px;">Dieser Code ist {validity_minutes} Minuten lang gültig.</p>
    </div>
    """
    message.attach(MIMEText(text_content, "plain"))
    message.attach(MIMEText(html_content, "html"))
    return message


def log_startup_status() -> None:
    """Beim Start einmal ausgeben, ob der Mailversand aktiv ist."""
    if smtp_is_configured():
        cfg = smtp_config()
        logger.info(
            "[SMTP] E-Mail-Versand: AKTIV (Host: %s, Port: %s, Absender: %s)",
            cfg["host"],
            cfg["port"],
            cfg["from"],
        )
    else:
        logger.warning(
            "[SMTP] E-Mail-Versand: DEAKTIVIERT -> Dev-Modus. Fehlende Variablen: %s",
            ", ".join(smtp_missing_keys()) or "keine",
        )
