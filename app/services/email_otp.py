"""Einmal-Codes per E-Mail - für die 2FA und für den Passwort-Reset.

In der Datenbank liegt nur die HMAC-Signatur des Codes. Im Dev-Modus (kein
SMTP) wird der Klartext-Code in der Antwort mitgeschickt, damit die Demo ohne
Mailserver bedienbar bleibt.
"""

import secrets
from datetime import datetime, timedelta

from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app import config
from app.errors import AppError, RateLimited
from app.mailer import send_otp_email
from app.models import EmailOTP
from app.security import generate_otp, hmac_code

LABELS = {"2fa": "Bestätigungscode", "reset": "Reset-Code"}


def create_code(db: Session, email: str, purpose: str) -> str:
    """Ersetzt einen alten Code durch einen neuen und liefert den Klartext-Code."""
    code = generate_otp()
    now = datetime.now()
    db.query(EmailOTP).filter_by(email=email, purpose=purpose).delete()
    db.add(
        EmailOTP(
            email=email,
            code=hmac_code(email, purpose, code),
            purpose=purpose,
            created_at=now,
            expires_at=now + timedelta(minutes=config.OTP_PURPOSES[purpose]),
        )
    )
    db.commit()
    return code


def challenge(db: Session, email: str) -> JSONResponse:
    """Neuen 2FA-Code anlegen, verschicken und die passende Antwort liefern."""
    code, sent = deliver(db, email, "2fa")
    if config.smtp_is_configured() and not sent:
        raise AppError("E-Mail konnte nicht gesendet werden.", status_code=500)
    return JSONResponse(payload(email, code, sent))


def deliver(db: Session, email: str, purpose: str) -> tuple[str, bool]:
    """Code anlegen und verschicken. Gibt (Klartext-Code, wurde_verschickt) zurück."""
    code = create_code(db, email, purpose)
    return code, send_otp_email(email, code, purpose)


def payload(email: str, code: str, sent: bool) -> dict:
    """Antwort nach dem Anfordern eines Codes."""
    if sent:
        message = f"Bestätigungscode wurde an {email} gesendet!"
    else:
        message = f"Kein SMTP-Server konfiguriert (Dev-Modus) – dein Bestätigungscode lautet: {code}"
    data = {"status": "2fa_required", "method": "email_otp", "email": email, "message": message}
    if not sent:
        data["dev_code"] = code
        data["dev_mode"] = True
    return data


def check_code(db: Session, email: str, purpose: str, code: str) -> None:
    """Prüft einen E-Mail-Code und zählt Fehlversuche.

    Kein Rückgabewert = Code richtig (und verbraucht), sonst `AppError`.
    Wird für 2FA und für den Passwort-Reset benutzt - beide sind damit
    gleichermaßen gegen Durchprobieren geschützt.
    """
    label = LABELS[purpose]
    otp = (
        db.query(EmailOTP)
        .filter(
            EmailOTP.email == email,
            EmailOTP.purpose == purpose,
            EmailOTP.expires_at > datetime.now(),
        )
        .first()
    )
    if otp is None:
        raise AppError(f"Ungültiger oder abgelaufener {label}.")

    if secrets.compare_digest(otp.code, hmac_code(email, purpose, code)):
        db.query(EmailOTP).filter_by(email=email, purpose=purpose).delete()
        db.commit()
        return

    otp.attempts = (otp.attempts or 0) + 1
    remaining = config.MAX_OTP_ATTEMPTS - otp.attempts
    if remaining <= 0:
        # Ohne diese Bremse wären 900.000 Kombinationen im Gültigkeitsfenster durchprobierbar.
        db.query(EmailOTP).filter_by(email=email, purpose=purpose).delete()
        db.commit()
        raise RateLimited(config.OTP_PURPOSES[purpose] * 60)

    db.commit()
    raise AppError(f"Ungültiger {label}. Noch {remaining} Versuche.")
