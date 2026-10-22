"""Gemeinsame Auth-Bausteine.

Die Abläufe "Session anlegen", "E-Mail-Code prüfen", "TOTP prüfen" und
"Rate-Limit anwenden" werden von mehreren Endpunkten gebraucht. Sie stehen
deshalb hier - und nicht dreimal kopiert in app.py.
"""

import io
import secrets
import time
from datetime import datetime, timedelta

import pyotp
import qrcode
import qrcode.image.svg
from fastapi import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

import config
from config import EMAIL_PATTERN, MAX_OTP_ATTEMPTS, OTP_PURPOSES, SESSION_COOKIE_NAME, SESSION_LIFETIME_DAYS
from mailer import send_otp_email
from models import EmailOTP, SessionToken, User
from ratelimit import limiter
from responses import error, too_many_requests
from security import decrypt_secret, generate_otp, hash_token, hmac_code, new_session_token, session_expiry

OTP_LABELS = {"2fa": "Bestätigungscode", "reset": "Reset-Code"}


# --- Eingaben & Rate-Limiting ---------------------------------------------------------------

def normalize_email(value: str) -> str:
    return value.strip().lower()


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_PATTERN.match(email))


def client_ip(request: Request) -> str:
    """IP des Aufrufers - hinter einem Proxy aus X-Forwarded-For.

    Der Header ist nur vertrauenswürdig, wenn tatsächlich ein Proxy davorsteht
    (TRUST_PROXY_HEADERS). Sonst könnte ihn jeder selbst setzen und das Limit
    umgehen.
    """
    if config.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit_error(request: Request, bucket: str, limits: tuple[int, int], subject: str = "") -> JSONResponse | None:
    """Prüft und zählt einen Versuch. None = erlaubt, sonst fertige 429-Antwort.

    Pro Aufruf wird entweder die IP (Standard) oder bei `subject` z. B. die
    E-Mail-Adresse gezählt - so lässt sich beides kombinieren.
    """
    if not config.RATE_LIMIT_ENABLED:
        return None

    limit, window_seconds = limits
    key = f"{bucket}:{subject or client_ip(request)}"
    wait = limiter.hit(key, limit, window_seconds)
    if wait is None:
        return None
    return too_many_requests(wait)


# --- Sessions -------------------------------------------------------------------------------

def create_session(db: Session, user_id: int) -> str:
    """Legt eine Session an und liefert das Cookie-Token im Klartext zurück."""
    token, token_hash = new_session_token()
    now = datetime.now()
    # Abgelaufene Sessions bei Gelegenheit aufräumen, damit die Tabelle nicht
    # unbegrenzt wächst. Kostet nur einen Index-Zugriff pro Login.
    db.query(SessionToken).filter(SessionToken.expires_at <= now).delete()
    db.add(
        SessionToken(
            token=token_hash,
            user_id=user_id,
            created_at=now,
            expires_at=session_expiry(now),
        )
    )
    db.commit()
    return token


def session_response(token: str, payload: dict, status_code: int = 200) -> JSONResponse:
    """Antwort mit Session-Cookie - die einzige Stelle, die das Cookie setzt."""
    response = JSONResponse(payload, status_code=status_code)
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=SESSION_LIFETIME_DAYS * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=config.session_cookie_secure(),
    )
    return response


def complete_login(db: Session, user: User, message: str = "Login erfolgreich.") -> JSONResponse:
    """Schließt einen erfolgreichen Login ab: Zeitstempel, Session, Cookie.

    Wird von Registrierung, Passwort-Login und 2FA-Prüfung benutzt (Regel der
    drei Wiederholungen) - die drei Abläufe enden identisch.
    """
    user.last_login_at = datetime.now()
    db.commit()
    return session_response(
        create_session(db, user.id),
        {"status": "success", "message": message, "redirect": "/welcome"},
    )


def resolve_session(db: Session, request: Request) -> SessionToken | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    return (
        db.query(SessionToken)
        .filter(SessionToken.token == hash_token(token), SessionToken.expires_at > datetime.now())
        .first()
    )


def current_user(db: Session, request: Request) -> User | None:
    token = resolve_session(db, request)
    if token is None:
        return None
    return db.query(User).filter_by(id=token.user_id).first()


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME)


# --- E-Mail-Codes ---------------------------------------------------------------------------

def create_email_otp(db: Session, email: str, purpose: str) -> str:
    """Ersetzt einen alten Code durch einen neuen und liefert den Klartext-Code.

    In der Datenbank landet nur die HMAC-Signatur.
    """
    code = generate_otp()
    now = datetime.now()
    db.query(EmailOTP).filter_by(email=email, purpose=purpose).delete()
    db.add(
        EmailOTP(
            email=email,
            code=hmac_code(email, purpose, code),
            purpose=purpose,
            created_at=now,
            expires_at=now + timedelta(minutes=OTP_PURPOSES[purpose]),
        )
    )
    db.commit()
    return code


def email_otp_payload(email: str, code: str, sent: bool) -> dict:
    """Antwort nach dem Anfordern eines Codes.

    Im Dev-Modus (kein SMTP) wird der Code mitgeschickt, damit die Demo ohne
    Mailserver funktioniert - die UI behauptet dann nicht, es sei eine Mail raus.
    """
    if sent:
        message = f"Bestätigungscode wurde an {email} gesendet!"
    else:
        message = f"Kein SMTP-Server konfiguriert (Dev-Modus) – dein Bestätigungscode lautet: {code}"
    payload = {"status": "2fa_required", "method": "email_otp", "email": email, "message": message}
    if not sent:
        payload["dev_code"] = code
        payload["dev_mode"] = True
    return payload


def email_otp_challenge(db: Session, email: str) -> JSONResponse:
    """Neuen 2FA-Code anlegen, verschicken und die passende Antwort liefern."""
    code = create_email_otp(db, email, "2fa")
    sent = send_otp_email(email, code, "2fa")
    if config.smtp_is_configured() and not sent:
        return error("E-Mail konnte nicht gesendet werden.", status_code=500)
    return JSONResponse(email_otp_payload(email, code, sent), status_code=200)


def check_email_code(db: Session, email: str, purpose: str, code: str) -> JSONResponse | None:
    """Prüft einen E-Mail-Code und zählt Fehlversuche.

    None = Code richtig (und verbraucht), sonst eine fertige Fehlerantwort.
    Wird für 2FA und für den Passwort-Reset benutzt - beide sind damit
    gleichermaßen gegen Durchprobieren geschützt.
    """
    label = OTP_LABELS[purpose]
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
        return error(f"Ungültiger oder abgelaufener {label}.")

    if secrets.compare_digest(otp.code, hmac_code(email, purpose, code)):
        db.query(EmailOTP).filter_by(email=email, purpose=purpose).delete()
        db.commit()
        return None

    otp.attempts = (otp.attempts or 0) + 1
    remaining = MAX_OTP_ATTEMPTS - otp.attempts
    if remaining <= 0:
        # Ohne diese Bremse wären 900.000 Kombinationen im Gültigkeitsfenster durchprobierbar.
        db.query(EmailOTP).filter_by(email=email, purpose=purpose).delete()
        db.commit()
        return too_many_requests(OTP_PURPOSES[purpose] * 60)

    db.commit()
    return error(f"Ungültiger {label}. Noch {remaining} Versuche.")


# --- TOTP (Authenticator-App) ---------------------------------------------------------------

def totp_qr_svg(email: str, secret: str) -> str:
    """SVG-QR-Code für die Authenticator-App (ohne Pillow erzeugbar)."""
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="Gruber Login")
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


def new_totp_secret() -> str:
    return pyotp.random_base32()


def check_totp(user: User, code: str) -> JSONResponse | None:
    """Prüft einen Authenticator-Code inklusive Bremse und Replay-Schutz.

    None = richtig. Der Aufrufer muss den geänderten `totp_last_step` committen.
    """
    key = f"totp:{user.email}"

    if config.RATE_LIMIT_ENABLED:
        wait = limiter.wait_time(key, *config.TOTP_LIMIT_PER_EMAIL)
        if wait is not None:
            return too_many_requests(wait)

    failure = _verify_totp_code(user, code)

    if failure is None:
        if config.RATE_LIMIT_ENABLED:
            limiter.clear(key)
        return None

    if config.RATE_LIMIT_ENABLED:
        limiter.record(key)
    return failure


def _verify_totp_code(user: User, code: str) -> JSONResponse | None:
    if not user.totp_secret:
        return error("TOTP nicht eingerichtet.")

    secret = decrypt_secret(user.totp_secret)
    if secret is None:
        return error("TOTP-Secret konnte nicht entschlüsselt werden. Bitte die App neu einrichten.")

    totp = pyotp.TOTP(secret)
    step = _matching_step(totp, code)
    if step is None:
        return error("Falscher Authenticator-Code.")

    # Replay-Schutz: derselbe Zeitschritt wird nur einmal akzeptiert.
    if user.totp_last_step is not None and step <= user.totp_last_step:
        return error("Dieser Code wurde bereits verwendet. Bitte den nächsten Code abwarten.")

    user.totp_last_step = step
    return None


def _matching_step(totp: pyotp.TOTP, code: str) -> int | None:
    """Welcher 30-Sekunden-Schritt gehört zu diesem Code? ±1 Schritt Toleranz."""
    now = time.time()
    for offset in (-1, 0, 1):
        timestamp = now + offset * totp.interval
        if totp.at(timestamp) == code:
            return int(timestamp // totp.interval)
    return None
