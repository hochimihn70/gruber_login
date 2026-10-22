"""TOTP (Authenticator-App): Secret erzeugen, QR-Code, Code prüfen."""

import io
import time

import pyotp
import qrcode
import qrcode.image.svg

from app import config
from app.errors import AppError, RateLimited
from app.models import User
from app.ratelimit import limiter
from app.security import decrypt_secret


def new_secret() -> str:
    return pyotp.random_base32()


def qr_svg(email: str, secret: str) -> str:
    """SVG-QR-Code für die Authenticator-App (ohne Pillow erzeugbar)."""
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=config.APP_NAME)
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


def check_code(user: User, code: str) -> None:
    """Prüft einen Authenticator-Code inklusive Bremse und Replay-Schutz.

    Kein Rückgabewert = Code richtig. Der Aufrufer muss den geänderten
    `totp_last_step` noch committen (passiert in `complete_login`).
    """
    key = f"totp:{user.email}"

    if config.RATE_LIMIT_ENABLED:
        wait = limiter.wait_time(key, *config.TOTP_LIMIT_PER_EMAIL)
        if wait is not None:
            raise RateLimited(wait)

    try:
        _verify(user, code)
    except AppError:
        if config.RATE_LIMIT_ENABLED:
            limiter.record(key)
        raise

    if config.RATE_LIMIT_ENABLED:
        limiter.clear(key)


def _verify(user: User, code: str) -> None:
    if not user.totp_secret:
        raise AppError("TOTP nicht eingerichtet.")

    secret = decrypt_secret(user.totp_secret)
    if secret is None:
        raise AppError("TOTP-Secret konnte nicht entschlüsselt werden. Bitte die App neu einrichten.")

    totp = pyotp.TOTP(secret)
    step = _matching_step(totp, code)
    if step is None:
        raise AppError("Falscher Authenticator-Code.")

    # Replay-Schutz: derselbe Zeitschritt wird nur einmal akzeptiert.
    if user.totp_last_step is not None and step <= user.totp_last_step:
        raise AppError("Dieser Code wurde bereits verwendet. Bitte den nächsten Code abwarten.")

    user.totp_last_step = step


def _matching_step(totp: pyotp.TOTP, code: str) -> int | None:
    """Welcher 30-Sekunden-Schritt gehört zu diesem Code? ±1 Schritt Toleranz."""
    now = time.time()
    for offset in (-1, 0, 1):
        timestamp = now + offset * totp.interval
        if totp.at(timestamp) == code:
            return int(timestamp // totp.interval)
    return None
