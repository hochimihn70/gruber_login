"""Kryptografie und Passwort-Regeln.

Alles, was mit Geheimnissen zu tun hat, liegt hier an einer Stelle:
Passwort-Hashing (Argon2id), HMAC für E-Mail-Codes, Verschlüsselung des
TOTP-Secrets und der Server-Schlüssel aus der .env.
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
import threading
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from app import config

logger = logging.getLogger(__name__)

# Argon2id nach OWASP-Empfehlung: 46 MiB, 1 Durchlauf, 1 Thread (~50 ms pro Aufruf).
password_hasher = PasswordHasher(time_cost=1, memory_cost=47104, parallelism=1)

# Wird bei unbekannter E-Mail geprüft, damit die Antwortzeit nicht verrät,
# ob ein Konto existiert.
_dummy_hash = password_hasher.hash("dummy-password-for-timing")

_app_secret: bytes | None = None
_secret_lock = threading.Lock()


# --- Server-Geheimnis -----------------------------------------------------------------------


def app_secret() -> bytes:
    """Server-Geheimnis aus APP_SECRET.

    Wird für HMAC-Signaturen und die Verschlüsselung des TOTP-Secrets gebraucht
    und muss deshalb stabil bleiben - sonst ist ein vorhandenes Secret nach dem
    Neustart nicht mehr entschlüsselbar.

    Der Lock verhindert, dass zwei gleichzeitige erste Aufrufe zwei
    verschiedene Schlüssel erzeugen (dann wäre einer davon unbrauchbar).
    """
    global _app_secret
    if _app_secret is not None:
        return _app_secret

    with _secret_lock:
        if _app_secret is None:
            configured = os.environ.get("APP_SECRET", "").strip().encode()
            if configured:
                _app_secret = configured
            else:
                _app_secret = secrets.token_bytes(32)
                logger.warning(
                    "Kein APP_SECRET gesetzt - es wurde ein zufälliges Geheimnis erzeugt. "
                    "Vorhandene TOTP-Secrets überleben keinen Neustart. "
                    'Eigenen Wert erzeugen: python3 -c "import secrets; print(secrets.token_hex(32))"'
                )
    return _app_secret


def hmac_code(email: str, purpose: str, code: str) -> str:
    """Signiert einen 6-stelligen Code. In der DB steht nur diese Signatur."""
    message = f"{email}|{purpose}|{code}".encode()
    return hmac.new(app_secret(), message, hashlib.sha256).hexdigest()


def encrypt_secret(plaintext: str) -> str:
    """Verschlüsselt einen Wert (TOTP-Secret) für die Datenbank."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str | None:
    """Entschlüsselt einen Wert. Falscher Schlüssel oder kaputte Daten -> None."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(app_secret()).digest())
    return Fernet(key)


# --- Passwörter -----------------------------------------------------------------------------


def password_error(password: str) -> str | None:
    """Serverseitige Passwort-Regel. None = in Ordnung.

    Der Browser prüft dasselbe, aber darauf darf man sich nicht verlassen:
    Ein Aufruf per curl umgeht jede Frontend-Validierung.
    """
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return f"Das Passwort muss mindestens {config.MIN_PASSWORD_LENGTH} Zeichen haben."
    if len(password) > config.MAX_PASSWORD_LENGTH:
        return f"Das Passwort darf höchstens {config.MAX_PASSWORD_LENGTH} Zeichen haben."
    return None


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        return password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def burn_password_check(password: str) -> None:
    """Rechnet einen Dummy-Vergleich, um die Antwortzeit anzugleichen."""
    verify_password(password, _dummy_hash)


# --- Session-Tokens -------------------------------------------------------------------------


def new_session_token() -> tuple[str, str]:
    """(Cookie-Wert, DB-Wert). In der DB liegt nur der SHA-256-Hash."""
    token = secrets.token_hex(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def session_expiry(now: datetime) -> datetime:
    return now + timedelta(days=config.SESSION_LIFETIME_DAYS)


def generate_otp() -> str:
    """Zufälliger Code mit OTP_LENGTH Ziffern (z. B. 6-stellig)."""
    low, high = config.OTP_CODE_RANGE
    return str(secrets.randbelow(high - low) + low)
