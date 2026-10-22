"""Konten: registrieren/aktualisieren und Passwort prüfen."""

from datetime import datetime

from sqlalchemy.orm import Session

from app import config
from app.errors import AppError
from app.models import User
from app.security import (
    burn_password_check,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    password_error,
    verify_password,
)
from app.services import totp
from app.validation import is_valid_email, normalize_email

# Dreimal derselbe Text (ungültige E-Mail, unbekanntes Konto, falsches Passwort):
# Eine Meldung, damit niemand daran ablesen kann, welcher Fall vorliegt.
INVALID_CREDENTIALS = "E-Mail oder Passwort ist falsch."


def register(db: Session, raw_email: str, password: str, raw_method: str) -> tuple[User, str | None]:
    """Legt ein Konto an oder aktualisiert ein bestehendes.

    Rückgabe: der Benutzer und - nur bei `totp` - das Klartext-Secret für den
    QR-Code. Für den Datenbankeintrag wird das Secret verschlüsselt.
    """
    email = normalize_email(raw_email)
    auth_method = (raw_method or "").strip().lower()
    if auth_method not in config.AUTH_METHODS:
        auth_method = "password"

    if not email or not password:
        raise AppError("E-Mail und Passwort fehlen.")
    if not is_valid_email(email):
        raise AppError("Bitte eine gültige E-Mail-Adresse eingeben.")
    if message := password_error(password):
        raise AppError(message)

    existing = db.query(User).filter_by(email=email).first()

    # Sicherheitsregel: Ein bestehendes Konto darf niemals ohne Passwort
    # überschrieben werden - sonst könnte jeder eine fremde E-Mail übernehmen.
    if existing is not None and not verify_password(password, existing.password):
        raise AppError(
            "Diese E-Mail ist bereits registriert und das Passwort stimmt nicht überein. "
            "Bitte melde dich an oder setze dein Passwort zurück.",
            status_code=401,
        )

    plain_secret = None
    encrypted_secret = None
    if auth_method == "totp":
        # Vorhandenes Secret behalten, damit die Authenticator-App weiter funktioniert.
        if existing is not None and existing.auth_method == "totp" and existing.totp_secret:
            plain_secret = decrypt_secret(existing.totp_secret)
        if plain_secret is None:
            plain_secret = totp.new_secret()
        encrypted_secret = encrypt_secret(plain_secret)

    if existing is not None:
        existing.password = hash_password(password)
        existing.auth_method = auth_method
        existing.totp_secret = encrypted_secret
        existing.totp_last_step = None  # neues Secret -> Replay-Zähler zurücksetzen
        user = existing
    else:
        user = User(
            email=email,
            password=hash_password(password),
            auth_method=auth_method,
            totp_secret=encrypted_secret,
            created_at=datetime.now(),
        )
        db.add(user)

    db.commit()
    return user, plain_secret


def authenticate(db: Session, email: str, password: str) -> User:
    """Prüft E-Mail und Passwort und liefert den Benutzer.

    Unbekannte E-Mail und falsches Passwort ergeben dieselbe Meldung; bei
    unbekannter E-Mail wird zusätzlich ein Dummy-Hash gerechnet, damit die
    Antwortzeit nicht verrät, ob das Konto existiert.
    """
    if not is_valid_email(email):
        burn_password_check(password)
        raise AppError(INVALID_CREDENTIALS, status_code=401)

    user = db.query(User).filter_by(email=email).first()
    if user is None:
        burn_password_check(password)
        raise AppError(INVALID_CREDENTIALS, status_code=401)

    if not verify_password(password, user.password):
        raise AppError(INVALID_CREDENTIALS, status_code=401)

    return user
