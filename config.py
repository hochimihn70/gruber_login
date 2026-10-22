"""Zentrale Konfiguration.

Alle Werte kommen aus der Umgebung: docker-compose liest die .env und reicht die
Variablen in den Container durch. Im Code ist nichts geheim und nichts hart
verdrahtet - hier stehen nur Namen, Grenzwerte und Defaults.
"""

import os
import re
from datetime import datetime

APP_NAME = "Gruber Login"

# --- Sessions -------------------------------------------------------------------------------
SESSION_COOKIE_NAME = "session_token"
SESSION_LIFETIME_DAYS = 7

# --- Einmal-Codes ---------------------------------------------------------------------------
# Gültigkeit in Minuten, je Verwendungszweck
OTP_PURPOSES = {"2fa": 10, "reset": 15}
OTP_LENGTH = 6
OTP_CODE_RANGE = (10 ** (OTP_LENGTH - 1), 10**OTP_LENGTH)
MAX_OTP_ATTEMPTS = 5

# --- Passwörter -----------------------------------------------------------------------------
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

AUTH_METHODS = ("password", "email_otp", "totp")

# --- Rate-Limiting --------------------------------------------------------------------------
# (Versuche, Zeitfenster in Sekunden). Gilt pro Prozess - für mehrere Worker
# müsste man das später z. B. über Redis teilen.
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"
# X-Forwarded-For nur hinter einem Proxy (z. B. Cloudflare Tunnel) auswerten.
# Direkt erreichbar wäre der Header fälschbar und würde das Limit aushebeln.
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "false").lower() == "true"

LOGIN_LIMIT_PER_IP = (20, 900)
LOGIN_LIMIT_PER_EMAIL = (10, 900)
REGISTER_LIMIT_PER_IP = (10, 3600)
FORGOT_LIMIT_PER_IP = (5, 900)
FORGOT_LIMIT_PER_EMAIL = (2, 3600)
VERIFY_LIMIT_PER_IP = (30, 900)
TOTP_LIMIT_PER_EMAIL = (5, 900)

# --- Zeitliche Login-Beschränkung (optional) ------------------------------------------------
LOGIN_RESTRICTION_ENABLED = os.environ.get("LOGIN_RESTRICTION_ENABLED", "false").lower() == "true"
LOGIN_ALLOWED_START_HOUR = int(os.environ.get("LOGIN_ALLOWED_START_HOUR", "6"))
LOGIN_ALLOWED_END_HOUR = int(os.environ.get("LOGIN_ALLOWED_END_HOUR", "22"))


def database_url() -> str:
    """Datenbank-URL aus der Umgebung. Fehlt sie, soll die App sofort abbrechen."""
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL ist nicht gesetzt. Vorlage: .env.example (docker compose liest .env)."
        )
    return url


def session_cookie_secure() -> bool:
    """Session-Cookie nur über HTTPS senden? Standard: ja."""
    return os.environ.get("SESSION_COOKIE_SECURE", "true").strip().lower() in ("true", "1", "yes", "on")


def smtp_config() -> dict:
    """SMTP-Konfiguration aus der Umgebung (einzige Quelle: .env)."""
    return {
        "host": os.environ.get("SMTP_HOST", "").strip(),
        "port": int(os.environ.get("SMTP_PORT", "587") or 587),
        "user": os.environ.get("SMTP_USER", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", "").strip(),
        "from": os.environ.get("SMTP_FROM", "").strip(),
    }


def smtp_missing_keys() -> list[str]:
    """Welche SMTP-Variablen fehlen noch? Ohne sie läuft die App im Dev-Modus."""
    cfg = smtp_config()
    needed = [("SMTP_HOST", cfg["host"]), ("SMTP_PASSWORD", cfg["password"]), ("SMTP_FROM", cfg["from"])]
    return [key for key, value in needed if not value]


def smtp_is_configured() -> bool:
    return not smtp_missing_keys()


def login_window_error() -> str | None:
    """None = Login gerade erlaubt, sonst die Begründung."""
    if not LOGIN_RESTRICTION_ENABLED:
        return None
    hour = datetime.now().hour
    if LOGIN_ALLOWED_START_HOUR <= hour < LOGIN_ALLOWED_END_HOUR:
        return None
    return (
        f"Login ist zu dieser Uhrzeit gesperrt. "
        f"Erlaubt: {LOGIN_ALLOWED_START_HOUR:02d}:00 bis {LOGIN_ALLOWED_END_HOUR:02d}:00 Uhr."
    )
