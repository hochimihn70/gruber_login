"""Eingabe-Prüfung, die von mehreren Abläufen gebraucht wird."""

from app import config


def normalize_email(value: str) -> str:
    """E-Mail einheitlich speichern und vergleichen (ohne Leerzeichen, klein)."""
    return (value or "").strip().lower()


def is_valid_email(email: str) -> bool:
    return bool(config.EMAIL_PATTERN.match(email))
