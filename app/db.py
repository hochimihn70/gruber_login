"""Datenbank-Anbindung.

Hier liegen Engine, Basisklasse, die Session-Dependency für FastAPI und eine
kleine Aufräum-Funktion für Schema-Änderungen aus früheren Versionen.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app import config

logger = logging.getLogger(__name__)

engine = create_engine(config.database_url(), pool_pre_ping=True)

# expire_on_commit=False: Nach dem Commit bleiben die geladenen Werte (z. B. user.id)
# lesbar. Das erspart das übliche "ID vor dem Schließen retten".
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


@contextmanager
def db_session() -> Iterator[Session]:
    """DB-Session als Context Manager: schließt auch bei einer Exception."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI-Dependency: eine Session pro Request, garantiert geschlossen."""
    with db_session() as session:
        yield session


def init_db() -> None:
    """Tabellen anlegen (falls neu) und alte Installationen nachziehen."""
    from app import models  # noqa: F401  - registriert die Tabellen an Base

    Base.metadata.create_all(engine)
    _upgrade_legacy_schema()
    _encrypt_legacy_totp_secrets()


def _upgrade_legacy_schema() -> None:
    """Ergänzt Spalten, die ältere Installationen noch nicht haben.

    Für eine neue Datenbank ist das ein No-op. Langfristig wäre Alembic der
    saubere Weg; für dieses Projekt reicht die Prüfung beim Start.
    """
    try:
        inspector = inspect(engine)
        existing = {
            "users": {column["name"] for column in inspector.get_columns("users")},
            "email_otps": {column["name"] for column in inspector.get_columns("email_otps")},
        }
    except Exception as exc:  # Datenbank noch nicht bereit o. ä.
        logger.warning("Schema-Prüfung übersprungen: %s", exc)
        return

    additions = {
        "users": {
            "auth_method": "VARCHAR(20) DEFAULT 'password'",
            "totp_secret": "VARCHAR(255) NULL",
            "totp_last_step": "INT NULL",
        },
        "email_otps": {
            "purpose": "VARCHAR(20) DEFAULT '2fa'",
            "attempts": "INT DEFAULT 0",
        },
    }

    try:
        with engine.begin() as conn:
            for table, columns in additions.items():
                for name, definition in columns.items():
                    if name not in existing[table]:
                        # Tabellen- und Spaltennamen sind feste Konstanten, keine Nutzereingabe
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {definition}"))
            _widen_legacy_columns(conn)
    except Exception as exc:
        logger.warning("Schema-Migration fehlgeschlagen: %s", exc)


def _widen_legacy_columns(conn) -> None:
    """MySQL kennt kein "ADD COLUMN, wenn zu schmal" - die zwei Spalten wurden
    später breiter (verschlüsseltes TOTP-Secret, HMAC-Signatur statt Code)."""
    if engine.dialect.name != "mysql":
        return
    columns = {
        table: {column["name"]: column["type"] for column in inspect(engine).get_columns(table)}
        for table in ("users", "email_otps")
    }
    if getattr(columns["users"].get("totp_secret"), "length", 0) < 255:
        conn.execute(text("ALTER TABLE users MODIFY COLUMN totp_secret VARCHAR(255) NULL"))
    if getattr(columns["email_otps"].get("code"), "length", 0) < 64:
        conn.execute(text("ALTER TABLE email_otps MODIFY COLUMN code VARCHAR(64)"))


def _encrypt_legacy_totp_secrets() -> None:
    """Alte Klartext-Secrets verschlüsseln und alte Klartext-Codes entfernen.

    Nur für Installationen aus einer früheren Version relevant, sonst ein No-op.
    Bereits verschlüsselte Werte (Fernet-Token beginnen mit "gAAAA") werden nicht
    angefasst - auch dann nicht, wenn sie mit einem anderen APP_SECRET erzeugt
    wurden. Sonst würde ein unlesbares Token ein zweites Mal verschlüsselt.
    """
    from app.security import encrypt_secret

    try:
        with engine.begin() as conn:
            rows = conn.execute(text("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL")).fetchall()
            for user_id, stored in rows:
                value = str(stored)
                if value.startswith("gAAAA"):
                    continue  # schon verschlüsselt
                conn.execute(
                    text("UPDATE users SET totp_secret = :value WHERE id = :id"),
                    {"value": encrypt_secret(value), "id": user_id},
                )
            # Codes ohne HMAC-Signatur sind für die Prüfung unbrauchbar geworden
            conn.execute(text("DELETE FROM email_otps WHERE LENGTH(code) <= 10"))
    except Exception as exc:
        logger.warning("Aufräumen alter Secrets fehlgeschlagen: %s", exc)
