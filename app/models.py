"""Datenbank-Modelle (SQLAlchemy)."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password: Mapped[str] = mapped_column(String(255))  # Argon2id-Hash inkl. Salt
    auth_method: Mapped[str] = mapped_column(String(20), default="password")  # password | email_otp | totp
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)  # verschlüsselt (Fernet)
    totp_last_step: Mapped[int | None] = mapped_column(Integer, nullable=True)  # Replay-Schutz (letzter Schritt)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class SessionToken(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # SHA-256-Hash des Cookies
    user_id: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class EmailOTP(Base):
    __tablename__ = "email_otps"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    code: Mapped[str] = mapped_column(String(64))  # HMAC-Signatur, nicht der Code selbst
    purpose: Mapped[str] = mapped_column(String(20), default="2fa")  # 2fa | reset
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
