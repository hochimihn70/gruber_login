"""Status- und Konto-Endpunkte."""

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import config
from app.db import get_db
from app.errors import AppError
from app.services import sessions

router = APIRouter(prefix="/api", tags=["system"])


@router.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    """Kurzer Status: Datenbank erreichbar? Ist der E-Mail-Versand konfiguriert?"""
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    smtp_configured = config.smtp_is_configured()
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else "fehler",
        "smtp_configured": smtp_configured,
        "smtp_missing": config.smtp_missing_keys(),
        "dev_mode": not smtp_configured,
    }


@router.get("/me")
def get_current_user(request: Request, db: Session = Depends(get_db)) -> dict:
    user = sessions.current_user(db, request)
    if user is None:
        raise AppError("Nicht eingeloggt.", status_code=401)

    return {
        "email": user.email,
        "auth_method": user.auth_method,
        "last_login_at": user.last_login_at.strftime("%d.%m.%Y %H:%M:%S") if user.last_login_at else "Erstmalig",
        "created_at": user.created_at.strftime("%d.%m.%Y %H:%M:%S"),
    }
