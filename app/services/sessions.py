"""Sessions: anlegen, im Cookie ausliefern, prüfen, beenden."""

from datetime import datetime

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app import config
from app.models import SessionToken, User
from app.security import hash_token, new_session_token, session_expiry


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
        key=config.SESSION_COOKIE_NAME,
        value=token,
        max_age=config.SESSION_LIFETIME_DAYS * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=config.session_cookie_secure(),
    )
    return response


def complete_login(db: Session, user: User, message: str = "Login erfolgreich.") -> JSONResponse:
    """Schließt einen erfolgreichen Login ab: Zeitstempel, Session, Cookie.

    Wird von Registrierung, Passwort-Login und 2FA-Prüfung benutzt - die drei
    Abläufe enden identisch.
    """
    user.last_login_at = datetime.now()
    db.commit()
    return session_response(
        create_session(db, user.id),
        {"status": "success", "message": message, "redirect": "/welcome"},
    )


def resolve_session(db: Session, request: Request) -> SessionToken | None:
    token = request.cookies.get(config.SESSION_COOKIE_NAME)
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
    response.delete_cookie(config.SESSION_COOKIE_NAME)
