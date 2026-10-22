"""Registrierung, Login, Zwei-Faktor-Prüfung und Logout."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app import config
from app.db import get_db
from app.errors import AppError
from app.models import SessionToken, User
from app.schemas import LoginRequest, RegisterRequest, Verify2FARequest
from app.security import hash_token
from app.services import accounts, email_otp, sessions, throttling, totp
from app.validation import normalize_email

router = APIRouter(prefix="/api", tags=["auth"])


@router.post("/register")
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)):
    """Konto anlegen oder - mit richtigem Passwort - die Sicherheitsstufe ändern."""
    throttling.enforce_limit(request, "register", config.REGISTER_LIMIT_PER_IP)

    user, secret = accounts.register(db, payload.email, payload.password, payload.auth_method)

    # Direkt in den passenden Ablauf übergehen (kein toter Klick):
    if user.auth_method == "password":
        return sessions.complete_login(db, user, "Registrierung erfolgreich.")
    if user.auth_method == "email_otp":
        return email_otp.challenge(db, user.email)

    return JSONResponse(
        {
            "status": "totp_setup",
            "auth_method": "totp",
            "email": user.email,
            "totp_secret": secret,
            "qr_svg": totp.qr_svg(user.email, secret),
        }
    )


@router.post("/login")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)):
    """Login Schritt 1: Passwort. Der zweite Faktor folgt über /verify-2fa."""
    throttling.enforce_limit(request, "login-ip", config.LOGIN_LIMIT_PER_IP)
    throttling.enforce_login_window()

    email = normalize_email(payload.email)
    if email:
        throttling.enforce_limit(request, "login-mail", config.LOGIN_LIMIT_PER_EMAIL, subject=email)

    user = accounts.authenticate(db, email, payload.password)

    if user.auth_method == "password":
        return sessions.complete_login(db, user)
    if user.auth_method == "email_otp":
        return email_otp.challenge(db, user.email)

    return JSONResponse(
        {
            "status": "2fa_required",
            "method": "totp",
            "email": user.email,
            "message": "Gib den 6-stelligen Code aus deiner Authenticator-App ein.",
        }
    )


@router.post("/verify-2fa")
def verify_2fa(request: Request, payload: Verify2FARequest, db: Session = Depends(get_db)):
    """Login Schritt 2: E-Mail- oder Authenticator-Code prüfen."""
    throttling.enforce_limit(request, "verify-ip", config.VERIFY_LIMIT_PER_IP)
    throttling.enforce_login_window()

    email = normalize_email(payload.email)
    code = payload.code.strip()
    if not email or not code:
        raise AppError("E-Mail und Code erforderlich.")

    user = db.query(User).filter_by(email=email).first()
    if user is None:
        # Kein eigener Fehlertext: verrät sonst, welche E-Mail registriert ist.
        raise AppError("Ungültiger Code.")

    if user.auth_method == "email_otp":
        email_otp.check_code(db, email, "2fa", code)
    elif user.auth_method == "totp":
        totp.check_code(user, code)
    else:
        raise AppError("Ungültiger Code.")

    return sessions.complete_login(db, user)


@router.post("/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get(config.SESSION_COOKIE_NAME)
    if token:
        db.query(SessionToken).filter_by(token=hash_token(token)).delete()
        db.commit()

    response = JSONResponse({"message": "Erfolgreich abgemeldet.", "redirect": "/"})
    sessions.clear_session_cookie(response)
    return response
