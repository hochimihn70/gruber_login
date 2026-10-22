"""FastAPI-App: Seiten und API-Endpunkte.

Die Logik liegt in den Modulen daneben (config, database, security, mailer,
auth, ratelimit). Hier stehen nur noch die Routen - so bleibt die Datei lesbar.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import text

import config
from auth import (
    check_email_code,
    check_totp,
    clear_session_cookie,
    complete_login,
    create_email_otp,
    current_user,
    email_otp_challenge,
    is_valid_email,
    new_totp_secret,
    normalize_email,
    rate_limit_error,
    resolve_session,
    totp_qr_svg,
)
from config import APP_NAME, AUTH_METHODS, SESSION_COOKIE_NAME
from database import db_session, init_db
from mailer import log_startup_status, send_otp_email
from models import SessionToken, User
from responses import error
from security import (
    burn_password_check,
    decrypt_secret,
    encrypt_secret,
    hash_password,
    hash_token,
    password_error,
    verify_password,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

BASE_DIR = Path(__file__).resolve().parent

# Dreimal derselbe Text (ungültige E-Mail, unbekanntes Konto, falsches Passwort):
# Eine Meldung, damit niemand daran ablesen kann, welcher Fall vorliegt.
INVALID_CREDENTIALS = "E-Mail oder Passwort ist falsch."


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Startarbeiten - bewusst nicht beim Import, sonst hat schon das bloße
    Importieren der App Seiteneffekte (DB-Verbindung, Migration, Logging)."""
    init_db()
    log_startup_status()
    yield


app = FastAPI(title=APP_NAME, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Standard-Sicherheits-Header bei jeder Antwort.

    - X-Frame-Options:           kein Einbetten in fremde iframes (Clickjacking)
    - X-Content-Type-Options:    Browser soll den Inhalt nicht sniffen
    - Referrer-Policy:           keine fremden URLs an Dritte weitergeben
    - Content-Security-Policy:   nur eigene Scripts/Styles, kein Inline-JavaScript

    Hinweis zu Cloudflare: Der Tunnel injiziert ein eigenes Script in die
    HTML-Ausgabe (Bot-Erkennung). Die strikte CSP blockiert es - die App selbst
    läuft davon nicht betroffen.
    """
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'"
    )
    # HTML immer neu validieren lassen, sonst hält der Browser eine alte app.js fest.
    if "text/html" in response.headers.get("content-type", ""):
        response.headers["Cache-Control"] = "no-cache"
    return response


# --- Request-Bodies -------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: str = ""
    password: str = ""
    auth_method: str = "password"


class LoginRequest(BaseModel):
    email: str = ""
    password: str = ""


class Verify2FARequest(BaseModel):
    email: str = ""
    code: str = ""


class ForgotPasswordRequest(BaseModel):
    email: str = ""


class ResetPasswordRequest(BaseModel):
    email: str = ""
    code: str = ""
    new_password: str = ""


# --- Seiten ---------------------------------------------------------------------------------

@app.get("/")
def show_login_page():
    return FileResponse(BASE_DIR / "templates" / "index.html")


@app.get("/welcome")
def show_welcome_page(request: Request):
    with db_session() as db:
        session = resolve_session(db, request)

    if session is None:
        response = RedirectResponse(url="/", status_code=303)
        clear_session_cookie(response)
        return response

    return FileResponse(BASE_DIR / "templates" / "welcome.html")


# --- API ------------------------------------------------------------------------------------

@app.get("/api/health")
def health():
    """Kurzer Status: Datenbank erreichbar? Ist der E-Mail-Versand konfiguriert?"""
    db_ok = True
    try:
        with db_session() as db:
            db.execute(text("SELECT 1"))
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


@app.get("/api/me")
def get_current_user(request: Request):
    with db_session() as db:
        user = current_user(db, request)
        if user is None:
            return error("Nicht eingeloggt.", status_code=401)

        return {
            "email": user.email,
            "auth_method": user.auth_method,
            "last_login_at": user.last_login_at.strftime("%d.%m.%Y %H:%M:%S") if user.last_login_at else "Erstmalig",
            "created_at": user.created_at.strftime("%d.%m.%Y %H:%M:%S"),
        }


@app.post("/api/register")
def register(request: Request, payload: RegisterRequest):
    if blocked := rate_limit_error(request, "register", config.REGISTER_LIMIT_PER_IP):
        return blocked

    email = normalize_email(payload.email)
    password = payload.password
    auth_method = payload.auth_method.strip().lower()

    if not email or not password:
        return error("E-Mail und Passwort fehlen.")
    if not is_valid_email(email):
        return error("Bitte eine gültige E-Mail-Adresse eingeben.")
    if validation_error := password_error(password):
        return error(validation_error)
    if auth_method not in AUTH_METHODS:
        auth_method = "password"

    with db_session() as db:
        existing_user = db.query(User).filter_by(email=email).first()

        # Sicherheitsregel: Ein bestehendes Konto darf niemals ohne Passwort
        # überschrieben werden - sonst könnte jeder eine fremde E-Mail übernehmen.
        if existing_user is not None and not verify_password(password, existing_user.password):
            return error(
                "Diese E-Mail ist bereits registriert und das Passwort stimmt nicht überein. "
                "Bitte melde dich unten an oder setze dein Passwort zurück.",
                status_code=401,
            )

        password_hash = hash_password(password)
        totp_secret = None
        totp_secret_encrypted = None
        qr_svg = None

        if auth_method == "totp":
            # Vorhandenes Secret behalten, damit die Authenticator-App weiter funktioniert.
            if existing_user is not None and existing_user.auth_method == "totp" and existing_user.totp_secret:
                totp_secret = decrypt_secret(existing_user.totp_secret)
            if totp_secret is None:
                totp_secret = new_totp_secret()
            totp_secret_encrypted = encrypt_secret(totp_secret)
            qr_svg = totp_qr_svg(email, totp_secret)

        if existing_user is not None:
            existing_user.password = password_hash
            existing_user.auth_method = auth_method
            existing_user.totp_secret = totp_secret_encrypted
            existing_user.totp_last_step = None  # neues Secret -> Replay-Zähler zurücksetzen
            user = existing_user
        else:
            user = User(
                email=email,
                password=password_hash,
                auth_method=auth_method,
                totp_secret=totp_secret_encrypted,
                created_at=datetime.now(),
            )
            db.add(user)
        db.commit()

        # Direkt in den passenden Ablauf übergehen (kein toter Klick):
        if auth_method == "password":
            return complete_login(db, user, "Registrierung erfolgreich.")

        if auth_method == "email_otp":
            return email_otp_challenge(db, email)

        return JSONResponse(
            {
                "status": "totp_setup",
                "auth_method": auth_method,
                "totp_secret": totp_secret,
                "qr_svg": qr_svg,
            },
            status_code=200,
        )


@app.post("/api/login")
def login(request: Request, payload: LoginRequest):
    if blocked := rate_limit_error(request, "login-ip", config.LOGIN_LIMIT_PER_IP):
        return blocked
    if window_error := config.login_window_error():
        return error(window_error, status_code=403)

    email = normalize_email(payload.email)
    password = payload.password

    if email and (blocked := rate_limit_error(request, "login-mail", config.LOGIN_LIMIT_PER_EMAIL, subject=email)):
        return blocked

    if not is_valid_email(email):
        # Gleicher Fehlertext und gleiche Antwortzeit wie bei unbekannter E-Mail.
        burn_password_check(password)
        return error(INVALID_CREDENTIALS, status_code=401)

    with db_session() as db:
        user = db.query(User).filter_by(email=email).first()
        if user is None:
            burn_password_check(password)
            return error(INVALID_CREDENTIALS, status_code=401)

        if not verify_password(password, user.password):
            return error(INVALID_CREDENTIALS, status_code=401)

        if user.auth_method == "password":
            return complete_login(db, user)

        if user.auth_method == "email_otp":
            return email_otp_challenge(db, email)

        return JSONResponse(
            {
                "status": "2fa_required",
                "method": "totp",
                "email": email,
                "message": "Gib den 6-stelligen Code aus deiner Authenticator-App ein.",
            },
            status_code=200,
        )


@app.post("/api/verify-2fa")
def verify_2fa(request: Request, payload: Verify2FARequest):
    if blocked := rate_limit_error(request, "verify-ip", config.VERIFY_LIMIT_PER_IP):
        return blocked
    if window_error := config.login_window_error():
        return error(window_error, status_code=403)

    email = normalize_email(payload.email)
    code = payload.code.strip()

    if not email or not code:
        return error("E-Mail und Code erforderlich.")

    with db_session() as db:
        user = db.query(User).filter_by(email=email).first()
        if user is None:
            # Kein eigener Fehlertext: verrät sonst, welche E-Mail registriert ist.
            return error("Ungültiger Code.")

        if user.auth_method == "email_otp":
            failure = check_email_code(db, email, "2fa", code)
        elif user.auth_method == "totp":
            failure = check_totp(user, code)
        else:
            failure = error("Ungültiger Code.")

        if failure is not None:
            return failure

        return complete_login(db, user)


@app.post("/api/forgot-password")
def forgot_password(request: Request, payload: ForgotPasswordRequest):
    if blocked := rate_limit_error(request, "forgot-ip", config.FORGOT_LIMIT_PER_IP):
        return blocked

    email = normalize_email(payload.email)
    if not email:
        return error("Bitte E-Mail eingeben.")
    if blocked := rate_limit_error(request, "forgot-mail", config.FORGOT_LIMIT_PER_EMAIL, subject=email):
        return blocked

    # Anti-Enumeration: Die Antwort ist immer gleich, egal ob die E-Mail existiert.
    generic = {"message": "Falls die E-Mail registriert ist, wurde ein Reset-Code gesendet."}

    with db_session() as db:
        user = db.query(User).filter_by(email=email).first()
        if user is None:
            return JSONResponse(generic, status_code=200)

        code = create_email_otp(db, email, "reset")

    sent = send_otp_email(email, code, "reset")

    # SMTP ist konfiguriert, der Versand ist aber fehlgeschlagen: kein Code in
    # der Antwort (sonst könnte ihn jeder über /api/forgot-password abholen).
    if config.smtp_is_configured() and not sent:
        return error("E-Mail konnte nicht gesendet werden.", status_code=500)

    # Nur im Dev-Modus wird der Code mitgegeben, damit der Reset ohne Mailserver
    # demonstrierbar bleibt.
    if not sent:
        return JSONResponse(
            {
                "message": f"Kein SMTP-Server konfiguriert (Dev-Modus) – dein Reset-Code lautet: {code}",
                "dev_code": code,
                "dev_mode": True,
            },
            status_code=200,
        )
    return JSONResponse(generic, status_code=200)


@app.post("/api/reset-password")
def reset_password(request: Request, payload: ResetPasswordRequest):
    if blocked := rate_limit_error(request, "reset-ip", config.VERIFY_LIMIT_PER_IP):
        return blocked

    email = normalize_email(payload.email)
    code = payload.code.strip()
    new_password = payload.new_password

    if not email or not code or not new_password:
        return error("Alle Felder müssen ausgefüllt sein.")
    if validation_error := password_error(new_password):
        return error(validation_error)

    with db_session() as db:
        user = db.query(User).filter_by(email=email).first()
        if user is None:
            return error("Ungültiger oder abgelaufener Reset-Code.")

        failure = check_email_code(db, email, "reset", code)
        if failure is not None:
            return failure

        user.password = hash_password(new_password)
        # Alle bestehenden Sessions beenden - wer das Passwort zurücksetzt, will
        # typischerweise auch, dass niemand sonst mit einer alten Session drin ist.
        db.query(SessionToken).filter_by(user_id=user.id).delete()
        db.commit()

    return JSONResponse({"message": "Passwort erfolgreich geändert! Du kannst dich jetzt anmelden."}, status_code=200)


@app.post("/api/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        with db_session() as db:
            db.query(SessionToken).filter_by(token=hash_token(token)).delete()
            db.commit()

    response = JSONResponse({"message": "Erfolgreich abgemeldet.", "redirect": "/"}, status_code=200)
    clear_session_cookie(response)
    return response
