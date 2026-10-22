"""Passwort-Reset per E-Mail-Code."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app import config
from app.db import get_db
from app.errors import AppError
from app.models import SessionToken, User
from app.schemas import ForgotPasswordRequest, ResetPasswordRequest
from app.security import hash_password, password_error
from app.services import email_otp, throttling
from app.validation import normalize_email

router = APIRouter(prefix="/api", tags=["password"])

# Anti-Enumeration: Die Antwort ist immer gleich, egal ob die E-Mail existiert.
GENERIC_MESSAGE = {"message": "Falls die E-Mail registriert ist, wurde ein Reset-Code gesendet."}


@router.post("/forgot-password")
def forgot_password(request: Request, payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    throttling.enforce_limit(request, "forgot-ip", config.FORGOT_LIMIT_PER_IP)

    email = normalize_email(payload.email)
    if not email:
        raise AppError("Bitte E-Mail eingeben.")
    throttling.enforce_limit(request, "forgot-mail", config.FORGOT_LIMIT_PER_EMAIL, subject=email)

    if db.query(User).filter_by(email=email).first() is None:
        return JSONResponse(GENERIC_MESSAGE)

    code, sent = email_otp.deliver(db, email, "reset")

    # SMTP ist konfiguriert, der Versand ist aber fehlgeschlagen: kein Code in
    # der Antwort (sonst könnte ihn jeder über /api/forgot-password abholen).
    if config.smtp_is_configured() and not sent:
        raise AppError("E-Mail konnte nicht gesendet werden.", status_code=500)

    # Nur im Dev-Modus wird der Code mitgegeben, damit der Reset ohne Mailserver
    # demonstrierbar bleibt.
    if not sent:
        return JSONResponse(
            {
                "message": f"Kein SMTP-Server konfiguriert (Dev-Modus) – dein Reset-Code lautet: {code}",
                "dev_code": code,
                "dev_mode": True,
            }
        )
    return JSONResponse(GENERIC_MESSAGE)


@router.post("/reset-password")
def reset_password(request: Request, payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    throttling.enforce_limit(request, "reset-ip", config.VERIFY_LIMIT_PER_IP)

    email = normalize_email(payload.email)
    code = payload.code.strip()
    new_password = payload.new_password

    if not email or not code or not new_password:
        raise AppError("Alle Felder müssen ausgefüllt sein.")
    if message := password_error(new_password):
        raise AppError(message)

    user = db.query(User).filter_by(email=email).first()
    if user is None:
        raise AppError("Ungültiger oder abgelaufener Reset-Code.")

    email_otp.check_code(db, email, "reset", code)

    user.password = hash_password(new_password)
    # Alle bestehenden Sessions beenden - wer das Passwort zurücksetzt, will
    # typischerweise auch, dass niemand sonst mit einer alten Session drin ist.
    db.query(SessionToken).filter_by(user_id=user.id).delete()
    db.commit()

    return JSONResponse({"message": "Passwort erfolgreich geändert! Du kannst dich jetzt anmelden."})
