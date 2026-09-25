import os                                                                                      # Zugriff auf Umgebungsvariablen (DATABASE_URL, SMTP_*)
import secrets                                                                                 # Fuer kryptografisch sichere Tokens und Codes
import smtplib                                                                                 # Fuer den E-Mail-Versand ueber SMTP
from datetime import datetime, timedelta                                                       # Fuer Ablaufzeiten und Datum
from email.mime.multipart import MIMEMultipart                                                 # Fuer E-Mails mit HTML und Text
from email.mime.text import MIMEText                                                           # Fuer E-Mail-Inhalte

import bcrypt                                                                                  # Zum Hashen und Pruefen von Passwoertern
from fastapi import FastAPI, Request                                                           # FastAPI-App und die eingehende Anfrage
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse                     # Antworten: Datei, JSON oder Weiterleitung
from fastapi.staticfiles import StaticFiles                                                    # Liefert CSS- und JS-Dateien aus
from sqlalchemy import DateTime, Integer, String, create_engine                                 # Spaltentypen und Datenbank-Verbindung
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column                     # Werkzeuge fuer Tabellen-Klassen


app = FastAPI()                                                                                # Die Web-App erstellen
app.mount("/static", StaticFiles(directory="static"), name="static")                           # Ordner "static" unter /static erreichbar machen
engine = create_engine(os.environ["DATABASE_URL"])                                             # Verbindung zu MySQL mit der Adresse aus docker-compose


class Base(DeclarativeBase):                                                                   # Grundklasse fuer alle Tabellen
    pass                                                                                       # Braucht keinen eigenen Inhalt


class User(Base):                                                                              # Diese Klasse beschreibt die Tabelle "users"
    __tablename__ = "users"                                                                    # Name der Tabelle in MySQL

    id: Mapped[int] = mapped_column(primary_key=True)                                          # Eindeutige ID, zaehlt automatisch hoch
    email: Mapped[str] = mapped_column(String(320), unique=True)                               # E-Mail, darf nur einmal vorkommen
    password: Mapped[str] = mapped_column(String(255))                                         # Nur der bcrypt-Hash, nie das echte Passwort
    created_at: Mapped[datetime] = mapped_column(DateTime)                                     # Wann der Benutzer registriert wurde
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)            # Letzter Login, leer wenn noch nie


class SessionToken(Base):                                                                      # Speichert gueltige Login-Sitzungen
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)                    # 64-Zeichen Zufallsschluessel
    user_id: Mapped[int] = mapped_column(Integer)                                              # Benutzer-ID
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)                                     # Ablaufdatum der Session (z.B. 7 Tage)


class EmailOTP(Base):                                                                          # Speichert temporaere 2FA-Einmalcodes
    __tablename__ = "email_otps"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)                                # E-Mail-Adresse
    code: Mapped[str] = mapped_column(String(6))                                                # 6-stelliger Zahlencode
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)                                     # Ablaufzeitpunkt (10 Minuten)


Base.metadata.create_all(engine)                                                               # Tabellen anlegen, falls sie noch nicht existieren


def send_otp_email(to_email: str, otp_code: str):                                              # Versendet den 2FA-Code per E-Mail
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    smtp_from = os.environ.get("SMTP_FROM", smtp_user or "noreply@smoothingo.com").strip()

    if not smtp_host:                                                                          # Fallback fuer Entwicklung: Code in den Logs ausgeben
        print(f"\n=======================================================", flush=True)
        print(f"[2FA-DEV-MODE] Verifizierungscode für {to_email}: >>> {otp_code} <<<", flush=True)
        print(f"=======================================================\n", flush=True)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Dein Verifizierungscode: {otp_code}"
    msg["From"] = smtp_from
    msg["To"] = to_email

    text_content = f"Hallo!\n\nDein Bestätigungscode lautet: {otp_code}\nDer Code ist 10 Minuten gültig.\n"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
      <h2 style="color: #333;">Zwei-Faktor-Verifizierung</h2>
      <p>Gib den folgenden 6-stelligen Code ein, um deinen Login abzuschließen:</p>
      <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #2563eb; background: #f0f4ff; padding: 15px; text-align: center; border-radius: 6px; margin: 20px 0;">
        {otp_code}
      </div>
      <p style="color: #666; font-size: 14px;">Dieser Code ist 10 Minuten lang gültig.</p>
    </div>
    """
    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as server:
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [to_email], msg.as_string())
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [to_email], msg.as_string())


@app.get("/")                                                                                  # Startseite mit Login- und Registrierungsformular
def show_login_page():
    return FileResponse("templates/index.html")


@app.get("/welcome")                                                                           # Geschuetzte Willkommensseite
def show_welcome_page(request: Request):
    token = request.cookies.get("session_token")                                               # Cookie auslesen
    if not token:                                                                              # Wenn kein Cookie existiert -> sofort zum Login
        return RedirectResponse(url="/", status_code=303)

    session = Session(engine)
    now = datetime.now()
    valid_session = session.query(SessionToken).filter(                                        # Pruefen, ob die Session gueltig ist
        SessionToken.token == token,
        SessionToken.expires_at > now
    ).first()
    session.close()

    if not valid_session:                                                                      # Ungueltig oder abgelaufen
        response = RedirectResponse(url="/", status_code=303)
        response.delete_cookie("session_token")
        return response

    return FileResponse("templates/welcome.html")                                              # Zugriff erlaubt!


@app.post("/api/register")                                                                     # Registrieren
async def register(request: Request):
    data = await request.json()
    email = data["email"].strip().lower()
    password = data["password"]

    if email == "" or password == "":
        return JSONResponse({"error": "E-Mail und Passwort fehlen."}, status_code=400)

    session = Session(engine)
    existing_user = session.query(User).filter_by(email=email).first()
    if existing_user is not None:
        session.close()
        return JSONResponse({"error": "E-Mail ist bereits registriert."}, status_code=409)

    password_bytes = password.encode()
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(password_bytes, salt).decode()

    new_user = User()
    new_user.email = email
    new_user.password = password_hash
    new_user.created_at = datetime.now()

    session.add(new_user)
    session.commit()
    session.close()

    return JSONResponse({"message": "Registrierung erfolgreich. Du kannst dich jetzt einloggen."}, status_code=201)


@app.post("/api/login")                                                                        # Schritt 1 des Logins: Passwort pruefen & 2FA-Code senden
async def login(request: Request):
    data = await request.json()
    email = data["email"].strip().lower()
    password = data["password"]

    session = Session(engine)
    user = session.query(User).filter_by(email=email).first()
    if user is None:
        session.close()
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)

    password_bytes = password.encode()
    saved_hash_bytes = user.password.encode()
    password_is_correct = bcrypt.checkpw(password_bytes, saved_hash_bytes)

    if password_is_correct == False:
        session.close()
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)

    # Passwort ist korrekt -> 6-stelligen OTP erzeugen und speichern
    otp_code = f"{secrets.randbelow(900000) + 100000}"
    expires_at = datetime.now() + timedelta(minutes=10)

    session.query(EmailOTP).filter_by(email=email).delete()                                     # Alte Codes loeschen
    new_otp = EmailOTP(email=email, code=otp_code, created_at=datetime.now(), expires_at=expires_at)
    session.add(new_otp)
    session.commit()
    session.close()

    try:
        send_otp_email(email, otp_code)
    except Exception as e:
        print(f"Fehler beim Mailversand: {e}", flush=True)
        return JSONResponse({"error": "E-Mail-Zustellung fehlgeschlagen. Bitte versuche es später."}, status_code=500)

    return JSONResponse({
        "status": "2fa_required",
        "email": email,
        "message": f"Bestätigungscode an {email} gesendet."
    }, status_code=200)


@app.post("/api/verify-2fa")                                                                   # Schritt 2 des Logins: 2FA-Code pruefen & Session erstellen
async def verify_2fa(request: Request):
    data = await request.json()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()

    if email == "" or code == "":
        return JSONResponse({"error": "E-Mail und Code erforderlich."}, status_code=400)

    session = Session(engine)
    now = datetime.now()
    otp_entry = session.query(EmailOTP).filter(
        EmailOTP.email == email,
        EmailOTP.code == code,
        EmailOTP.expires_at > now
    ).first()

    if not otp_entry:
        session.close()
        return JSONResponse({"error": "Ungültiger oder abgelaufener Bestätigungscode."}, status_code=400)

    # Code ist gueltig -> OTP loeschen
    session.query(EmailOTP).filter_by(email=email).delete()

    user = session.query(User).filter_by(email=email).first()
    user_id = user.id if user else 0
    if user:
        user.last_login_at = now

    # Neue sichere Session anlegen (7 Tage gueltig)
    token = secrets.token_hex(32)
    session_expires = now + timedelta(days=7)
    new_session = SessionToken(token=token, user_id=user_id, created_at=now, expires_at=session_expires)
    session.add(new_session)
    session.commit()
    session.close()

    # Antwort mit HttpOnly-Cookie zurueckgeben
    response = JSONResponse({"message": "Login erfolgreich.", "redirect": "/welcome"}, status_code=200)
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=7 * 24 * 3600,
        httponly=True,
        samesite="lax",
        secure=False
    )
    return response


@app.post("/api/logout")                                                                       # Logout: Session ungueltig machen
async def logout(request: Request):
    token = request.cookies.get("session_token")
    if token:
        session = Session(engine)
        session.query(SessionToken).filter_by(token=token).delete()
        session.commit()
        session.close()

    response = JSONResponse({"message": "Abmeldung erfolgreich.", "redirect": "/"}, status_code=200)
    response.delete_cookie("session_token")
    return response
