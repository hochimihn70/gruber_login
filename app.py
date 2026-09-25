import io                                                                                      # Fuer Byte-Puffer (QR-Code-Erzeugung)
import os                                                                                      # Zugriff auf Umgebungsvariablen (DATABASE_URL, SMTP_*)
import secrets                                                                                 # Fuer kryptografisch sichere Tokens und Zufallscodes
import smtplib                                                                                 # Fuer E-Mail-Versand ueber SMTP
from datetime import datetime, timedelta                                                       # Fuer Datum, Uhrzeit und Zeitdifferenzen
from email.mime.multipart import MIMEMultipart                                                 # Fuer E-Mails mit Text und HTML
from email.mime.text import MIMEText                                                           # Fuer E-Mail-Inhalt

import bcrypt                                                                                  # Zum Hashen und Pruefen auf Serverseite
from fastapi import FastAPI, Request                                                           # FastAPI-Kern
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse                     # HTTP-Antworten
from fastapi.staticfiles import StaticFiles                                                    # Fuer CSS und JS
import pyotp                                                                                   # Fuer TOTP Authenticator (RFC 6238)
import qrcode                                                                                  # Fuer QR-Codes
import qrcode.image.svg                                                                        # SVG-Generator (benoetigt kein Pillow)
from sqlalchemy import DateTime, Integer, String, create_engine                                 # SQLAlchemy Spaltentypen
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column                     # SQLAlchemy ORM


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
engine = create_engine(os.environ["DATABASE_URL"])


class Base(DeclarativeBase):
    pass


class User(Base):                                                                              # Tabelle "users"
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password: Mapped[str] = mapped_column(String(255))                                         # bcrypt-Hash des clientseitigen SHA-256
    auth_method: Mapped[str] = mapped_column(String(20), default="password")                   # "password", "email_otp" oder "totp"
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)                # Base32 Secret fuer Authenticator-Apps
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)            # Letzter Login (fuer Analysen/Zeitpruefung)


class SessionToken(Base):                                                                      # Tabelle "sessions"
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


class EmailOTP(Base):                                                                          # Tabelle "email_otps"
    __tablename__ = "email_otps"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    code: Mapped[str] = mapped_column(String(6))
    purpose: Mapped[str] = mapped_column(String(20), default="2fa")                            # "2fa" oder "reset"
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


Base.metadata.create_all(engine)                                                               # Tabellen anlegen falls neu

# Automatische Spalten-Pruefung fuer bestehende Datenbanken (Migration)
with engine.connect() as conn:
    try:
        cols = [r[0] for r in conn.exec_driver_sql("SHOW COLUMNS FROM users").fetchall()]
        if "auth_method" not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN auth_method VARCHAR(20) DEFAULT 'password'")
        if "totp_secret" not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) NULL")
        
        otp_cols = [r[0] for r in conn.exec_driver_sql("SHOW COLUMNS FROM email_otps").fetchall()]
        if "purpose" not in otp_cols:
            conn.exec_driver_sql("ALTER TABLE email_otps ADD COLUMN purpose VARCHAR(20) DEFAULT '2fa'")
        conn.commit()
    except Exception as e:
        pass


# Zeitliche Beschraenkung (optional konfigurierbar via .env fuer Demonstrationszwecke)
LOGIN_RESTRICTION_ENABLED = os.environ.get("LOGIN_RESTRICTION_ENABLED", "false").lower() == "true"
LOGIN_ALLOWED_START_HOUR = int(os.environ.get("LOGIN_ALLOWED_START_HOUR", "6"))
LOGIN_ALLOWED_END_HOUR = int(os.environ.get("LOGIN_ALLOWED_END_HOUR", "22"))

def is_login_allowed_now() -> tuple[bool, str]:                                                # Zeitliche Beschraenkung pruefen
    if not LOGIN_RESTRICTION_ENABLED:
        return True, ""
    current_hour = datetime.now().hour
    if not (LOGIN_ALLOWED_START_HOUR <= current_hour < LOGIN_ALLOWED_END_HOUR):
        return False, f"Login ist zu dieser Uhrzeit gesperrt. Erlaubt: {LOGIN_ALLOWED_START_HOUR:02d}:00 bis {LOGIN_ALLOWED_END_HOUR:02d}:00 Uhr."
    return True, ""


def generate_totp_qr_svg(email: str, secret: str) -> str:                                     # Erzeugt einen SVG-QR-Code
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="Gruber Login")
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(uri, image_factory=factory)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def send_otp_email(to_email: str, otp_code: str, purpose: str = "2fa"):                       # Versendet E-Mails via SMTP
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    smtp_from = os.environ.get("SMTP_FROM", smtp_user or "noreply@smoothingo.com").strip()

    title = "Dein Verifizierungscode" if purpose == "2fa" else "Passwort zurücksetzen"

    if not smtp_host:                                                                          # Fallback fuer Entwicklung ohne SMTP
        print(f"\n=======================================================", flush=True)
        print(f"[{title.upper()}] für {to_email}: >>> {otp_code} <<<", flush=True)
        print(f"=======================================================\n", flush=True)
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{title}: {otp_code}"
    msg["From"] = smtp_from
    msg["To"] = to_email

    text_content = f"Hallo!\n\nDein Code lautet: {otp_code}\nEr ist 10 Minuten gueltig.\n"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
      <h2 style="color: #333;">{title}</h2>
      <p>Gib den folgenden 6-stelligen Code ein:</p>
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


@app.get("/")
def show_login_page():
    return FileResponse("templates/index.html")


@app.get("/welcome")                                                                           # Geschuetzte Willkommensseite
def show_welcome_page(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return RedirectResponse(url="/", status_code=303)

    session = Session(engine)
    now = datetime.now()
    valid_session = session.query(SessionToken).filter(
        SessionToken.token == token,
        SessionToken.expires_at > now
    ).first()
    session.close()

    if not valid_session:
        response = RedirectResponse(url="/", status_code=303)
        response.delete_cookie("session_token")
        return response

    return FileResponse("templates/welcome.html")


@app.get("/api/me")                                                                            # Liefert Benutzerdaten fuer /welcome
async def get_current_user(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return JSONResponse({"error": "Nicht eingeloggt."}, status_code=401)

    session = Session(engine)
    now = datetime.now()
    st = session.query(SessionToken).filter(SessionToken.token == token, SessionToken.expires_at > now).first()
    if not st:
        session.close()
        return JSONResponse({"error": "Session ungültig."}, status_code=401)

    user = session.query(User).filter_by(id=st.user_id).first()
    session.close()

    if not user:
        return JSONResponse({"error": "Benutzer nicht gefunden."}, status_code=404)

    return {
        "email": user.email,
        "auth_method": user.auth_method,
        "last_login_at": user.last_login_at.strftime("%d.%m.%Y %H:%M:%S") if user.last_login_at else "Erstmalig",
        "created_at": user.created_at.strftime("%d.%m.%Y %H:%M:%S")
    }


@app.post("/api/register")                                                                     # Registrieren mit Auswahl der Auth-Methode
async def register(request: Request):
    data = await request.json()
    email = data.get("email", "").strip().lower()
    password_hash = data.get("password_hash", "")                                              # Clientseitig mit SHA-256 gehasht
    auth_method = data.get("auth_method", "password").strip().lower()

    if not email or not password_hash:
        return JSONResponse({"error": "E-Mail und Passwort fehlen."}, status_code=400)

    if auth_method not in ("password", "email_otp", "totp"):
        auth_method = "password"

    session = Session(engine)
    existing_user = session.query(User).filter_by(email=email).first()
    if existing_user is not None:
        session.close()
        return JSONResponse({"error": "E-Mail ist bereits registriert."}, status_code=409)

    salt = bcrypt.gensalt()
    server_hash = bcrypt.hashpw(password_hash.encode(), salt).decode()

    totp_secret = None
    qr_svg = None
    if auth_method == "totp":
        totp_secret = pyotp.random_base32()
        qr_svg = generate_totp_qr_svg(email, totp_secret)

    new_user = User(
        email=email,
        password=server_hash,
        auth_method=auth_method,
        totp_secret=totp_secret,
        created_at=datetime.now()
    )
    session.add(new_user)
    session.commit()
    session.close()

    return JSONResponse({
        "message": "Registrierung erfolgreich!",
        "auth_method": auth_method,
        "totp_secret": totp_secret,
        "qr_svg": qr_svg
    }, status_code=201)


@app.post("/api/login")                                                                        # Login (Schritt 1)
async def login(request: Request):
    allowed, reason = is_login_allowed_now()
    if not allowed:
        return JSONResponse({"error": reason}, status_code=403)

    data = await request.json()
    email = data.get("email", "").strip().lower()
    password_hash = data.get("password_hash", "")

    session = Session(engine)
    user = session.query(User).filter_by(email=email).first()
    if user is None:
        session.close()
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)

    if not bcrypt.checkpw(password_hash.encode(), user.password.encode()):
        session.close()
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)

    now = datetime.now()

    # Variante 1: Nur Passwort -> direkt anmelden
    if user.auth_method == "password":
        user.last_login_at = now
        token = secrets.token_hex(32)
        session_token = SessionToken(token=token, user_id=user.id, created_at=now, expires_at=now + timedelta(days=7))
        session.add(session_token)
        session.commit()
        session.close()

        response = JSONResponse({"status": "success", "redirect": "/welcome"}, status_code=200)
        response.set_cookie(key="session_token", value=token, max_age=7*24*3600, httponly=True, samesite="lax", secure=False)
        return response

    # Variante 2: E-Mail-Code (2FA)
    elif user.auth_method == "email_otp":
        otp_code = f"{secrets.randbelow(900000) + 100000}"
        expires_at = now + timedelta(minutes=10)
        session.query(EmailOTP).filter_by(email=email, purpose="2fa").delete()
        new_otp = EmailOTP(email=email, code=otp_code, purpose="2fa", created_at=now, expires_at=expires_at)
        session.add(new_otp)
        session.commit()
        session.close()

        try:
            send_otp_email(email, otp_code, "2fa")
        except Exception as e:
            print(f"Mail-Fehler: {e}", flush=True)
            return JSONResponse({"error": "E-Mail konnte nicht gesendet werden."}, status_code=500)

        return JSONResponse({
            "status": "2fa_required",
            "method": "email_otp",
            "email": email,
            "message": f"6-stelliger Bestätigungscode an {email} gesendet."
        }, status_code=200)

    # Variante 3: Authenticator-App (TOTP)
    elif user.auth_method == "totp":
        session.close()
        return JSONResponse({
            "status": "2fa_required",
            "method": "totp",
            "email": email,
            "message": "Gib den 6-stelligen Code aus deiner Authenticator-App ein."
        }, status_code=200)


@app.post("/api/verify-2fa")                                                                   # Login (Schritt 2: 2FA-Code pruefen)
async def verify_2fa(request: Request):
    allowed, reason = is_login_allowed_now()
    if not allowed:
        return JSONResponse({"error": reason}, status_code=403)

    data = await request.json()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()

    if not email or not code:
        return JSONResponse({"error": "E-Mail und Code erforderlich."}, status_code=400)

    session = Session(engine)
    user = session.query(User).filter_by(email=email).first()
    if not user:
        session.close()
        return JSONResponse({"error": "Benutzer nicht gefunden."}, status_code=404)

    now = datetime.now()

    if user.auth_method == "email_otp":
        otp = session.query(EmailOTP).filter(
            EmailOTP.email == email,
            EmailOTP.code == code,
            EmailOTP.purpose == "2fa",
            EmailOTP.expires_at > now
        ).first()
        if not otp:
            session.close()
            return JSONResponse({"error": "Ungültiger oder abgelaufener E-Mail-Code."}, status_code=400)
        session.query(EmailOTP).filter_by(email=email, purpose="2fa").delete()

    elif user.auth_method == "totp":
        if not user.totp_secret:
            session.close()
            return JSONResponse({"error": "TOTP nicht eingerichtet."}, status_code=400)
        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(code, valid_window=1):                                              # Toleriert kleine Zeitabweichungen (+/- 30s)
            session.close()
            return JSONResponse({"error": "Falscher Authenticator-Code."}, status_code=400)

    # 2FA erfolgreich -> Session setzen
    user.last_login_at = now
    token = secrets.token_hex(32)
    new_session = SessionToken(token=token, user_id=user.id, created_at=now, expires_at=now + timedelta(days=7))
    session.add(new_session)
    session.commit()
    session.close()

    response = JSONResponse({"message": "Login erfolgreich.", "redirect": "/welcome"}, status_code=200)
    response.set_cookie(key="session_token", value=token, max_age=7*24*3600, httponly=True, samesite="lax", secure=False)
    return response


@app.post("/api/forgot-password")                                                              # Bonus: Passwort-Reset anfordern
async def forgot_password(request: Request):
    data = await request.json()
    email = data.get("email", "").strip().lower()
    if not email:
        return JSONResponse({"error": "Bitte E-Mail eingeben."}, status_code=400)

    session = Session(engine)
    user = session.query(User).filter_by(email=email).first()
    if not user:
        session.close()
        return JSONResponse({"message": "Falls die E-Mail registriert ist, wurde ein Reset-Code gesendet."}, status_code=200)

    code = f"{secrets.randbelow(900000) + 100000}"
    now = datetime.now()
    session.query(EmailOTP).filter_by(email=email, purpose="reset").delete()
    new_otp = EmailOTP(email=email, code=code, purpose="reset", created_at=now, expires_at=now + timedelta(minutes=15))
    session.add(new_otp)
    session.commit()
    session.close()

    try:
        send_otp_email(email, code, "reset")
    except Exception as e:
        print(f"Mail-Fehler: {e}", flush=True)

    return JSONResponse({"message": "Falls die E-Mail registriert ist, wurde ein Reset-Code gesendet."}, status_code=200)


@app.post("/api/reset-password")                                                               # Bonus: Neues Passwort mit Reset-Code setzen
async def reset_password(request: Request):
    data = await request.json()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()
    new_password_hash = data.get("new_password_hash", "")

    if not email or not code or not new_password_hash:
        return JSONResponse({"error": "Alle Felder müssen ausgefüllt sein."}, status_code=400)

    session = Session(engine)
    now = datetime.now()
    otp = session.query(EmailOTP).filter(
        EmailOTP.email == email,
        EmailOTP.code == code,
        EmailOTP.purpose == "reset",
        EmailOTP.expires_at > now
    ).first()

    if not otp:
        session.close()
        return JSONResponse({"error": "Ungültiger oder abgelaufener Reset-Code."}, status_code=400)

    user = session.query(User).filter_by(email=email).first()
    if not user:
        session.close()
        return JSONResponse({"error": "Benutzer nicht gefunden."}, status_code=404)

    salt = bcrypt.gensalt()
    user.password = bcrypt.hashpw(new_password_hash.encode(), salt).decode()
    session.query(EmailOTP).filter_by(email=email, purpose="reset").delete()
    session.commit()
    session.close()

    return JSONResponse({"message": "Passwort erfolgreich geändert! Du kannst dich jetzt anmelden."}, status_code=200)


@app.post("/api/logout")                                                                       # Abmelden
async def logout(request: Request):
    token = request.cookies.get("session_token")
    if token:
        session = Session(engine)
        session.query(SessionToken).filter_by(token=token).delete()
        session.commit()
        session.close()

    response = JSONResponse({"message": "Erfolgreich abgemeldet.", "redirect": "/"}, status_code=200)
    response.delete_cookie("session_token")
    return response
