import base64                                                                                 # Für die Base64-Kodierung des Verschlüsselungsschlüssels
import hashlib                                                                                 # Für SHA-256 (Session-Token in der DB hashen, Schlüssel ableiten)
import hmac                                                                                    # Für HMAC (2FA-Code signieren statt im Klartext zu speichern)
import io                                                                                      # Für Byte-Puffer (QR-Code-Erzeugung)
import os                                                                                      # Zugriff auf Umgebungsvariablen (DATABASE_URL, SMTP_*)
import re                                                                                      # Für die E-Mail-Formatprüfung
import secrets                                                                                 # Für kryptografisch sichere Tokens und Zufallscodes
import smtplib                                                                                 # Für E-Mail-Versand über SMTP
from datetime import datetime, timedelta                                                       # Für Datum, Uhrzeit und Zeitdifferenzen
from email.mime.multipart import MIMEMultipart                                                 # Für E-Mails mit Text und HTML
from email.mime.text import MIMEText                                                           # Für E-Mail-Inhalt

from argon2 import PasswordHasher                                                                 # Argon2id: heutiger Standard für Passwort-Hashing
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError           # Fehler beim Prüfen eines Hashes
from cryptography.fernet import Fernet, InvalidToken                                             # Verschlüsselung für das TOTP-Secret
from fastapi import FastAPI, Request                                                           # FastAPI-Kern
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse                     # HTTP-Antworten
from fastapi.staticfiles import StaticFiles                                                    # Für CSS und JS
import pyotp                                                                                   # Für TOTP Authenticator (RFC 6238)
import qrcode                                                                                  # Für QR-Codes
import qrcode.image.svg                                                                        # SVG-Generator (benötigt kein Pillow)
from sqlalchemy import DateTime, Integer, String, create_engine, text                         # SQLAlchemy Spaltentypen
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column                     # SQLAlchemy ORM


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
engine = create_engine(os.environ["DATABASE_URL"])


@app.middleware("http")                                                                          # Standard-Sicherheits-Header
async def security_headers(request: Request, call_next):
    """Sendet bei jeder Antwort ein paar Standard-Sicherheits-Header mit.

    - X-Frame-Options:      Seite darf nicht in einem fremden <iframe> eingebettet werden (Clickjacking)
    - X-Content-Type-Options: Browser soll den Inhalt nicht sniffen
    - Referrer-Policy:     keine fremden URLs an Dritte weitergeben
    - Content-Security-Policy:  nur eigene Scripts/Styles laden, kein Inline-JavaScript

    Hinweis zu Cloudflare: Der Tunnel injiziert ein eigenes kleines Script in die
    HTML-Ausgabe (Bot-Erkennung, /cdn-cgi/challenge-platform/). Die strikte CSP
    blockiert es - die App selbst läuft davon nicht betroffen. Sollte es doch
    nötig werden, "script-src 'self' 'unsafe-inline'" verwenden.
    """
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'"
    )
    # HTML immer neu validieren lassen. Ohne diese Angabe nutzt der Browser eine
    # gecachte Kopie (Heuristic Caching) - und lädt dann eine alte app.js-Version.
    if "text/html" in response.headers.get("content-type", ""):
        response.headers["Cache-Control"] = "no-cache"
    return response


class Base(DeclarativeBase):
    pass


class User(Base):                                                                              # Tabelle "users"
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    password: Mapped[str] = mapped_column(String(255))                                         # Argon2id-Hash (inkl. Zufalls-Salt)
    auth_method: Mapped[str] = mapped_column(String(20), default="password")                   # "password", "email_otp" oder "totp"
    totp_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)               # Verschlüsseltes TOTP-Secret (Base32)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)            # Letzter Login (für Analysen/Zeitprüfung)


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
    code: Mapped[str] = mapped_column(String(64))                                            # HMAC-Signatur des Codes (nicht der Code selbst)
    purpose: Mapped[str] = mapped_column(String(20), default="2fa")                            # "2fa" oder "reset"
    attempts: Mapped[int] = mapped_column(Integer, default=0)                                 # Fehlversuche (Brute-Force-Bremse)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    expires_at: Mapped[datetime] = mapped_column(DateTime)


Base.metadata.create_all(engine)                                                               # Tabellen anlegen falls neu

# Automatische Spalten-Prüfung für bestehende Datenbanken (Migration)
with engine.connect() as conn:
    try:
        cols = [r[0] for r in conn.exec_driver_sql("SHOW COLUMNS FROM users").fetchall()]
        if "auth_method" not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN auth_method VARCHAR(20) DEFAULT 'password'")
        if "totp_secret" not in cols:
            conn.exec_driver_sql("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(255) NULL")
        else:
            # breiter machen: das TOTP-Secret wird jetzt verschlüsselt gespeichert
            conn.exec_driver_sql("ALTER TABLE users MODIFY COLUMN totp_secret VARCHAR(255) NULL")

        otp_cols = [r[0] for r in conn.exec_driver_sql("SHOW COLUMNS FROM email_otps").fetchall()]
        if "purpose" not in otp_cols:
            conn.exec_driver_sql("ALTER TABLE email_otps ADD COLUMN purpose VARCHAR(20) DEFAULT '2fa'")
        if "attempts" not in otp_cols:
            conn.exec_driver_sql("ALTER TABLE email_otps ADD COLUMN attempts INT DEFAULT 0")
        # breiter machen: statt des 6-stelligen Codes steht jetzt eine 64-stellige HMAC-Signatur
        conn.exec_driver_sql("ALTER TABLE email_otps MODIFY COLUMN code VARCHAR(64)")
        conn.commit()
    except Exception as e:
        pass


# ------------------------------------------------------------------------------------------
# Server-Geheimnis (APP_SECRET)
#
# Wird für zwei Dinge gebraucht:
#   1. HMAC über die 2FA-Codes  -> in der DB steht keine gültige Code-Ziffernfolge mehr
#   2. Verschlüsselung des TOTP-Secrets -> in der DB steht kein lesbares Secret mehr
#
# Wichtig: Das Geheimnis muss stabil sein, sonst lässt sich das TOTP-Secret nach einem
# Neustart nicht mehr entschlüsseln. Deshalb kommt es aus der .env.
# ------------------------------------------------------------------------------------------
def app_secret() -> bytes:
    """Liefert das Server-Geheimnis. Fehlt es, wird einmalig ein zufälliges erzeugt -
    dann überleben aber die TOTP-Secrets keinen Container-Neustart."""
    global _APP_SECRET
    if _APP_SECRET is None:
        configured = os.environ.get("APP_SECRET", "").strip()
        if configured:
            _APP_SECRET = configured.encode()
        else:
            _APP_SECRET = secrets.token_bytes(32)
            print("[SECRET] WARNUNG: Kein APP_SECRET in der .env gesetzt - es wurde ein "
                  "zufälliges Geheimnis erzeugt.\n"
                  "         Nach einem Neustart des Containers können vorhandene TOTP-Secrets "
                  "nicht mehr entschlüsselt werden.\n"
                  "         In der .env eintragen: APP_SECRET=<eigener Wert>", flush=True)
    return _APP_SECRET


_APP_SECRET: bytes | None = None


def hmac_code(email: str, purpose: str, code: str) -> str:
    """Signiert einen 2FA-Code mit HMAC-SHA256.

    In der Datenbank steht damit NICHT mehr der Code selbst, sondern nur diese
    Signatur. Ein DB-Dump zeigt damit keinen gültigen Bestätigungscode mehr.
    Für die Prüfung wird aus der eingegebenen Ziffernfolge dieselbe Signatur
    berechnet und verglichen.
    """
    message = f"{email}|{purpose}|{code}".encode()
    return hmac.new(app_secret(), message, hashlib.sha256).hexdigest()


def _fernet() -> Fernet:
    """Verschlüsselungsschlüssel aus dem Server-Geheimnis ableiten (Fernet erwartet 32 Byte)."""
    key = base64.urlsafe_b64encode(hashlib.sha256(app_secret()).digest())
    return Fernet(key)


def encrypt_secret(plaintext: str) -> str:
    """Verschlüsselt einen Wert (z. B. das TOTP-Secret) für die Datenbank."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str | None:
    """Entschlüsselt einen Wert. Bei falschem Schlüssel oder kaputten Daten -> None."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, ValueError):
        return None


# Nachrüsten: alte Klartext-Secrets verschlüsseln und alte Klartext-Codes entfernen.
# (Nur nötig beim Umstieg von einer älteren Version - für neue Installationen ein No-op.)
try:
    with engine.connect() as conn:
        rows = conn.exec_driver_sql("SELECT id, totp_secret FROM users WHERE totp_secret IS NOT NULL;").fetchall()
        for row in rows:
            if not str(row[1]).startswith("gAAAA"):        # kein Fernet-Token -> noch im Klartext
                conn.exec_driver_sql("UPDATE users SET totp_secret = ? WHERE id = ?",
                                     (encrypt_secret(str(row[1])), row[0]))
        # alte Codes im Klartext sind jetzt unbrauchbar (Prüfung läuft über HMAC) -> weg damit
        conn.exec_driver_sql("DELETE FROM email_otps WHERE LENGTH(code) <= 10;")
        conn.commit()
except Exception:
    pass


# Zeitliche Beschränkung (optional konfigurierbar via .env für Demonstrationszwecke)
LOGIN_RESTRICTION_ENABLED = os.environ.get("LOGIN_RESTRICTION_ENABLED", "false").lower() == "true"
LOGIN_ALLOWED_START_HOUR = int(os.environ.get("LOGIN_ALLOWED_START_HOUR", "6"))
LOGIN_ALLOWED_END_HOUR = int(os.environ.get("LOGIN_ALLOWED_END_HOUR", "22"))

def is_login_allowed_now() -> tuple[bool, str]:                                                # Zeitliche Beschränkung prüfen
    if not LOGIN_RESTRICTION_ENABLED:
        return True, ""
    current_hour = datetime.now().hour
    if not (LOGIN_ALLOWED_START_HOUR <= current_hour < LOGIN_ALLOWED_END_HOUR):
        return False, f"Login ist zu dieser Uhrzeit gesperrt. Erlaubt: {LOGIN_ALLOWED_START_HOUR:02d}:00 bis {LOGIN_ALLOWED_END_HOUR:02d}:00 Uhr."
    return True, ""


def session_cookie_secure() -> bool:                                                            # Session-Cookie nur über HTTPS senden?
    """Standard: ja. Über die .env abschaltbar (SESSION_COOKIE_SECURE=false) - nötig,
    wenn die App testweise über eine LAN-IP ohne HTTPS aufgerufen wird."""
    return os.environ.get("SESSION_COOKIE_SECURE", "true").strip().lower() in ("true", "1", "yes", "on")


EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")                                      # Einfache E-Mail-Prüfung
MAX_OTP_ATTEMPTS = 5                                                                            # Max. Fehlversuche für einen 2FA-Code


# ------------------------------------------------------------------------------------------
# Passwort-Hashing mit Argon2id
#
# Argon2id ist der heutige Standard (OWASP Password Storage Cheat Sheet) und läuft in drei
# Schritten: Argon2id ist speicherresistent (der Angreifer kann nicht einfach viele
# Hashes parallel berechnen) und bewusst langsam. Der zufaellige Salt steckt bereits
# im Hash-String, er muss also nicht separat gespeichert werden.
#
# Parameter nach OWASP: 46 MiB Speicher, 1 Durchlauf, 1 Thread -> ca. 50 ms pro Aufruf.
# ------------------------------------------------------------------------------------------
password_hasher = PasswordHasher(time_cost=1, memory_cost=47104, parallelism=1)
DUMMY_HASH = password_hasher.hash("dummy-password-for-timing")                                # Dummy-Hash für gleiche Antwortzeiten


def hash_password(password: str) -> str:                                                        # Passwort hashen
    """Hasht ein Passwort mit Argon2id. Das Ergebnis enthält den Zufalls-Salt bereits."""
    return password_hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:                                    # Passwort prüfen
    """Prüft ein Passwort gegen den gespeicherten Hash. Falsch -> False, kein Fehler."""
    try:
        return password_hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def is_valid_email(email: str) -> bool:                                                         # E-Mail-Format prüfen
    """Prüft das Format der E-Mail - auch serverseitig, nicht nur im Browser."""
    return bool(EMAIL_PATTERN.match(email))


def hash_token(token: str) -> str:                                                              # Session-Token für die DB hashen
    """In der Datenbank steht NICHT das Token selbst, sondern nur sein SHA-256-Hash.

    Warum das sicher ist: Das Token hat 256 Bit Zufall - ein SHA-256-Hash davon kann
    nicht zurückgerechnet werden. Ein DB-Leak reicht damit nicht mehr, um die
    Session zu übernehmen, weil der Angreifer den echten Cookie-Wert nicht kennt.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def start_session(user_id: int, payload: dict) -> JSONResponse:                                 # Session anlegen + Cookie setzen
    """Legt eine 7-Tage-Session an und hängt das Session-Cookie an die Antwort.

    Diese eine Funktion ersetzt dreifach kopierten Code - das Cookie kann so nur
    an EINER Stelle konfiguriert werden.
    """
    now = datetime.now()
    token = secrets.token_hex(32)                                                               # 256 Bit Zufall aus dem kryptografischen PRNG
    session = Session(engine)
    session.add(SessionToken(token=hash_token(token), user_id=user_id, created_at=now, expires_at=now + timedelta(days=7)))
    session.commit()
    session.close()

    response = JSONResponse(payload, status_code=200)
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=7 * 24 * 3600,                                                                   # 7 Tage
        httponly=True,                                                                          # JavaScript kann das Cookie nicht auslesen
        samesite="lax",                                                                         # schützt gegen CSRF
        secure=session_cookie_secure(),                                                         # nur über HTTPS senden
    )
    return response


def generate_totp_qr_svg(email: str, secret: str) -> str:                                     # Erzeugt einen SVG-QR-Code
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name="Gruber Login")
    factory = qrcode.image.svg.SvgPathImage
    img = qrcode.make(uri, image_factory=factory)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")


def smtp_config() -> dict:                                                                    # SMTP-Konfiguration aus der Umgebung
    """Liest die SMTP-Konfiguration aus der Umgebung.

    Quelle ist ausschließlich die .env-Datei (via docker-compose -> Container-ENV).
    Im Code ist bewusst NICHTS hart verdrahtet - alle Werte kommen von außen.
    """
    return {
        "host": os.environ.get("SMTP_HOST", "").strip(),
        "port": int(os.environ.get("SMTP_PORT", "587") or 587),
        "user": os.environ.get("SMTP_USER", "").strip(),
        "password": os.environ.get("SMTP_PASSWORD", "").strip(),
        "from": os.environ.get("SMTP_FROM", "").strip(),
    }


def smtp_missing_keys() -> list[str]:                                                         # Welche SMTP-Variablen fehlen noch?
    cfg = smtp_config()
    needed = [("SMTP_HOST", cfg["host"]), ("SMTP_PASSWORD", cfg["password"]), ("SMTP_FROM", cfg["from"])]
    return [key for key, value in needed if not value]


def smtp_is_configured() -> bool:                                                              # Ist der E-Mail-Versand einsatzbereit?
    """SMTP gilt erst als konfiguriert, wenn Host, Passwort UND Absender gesetzt sind.

    So läuft die App im Dev-Modus weiter, solange z. B. der API-Key noch fehlt -
    statt mit einem halb konfigurierten Server ins Zeitouts zu laufen.
    """
    return not smtp_missing_keys()


def send_otp_email(to_email: str, otp_code: str, purpose: str = "2fa") -> bool:                # Versendet E-Mails via SMTP
    """Schickt den Bestätigungscode per E-Mail.

    Rückgabe: True  = E-Mail erfolgreich verschickt
               False = nicht verschickt (kein SMTP konfiguriert ODER Versandfehler)
    """
    smtp_host = os.environ.get("SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587") or 587)
    smtp_user = os.environ.get("SMTP_USER", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    smtp_from = os.environ.get("SMTP_FROM", "").strip()

    title = "Dein Verifizierungscode" if purpose == "2fa" else "Passwort zurücksetzen"

    print(f"\n=======================================================", flush=True)
    print(f"[{title.upper()}] für {to_email}: >>> {otp_code} <<<", flush=True)
    print(f"=======================================================\n", flush=True)

    if not smtp_host:                                                                          # Dev-Modus: nur Log, keine E-Mail
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = title                                                                      # Code NICHT im Betreff (sonst im Sperrbildschirm sichtbar)
    msg["From"] = smtp_from
    msg["To"] = to_email

    text_content = f"Hallo!\n\nDein Code lautet: {otp_code}\nEr ist 10 Minuten gültig.\n"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
      <h2 style="color: #333;">{title}</h2>
      <p>Gib den folgenden 6-stelligen Code ein:</p>
      <div style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #111827; background: #f3f4f6; padding: 15px; text-align: center; border-radius: 6px; margin: 20px 0;">
        {otp_code}
      </div>
      <p style="color: #666; font-size: 14px;">Dieser Code ist 10 Minuten lang gültig.</p>
    </div>
    """
    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    try:
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
    except Exception as e:
        print(f"Mail-Fehler: {e}", flush=True)
        return False

    return True


# Status beim Start ausgeben - so sieht man sofort, ob der E-Mail-Versand wirklich aktiv ist
_cfg = smtp_config()
if smtp_is_configured():
    print(f"[SMTP] E-Mail-Versand: AKTIV (Host: {_cfg['host']}, Port: {_cfg['port']}, "
          f"User: {_cfg['user']}, From: {_cfg['from']})", flush=True)
else:
    print(f"[SMTP] E-Mail-Versand: DEAKTIVIERT -> Dev-Modus! "
          f"Fehlende Variablen in der .env: {', '.join(smtp_missing_keys())}", flush=True)
    print("       Die Codes stehen nur im Log und werden direkt im Browser angezeigt.", flush=True)


def otp_response(email: str, otp_code: str, sent: bool) -> dict:                              # Antwort für den 2FA-Schritt
    """Baut die Antwort, die nach dem Anfordern eines E-Mail-Codes zurückgegeben wird.

    Im Dev-Modus (kein SMTP-Server konfiguriert) wird der Code direkt mitgeschickt und
    im Browser angezeigt - so bleibt der Login auch ohne Mailserver demonstrierbar
    und die UI behauptet nicht fälschlich, es sei eine E-Mail verschickt worden.
    """
    if sent:
        message = f"Bestätigungscode wurde an {email} gesendet!"
    else:
        message = f"Kein SMTP-Server konfiguriert (Dev-Modus) – dein Bestätigungscode lautet: {otp_code}"
    response = {
        "status": "2fa_required",
        "method": "email_otp",
        "email": email,
        "message": message,
    }
    if not sent:
        response["dev_code"] = otp_code
        response["dev_mode"] = True
    return response


@app.get("/")
def show_login_page():
    return FileResponse("templates/index.html")


@app.get("/welcome")                                                                           # Geschützte Willkommensseite
def show_welcome_page(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return RedirectResponse(url="/", status_code=303)

    session = Session(engine)
    now = datetime.now()
    valid_session = session.query(SessionToken).filter(
        SessionToken.token == hash_token(token),
        SessionToken.expires_at > now
    ).first()
    session.close()

    if not valid_session:
        response = RedirectResponse(url="/", status_code=303)
        response.delete_cookie("session_token")
        return response

    return FileResponse("templates/welcome.html")


@app.get("/api/health")                                                                           # Systemstatus (Debug-Hilfe)
async def health():
    """Kurzer Status: Datenbank erreichbar? Ist der E-Mail-Versand konfiguriert?"""
    db_ok = True
    try:
        s = Session(engine)
        s.execute(text("SELECT 1"))
        s.close()
    except Exception:
        db_ok = False

    cfg = smtp_config()
    return {
        "status": "ok" if db_ok else "degraded",
        "database": "ok" if db_ok else "fehler",
        "smtp_configured": smtp_is_configured(),
        "smtp_host": cfg["host"],
        "smtp_port": cfg["port"],
        "smtp_from": cfg["from"],
        "smtp_missing": smtp_missing_keys(),
        "dev_mode": not smtp_is_configured(),
    }


@app.get("/api/me")                                                                            # Liefert Benutzerdaten für /welcome
async def get_current_user(request: Request):
    token = request.cookies.get("session_token")
    if not token:
        return JSONResponse({"error": "Nicht eingeloggt."}, status_code=401)

    session = Session(engine)
    now = datetime.now()
    st = session.query(SessionToken).filter(SessionToken.token == hash_token(token), SessionToken.expires_at > now).first()
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
    password = data.get("password", "")                                                        # Klartextpasswort (kommt verschlüsselt über HTTPS)
    auth_method = data.get("auth_method", "password").strip().lower()

    if not email or not password:
        return JSONResponse({"error": "E-Mail und Passwort fehlen."}, status_code=400)

    if not is_valid_email(email):
        return JSONResponse({"error": "Bitte eine gültige E-Mail-Adresse eingeben."}, status_code=400)

    if auth_method not in ("password", "email_otp", "totp"):
        auth_method = "password"

    session = Session(engine)
    existing_user = session.query(User).filter_by(email=email).first()

    # ------------------------------------------------------------------------------------------
    # SICHERHEITSREGEL: Ein bestehendes Konto darf NIEMALS ohne Passwort überschrieben werden.
    # Sonst könnte jeder, der eine fremde E-Mail-Adresse kennt, das Konto übernehmen.
    # Wer die E-Mail schon hat, muss also das aktuelle Passwort eingeben - dann wird das
    # Konto aktualisiert (z. B. um die Sicherheitsstufe zu ändern).
    # ------------------------------------------------------------------------------------------
    if existing_user is not None:
        if not verify_password(password, existing_user.password):
            session.close()
            return JSONResponse({
                "error": "Diese E-Mail ist bereits registriert und das Passwort stimmt nicht überein. "
                         "Bitte melde dich unten an oder setze dein Passwort zurück."
            }, status_code=401)

    server_hash = hash_password(password)

    totp_secret = None          # Klartext-Secret (nur für QR-Code und Antwort)
    stored_totp_secret = None   # verschlüsselte Fassung für die Datenbank
    qr_svg = None
    if auth_method == "totp":
        if existing_user is not None and existing_user.auth_method == "totp" and existing_user.totp_secret:
            # Secret beibehalten -> die vorhandene Authenticator-App funktioniert weiter
            totp_secret = decrypt_secret(existing_user.totp_secret)
            if totp_secret is None:
                # Altes Format (unverschlüsselt) oder Schlüssel passt nicht -> neues Secret
                totp_secret = pyotp.random_base32()
        else:
            totp_secret = pyotp.random_base32()
        stored_totp_secret = encrypt_secret(totp_secret)
        qr_svg = generate_totp_qr_svg(email, totp_secret)

    now = datetime.now()
    if existing_user is not None:
        existing_user.password = server_hash
        existing_user.auth_method = auth_method
        existing_user.totp_secret = stored_totp_secret
        user = existing_user
    else:
        user = User(
            email=email,
            password=server_hash,
            auth_method=auth_method,
            totp_secret=stored_totp_secret,
            created_at=now
        )
        session.add(user)

    session.commit()

    # Sofort in den entsprechenden Ablauf übergehen (kein toter Klick mehr!):
    # Fall 1: Nur Passwort -> Direkt einloggen und zu /welcome
    if auth_method == "password":
        user.last_login_at = now
        session.commit()
        user_id = user.id                                         # ID vor dem Schließen auslesen (danach ist das Objekt detached)
        session.close()
        return start_session(user_id, {"status": "success", "redirect": "/welcome"})

    # Fall 2: E-Mail-Code (2FA) -> Direkt Code versenden und 2FA-Maske öffnen
    elif auth_method == "email_otp":
        otp_code = f"{secrets.randbelow(900000) + 100000}"
        expires_at = now + timedelta(minutes=10)
        session.query(EmailOTP).filter_by(email=email, purpose="2fa").delete()
        # In der DB steht nur die HMAC-Signatur, nicht der Code selbst
        new_otp = EmailOTP(email=email, code=hmac_code(email, "2fa", otp_code), purpose="2fa",
                           created_at=now, expires_at=expires_at)
        session.add(new_otp)
        session.commit()
        session.close()

        sent = send_otp_email(email, otp_code, "2fa")
        if smtp_is_configured() and not sent:
            return JSONResponse({"error": "E-Mail konnte nicht gesendet werden."}, status_code=500)

        return JSONResponse(otp_response(email, otp_code, sent), status_code=200)

    # Fall 3: Authenticator-App -> Direkt QR-Code anzeigen
    elif auth_method == "totp":
        session.close()
        return JSONResponse({
            "status": "totp_setup",
            "auth_method": auth_method,
            "totp_secret": totp_secret,
            "qr_svg": qr_svg
        }, status_code=200)


@app.post("/api/login")                                                                        # Login (Schritt 1)
async def login(request: Request):
    allowed, reason = is_login_allowed_now()
    if not allowed:
        return JSONResponse({"error": reason}, status_code=403)

    data = await request.json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not is_valid_email(email):
        # Kein eigener Fehlertext, sonst könnte man die Formateingabe umgehen und
        # zwischen "E-Mail kaputt" und "E-Mail unbekannt" unterscheiden.
        verify_password(password, DUMMY_HASH)                    # Antwortzeit angleichen
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)

    session = Session(engine)
    user = session.query(User).filter_by(email=email).first()
    if user is None:
        # Auch bei unbekannter E-Mail wird ein Argon2-Vergleich gerechnet. Sonst wäre die
        # Antwortzeit ein Rauschanzeiger: 6 ms (User existiert nicht) vs. 230 ms (existiert).
        verify_password(password, DUMMY_HASH)
        session.close()
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)

    if not verify_password(password, user.password):
        session.close()
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)

    now = datetime.now()

    # Variante 1: Nur Passwort -> direkt anmelden
    if user.auth_method == "password":
        user.last_login_at = now
        session.commit()
        user_id = user.id                                         # ID vor dem Schließen auslesen
        session.close()
        return start_session(user_id, {"status": "success", "redirect": "/welcome"})

    # Variante 2: E-Mail-Code (2FA)
    elif user.auth_method == "email_otp":
        otp_code = f"{secrets.randbelow(900000) + 100000}"
        expires_at = now + timedelta(minutes=10)
        session.query(EmailOTP).filter_by(email=email, purpose="2fa").delete()
        # In der DB steht nur die HMAC-Signatur, nicht der Code selbst
        new_otp = EmailOTP(email=email, code=hmac_code(email, "2fa", otp_code), purpose="2fa",
                           created_at=now, expires_at=expires_at)
        session.add(new_otp)
        session.commit()
        session.close()

        sent = send_otp_email(email, otp_code, "2fa")
        if smtp_is_configured() and not sent:
            return JSONResponse({"error": "E-Mail konnte nicht gesendet werden."}, status_code=500)

        return JSONResponse(otp_response(email, otp_code, sent), status_code=200)

    # Variante 3: Authenticator-App (TOTP)
    elif user.auth_method == "totp":
        session.close()
        return JSONResponse({
            "status": "2fa_required",
            "method": "totp",
            "email": email,
            "message": "Gib den 6-stelligen Code aus deiner Authenticator-App ein."
        }, status_code=200)


@app.post("/api/verify-2fa")                                                                   # Login (Schritt 2: 2FA-Code prüfen)
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
        # Den aktiven Code holen (nicht direkt mit dem eingegebenen Code vergleichen),
        # damit wir die Fehlversuche zählen können.
        otp = session.query(EmailOTP).filter(
            EmailOTP.email == email,
            EmailOTP.purpose == "2fa",
            EmailOTP.expires_at > now
        ).first()
        if not otp:
            session.close()
            return JSONResponse({"error": "Ungültiger oder abgelaufener E-Mail-Code."}, status_code=400)

        # Signatur des eingegebenen Codes berechnen und vergleichen
        if not secrets.compare_digest(otp.code, hmac_code(email, "2fa", code)):
            otp.attempts += 1
            remaining = MAX_OTP_ATTEMPTS - otp.attempts           # Wert VOR dem Commit lesen
            if remaining <= 0:
                # Zu viele Fehlversuche: Code verbrauchen. Ohne diese Bremse wären
                # 900.000 Kombinationen in 10 Minuten durchprobierbar.
                session.query(EmailOTP).filter_by(email=email, purpose="2fa").delete()
                session.commit()
                session.close()
                return JSONResponse({
                    "error": f"Zu viele Fehlversuche ({MAX_OTP_ATTEMPTS}). Bitte fordere einen neuen Code an."
                }, status_code=429)
            session.commit()
            session.close()
            return JSONResponse({
                "error": f"Ungültiger Bestätigungscode. Noch {remaining} Versuche."
            }, status_code=400)

        session.query(EmailOTP).filter_by(email=email, purpose="2fa").delete()

    elif user.auth_method == "totp":
        if not user.totp_secret:
            session.close()
            return JSONResponse({"error": "TOTP nicht eingerichtet."}, status_code=400)
        plain_secret = decrypt_secret(user.totp_secret)
        if not plain_secret:
            session.close()
            return JSONResponse({
                "error": "TOTP-Secret konnte nicht entschlüsselt werden. Bitte die App neu einrichten."
            }, status_code=400)
        totp = pyotp.TOTP(plain_secret)
        if not totp.verify(code, valid_window=1):                                              # Toleriert kleine Zeitabweichungen (+/- 30s)
            session.close()
            return JSONResponse({"error": "Falscher Authenticator-Code."}, status_code=400)

    # 2FA erfolgreich -> Session setzen
    user.last_login_at = now
    session.commit()
    user_id = user.id                                             # ID vor dem Schließen auslesen
    session.close()
    return start_session(user_id, {"message": "Login erfolgreich.", "redirect": "/welcome"})


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
    new_otp = EmailOTP(email=email, code=hmac_code(email, "reset", code), purpose="reset",
                       created_at=now, expires_at=now + timedelta(minutes=15))
    session.add(new_otp)
    session.commit()
    session.close()

    sent = send_otp_email(email, code, "reset")

    # Anti-Enumeration: Die Antwort ist generisch, damit niemand herausfinden kann,
    # welche E-Mail-Adressen registriert sind. Nur im Dev-Modus wird der Code mitgegeben,
    # damit der Reset ohne Mailserver demonstrierbar bleibt.
    generic = {"message": "Falls die E-Mail registriert ist, wurde ein Reset-Code gesendet."}
    if not sent:
        generic = {
            "message": f"Kein SMTP-Server konfiguriert (Dev-Modus) – dein Reset-Code lautet: {code}",
            "dev_code": code,
            "dev_mode": True,
        }
    return JSONResponse(generic, status_code=200)


@app.post("/api/reset-password")                                                               # Bonus: Neues Passwort mit Reset-Code setzen
async def reset_password(request: Request):
    data = await request.json()
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()
    new_password = data.get("new_password", "")

    if not email or not code or not new_password:
        return JSONResponse({"error": "Alle Felder müssen ausgefüllt sein."}, status_code=400)

    session = Session(engine)
    now = datetime.now()
    otp = session.query(EmailOTP).filter(
        EmailOTP.email == email,
        EmailOTP.code == hmac_code(email, "reset", code),
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

    user.password = hash_password(new_password)
    session.query(EmailOTP).filter_by(email=email, purpose="reset").delete()
    # Alle bestehenden Sessions des Users beenden. Wer das Passwort zurücksetzt,
    # will (typischerweise) auch, dass niemand sonst mit einer alten Session drin ist.
    session.query(SessionToken).filter_by(user_id=user.id).delete()
    session.commit()
    session.close()

    return JSONResponse({"message": "Passwort erfolgreich geändert! Du kannst dich jetzt anmelden."}, status_code=200)


@app.post("/api/logout")                                                                       # Abmelden
async def logout(request: Request):
    token = request.cookies.get("session_token")
    if token:
        session = Session(engine)
        session.query(SessionToken).filter_by(token=hash_token(token)).delete()
        session.commit()
        session.close()

    response = JSONResponse({"message": "Erfolgreich abgemeldet.", "redirect": "/"}, status_code=200)
    response.delete_cookie("session_token")
    return response
