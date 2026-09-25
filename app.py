import os
from datetime import datetime, timezone

import bcrypt
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import DateTime, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
engine = create_engine(os.environ["DATABASE_URL"])
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


# Mapped verbindet die Python-Felder mit den Spalten der MySQL-Tabelle.
class User(Base):
    __tablename__ = "users"  # Diese Klasse beschreibt die MySQL-Tabelle.

    id: Mapped[int] = mapped_column(primary_key=True)  # Eindeutige Benutzer-ID.
    email: Mapped[str] = mapped_column(String(320), unique=True)  # E-Mail, nur einmal erlaubt.
    password: Mapped[str] = mapped_column(String(255))  # Passwort-Hash des Benutzers.
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))  # Erstellungszeitpunkt.
    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)  # Letzter Login oder leer.


Base.metadata.create_all(engine)  # Tabellen beim Start anlegen.


def now():
    return datetime.now(timezone.utc)


@app.get("/", response_class=HTMLResponse)
def home():
    with open("templates/index.html", encoding="utf-8") as file:  # Startseite öffnen.
        return file.read()


@app.get("/welcome", response_class=HTMLResponse)
def welcome():
    with open("templates/welcome.html", encoding="utf-8") as file:  # Willkommensseite öffnen.
        return file.read()


@app.post("/api/register")
async def register(request: Request):
    data = await request.json()  # JSON-Daten vom Frontend lesen.
    email = data.get("email", "").strip().lower()  # E-Mail vereinheitlichen.
    password = data.get("password", "")  # Passwort auslesen.

    if email == "" or password == "":
        return JSONResponse({"error": "E-Mail und Passwort fehlen."}, status_code=400)

    with Session() as session:
        if session.query(User).filter_by(email=email).first() is not None:
            return JSONResponse({"error": "E-Mail ist bereits registriert."}, status_code=409)

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # Passwort hashen.
        user = User(email=email, password=password_hash, created_at=now())  # Benutzer vorbereiten.
        session.add(user)  # Benutzer für das Speichern vormerken.
        session.commit()  # Benutzer in MySQL speichern.

    return JSONResponse({"message": "Registrierung erfolgreich."}, status_code=201)


@app.post("/api/login")
async def login(request: Request):
    data = await request.json()  # JSON-Daten vom Frontend lesen.
    email = data.get("email", "").strip().lower()  # E-Mail vereinheitlichen.
    password = data.get("password", "")  # Passwort auslesen.

    with Session() as session:  # Verbindung zur Datenbank oeffnen.
        user = session.query(User).filter_by(email=email).first()  # Benutzer per E-Mail suchen.
        password_is_correct = False  # Passwort zuerst als falsch annehmen.
        if user is not None:  # Nur vorhandene Benutzer pruefen.
            if user.password.startswith("$2b$"):  # Neuen bcrypt-Hash pruefen.
                password_is_correct = bcrypt.checkpw(password.encode(), user.password.encode())
            else:  # Alten Testdatensatz einmalig akzeptieren.
                password_is_correct = user.password == password
                if password_is_correct:
                    user.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()  # Altes Passwort hashen und als Text speichern.

        if user is None or not password_is_correct:  # Benutzer und Passwort muessen stimmen.
            return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)  # Login ablehnen.

        user.last_login_at = now()  # Zeitpunkt des erfolgreichen Logins speichern.
        session.commit()  # Änderung in MySQL speichern.

    return {"message": "Login erfolgreich."}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=5000)
