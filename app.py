import os                                                                                      # Zugriff auf Umgebungsvariablen (DATABASE_URL)
from datetime import datetime                                                                  # Fuer Datum und Uhrzeit

import bcrypt                                                                                  # Zum Hashen und Pruefen von Passwoertern
from fastapi import FastAPI, Request                                                           # FastAPI-App und die eingehende Anfrage
from fastapi.responses import FileResponse, JSONResponse                                       # Antworten: Datei oder JSON
from fastapi.staticfiles import StaticFiles                                                    # Liefert CSS- und JS-Dateien aus
from sqlalchemy import DateTime, String, create_engine                                         # Spaltentypen und Datenbank-Verbindung
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


Base.metadata.create_all(engine)                                                               # Tabelle anlegen, falls sie noch nicht existiert


@app.get("/")                                                                                  # Wenn jemand die Startseite aufruft
def show_login_page():                                                                         # Funktion fuer die Login-Seite
    return FileResponse("templates/index.html")                                                # Die HTML-Datei zurueckschicken


@app.get("/welcome")                                                                           # Wenn jemand /welcome aufruft
def show_welcome_page():                                                                       # Funktion fuer die Willkommensseite
    return FileResponse("templates/welcome.html")                                              # Die HTML-Datei zurueckschicken


@app.post("/api/register")                                                                     # Das Registrieren-Formular schickt hierher
async def register(request: Request):                                                          # Funktion fuers Registrieren
    data = await request.json()                                                                # Die JSON-Daten vom Browser lesen
    email = data["email"].strip().lower()                                                      # E-Mail ohne Leerzeichen und in Kleinbuchstaben
    password = data["password"]                                                                # Das eingegebene Passwort

    if email == "" or password == "":                                                          # Wenn etwas fehlt
        return JSONResponse({"error": "E-Mail und Passwort fehlen."}, status_code=400)         # Fehler zurueckschicken

    session = Session(engine)                                                                  # Verbindung zur Datenbank oeffnen

    existing_user = session.query(User).filter_by(email=email).first()                         # Gibt es diese E-Mail schon?
    if existing_user is not None:                                                              # Wenn ja
        session.close()                                                                        # Verbindung schliessen
        return JSONResponse({"error": "E-Mail ist bereits registriert."}, status_code=409)     # Fehler zurueckschicken

    password_bytes = password.encode()                                                         # Passwort in Bytes umwandeln, bcrypt braucht Bytes
    salt = bcrypt.gensalt()                                                                    # Zufaelliges Salt erzeugen, damit gleiche Passwoerter verschiedene Hashes haben
    password_hash = bcrypt.hashpw(password_bytes, salt).decode()                               # Hash berechnen und wieder in Text umwandeln

    new_user = User()                                                                          # Neuen leeren Benutzer erstellen
    new_user.email = email                                                                     # E-Mail eintragen
    new_user.password = password_hash                                                          # Den Hash eintragen, nicht das Passwort
    new_user.created_at = datetime.now()                                                       # Aktuelle Zeit als Registrierungszeit

    session.add(new_user)                                                                      # Benutzer zum Speichern vormerken
    session.commit()                                                                           # Wirklich in MySQL speichern
    session.close()                                                                            # Verbindung schliessen

    return JSONResponse({"message": "Registrierung erfolgreich."}, status_code=201)            # Erfolg zurueckschicken


@app.post("/api/login")                                                                        # Das Login-Formular schickt hierher
async def login(request: Request):                                                             # Funktion fuers Einloggen
    data = await request.json()                                                                # Die JSON-Daten vom Browser lesen
    email = data["email"].strip().lower()                                                      # E-Mail ohne Leerzeichen und in Kleinbuchstaben
    password = data["password"]                                                                # Das eingegebene Passwort

    session = Session(engine)                                                                  # Verbindung zur Datenbank oeffnen

    user = session.query(User).filter_by(email=email).first()                                  # Benutzer mit dieser E-Mail suchen
    if user is None:                                                                           # Wenn es ihn nicht gibt
        session.close()                                                                        # Verbindung schliessen
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)    # Fehler zurueckschicken

    password_bytes = password.encode()                                                         # Eingegebenes Passwort in Bytes umwandeln
    saved_hash_bytes = user.password.encode()                                                  # Gespeicherten Hash in Bytes umwandeln
    password_is_correct = bcrypt.checkpw(password_bytes, saved_hash_bytes)                     # bcrypt vergleicht Passwort mit Hash

    if password_is_correct == False:                                                           # Wenn das Passwort falsch ist
        session.close()                                                                        # Verbindung schliessen
        return JSONResponse({"error": "E-Mail oder Passwort ist falsch."}, status_code=401)    # Fehler zurueckschicken

    user.last_login_at = datetime.now()                                                        # Zeit des Logins eintragen
    session.commit()                                                                           # Aenderung in MySQL speichern
    session.close()                                                                            # Verbindung schliessen

    return JSONResponse({"message": "Login erfolgreich."}, status_code=200)                    # Erfolg zurueckschicken
