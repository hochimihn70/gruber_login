# Gruber Login – Login mit FastAPI und MySQL

Kleine Login-Anwendung mit drei wählbaren Anmeldemodi, Session-Schutz, Passwort-Reset und optionaler zeitlicher Login-Beschränkung. Läuft komplett in Docker und ist optional über einen Cloudflare Tunnel per HTTPS erreichbar.

## Funktionen

- **Drei Login-Modi** (bei der Registrierung wählbar):
  - `password` – nur Passwort
  - `email_otp` – Passwort + 6-stelliger Code per E-Mail (10 Minuten gültig)
  - `totp` – Passwort + Authenticator-App (QR-Code, RFC 6238, z. B. Google Authenticator, Aegis, 2FAS)
- **Clientseitiges SHA-256:** Das Passwort wird schon im Browser gehasht; der Server speichert davon zusätzlich einen bcrypt-Hash.
- **Geschützte Route:** `/welcome` ist nur mit gültiger Session erreichbar, sonst Weiterleitung auf `/`. Die Session ist 7 Tage gültig (HttpOnly-Cookie).
- **Passwort-Reset** per E-Mail-Code (15 Minuten gültig).
- **Zeitliche Login-Beschränkung** (optional, siehe unten).

## Voraussetzungen

- [Docker](https://docs.docker.com/get-docker/) mit Docker Compose v2 (`docker compose`)
- Für den Zugriff aus dem Internet (optional): ein Cloudflare-Account mit Zero Trust und einer eigenen Domain
- Für echten E-Mail-Versand (optional): ein SMTP-Zugang, z. B. [Resend](https://resend.com), Brevo oder ein eigener Server

Für einen reinen lokalen Test brauchst du **nur Docker**.

## Schnellstart (lokal)

```bash
git clone <repo-url> gruber_login
cd gruber_login
cp .env.example .env
docker compose up -d --build db web
```

Danach ist die App unter http://localhost:5000 erreichbar.

> `db web` startet bewusst nur Datenbank und Webanwendung. Der `cloudflared`-Container braucht ein Tunnel-Token und würde ohne dieses in einer Fehlerschleife laufen. Wenn du den Tunnel nutzen willst, siehe nächster Abschnitt.

Beim ersten Start legt die App die Tabellen `users`, `sessions` und `email_otps` automatisch an. Die MySQL-Daten liegen im Docker-Volume `mysql_data`. Die App wartet über einen Healthcheck, bis MySQL bereit ist (kann beim allerersten Start ca. 20–30 Sekunden dauern).

### Ausprobieren

1. http://localhost:5000 öffnen und registrieren – E-Mail, Passwort und Login-Modus wählen.
2. Je nach Modus:
   - **Passwort:** du wirst sofort eingeloggt und landest auf `/welcome`.
   - **E-Mail-Code:** Code eingeben. Ohne SMTP-Konfiguration steht er in den Logs (siehe unten).
   - **Authenticator:** QR-Code mit der App scannen, dann den angezeigten 6-stelligen Code eingeben.
3. Beim nächsten Login wird je nach Modus der zweite Faktor abgefragt.

## Öffentlich erreichbar mit Cloudflare Tunnel (optional)

Der Tunnel macht die App per HTTPS erreichbar, ohne dass Ports am Router geöffnet werden müssen.

1. Im [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/) unter **Networks → Tunnels** einen Tunnel erstellen (Typ *Cloudflared*) und das Token kopieren.
2. Das Token in `.env` bei `TUNNEL_TOKEN` eintragen.
3. Beim Tunnel einen **Public Hostname** anlegen:
   - **Domain:** deine Domain, z. B. `logintest.smoothingo.com`
   - **Type:** `HTTP`
   - **URL:** `web:5000`
4. Alles starten:
   ```bash
   docker compose up -d --build
   ```

Die App ist dann unter `https://<deine-domain>` erreichbar (lokal weiterhin unter http://localhost:5000).

## Konfiguration (`.env`)

| Variable | Bedeutung | Standard |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy-URL der Datenbank | `mysql+pymysql://authuser:authpassword@db:3306/authdb` |
| `TUNNEL_TOKEN` | Cloudflare-Tunnel-Token (nur für `cloudflared`) | leer |
| `SMTP_HOST` | SMTP-Server; leer = kein Mailversand (Dev-Modus) | leer |
| `SMTP_PORT` | `587` (STARTTLS) oder `465` (SSL) | `587` |
| `SMTP_USER` / `SMTP_PASSWORD` | SMTP-Zugangsdaten | leer |
| `SMTP_FROM` | Absenderadresse | `noreply@smoothingo.com` |
| `LOGIN_RESTRICTION_ENABLED` | `true` aktiviert die Zeitbeschränkung | `false` |
| `LOGIN_ALLOWED_START_HOUR` | Erste erlaubte Stunde (0–23) | `6` |
| `LOGIN_ALLOWED_END_HOUR` | Erste *nicht mehr* erlaubte Stunde (0–23) | `22` |

Nach Änderungen an der `.env` die Container neu erzeugen: `docker compose up -d`.

> **Hinweis zur Zeitbeschränkung:** `docker-compose.yml` reicht die `LOGIN_*`-Variablen aktuell nicht an den `web`-Container durch. Zum Aktivieren müssen im Service `web` unter `environment:` diese Zeilen ergänzt werden:
> ```yaml
> LOGIN_RESTRICTION_ENABLED: ${LOGIN_RESTRICTION_ENABLED:-false}
> LOGIN_ALLOWED_START_HOUR: ${LOGIN_ALLOWED_START_HOUR:-6}
> LOGIN_ALLOWED_END_HOUR: ${LOGIN_ALLOWED_END_HOUR:-22}
> ```
> Geprüft wird die Serverzeit des Containers (standardmäßig UTC). Gesperrt sind `/api/login` und `/api/verify-2fa`.

### E-Mail-Versand

- **Mit SMTP:** `SMTP_*` in der `.env` setzen. Kostenlose Empfehlung: [Resend](https://resend.com) (3.000 Mails/Monat gratis, DNS-Einbindung in Cloudflare möglich).
- **Dev-Modus ohne SMTP:** Codes werden **immer** zusätzlich in die Logs geschrieben und bei leerem `SMTP_HOST` nur dort ausgegeben:
  ```bash
  docker compose logs -f web
  ```
  Dort erscheint ein Block wie `[DEIN VERIFIZIERUNGSCODE] für user@example.com: >>> 123456 <<<`.

> Achtung: Da Codes im Klartext in den Logs stehen, ist das Setup in dieser Form für Entwicklung und Demos gedacht, nicht für den Produktivbetrieb.

## Ressourcenverbrauch

> **Richtwerte, nicht gemessen** – typische Erfahrungswerte für diese Images im Leerlauf bzw. bei wenigen Nutzern. Auf dem Zielsystem lässt sich der echte Verbrauch mit `docker stats` prüfen.

| Container | RAM (ca.) | CPU im Leerlauf | CPU bei Last |
|---|---|---|---|
| `db` (MySQL 8.4) | 400–600 MB | < 1 % | kurze Spitzen bei Abfragen |
| `web` (FastAPI/uvicorn) | 60–100 MB | < 1 % | bcrypt-Hashing beim Login/Registrieren ca. 50–300 ms CPU-Zeit pro Anfrage |
| `cloudflared` | 20–50 MB | < 1 % | gering |
| **Gesamt** | **ca. 0,5–0,8 GB** | **praktisch idle** | – |

- **Festplatte:** ca. 1 GB für die Images (MySQL ist der größte Teil) plus das Volume `mysql_data` (leer ca. 200–300 MB, pro Benutzer nur wenige KB).
- **Mindestanforderung:** 1 vCPU und 1 GB RAM genügen; empfohlen sind 2 GB RAM, damit MySQL und Docker Reserve haben.
- **Sparen:** Ohne Cloudflare Tunnel entfällt der `cloudflared`-Container (`docker compose up -d db web`).

Echten Verbrauch messen:

```bash
docker stats --no-stream
```

## Nützliche Befehle

```bash
docker compose ps                  # Status der Container
docker compose logs -f web         # Logs der App (inkl. Codes)
docker compose up -d --build web   # Nach Code-Änderungen neu bauen
docker compose down                # Stoppen (Daten bleiben erhalten)
docker compose down -v             # Stoppen und Datenbank löschen
```

## Ohne Docker entwickeln

Python 3.11+ und eine laufende MySQL-Datenbank vorausgesetzt:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="mysql+pymysql://authuser:authpassword@localhost:3306/authdb"
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```

## Fehlerbehebung

| Problem | Lösung |
|---|---|
| `cloudflared` startet ständig neu | `TUNNEL_TOKEN` fehlt oder ist ungültig – Token eintragen oder nur `db web` starten. |
| `web` startet neu / Datenbankfehler | MySQL ist noch nicht bereit; kurz warten und `docker compose logs web` prüfen. Bei geänderten DB-Zugangsdaten das Volume mit `docker compose down -v` zurücksetzen. |
| Kein E-Mail-Code erhalten | Ohne `SMTP_HOST` steht der Code nur in `docker compose logs web`. Mit SMTP: Zugangsdaten, Port und Absenderdomain prüfen (Fehler stehen als `Mail-Fehler: …` in den Logs). |
| Authenticator-Code wird abgelehnt | Uhrzeit von Server und Handy synchronisieren (Toleranz: ±30 Sekunden). |
| Login meldet „zu dieser Uhrzeit gesperrt" | `LOGIN_RESTRICTION_ENABLED=false` setzen oder die erlaubten Stunden anpassen. |
| Änderungen an `static/app.js` greifen nicht | Browser-Cache leeren (Strg+Shift+R); die Script-URL enthält eine Versionsnummer in `templates/index.html`. |

## Architektur

- **FastAPI** (`app.py`) liefert die Seiten aus `templates/` und die API unter `/api/*`; statische Dateien liegen in `static/`.
- **MySQL 8.4** speichert Benutzer (`users`), Sessions (`sessions`) und temporäre Codes (`email_otps`).
- **Passwörter:** SHA-256 im Browser, anschließend bcrypt auf dem Server – das Klartext-Passwort erreicht den Server nie und kann aus der Datenbank nicht zurückgerechnet werden.
- **Cloudflared** stellt die Verbindung über den Cloudflare Tunnel her (keine offenen Ports nötig).

### API-Endpunkte

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/` | Login-/Registrierungsseite |
| GET | `/welcome` | Geschützte Willkommensseite |
| GET | `/api/me` | Daten des eingeloggten Benutzers |
| POST | `/api/register` | Registrieren (oder Methode/Passwort eines bestehenden Benutzers aktualisieren) |
| POST | `/api/login` | Login Schritt 1 (Passwort) |
| POST | `/api/verify-2fa` | Login Schritt 2 (E-Mail- oder Authenticator-Code) |
| POST | `/api/forgot-password` | Reset-Code anfordern |
| POST | `/api/reset-password` | Neues Passwort mit Reset-Code setzen |
| POST | `/api/logout` | Abmelden |
