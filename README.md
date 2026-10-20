# Gruber Login – Login mit FastAPI und MySQL

Kleine Login-Anwendung mit drei wählbaren Anmeldemodi, Session-Schutz, Passwort-Reset und optionaler zeitlicher Login-Beschränkung. Läuft komplett in Docker und ist optional über einen Cloudflare Tunnel per HTTPS erreichbar.

## Funktionen

- **Drei Login-Modi** (bei der Registrierung im zweiten Schritt wählbar):
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

1. http://localhost:5000 öffnen und registrieren – zuerst E-Mail und Passwort, dann im zweiten Schritt entscheiden, ob das Konto zusätzlich abgesichert werden soll.
2. Je nach Modus:
   - **Passwort:** du wirst sofort eingeloggt und landest auf `/welcome`.
   - **E-Mail-Code:** Code eingeben. Ohne SMTP-Konfiguration steht er in den Logs **und wird direkt im Browser angezeigt** (siehe unten).
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
| `SESSION_COOKIE_SECURE` | Session-Cookie nur über HTTPS senden | `true` |
| `LOGIN_RESTRICTION_ENABLED` | `true` aktiviert die Zeitbeschränkung | `false` |
| `LOGIN_ALLOWED_START_HOUR` | Erste erlaubte Stunde (0–23) | `6` |
| `LOGIN_ALLOWED_END_HOUR` | Erste *nicht mehr* erlaubte Stunde (0–23) | `22` |

Nach Änderungen an der `.env` die Container **neu erstellen**:

```bash
docker compose up -d --force-recreate web
```

> `docker compose restart` reicht **nicht** – Umgebungsvariablen werden nur beim Erstellen des Containers gesetzt. Ein einfaches `docker compose up -d` genügt nur, wenn Compose den Konfigurationsunterschied selbst erkennt.

> **Hinweis zur Zeitbeschränkung:** Die `LOGIN_*`-Variablen werden vom `docker-compose.yml` an den `web`-Container durchgereicht. Geprüft wird die Serverzeit des Containers (standardmäßig UTC). Gesperrt sind `/api/login` und `/api/verify-2fa` – beide antworten dann mit HTTP 403.
>
> `SESSION_COOKIE_SECURE=true` heißt: Das Session-Cookie wird nur über HTTPS verschickt. Das ist für den Betrieb hinter dem Cloudflare Tunnel richtig. Nur wenn die App testweise über eine LAN-IP **ohne** HTTPS aufgerufen wird, muss der Wert auf `false` – sonst blockiert der Browser das Cookie und der Login funktioniert nicht.

### E-Mail-Versand

- **Mit SMTP:** `SMTP_*` in der `.env` setzen. Kostenlose Empfehlung: [Resend](https://resend.com) (3.000 Mails/Monat gratis, DNS-Einbindung in Cloudflare möglich).
- **Dev-Modus ohne SMTP:** Codes werden **immer** zusätzlich in die Logs geschrieben. Ist kein SMTP-Server konfiguriert (fehlender `SMTP_HOST`, `SMTP_PASSWORD` oder `SMTP_FROM`), wird **keine** E-Mail verschickt – der Code wird dann **direkt im Browser angezeigt** und automatisch ins Eingabefeld eingetragen. Die Oberfläche sagt das auch, statt fälschlich „Code wurde gesendet" zu behaupten.
  ```bash
  docker compose logs -f web
  ```
  Dort erscheint ein Block wie `[DEIN VERIFIZIERUNGSCODE] für user@example.com: >>> 123456 <<<`.
- **Status prüfen:** `curl http://localhost:5000/api/health` zeigt, ob der E-Mail-Versand konfiguriert ist und welche Variablen noch fehlen.

> Achtung: Da Codes im Klartext in den Logs stehen, ist das Setup in dieser Form für Entwicklung und Demos gedacht, nicht für den Produktivbetrieb.

### E-Mail mit Resend einrichten

1. **API-Key anlegen:** [resend.com → API Keys](https://resend.com/dashboard/api-keys) → *Create API Key* (beginnt mit `re_`).
2. **Domain verifizieren:** [resend.com → Domains](https://resend.com/dashboard/domains) → z. B. `smoothingo.com` hinzufügen.
3. **DNS-Records in Cloudflare anlegen** (Werte stehen im Resend-Dashboard unter *Records*):

   | Typ | Name | Ziel | Proxy |
   |---|---|---|---|
   | `MX` | `send` | Wert aus Resend (Priority 10) | DNS only |
   | `TXT` | `send` | `"v=spf1 include:amazonses.com ~all"` | DNS only |
   | `TXT` | `resend._domainkey` | DKIM-Wert von Resend | **DNS only!** |

   > Nur den Subdomain-Namen eintragen (nicht die volle Domain) und **kein Proxy-Orange-Cloud** – sonst schlägt die Verifizierung fehl.
4. **In der `.env` eintragen:**

   ```bash
   SMTP_HOST=smtp.resend.com
   SMTP_PORT=587          # 587 = STARTTLS, 465 = implizites SSL (beides unterstützt)
   SMTP_USER=resend       # fest "resend", nicht die eigene E-Mail-Adresse
   SMTP_PASSWORD=re_DEIN_API_KEY
   SMTP_FROM=noreply@smoothingo.com   # muss auf einer verifizierten Domain liegen
   ```

5. **Container neu erstellen**, damit die Variablen übernommen werden:

   ```bash
   docker compose up -d --force-recreate web
   ```

   Der Start-Log bestätigt den Zustand: `[SMTP] E-Mail-Versand: AKTIV (Host: smtp.resend.com, …)`.

## Sicherheitsregeln

Drei Regeln, die den ganzen Login-Schutz ausmachen:

### 1. Ein fremdes Konto kann nicht übernommen werden

Registriert sich jemand mit einer E-Mail, die schon vergeben ist, passiert **nichts** – es sei denn, das eingegebene Passwort stimmt mit dem bestehenden Konto überein.

```
E-Mail unbekannt          → Konto wird neu angelegt
E-Mail bekannt, Passwort richtig → Konto wird aktualisiert (z. B. neue Sicherheitsstufe)
E-Mail bekannt, Passwort falsch → HTTP 401, es ändert sich NICHTS
```

**Warum:** Ohne diese Prüfung könnte jeder, der eine fremde E-Mail-Adresse kennt, das Konto übernehmen – einfach durch erneutes Registrieren. So braucht man für den Zugriff immer das Passwort.

### 2. Das Session-Cookie ist geschützt

| Flag | Wirkung |
|---|---|
| `HttpOnly` | JavaScript im Browser kann das Cookie nicht auslesen (schützt vor Token-Diebstahl per XSS) |
| `SameSite=Lax` | blockiert Cross-Site-POSTs (Grundschutz gegen CSRF) |
| `Secure` | das Cookie wird nur über HTTPS verschickt, nie über unverschlüsseltes HTTP |
| `Max-Age` | läuft nach 7 Tagen ab |

Die Session selbst liegt **serverseitig** in der Tabelle `sessions`, nicht im Token. Deshalb kann ein Logout sie sofort und endgültig ungültig machen.

### 3. Passwörter sind doppelt gehasht

```
Passwort (Klartext, im Browser)
   → SHA-256 (Web Crypto API)      → wird übertragen
   → bcrypt + Salt (auf dem Server) → wird gespeichert
```

Der Klartext erreicht den Server nie. Aus der Datenbank lässt sich das Passwort nicht zurückrechnen. Der bcrypt-Hash hat zusätzlich ein Salt pro User, gleiche Passwörter erzeugen also unterschiedliche Hashes.

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
| Kein E-Mail-Code erhalten | Ohne SMTP-Konfiguration wird der Code **im Browser angezeigt** und zusätzlich ins Log geschrieben (`docker compose logs web`). Mit SMTP: Zugangsdaten, Port und Absenderdomain prüfen (Fehler stehen als `Mail-Fehler: …` in den Logs). `curl localhost:5000/api/health` zeigt, ob SMTP überhaupt konfiguriert ist. |
| Registrierung schlägt mit „E-Mail ist bereits registriert" fehl | Die E-Mail existiert schon, das Passwort passt aber nicht. Mit dem **richtigen** Passwort kann die Sicherheitsstufe geändert werden – oder man meldet sich normal an bzw. setzt das Passwort zurück. |
| Authenticator-Code wird abgelehnt | Uhrzeit von Server und Handy synchronisieren (Toleranz: ±30 Sekunden). |
| Login meldet „zu dieser Uhrzeit gesperrt" | `LOGIN_RESTRICTION_ENABLED=false` setzen oder die erlaubten Stunden anpassen. |
| Änderungen an `static/app.js` greifen nicht | Browser-Cache leeren (Strg+Shift+R); die Script-URL enthält eine Versionsnummer in `templates/index.html`. |

## Architektur

- **FastAPI** (`app.py`) liefert die Seiten aus `templates/` und die API unter `/api/*`; statische Dateien liegen in `static/`.
- **MySQL 8.4** speichert Benutzer (`users`), Sessions (`sessions`) und temporäre Codes (`email_otps`).
- **Passwörter:** SHA-256 im Browser, anschließend bcrypt auf dem Server – das Klartext-Passwort erreicht den Server nie und kann aus der Datenbank nicht zurückgerechnet werden.
- **Cloudflared** stellt die Verbindung über den Cloudflare Tunnel her (keine offenen Ports nötig).

### Konfigurations-Ebenen

| Ebene | Datei | Aufgabe |
|---|---|---|
| Defaults | `docker-compose.yml` | Fallback-Werte via `${VAR:-default}` |
| Secrets | `.env` (gitignored) | überschreibt die Defaults |
| Vorlage | `.env.example` | reine Dokumentation, wirkt **nicht** zur Laufzeit |
| Laufzeit | Container-ENV | wird von `os.environ` in `app.py` gelesen |

Die App liest die `.env` **nicht selbst** – sie kennt nur `os.environ`. Alle SMTP-Werte stehen deshalb ausschließlich in der `.env`, im Code ist nichts hart verdrahtet.

### API-Endpunkte

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/` | Login-/Registrierungsseite |
| GET | `/welcome` | Geschützte Willkommensseite |
| GET | `/api/health` | Status: Datenbank, SMTP-Konfiguration, fehlende Variablen |
| GET | `/api/me` | Daten des eingeloggten Benutzers |
| POST | `/api/register` | Registrieren (oder Methode/Passwort eines bestehenden Benutzers aktualisieren) |
| POST | `/api/login` | Login Schritt 1 (Passwort) |
| POST | `/api/verify-2fa` | Login Schritt 2 (E-Mail- oder Authenticator-Code) |
| POST | `/api/forgot-password` | Reset-Code anfordern |
| POST | `/api/reset-password` | Neues Passwort mit Reset-Code setzen |
| POST | `/api/logout` | Abmelden |
