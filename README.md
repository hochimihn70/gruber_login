# Gruber Login – Login mit FastAPI und MySQL

Kleine Login-Anwendung mit drei wählbaren Anmeldemodi, Session-Schutz, Passwort-Reset und optionaler zeitlicher Login-Beschränkung. Läuft komplett in Docker und ist optional über einen Cloudflare Tunnel per HTTPS erreichbar.

## Funktionen

- **Drei Login-Modi** (bei der Registrierung im zweiten Schritt wählbar):
  - `password` – nur Passwort
  - `email_otp` – Passwort + 6-stelliger Code per E-Mail (10 Minuten gültig)
  - `totp` – Passwort + Authenticator-App (QR-Code, RFC 6238, z. B. Google Authenticator, Aegis, 2FAS)
- **Passwort-Hashing mit Argon2id:** Das Passwort geht verschlüsselt (HTTPS) zum Server und wird dort mit Argon2id gehasht – inklusive zufälligem Salt pro User. Das ist der heutige Standard (OWASP) und läuft in Django, Rails, Laravel, Spring und Next.js genauso.
- **Geschützte Route:** `/welcome` ist nur mit gültiger Session erreichbar, sonst Weiterleitung auf `/`. Die Session ist 7 Tage gültig (HttpOnly-Cookie).
- **Passwort-Reset** per E-Mail-Code (15 Minuten gültig).
- **Brute-Force-Schutz:** Fehlversuchs-Bremse für 2FA-/Reset-Codes, Rate-Limits pro IP und E-Mail, TOTP-Replay-Schutz.
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

> **Kein Cloudflare nötig:** `TUNNEL_TOKEN` darf leer bleiben – die App läuft dann einfach nur lokal. Der Tunnel ist ein **optionales Compose-Profil** und startet mit `docker compose up` gar nicht erst (siehe unten).
>
> **E-Mail ist optional:** Ohne `SMTP_PASSWORD` läuft der Dev-Modus – die 2FA-Codes erscheinen dann direkt im Browser und im Log (`docker compose logs -f web`). Damit lassen sich alle drei Anmeldemodi ohne Mailserver testen.
>
> **Eigenes `APP_SECRET`:** In der `.env` ist der Wert bewusst leer. Ohne ihn startet die App mit einem zufälligen Geheimnis – dann überleben TOTP-Secrets keinen Neustart. Für den echten Betrieb einen eigenen Wert erzeugen und eintragen: `python3 -c "import secrets; print(secrets.token_hex(32))"`. Der Wert muss stabil bleiben, sonst lassen sich vorhandene TOTP-Secrets nicht mehr entschlüsseln.

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
4. Alles starten – **mit dem Profil `tunnel`**, damit der Tunnel mitstartet:
   ```bash
   docker compose --profile tunnel up -d --build
   ```

Die App ist dann unter `https://<deine-domain>` erreichbar (lokal weiterhin unter http://localhost:5000).

> **Warum ein Profil?** Der Tunnel braucht ein Token. Ohne Token würde `cloudflared` sofort beenden und immer wieder neu starten – das sieht nach einem Fehler aus, obwohl die App völlig in Ordnung ist. Mit dem Profil startet `docker compose up` nur Datenbank und Webanwendung, der Tunnel läuft nur, wenn man ihn ausdrücklich startet. Zusätzlich gibt es `restart: on-failure:5` – ein ungültiges Token führt zu 5 Versuchen und dann zu einem sauberen Stopp statt zu einer Endlosschleife.

## Konfiguration (`.env`)

| Variable | Bedeutung | Standard |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy-URL der Datenbank | `mysql+pymysql://authuser:authpassword@db:3306/authdb` |
| `TUNNEL_TOKEN` | Cloudflare-Tunnel-Token (nur für `cloudflared`) | leer |
| `SMTP_HOST` | SMTP-Server; leer = kein Mailversand (Dev-Modus) | leer |
| `SMTP_PORT` | `587` (STARTTLS) oder `465` (SSL) | `587` |
| `SMTP_USER` / `SMTP_PASSWORD` | SMTP-Zugangsdaten | leer |
| `SMTP_FROM` | Absenderadresse | `noreply@smoothingo.com` |
| `APP_SECRET` | Server-Geheimnis für HMAC (2FA-Codes) und Verschlüsselung (TOTP-Secret). Leer = zufällig erzeugt (nur für Wegwerf-Demos, TOTP-Secrets überleben keinen Neustart) | zufällig |
| `SESSION_COOKIE_SECURE` | Session-Cookie nur über HTTPS senden | `true` |
| `LOGIN_RESTRICTION_ENABLED` | `true` aktiviert die Zeitbeschränkung | `false` |
| `LOGIN_ALLOWED_START_HOUR` | Erste erlaubte Stunde (0–23) | `6` |
| `LOGIN_ALLOWED_END_HOUR` | Erste *nicht mehr* erlaubte Stunde (0–23) | `22` |
| `RATE_LIMIT_ENABLED` | Rate-Limiting für Login/Registrierung/Reset | `true` |
| `TRUST_PROXY_HEADERS` | echte Client-IP aus `X-Forwarded-For` lesen (nur hinter Proxy) | `false` |

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

### 3. Passwörter werden mit Argon2id gehasht

```
Passwort (Klartext)
   → HTTPS (verschlüsselt)          → Server
   → Argon2id + Zufalls-Salt        → wird in der DB gespeichert
```

**Argon2id** ist der heutige Standard (OWASP Password Storage Cheat Sheet) und läuft in drei Schritten: Es ist **speicherresistent** (ein Angreifer kann nicht einfach viele Hashes parallel berechnen) und **bewusst langsam** – hier rund 50 ms pro Aufruf bei 46 MiB Speicher.

| | Wert |
|---|---|
| Algorithmus | Argon2id (`$argon2id$v=19$m=47104,t=1,p=1$…`) |
| Speicher | 46 MiB |
| Durchläufe | 1 |
| Salt | zufällig pro Hash, steckt im Hash-String |
| Dauer | ca. 50 ms |

Der Salt steckt bereits im gespeicherten Hash – er muss nicht separat in der DB liegen. Zwei User mit dem gleichen Passwort haben deshalb trotzdem zwei verschiedene Hashes.

**Warum nicht bcrypt?** bcrypt ist weiterhin völlig okay und war lange Standard. Argon2id ist schneller *und* speicherresistenter, deshalb wurde hier umgestellt. Beides gilt als sicher – Argon2id ist die Empfehlung für neue Projekte.

> **Hinweis:** Wer von einer älteren Version umsteigt, muss die Passwörter der vorhandenen User neu setzen lassen: Der Hash-Algorithmus hat sich geändert, alte Hashes können nicht geprüft werden. (Praktisch lässt sich das umgehen, indem beim Login ein alter Hash erkannt und durch Argon2id ersetzt wird – für dieses Projekt aber nicht nötig.)

### 4. Brute-Force wird gebremst

Ein 6-stelliger 2FA-Code hat nur 900.000 Kombinationen – ohne Bremse wäre er in den 10 Minuten Gültigkeit durchprobierbar. Deshalb gilt:

| Vorgang | Regel |
|---|---|
| 2FA-Code | nach **5 Fehlversuchen** wird der Code ungültig (HTTP 429) |
| Reset-Code | dieselbe Bremse: nach **5 Fehlversuchen** ungültig (HTTP 429) |
| TOTP-Code | nach **5 Fehlversuchen** für 15 Minuten gesperrt (HTTP 429) |
| TOTP-Replay | jeder 30-Sekunden-Schritt wird nur **einmal** akzeptiert |
| Vergleich | mit `secrets.compare_digest` (konstante Laufzeit) |
| Passwort | Argon2id – rund 50 ms pro Versuch, mindestens 8 Zeichen (serverseitig geprüft) |

Zusätzlich bremst ein **In-Memory-Rate-Limiter** (gleitendes Zeitfenster) die Endpunkte:

| Endpunkt | Limit |
|---|---|
| `/api/login` | 20 Versuche / 15 min pro IP, 10 / 15 min pro E-Mail |
| `/api/register` | 10 / Stunde pro IP |
| `/api/forgot-password` | 5 / 15 min pro IP, 2 / Stunde pro E-Mail (verhindert Mail-Bombing) |
| `/api/verify-2fa`, `/api/reset-password` | 30 / 15 min pro IP |

Der Limiter zählt **pro Prozess**. Für mehrere Uvicorn-Worker müsste der Zustand geteilt werden (z. B. Redis) – bei diesem Setup läuft bewusst ein Prozess.

> **Wichtig hinter einem Proxy:** Steht die App hinter dem Cloudflare Tunnel, kommen alle Requests von der Tunnel-IP. Dann `TRUST_PROXY_HEADERS=true` setzen, damit die echte Client-IP aus `X-Forwarded-For` gelesen wird. Bei direkt erreichbarem Port 5000 muss der Wert `false` bleiben – sonst kann jeder den Header selbst setzen.

Für das Passwort ist keine eigene Bremse nötig: Der Server rechnet einen **Dummy-Argon2id-Vergleich** auch dann, wenn die E-Mail unbekannt ist. Sonst wäre die Antwortzeit ein Rauschanzeiger:

```
vorher:   unbekannte E-Mail  →   6 ms     bekannte E-Mail  →  230 ms   (97 % Unterschied!)
nachher:  unbekannte E-Mail  →  76 ms     bekannte E-Mail  →   75 ms   (1 % Unterschied)
```

So lässt sich nicht herausfinden, welche E-Mail-Adressen registriert sind.

### 5. Weitere Schutzmaßnahmen

| Maßnahme | Umsetzung |
|---|---|
| Session-Token in der DB | nur als SHA-256-Hash – ein DB-Leak reicht nicht, um die Session zu übernehmen |
| 2FA-Code in der DB | nur als HMAC-Signatur (`APP_SECRET`) – ein DB-Dump zeigt keinen gültigen Code |
| TOTP-Secret in der DB | verschlüsselt (AES-GCM via Fernet) – aus dem Dump lässt sich das Secret nicht zurückrechnen |
| E-Mail-Prüfung | auch serverseitig (nicht nur im Browser) |
| Sessions beim Passwort-Reset | alle bestehenden Sessions des Users werden beendet |
| Sicherheits-Header | `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy` |
| CSP | `script-src 'self'` – kein Inline-JavaScript. Deshalb liegt der Code der Willkommensseite in `static/welcome.js` statt im HTML |
| Container | Prozess läuft als Benutzer `app` (UID 10001), `cap_drop: ALL`, `no-new-privileges` |

> **Hinweis zu Cloudflare:** Der Tunnel injiziert ein eigenes Script in die HTML-Ausgabe (Bot-Erkennung). Die strikte CSP blockiert es – die App ist davon nicht betroffen. Falls es doch nötig wird: `script-src 'self' 'unsafe-inline'`.

### Browser-Cache

Die HTML-Seiten werden mit `Cache-Control: no-cache` ausgeliefert: Der Browser fragt damit bei jedem Aufruf nach, ob sich etwas geändert hat, und lädt die Seite notfalls neu. Ohne diese Angabe würde der Browser eine alte Kopie behalten – und damit auch eine alte `app.js` mit altem Code.

Die statischen Dateien selbst (`app.js`, `style.css`) bekommen die Versionsnummer direkt in der URL (`app.js?v=9`). Wird eine davon geändert, zählt man die Nummer in `templates/index.html` hoch – dann ist der neue Stand garantiert geladen.

### 6. Was in der Datenbank steht – und was nicht

| Wert | gespeichert als | wiederherstellbar? |
|---|---|---|
| Passwort | Argon2id-Hash | nein |
| Session-Token | SHA-256-Hash | nein |
| 2FA-Code (E-Mail) | HMAC-SHA256-Signatur | nein |
| TOTP-Secret | verschlüsselt (Fernet/AES-GCM) | nur mit `APP_SECRET` |

**Warum HMAC für den 2FA-Code?** Ein 6-stelliger Code hat nur 900.000 mögliche Werte – ein einfacher SHA-256-Hash davon wäre aus einem DB-Dump in Sekunden zurückgerechnet. Der HMAC rechnet zusätzlich das `APP_SECRET` ein, das **nur** auf dem Server liegt. Wer den Dump hat, kann mit den 900.000 Kombinationen trotzdem nichts anfangen, weil die Signatur ohne das Secret nicht nachvollziehbar ist.

**Warum Verschlüsselung für das TOTP-Secret?** Anders als ein Code muss das TOTP-Secret **entschlüsselbar** sein – der Server braucht es, um den erwarteten Code zu berechnen. Hashen ist also nicht möglich. Stattdessen wird es mit einem aus `APP_SECRET` abgeleiteten Schlüssel verschlüsselt gespeichert (Fernet = AES-GCM, authentifiziert).

> **Wichtig:** `APP_SECRET` muss **stabil** bleiben. Ändert es sich, lassen sich vorhandene TOTP-Secrets nicht mehr entschlüsseln – die Authenticator-App des Users wäre dann tot. Der Wert steht in der `.env`:
> ```bash
> APP_SECRET=<64 Hex-Zeichen>
> ```
> Eigenen Wert erzeugen: `python3 -c "import secrets; print(secrets.token_hex(32))"`
> Fehlt der Wert, startet die App trotzdem – aber mit einer Warnung, und die TOTP-Secrets überleben dann keinen Neustart.

## Ressourcenverbrauch

> **Richtwerte, nicht gemessen** – typische Erfahrungswerte für diese Images im Leerlauf bzw. bei wenigen Nutzern. Auf dem Zielsystem lässt sich der echte Verbrauch mit `docker stats` prüfen.

| Container | RAM (ca.) | CPU im Leerlauf | CPU bei Last |
|---|---|---|---|
| `db` (MySQL 8.4) | 400–600 MB | < 1 % | kurze Spitzen bei Abfragen |
| `web` (FastAPI/uvicorn) | 60–100 MB | < 1 % | Argon2id-Hashing beim Login/Registrieren ca. 50 ms CPU-Zeit pro Anfrage |
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
docker compose ps                        # Status der Container
docker compose logs -f web               # Logs der App (inkl. Codes)
docker compose up -d --build web         # Nach Code-Änderungen neu bauen
docker compose down                      # Stoppen (Daten bleiben erhalten)
docker compose down -v                   # Stoppen und Datenbank löschen

docker compose --profile tunnel up -d    # Tunnel zusätzlich starten
docker compose --profile tunnel logs -f  # Tunnel-Logs
```

### Compose-Profile

| Befehl | Startet |
|---|---|
| `docker compose up -d` | nur `db` und `web` → läuft lokal auf http://localhost:5000 |
| `docker compose --profile tunnel up -d` | zusätzlich `cloudflared` → die App ist auch über die HTTPS-Domain erreichbar |

Der `web`-Container hat einen Healthcheck. `docker compose ps` zeigt deshalb `healthy`, sobald die App wirklich bereit ist – nicht nur, dass der Prozess läuft.

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
| `cloudflared` beendet sich mit Fehler 255 | `TUNNEL_TOKEN` fehlt oder ist ungültig. Entweder Token eintragen und mit `--profile tunnel` starten, oder den Tunnel weglassen – die App läuft auch ohne tunnel. Nach 5 Fehlversuchen stoppt der Container (keine Endlosschleife). |
| `web` startet neu / Datenbankfehler | MySQL ist noch nicht bereit; kurz warten und `docker compose logs web` prüfen. Bei geänderten DB-Zugangsdaten das Volume mit `docker compose down -v` zurücksetzen. |
| Kein E-Mail-Code erhalten | Ohne SMTP-Konfiguration wird der Code **im Browser angezeigt** und zusätzlich ins Log geschrieben (`docker compose logs web`). Mit SMTP: Zugangsdaten, Port und Absenderdomain prüfen (Fehler stehen als `Mail-Fehler: …` in den Logs). `curl localhost:5000/api/health` zeigt, ob SMTP überhaupt konfiguriert ist. |
| Registrierung schlägt mit „E-Mail ist bereits registriert" fehl | Die E-Mail existiert schon, das Passwort passt aber nicht. Mit dem **richtigen** Passwort kann die Sicherheitsstufe geändert werden – oder man meldet sich normal an bzw. setzt das Passwort zurück. |
| Authenticator-Code wird abgelehnt | Uhrzeit von Server und Handy synchronisieren (Toleranz: ±30 Sekunden). |
| Login meldet „zu dieser Uhrzeit gesperrt" | `LOGIN_RESTRICTION_ENABLED=false` setzen oder die erlaubten Stunden anpassen. |
| Änderungen an `static/app.js` greifen nicht | Die Script-URL enthält eine Versionsnummer in `templates/index.html` – nach einer Änderung dort hochzählen (z. B. `app.js?v=9`). Das HTML selbst wird mit `Cache-Control: no-cache` immer neu validiert, der Browser holt sich also zuverlässig die neue Version. |

## Architektur

- **FastAPI** (`app.py`) liefert die Seiten aus `templates/` und die API unter `/api/*`; statische Dateien liegen in `static/`.
- **MySQL 8.4** speichert Benutzer (`users`), Sessions (`sessions`) und temporäre Codes (`email_otps`).
- **Passwörter:** Argon2id auf dem Server, mit zufälligem Salt pro User – aus der Datenbank lässt sich ein Passwort nicht zurückrechnen.
- **Cloudflared** stellt die Verbindung über den Cloudflare Tunnel her (keine offenen Ports nötig).

### Dateien

| Datei | Aufgabe |
|---|---|
| `app.py` | FastAPI-App: Sicherheits-Header und die Endpunkte |
| `auth.py` | gemeinsame Abläufe: Sessions, E-Mail-Codes, TOTP inkl. Replay-Schutz |
| `ratelimit.py` | In-Memory-Limiter (gleitendes Zeitfenster) |
| `responses.py` | einheitliche Fehlerantworten (`error`, `too_many_requests`) |
| `security.py` | Argon2id, HMAC, Verschlüsselung, Passwort-Regeln |
| `mailer.py` | SMTP-Versand und Dev-Modus (Code nur im Log) |
| `config.py` | Grenzwerte und Umgebungsvariablen an einer Stelle |
| `database.py` | Engine, Session-Context-Manager, Schema-Upgrade |
| `models.py` | Tabellen `users`, `sessions`, `email_otps` |

Die Trennung ist bewusst flach: keine Service-Klassen, keine Vererbungshierarchie –
nur Module mit klaren Aufgaben. `app.py` enthält deshalb nur noch die Routen.

### Tests

```bash
pip install -r requirements-dev.txt
pytest          # 27 Tests, laufen gegen eine temporäre SQLite-Datei
ruff check .    # Stil- und Import-Prüfung
```

Die Tests decken Registrierung, Login, Session, E-Mail-2FA, TOTP inkl.
Replay-Schutz, Passwort-Reset, die serverseitige Passwortregel, alle
Rate-Limits und die Migration alter Datenbestände ab. Sie brauchen weder
MySQL noch einen Mailserver.

### Konfigurations-Ebenen

| Ebene | Datei | Aufgabe |
|---|---|---|
| Defaults | `docker-compose.yml` | Fallback-Werte via `${VAR:-default}` |
| Secrets | `.env` (gitignored) | überschreibt die Defaults |
| Vorlage | `.env.example` | reine Dokumentation, wirkt **nicht** zur Laufzeit |
| Laufzeit | Container-ENV | wird in `config.py` aus `os.environ` gelesen |

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

Statuscodes der Fehlerfälle: `400` (Eingabe falsch), `401` (E-Mail/Passwort falsch oder Konto existiert schon), `403` (Login gesperrt), `429` (zu viele 2FA-/Reset-Versuche oder Rate-Limit, inkl. `Retry-After`), `500` (Serverfehler).
