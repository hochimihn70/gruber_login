# Einfaches Login mit FastAPI und MySQL

## Start

1. Konfigurationsdatei aus Vorlage anlegen:
   ```bash
   cp .env.example .env
   ```
2. In der `.env`-Datei das Cloudflare Tunnel Token bei `TUNNEL_TOKEN` eintragen.
3. Im Cloudflare Zero Trust Dashboard für den Tunnel den Public Hostname anlegen:
   - **Domain:** `logintest.smoothingo.com`
   - **Type:** `HTTP`
   - **URL:** `web:5000`
4. Container starten:
   ```bash
   docker compose up -d --build
   ```

Danach ist die Anwendung sicher über HTTPS unter https://logintest.smoothingo.com erreichbar (lokal weiterhin unter http://localhost:5000).

## 2-Faktor-Authentifizierung (2FA) & Session-Schutz

- **Routenschutz:** Die Willkommensseite `/welcome` ist geschützt. Wer ohne gültige Session darauf zugreift, wird automatisch auf `/` (Login) weitergeleitet.
- **2FA-Ablauf:** Nach Eingabe von E-Mail und Passwort wird ein 6-stelliger Code generiert (10 Minuten gültig). Nach Eingabe des Codes wird eine sichere 7-tägige Session als HttpOnly-Cookie gesetzt.
- **E-Mail-Zustellung:** Über Standard-SMTP in der `.env`.
  - **Kostenlose Empfehlung:** [Resend](https://resend.com) (3.000 Mails/Monat gratis, einfache DNS-Einbindung in Cloudflare).
  - **Dev-Modus:** Solange keine SMTP-Daten eingetragen sind, wird der Verifizierungscode direkt in den Logs ausgegeben (`docker logs gruber_login-web-1`).

## Architektur

- MySQL speichert Benutzer, Sessions und temporäre 2FA-Codes.
- Das Passwort wird mit bcrypt als Hash gespeichert und kann nicht zurückgerechnet werden.
- Cloudflared stellt eine sichere Verbindung über den Cloudflare Tunnel her (keine offenen Ports nötig).
