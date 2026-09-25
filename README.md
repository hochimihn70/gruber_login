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

## Architektur

- MySQL speichert E-Mail, Passwort und Login-Zeitstempel.
- Das Passwort wird mit bcrypt als Hash gespeichert und kann nicht zurueckgerechnet werden.
- Cloudflared stellt eine sichere Verbindung über den Cloudflare Tunnel her (keine offenen Ports im Router/Proxmox nötig).
- Der Login ist jederzeit moeglich.
