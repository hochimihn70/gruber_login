# Einfaches Login mit FastAPI und MySQL

## Start

```powershell
docker compose up --build
```

Danach ist die Anwendung unter http://localhost:5000 erreichbar.

## Architektur

- MySQL speichert E-Mail, Passwort und Login-Zeitstempel.
- Das Passwort wird mit bcrypt als Hash gespeichert und kann nicht zurueckgerechnet werden.
- Der Login ist jederzeit moeglich.

Fuer Produktion muss HTTPS verwendet werden.
