"""FastAPI-Anwendung: App-Factory, Middleware und Fehlerbehandlung.

Die eigentlichen Abläufe liegen in `app/routers` (HTTP) und `app/services`
(Fachlogik). Diese Datei verbindet beides und enthält sonst nichts.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app import config
from app.db import init_db
from app.errors import AppError
from app.mailer import log_startup_status
from app.routers import auth, pages, password, system

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Startarbeiten bewusst nicht beim Import, sonst hätte schon das bloße
    Importieren der App Seiteneffekte (DB-Verbindung, Migration, Logging)."""
    init_db()
    log_startup_status()
    yield


def create_app() -> FastAPI:
    """Baut die App zusammen: Routen, Static-Files, Header, Fehler."""
    application = FastAPI(title=config.APP_NAME, lifespan=lifespan)

    application.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
    application.middleware("http")(security_headers)

    @application.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        """Alle erwarteten Fehler werden hier einheitlich zu JSON."""
        return JSONResponse({"error": exc.message}, status_code=exc.status_code, headers=exc.headers)

    application.include_router(pages.router)
    application.include_router(auth.router)
    application.include_router(password.router)
    application.include_router(system.router)
    return application


async def security_headers(request: Request, call_next):
    """Standard-Sicherheits-Header bei jeder Antwort.

    - X-Frame-Options:           kein Einbetten in fremde iframes (Clickjacking)
    - X-Content-Type-Options:    Browser soll den Inhalt nicht sniffen
    - Referrer-Policy:           keine fremden URLs an Dritte weitergeben
    - Content-Security-Policy:   nur eigene Scripts/Styles, kein Inline-JavaScript

    Hinweis zu Cloudflare: Der Tunnel injiziert ein eigenes Script in die
    HTML-Ausgabe (Bot-Erkennung). Die strikte CSP blockiert es - die App selbst
    läuft davon nicht betroffen.
    """
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; frame-ancestors 'none'"
    )
    # HTML immer neu validieren lassen, sonst hält der Browser eine alte app.js fest.
    if "text/html" in response.headers.get("content-type", ""):
        response.headers["Cache-Control"] = "no-cache"
    return response


app = create_app()
