"""HTML-Seiten."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy.orm import Session

from app import config
from app.db import get_db
from app.services import sessions

router = APIRouter(tags=["pages"])


@router.get("/")
def login_page() -> FileResponse:
    return FileResponse(config.TEMPLATE_DIR / "index.html")


@router.get("/welcome")
def welcome_page(request: Request, db: Session = Depends(get_db)):
    """Geschützter Bereich - ohne gültige Session zurück zur Startseite."""
    if sessions.resolve_session(db, request) is None:
        response = RedirectResponse(url="/", status_code=303)
        sessions.clear_session_cookie(response)
        return response

    return FileResponse(config.TEMPLATE_DIR / "welcome.html")
