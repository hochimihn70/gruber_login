"""Bremse gegen Durchprobieren: Client-IP, Rate-Limits, Login-Zeitfenster."""

from fastapi import Request

from app import config
from app.errors import AppError, RateLimited
from app.ratelimit import limiter


def client_ip(request: Request) -> str:
    """IP des Aufrufers - hinter einem Proxy aus X-Forwarded-For.

    Der Header ist nur vertrauenswürdig, wenn tatsächlich ein Proxy davorsteht
    (TRUST_PROXY_HEADERS). Sonst könnte ihn jeder selbst setzen und das Limit
    umgehen.
    """
    if config.TRUST_PROXY_HEADERS:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def enforce_limit(request: Request, bucket: str, limits: tuple[int, int], subject: str = "") -> None:
    """Zählt einen Versuch und wirft bei Überschreitung `RateLimited`.

    Pro Aufruf wird entweder die IP (Standard) oder bei `subject` z. B. die
    E-Mail-Adresse gezählt - so lässt sich beides kombinieren.
    """
    if not config.RATE_LIMIT_ENABLED:
        return

    limit, window_seconds = limits
    key = f"{bucket}:{subject or client_ip(request)}"
    wait = limiter.hit(key, limit, window_seconds)
    if wait is not None:
        raise RateLimited(wait)


def enforce_login_window() -> None:
    """Wirft 403, wenn der Login gerade zeitlich gesperrt ist."""
    message = config.login_window_error()
    if message:
        raise AppError(message, status_code=403)
