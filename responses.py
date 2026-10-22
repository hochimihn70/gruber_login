"""Einheitliche JSON-Fehlerantworten.

Vorher stand `JSONResponse({"error": ...}, status_code=...)` an rund 20 Stellen.
Drei Wiederholungen sind die Grenze - danach wird abstrahiert.
"""

from fastapi.responses import JSONResponse


def error(message: str, status_code: int = 400, headers: dict | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status_code, headers=headers)


def too_many_requests(wait_seconds: int) -> JSONResponse:
    return error(
        f"Zu viele Versuche. Bitte in {wait_seconds} Sekunden erneut versuchen.",
        status_code=429,
        headers={"Retry-After": str(wait_seconds)},
    )
