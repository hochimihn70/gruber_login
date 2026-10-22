"""Fehler, die als JSON-Antwort beim Client landen.

Services werfen diese Exceptions, statt `JSONResponse` zurückzugeben. Dadurch
bleibt die Fachlogik frei von HTTP-Details, und die Router müssen nicht an jeder
Stelle prüfen, ob ein Aufruf fehlgeschlagen ist.
"""


class AppError(Exception):
    """Erwarteter Fehler mit Meldung und HTTP-Status."""

    def __init__(self, message: str, status_code: int = 400, headers: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.headers = headers


class RateLimited(AppError):
    """Zu viele Versuche - 429 inklusive `Retry-After`."""

    def __init__(self, wait_seconds: int):
        super().__init__(
            f"Zu viele Versuche. Bitte in {wait_seconds} Sekunden erneut versuchen.",
            status_code=429,
            headers={"Retry-After": str(wait_seconds)},
        )
        self.wait_seconds = wait_seconds
