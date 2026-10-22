"""In-Memory-Rate-Limiter (Sliding Window).

Zählt Versuche pro Schlüssel in einem gleitenden Zeitfenster. Bewusst ohne
Redis: Die App läuft mit einem Prozess. Bei mehreren Workern müsste der Zustand
geteilt werden - das steht als Kommentar in der README.

Der Limiter kennt kein HTTP. Er lässt sich damit mit einer Fake-Uhr testen.
"""

import threading
import time
from collections import deque

# Ab dieser Anzahl Schlüssel werden abgelaufene Einträge aufgeräumt, damit
# ein Angriff mit vielen erfundenen E-Mails keinen Speicher vollmüllt.
PRUNE_THRESHOLD = 10_000
# Alles, was älter ist, kann kein sinnvolles Fenster mehr beeinflussen.
MAX_WINDOW_SECONDS = 24 * 3600


class SlidingWindowLimiter:
    def __init__(self, clock=time.monotonic):
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: int) -> int | None:
        """Registriert einen Versuch.

        None = erlaubt. Sonst die Wartezeit in Sekunden, bis wieder Platz ist.
        """
        now = self._clock()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            self._drop_old(hits, now, window_seconds)

            if len(hits) >= limit:
                return max(1, int(hits[0] + window_seconds - now + 0.999))

            hits.append(now)
            self._maybe_prune(now)
            return None

    def wait_time(self, key: str, limit: int, window_seconds: int) -> int | None:
        """Prüft ohne zu zählen, ob der Schlüssel gerade blockiert ist."""
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return None
            self._drop_old(hits, now, window_seconds)
            if len(hits) < limit:
                return None
            return max(1, int(hits[0] + window_seconds - now + 0.999))

    def record(self, key: str) -> None:
        """Zählt einen Fehlversuch, ohne ein Limit zu prüfen."""
        with self._lock:
            self._hits.setdefault(key, deque()).append(self._clock())

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def reset(self) -> None:
        """Alles vergessen - für Tests."""
        with self._lock:
            self._hits.clear()

    @staticmethod
    def _drop_old(hits: deque[float], now: float, window_seconds: int) -> None:
        cutoff = now - window_seconds
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def _maybe_prune(self, now: float) -> None:
        if len(self._hits) < PRUNE_THRESHOLD:
            return
        cutoff = now - MAX_WINDOW_SECONDS
        for key in [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]:
            del self._hits[key]


limiter = SlidingWindowLimiter()
