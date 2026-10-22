"""Fachlogik, unabhängig von der HTTP-Schicht.

Die Router in `app/routers` sind nur noch Adapter: Request lesen, Service
aufrufen, Ergebnis als JSON zurückgeben. Alles, was Regeln hat (Sessions,
Codes, TOTP, Konten), steht hier.
"""
