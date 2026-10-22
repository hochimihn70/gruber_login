"""Tests für Rate-Limiting, TOTP-Bremse und Replay-Schutz."""

import time

import pyotp
import pytest
from helpers import login, register, request_reset, verify

from app import config
from app.ratelimit import SlidingWindowLimiter


class FakeClock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now


def test_limiter_zählt_im_gleitenden_fenster():
    clock = FakeClock()
    limiter = SlidingWindowLimiter(clock)

    assert limiter.hit("k", limit=2, window_seconds=60) is None
    assert limiter.hit("k", limit=2, window_seconds=60) is None
    assert limiter.hit("k", limit=2, window_seconds=60) == 60

    clock.now += 30
    assert limiter.hit("k", limit=2, window_seconds=60) == 30

    clock.now += 31  # beide alten Treffer sind jetzt älter als 60 s
    assert limiter.hit("k", limit=2, window_seconds=60) is None


def test_wait_time_zählt_nicht_mit():
    limiter = SlidingWindowLimiter(FakeClock())
    limiter.hit("k", limit=1, window_seconds=60)

    assert limiter.wait_time("k", limit=1, window_seconds=60) is not None
    assert limiter.wait_time("k", limit=2, window_seconds=60) is None
    assert limiter.hit("k", limit=2, window_seconds=60) is None  # nur ein Treffer gezählt


@pytest.fixture
def aktives_limit(monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(config, "REGISTER_LIMIT_PER_IP", (100, 3600))
    monkeypatch.setattr(config, "LOGIN_LIMIT_PER_IP", (100, 900))
    monkeypatch.setattr(config, "LOGIN_LIMIT_PER_EMAIL", (100, 900))
    monkeypatch.setattr(config, "VERIFY_LIMIT_PER_IP", (100, 900))
    monkeypatch.setattr(config, "FORGOT_LIMIT_PER_IP", (100, 900))
    monkeypatch.setattr(config, "FORGOT_LIMIT_PER_EMAIL", (100, 3600))


def test_login_wird_pro_ip_gebremst(client, aktives_limit, monkeypatch):
    monkeypatch.setattr(config, "LOGIN_LIMIT_PER_IP", (3, 60))

    for _ in range(3):
        assert login(client, email="egal@example.com").status_code == 401

    response = login(client, email="egal@example.com")
    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_login_wird_pro_mail_gebremst(client, aktives_limit, monkeypatch):
    register(client)
    monkeypatch.setattr(config, "LOGIN_LIMIT_PER_EMAIL", (2, 900))

    assert login(client, password="falsch1234").status_code == 401
    assert login(client, password="falsch1234").status_code == 401
    assert login(client, password="falsch1234").status_code == 429


def test_registrierung_wird_gebremst(client, aktives_limit, monkeypatch):
    monkeypatch.setattr(config, "REGISTER_LIMIT_PER_IP", (1, 3600))

    assert register(client, email="eins@example.com").status_code == 200
    assert register(client, email="zwei@example.com").status_code == 429


def test_reset_anfrage_wird_pro_mail_gebremst(client, aktives_limit, monkeypatch):
    register(client)
    monkeypatch.setattr(config, "FORGOT_LIMIT_PER_EMAIL", (1, 3600))

    assert request_reset(client).status_code == 200
    assert request_reset(client).status_code == 429


def test_totp_wird_nach_fünf_fehlversuchen_gebremst(client, aktives_limit, monkeypatch):
    monkeypatch.setattr(config, "TOTP_LIMIT_PER_EMAIL", (5, 900))
    secret = register(client, method="totp").json()["totp_secret"]
    login(client)

    for _ in range(5):
        assert verify(client, "test@example.com", falscher_totp_code(secret)).status_code == 400

    assert verify(client, "test@example.com", falscher_totp_code(secret)).status_code == 429
    # Auch der richtige Code bleibt gesperrt, bis das Fenster abgelaufen ist.
    assert verify(client, "test@example.com", pyotp.TOTP(secret).now()).status_code == 429


def test_totp_code_kann_nicht_wiederverwendet_werden(client):
    secret = register(client, method="totp").json()["totp_secret"]
    login(client)
    code = pyotp.TOTP(secret).now()

    assert verify(client, "test@example.com", code).status_code == 200

    replay = verify(client, "test@example.com", code)
    assert replay.status_code == 400
    assert "bereits verwendet" in replay.json()["error"]


def falscher_totp_code(secret: str) -> str:
    """6-stelliger Code, der sicher nicht im aktuellen Toleranzfenster gültig ist."""
    totp = pyotp.TOTP(secret)
    now = time.time()
    valid_codes = {totp.at(now + offset * totp.interval) for offset in (-1, 0, 1)}
    return next(code for code in ("000000", "111111", "222222") if code not in valid_codes)
