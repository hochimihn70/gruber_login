"""Test-Setup: eigene SQLite-Datei und feste Umgebung, bevor die App importiert wird."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Muss vor dem Import von app/config/database passieren.
_TEST_DIR = tempfile.mkdtemp(prefix="gruber-login-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DIR}/test.db"
os.environ["APP_SECRET"] = "test-secret-nur-zum-testen"
os.environ["SESSION_COOKIE_SECURE"] = "false"
os.environ["LOGIN_RESTRICTION_ENABLED"] = "false"
os.environ["RATE_LIMIT_ENABLED"] = "false"  # einzelne Tests aktivieren es gezielt
os.environ["TRUST_PROXY_HEADERS"] = "false"
# Dev-Modus erzwingen: kein echter Mailversand, Codes kommen in der Antwort zurück.
os.environ["SMTP_HOST"] = ""
os.environ["SMTP_PORT"] = "587"
os.environ["SMTP_USER"] = ""
os.environ["SMTP_PASSWORD"] = ""
os.environ["SMTP_FROM"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402
from database import Base, engine  # noqa: E402
from ratelimit import limiter  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_database():
    """Jeder Test startet mit leeren Tabellen."""
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
