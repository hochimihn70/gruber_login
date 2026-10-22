"""End-to-End-Tests für die Auth-Abläufe (SQLite, Dev-Modus ohne SMTP)."""

from datetime import datetime

import pyotp
from cryptography.fernet import Fernet
from helpers import login, register, request_reset, reset, verify

from app import db as app_db
from app.db import db_session
from app.models import User
from app.security import decrypt_secret

# --- Registrierung & Login ------------------------------------------------------------------


def test_registrierung_loggt_direkt_ein(client):
    response = register(client)

    assert response.status_code == 200
    assert response.json()["redirect"] == "/welcome"
    assert client.get("/api/me").json()["email"] == "test@example.com"
    assert client.get("/welcome").status_code == 200


def test_passwortregel_gilt_auch_serverseitig(client):
    response = register(client, password="kurz")

    assert response.status_code == 400
    assert "mindestens 8" in response.json()["error"]


def test_bestehendes_konto_bleibt_ohne_passwort_unverändert(client):
    register(client)

    response = register(client, password="falschesPasswort1", method="email_otp")

    assert response.status_code == 401
    # Das ursprüngliche Passwort funktioniert weiterhin.
    assert login(client).json()["status"] == "success"


def test_login_meldet_unbekannte_mail_wie_falsches_passwort(client):
    register(client)

    falsch = login(client, password="falschesPasswort1")
    unbekannt = login(client, email="niemand@example.com", password="falschesPasswort1")

    assert falsch.status_code == unbekannt.status_code == 401
    assert falsch.json()["error"] == unbekannt.json()["error"]


def test_logout_beendet_die_session(client):
    register(client)

    assert client.post("/api/logout").status_code == 200
    assert client.get("/api/me").status_code == 401


# --- E-Mail-Code (2FA) ----------------------------------------------------------------------


def test_email_code_führt_zum_login(client):
    response = register(client, method="email_otp")
    data = response.json()
    assert data["status"] == "2fa_required"
    code = data["dev_code"]

    falsch = verify(client, "test@example.com", "000000")
    assert falsch.status_code == 400
    assert "Noch 4 Versuche" in falsch.json()["error"]

    richtig = verify(client, "test@example.com", code)
    assert richtig.status_code == 200
    assert client.get("/api/me").json()["email"] == "test@example.com"


def test_email_code_wird_nach_fünf_fehlversuchen_ungültig(client):
    code = register(client, method="email_otp").json()["dev_code"]

    for _ in range(5):
        response = verify(client, "test@example.com", "000000")

    assert response.status_code == 429
    # Auch der richtige Code ist jetzt verbraucht.
    assert verify(client, "test@example.com", code).status_code == 400


# --- Authenticator-App (TOTP) ---------------------------------------------------------------


def test_totp_einrichtung_und_login(client):
    response = register(client, method="totp")
    data = response.json()
    assert data["status"] == "totp_setup"
    assert data["totp_secret"]
    assert "<svg" in data["qr_svg"]

    challenge = login(client)
    assert challenge.json()["method"] == "totp"

    code = pyotp.TOTP(data["totp_secret"]).now()
    assert verify(client, "test@example.com", code).status_code == 200
    assert client.get("/api/me").status_code == 200


def test_totp_falscher_code_wird_abgelehnt(client):
    register(client, method="totp")
    login(client)

    assert verify(client, "test@example.com", "000000").status_code == 400


def test_totp_secret_bleibt_bei_erneuter_registrierung_erhalten(client):
    erstes_secret = register(client, method="totp").json()["totp_secret"]

    zweites_secret = register(client, method="totp").json()["totp_secret"]

    assert zweites_secret == erstes_secret


# --- Passwort-Reset -------------------------------------------------------------------------


def test_reset_setzt_passwort_und_beendet_alte_sessions(client):
    register(client)
    code = request_reset(client).json()["dev_code"]

    assert reset(client, "test@example.com", "000000").status_code == 400
    assert reset(client, "test@example.com", code).status_code == 200

    # Die Session von vor dem Reset ist ungültig.
    assert client.get("/api/me").status_code == 401
    assert login(client, password="neuesgeheim123").status_code == 200


def test_reset_code_hat_dieselbe_brute_force_bremse(client):
    register(client)
    request_reset(client)

    for _ in range(5):
        response = reset(client, "test@example.com", "000000")

    assert response.status_code == 429


def test_reset_verrät_keine_registrierten_mails(client):
    response = request_reset(client, email="niemand@example.com")

    assert response.status_code == 200
    assert "dev_code" not in response.json()


def test_reset_verrät_keinen_code_wenn_der_versand_fehlschlägt(client, monkeypatch):
    register(client)
    monkeypatch.setattr("app.config.smtp_is_configured", lambda: True)
    monkeypatch.setattr("app.services.email_otp.send_otp_email", lambda *args, **kwargs: False)

    response = request_reset(client)

    assert response.status_code == 500
    assert "dev_code" not in response.json()


def test_2fa_verrät_keinen_code_wenn_der_versand_fehlschlägt(client, monkeypatch):
    monkeypatch.setattr("app.config.smtp_is_configured", lambda: True)
    monkeypatch.setattr("app.services.email_otp.send_otp_email", lambda *args, **kwargs: False)

    response = register(client, method="email_otp")

    assert response.status_code == 500
    assert "dev_code" not in response.json()


def test_reset_lehnt_kurzes_passwort_ab(client):
    register(client)
    code = request_reset(client).json()["dev_code"]

    response = reset(client, "test@example.com", code, new_password="kurz")

    assert response.status_code == 400


# --- Status-Endpunkt ------------------------------------------------------------------------


def test_health_zeigt_keine_smtp_zugangsdaten(client):
    data = client.get("/api/health").json()

    assert data["database"] == "ok"
    assert data["dev_mode"] is True
    for key in ("smtp_host", "smtp_port", "smtp_from", "smtp_password"):
        assert key not in data


# --- Migration alter Datenbestände ----------------------------------------------------------


def test_klartext_totp_secret_wird_verschlüsselt(client):
    with db_session() as db:
        db.add(
            User(
                email="alt@example.com",
                password="egal",
                auth_method="totp",
                totp_secret="JBSWY3DPEHPK3PXP",
                created_at=datetime.now(),
            )
        )
        db.commit()

    app_db._encrypt_legacy_totp_secrets()

    with db_session() as db:
        stored = db.query(User).filter_by(email="alt@example.com").one().totp_secret

    assert stored.startswith("gAAAA")
    assert decrypt_secret(stored) == "JBSWY3DPEHPK3PXP"


def test_unlesbares_token_wird_nicht_doppelt_verschlüsselt(client):
    fremdes_token = Fernet(Fernet.generate_key()).encrypt(b"altes-secret").decode()
    with db_session() as db:
        db.add(
            User(
                email="alt2@example.com",
                password="egal",
                auth_method="totp",
                totp_secret=fremdes_token,
                created_at=datetime.now(),
            )
        )
        db.commit()

    app_db._encrypt_legacy_totp_secrets()

    with db_session() as db:
        stored = db.query(User).filter_by(email="alt2@example.com").one().totp_secret

    assert stored == fremdes_token
