"""Landingpage und statische Dateien."""

VIEWS = ("login", "register", "twofactor", "totp", "forgot")


def test_landingpage_enthaelt_alle_ansichten(client):
    response = client.get("/")

    assert response.status_code == 200
    for view in VIEWS:
        assert f'data-view="{view}"' in response.text
    assert "/static/app.js" in response.text


def test_statische_dateien_werden_ausgeliefert(client):
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/welcome.js").status_code == 200


def test_geschuetzte_seite_leitet_ohne_session_um(client):
    response = client.get("/welcome", follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/"
