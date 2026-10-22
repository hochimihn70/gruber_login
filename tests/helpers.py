"""Kleine Helfer für die API-Aufrufe in den Tests."""


def register(client, email="test@example.com", password="geheim123", method="password"):
    return client.post(
        "/api/register",
        json={"email": email, "password": password, "auth_method": method},
    )


def login(client, email="test@example.com", password="geheim123"):
    return client.post("/api/login", json={"email": email, "password": password})


def verify(client, email, code):
    return client.post("/api/verify-2fa", json={"email": email, "code": code})


def request_reset(client, email="test@example.com"):
    return client.post("/api/forgot-password", json={"email": email})


def reset(client, email, code, new_password="neuesgeheim123"):
    return client.post(
        "/api/reset-password",
        json={"email": email, "code": code, "new_password": new_password},
    )
