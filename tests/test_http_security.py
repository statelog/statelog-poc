from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


def test_security_headers_are_present(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert (
        response.headers["Permissions-Policy"]
        == "camera=(), microphone=(), geolocation=()"
    )


def test_hsts_is_absent_outside_production(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_is_absent_for_plain_http_in_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "prod")

    with TestClient(app, base_url="http://testserver") as test_client:
        response = test_client.get("/healthz")

    assert response.status_code == 200
    assert "Strict-Transport-Security" not in response.headers


def test_hsts_is_present_for_https_in_production(monkeypatch):
    monkeypatch.setattr(settings, "environment", "prod")

    with TestClient(app, base_url="https://testserver") as test_client:
        response = test_client.get("/healthz")

    assert response.status_code == 200
    assert (
        response.headers["Strict-Transport-Security"]
        == "max-age=31536000; includeSubDomains"
    )


def test_untrusted_host_is_rejected(client):
    response = client.get(
        "/healthz",
        headers={"Host": "evil.example"},
    )

    assert response.status_code == 400


def test_trusted_host_is_allowed(client):
    response = client.get(
        "/healthz",
        headers={"Host": "testserver"},
    )

    assert response.status_code == 200


def test_docs_are_available_outside_production(client):
    response = client.get("/docs")

    assert response.status_code == 200


def test_openapi_is_available_outside_production(client):
    response = client.get("/openapi.json")

    assert response.status_code == 200