import pytest

from tests.test_smoke import HEADERS, ensure_setup

from app.config import settings
from app.database import SessionLocal
from app.models import WebhookSubscription
from app.security import decrypt_secret, hash_with_pepper

@pytest.fixture(autouse=True)
def setup_webhook_test_client(client):
    ensure_setup(client)

def webhook_payload(**overrides):
    payload = {
        "tenant_id": "tenant-demo",
        "target_url": "https://example.com/webhook",
        "event_type": "decision.allowed",
        "signing_secret": "webhook-secret-775",
    }
    payload.update(overrides)
    return payload


# #775
def test_webhook_subscription_accepts_valid_payload(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(),
    )

    assert response.status_code == 200
    assert isinstance(response.json()["subscription_id"], int)


# #776
def test_webhook_subscription_rejects_empty_tenant_id(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(tenant_id=""),
    )

    assert response.status_code == 422


# #777
def test_webhook_subscription_rejects_whitespace_tenant_id(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(tenant_id="   "),
    )

    assert response.status_code == 422


# #778
def test_webhook_subscription_rejects_empty_event_type(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(event_type=""),
    )

    assert response.status_code == 422


# #779
def test_webhook_subscription_rejects_whitespace_event_type(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(event_type="   "),
    )

    assert response.status_code == 422


# #780
def test_webhook_subscription_rejects_empty_signing_secret(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(signing_secret=""),
    )

    assert response.status_code == 422


# #781
def test_webhook_subscription_rejects_whitespace_signing_secret(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(signing_secret="   "),
    )

    assert response.status_code == 422


# #782
def test_webhook_subscription_rejects_invalid_target_url(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(target_url="not-a-url"),
    )

    assert response.status_code == 422


# #783
def test_webhook_subscription_rejects_tenant_mismatch(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(tenant_id="another-tenant"),
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


# #784
def test_webhook_subscription_encrypts_and_hashes_secret(client):
    secret = "webhook-secret-784"

    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(signing_secret=secret),
    )

    assert response.status_code == 200
    subscription_id = response.json()["subscription_id"]

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.signing_secret_encrypted != secret
        assert decrypt_secret(
            subscription.signing_secret_encrypted
        ) == secret
        assert subscription.signing_secret_hash == hash_with_pepper(
            secret,
            settings.webhook_secret_pepper,
        )