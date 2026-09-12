import pytest

from tests.test_smoke import HEADERS, ensure_setup

from app.config import settings
from app.database import SessionLocal
from app.models import WebhookSubscription
from app.security import decrypt_secret, hash_with_pepper
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.main import get_db

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

class _TrackingSession:
    def __init__(self, real_db, commit_error=None):
        self.real_db = real_db
        self.commit_error = commit_error
        self.added = []
        self.commit_calls = 0
        self.rollback_calls = 0

    def scalar(self, statement):
        return self.real_db.scalar(statement)

    def add(self, value):
        self.added.append(value)
        self.real_db.add(value)

    def commit(self):
        self.commit_calls += 1
        if self.commit_error is not None:
            raise self.commit_error
        self.real_db.commit()

    def rollback(self):
        self.rollback_calls += 1
        self.real_db.rollback()

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

def test_webhook_subscription_rejects_loopback_target_url(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(
            target_url="http://127.0.0.1:8080/webhook",
        ),
    )

    assert response.status_code == 422

def test_webhook_subscription_rejects_localhost_target_url(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(
            target_url="http://localhost:8080/webhook",
        ),
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

# #785
def test_webhook_subscription_returns_503_on_database_failure(
    client,
):
    real_db = SessionLocal()

    class _FailingCommitSession:
        def __init__(self, real_db, error):
            self.real_db = real_db
            self.error = error
            self.added = None
            self.commit_called = False
            self.rollback_called = False

        def scalar(self, statement):
            return self.real_db.scalar(statement)

        def add(self, value):
            self.added = value
            self.real_db.add(value)

        def commit(self):
            self.commit_called = True
            raise self.error

        def rollback(self):
            self.rollback_called = True
            self.real_db.rollback()

    session = _FailingCommitSession(
        real_db,
        SQLAlchemyError("database_unavailable"),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert response.json()["detail"] == "persistence_unavailable"
    assert session.commit_called is True
    assert session.rollback_called is True
    assert session.added is not None
    assert response.json()["detail"] == "persistence_unavailable"
    assert session.rollback_called is True
    assert session.added is not None

# #786
def test_webhook_subscription_returns_409_on_integrity_conflict(client):
    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        IntegrityError(
            "insert webhook subscription",
            {},
            Exception("constraint_failure"),
        ),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 409
    assert response.json()["detail"] == "webhook_subscription_conflict"


# #787
def test_webhook_subscription_integrity_conflict_rolls_back(client):
    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        IntegrityError(
            "insert webhook subscription",
            {},
            Exception("constraint_failure"),
        ),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert session.commit_calls == 1
    assert session.rollback_calls == 1


# #788
def test_webhook_subscription_database_failure_does_not_persist(client):
    before_count = None

    with SessionLocal() as db:
        before_count = db.query(WebhookSubscription).count()

    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        SQLAlchemyError("database_unavailable"),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(
                target_url="https://example.com/788",
            ),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503

    with SessionLocal() as db:
        after_count = db.query(WebhookSubscription).count()

    assert after_count == before_count


# #789
def test_webhook_subscription_integrity_conflict_does_not_persist(client):
    with SessionLocal() as db:
        before_count = db.query(WebhookSubscription).count()

    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        IntegrityError(
            "insert webhook subscription",
            {},
            Exception("constraint_failure"),
        ),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(
                target_url="https://example.com/789",
            ),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 409

    with SessionLocal() as db:
        after_count = db.query(WebhookSubscription).count()

    assert after_count == before_count


# #790
def test_webhook_subscription_recovers_after_database_failure(client):
    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        SQLAlchemyError("database_unavailable"),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        failed_response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(
                target_url="https://example.com/790-failed",
            ),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert failed_response.status_code == 503

    success_response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(
            target_url="https://example.com/790-success",
        ),
    )

    assert success_response.status_code == 200
    assert isinstance(
        success_response.json()["subscription_id"],
        int,
    )


# #791
def test_webhook_subscription_recovers_after_integrity_conflict(client):
    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        IntegrityError(
            "insert webhook subscription",
            {},
            Exception("constraint_failure"),
        ),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        failed_response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(
                target_url="https://example.com/791-failed",
            ),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert failed_response.status_code == 409

    success_response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(
            target_url="https://example.com/791-success",
        ),
    )

    assert success_response.status_code == 200


# #792
def test_webhook_subscription_success_commits_once(client):
    real_db = SessionLocal()
    session = _TrackingSession(real_db)

    def tracking_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = tracking_db

    try:
        response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(
                target_url="https://example.com/792",
            ),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert session.commit_calls == 1
    assert session.rollback_calls == 0


# #793
def test_webhook_subscription_database_error_is_not_exposed(client):
    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        SQLAlchemyError("secret_database_failure_details"),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert response.json() == {
        "detail": "persistence_unavailable",
    }
    assert "secret_database_failure_details" not in response.text


# #794
def test_webhook_subscription_integrity_error_is_not_exposed(client):
    real_db = SessionLocal()
    session = _TrackingSession(
        real_db,
        IntegrityError(
            "secret_insert_statement",
            {"secret": "value"},
            Exception("secret_constraint_details"),
        ),
    )

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        response = client.post(
            "/webhooks/subscriptions",
            headers=HEADERS,
            json=webhook_payload(),
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "webhook_subscription_conflict",
    }
    assert "secret_constraint_details" not in response.text