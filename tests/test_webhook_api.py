import json
import pytest

from tests.test_smoke import ADMIN_HEADERS, HEADERS, ensure_setup

from app.config import settings
import app.security as security_module
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

def test_webhook_subscription_records_secret_encryption_key_version(
    client,
    monkeypatch,
):
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "enc-v7",
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        "",
    )

    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json=webhook_payload(
            signing_secret="webhook-encryption-version-test",
        ),
    )

    assert response.status_code == 200
    subscription_id = response.json()["subscription_id"]

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.signing_secret_key_version == "enc-v7"
        assert subscription.signing_secret_key_version_verified is True

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

def test_admin_reencrypts_webhook_secret_with_active_encryption_key(
    client,
    monkeypatch,
):
    old_key = "old-webhook-encryption-key-123456"
    new_key = "new-webhook-encryption-key-123456"
    secret = "webhook-secret-to-reencrypt"

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v1": old_key,
                "v2": new_key,
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v1",
    )

    encrypted_with_old_key = security_module.encrypt_secret(secret)

    with SessionLocal() as db:
        subscription = WebhookSubscription(
            tenant_id="tenant-demo",
            target_url="https://example.com/reencrypt",
            event_type="decision.allowed",
            signing_secret_hash=hash_with_pepper(
                secret,
                settings.webhook_secret_pepper,
            ),
            signing_secret_encrypted=encrypted_with_old_key,
            signing_secret_key_version="v1",
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        subscription_id = subscription.id

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    response = client.post(
        "/admin/webhooks/re-encrypt",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["reencrypted"] == 1

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.signing_secret_key_version == "v2"
        assert (
            subscription.signing_secret_encrypted
            != encrypted_with_old_key
        )
        assert security_module.decrypt_secret(
            subscription.signing_secret_encrypted,
            key_version="v2",
        ) == secret
def test_admin_reencrypt_skips_subscription_already_on_active_key(
    client,
    monkeypatch,
):
    key = "active-webhook-encryption-key-123456"
    secret = "already-active-webhook-secret"

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v2": key,
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    encrypted = security_module.encrypt_secret(secret)

    with SessionLocal() as db:
        subscription = WebhookSubscription(
            tenant_id="tenant-demo",
            target_url="https://example.com/already-active",
            event_type="decision.allowed",
            signing_secret_hash=hash_with_pepper(
                secret,
                settings.webhook_secret_pepper,
            ),
            signing_secret_encrypted=encrypted,
            signing_secret_key_version="v2",
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        subscription_id = subscription.id

    response = client.post(
        "/admin/webhooks/re-encrypt",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["reencrypted"] == 0

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.signing_secret_key_version == "v2"
        assert subscription.signing_secret_encrypted == encrypted
def test_admin_reencrypt_database_failure_rolls_back_and_returns_503(
    client,
    monkeypatch,
):
    old_key = "old-webhook-encryption-key-123456"
    new_key = "new-webhook-encryption-key-123456"
    secret = "webhook-secret-rollback-test"

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v1": old_key,
                "v2": new_key,
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v1",
    )

    encrypted_with_old_key = security_module.encrypt_secret(secret)

    with SessionLocal() as db:
        subscription = WebhookSubscription(
            tenant_id="tenant-demo",
            target_url="https://example.com/reencrypt-rollback",
            event_type="decision.allowed",
            signing_secret_hash=hash_with_pepper(
                secret,
                settings.webhook_secret_pepper,
            ),
            signing_secret_encrypted=encrypted_with_old_key,
            signing_secret_key_version="v1",
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        subscription_id = subscription.id

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    real_db = SessionLocal()

    class _FailingReencryptSession:
        def __init__(self, real_db):
            self.real_db = real_db
            self.commit_calls = 0
            self.rollback_calls = 0

        def scalars(self, statement):
            return self.real_db.scalars(statement)

        def execute(self, statement):
            return self.real_db.execute(statement)

        def get(self, model, identity):
            return self.real_db.get(model, identity)

        def commit(self):
            self.commit_calls += 1
            raise SQLAlchemyError("database_unavailable")

        def rollback(self):
            self.rollback_calls += 1
            self.real_db.rollback()

    session = _FailingReencryptSession(real_db)

    def failing_db():
        try:
            yield session
        finally:
            real_db.close()

    client.app.dependency_overrides[get_db] = failing_db

    try:
        response = client.post(
            "/admin/webhooks/re-encrypt",
            headers=ADMIN_HEADERS,
        )
    finally:
        client.app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert response.json()["detail"] == "persistence_unavailable"
    assert session.commit_calls == 1
    assert session.rollback_calls == 1

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.signing_secret_key_version == "v1"
        assert (
            subscription.signing_secret_encrypted
            == encrypted_with_old_key
        )


def test_admin_reencrypt_requires_admin_auth(client):
    response = client.post(
        "/admin/webhooks/re-encrypt",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_admin_reencrypt_undecryptable_secret_rolls_back_entire_batch(
    client,
    monkeypatch,
):
    old_key = "old-webhook-encryption-key-123456"
    new_key = "new-webhook-encryption-key-123456"
    valid_secret = "valid-webhook-secret"

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v1": old_key,
                "v2": new_key,
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v1",
    )

    valid_ciphertext = security_module.encrypt_secret(valid_secret)

    with SessionLocal() as db:
        valid_subscription = WebhookSubscription(
            tenant_id="tenant-demo",
            target_url="https://example.com/reencrypt-valid",
            event_type="decision.allowed",
            signing_secret_hash=hash_with_pepper(
                valid_secret,
                settings.webhook_secret_pepper,
            ),
            signing_secret_encrypted=valid_ciphertext,
            signing_secret_key_version="v1",
        )
        invalid_subscription = WebhookSubscription(
            tenant_id="tenant-demo",
            target_url="https://example.com/reencrypt-invalid",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="not-valid-fernet-ciphertext",
            signing_secret_key_version="v1",
        )

        db.add(valid_subscription)
        db.add(invalid_subscription)
        db.commit()
        db.refresh(valid_subscription)
        db.refresh(invalid_subscription)

        valid_subscription_id = valid_subscription.id
        invalid_subscription_id = invalid_subscription.id

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    response = client.post(
        "/admin/webhooks/re-encrypt",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "webhook_secret_reencryption_failed"

    with SessionLocal() as db:
        valid_subscription = db.get(
            WebhookSubscription,
            valid_subscription_id,
        )
        invalid_subscription = db.get(
            WebhookSubscription,
            invalid_subscription_id,
        )

        assert valid_subscription is not None
        assert invalid_subscription is not None

        assert valid_subscription.signing_secret_key_version == "v1"
        assert valid_subscription.signing_secret_encrypted == valid_ciphertext

        assert invalid_subscription.signing_secret_key_version == "v1"
        assert (
            invalid_subscription.signing_secret_encrypted
            == "not-valid-fernet-ciphertext"
        )

def _create_reencrypt_batch_subscriptions(
    *,
    count,
    old_key,
):
    original_ciphertexts = {}

    security_module.settings.secret_encryption_active_kid = "v1"

    with SessionLocal() as db:
        for index in range(count):
            secret = f"batch-secret-{index}"
            encrypted = security_module.encrypt_secret(secret)

            subscription = WebhookSubscription(
                tenant_id="tenant-demo",
                target_url=f"https://example.com/batch-{index}",
                event_type="decision.allowed",
                signing_secret_hash=hash_with_pepper(
                    secret,
                    settings.webhook_secret_pepper,
                ),
                signing_secret_encrypted=encrypted,
                signing_secret_key_version="v1",
            )
            db.add(subscription)
            db.flush()

            original_ciphertexts[subscription.id] = encrypted

        db.commit()

    return original_ciphertexts


def test_admin_reencrypt_respects_explicit_batch_limit(
    client,
    monkeypatch,
):
    old_key = "old-webhook-encryption-key-123456"
    new_key = "new-webhook-encryption-key-123456"

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v1": old_key,
                "v2": new_key,
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v1",
    )

    original_ciphertexts = _create_reencrypt_batch_subscriptions(
        count=3,
        old_key=old_key,
    )

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    response = client.post(
        "/admin/webhooks/re-encrypt?limit=2",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["reencrypted"] == 2
    assert response.json()["remaining"] is True

    with SessionLocal() as db:
        subscriptions = (
            db.query(WebhookSubscription)
            .filter(
                WebhookSubscription.id.in_(
                    original_ciphertexts.keys()
                )
            )
            .order_by(WebhookSubscription.id)
            .all()
        )

        assert [
            subscription.signing_secret_key_version
            for subscription in subscriptions
        ] == ["v2", "v2", "v1"]


def test_admin_reencrypt_second_batch_finishes_remaining_rows(
    client,
    monkeypatch,
):
    old_key = "old-webhook-encryption-key-123456"
    new_key = "new-webhook-encryption-key-123456"

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v1": old_key,
                "v2": new_key,
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v1",
    )

    _create_reencrypt_batch_subscriptions(
        count=3,
        old_key=old_key,
    )

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    first_response = client.post(
        "/admin/webhooks/re-encrypt?limit=2",
        headers=ADMIN_HEADERS,
    )
    second_response = client.post(
        "/admin/webhooks/re-encrypt?limit=2",
        headers=ADMIN_HEADERS,
    )

    assert first_response.status_code == 200
    assert first_response.json()["reencrypted"] == 2
    assert first_response.json()["remaining"] is True

    assert second_response.status_code == 200
    assert second_response.json()["reencrypted"] == 1
    assert second_response.json()["remaining"] is False


def test_admin_reencrypt_zero_limit_is_rejected(client):
    response = client.post(
        "/admin/webhooks/re-encrypt?limit=0",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 422


def test_admin_reencrypt_negative_limit_is_rejected(client):
    response = client.post(
        "/admin/webhooks/re-encrypt?limit=-1",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 422


def test_admin_reencrypt_excessive_limit_is_rejected(client):
    response = client.post(
        "/admin/webhooks/re-encrypt?limit=1001",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 422

def test_admin_reencrypt_repairs_historically_mislabeled_active_key_version(
    client,
    monkeypatch,
):
    old_key = "old-webhook-encryption-key-123456"
    new_key = "new-webhook-encryption-key-123456"
    secret = "historically-mislabeled-secret"

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v1": old_key,
                "v2": new_key,
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v1",
    )

    old_ciphertext = security_module.encrypt_secret(secret)

    with SessionLocal() as db:
        subscription = WebhookSubscription(
            tenant_id="tenant-demo",
            target_url="https://example.com/mislabeled",
            event_type="decision.allowed",
            signing_secret_hash=hash_with_pepper(
                secret,
                settings.webhook_secret_pepper,
            ),
            signing_secret_encrypted=old_ciphertext,
            signing_secret_key_version="v2",
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        subscription_id = subscription.id

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    response = client.post(
        "/admin/webhooks/re-encrypt?limit=100",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.signing_secret_key_version == "v2"
        assert subscription.signing_secret_encrypted != old_ciphertext
        assert subscription.signing_secret_key_version_verified is True

def test_webhook_subscription_can_be_disabled(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "target_url": "https://example.com/webhook",
            "event_type": "access.decision",
            "signing_secret": "test-webhook-secret",
        },
    )

    assert response.status_code == 200
    subscription_id = response.json()["subscription_id"]

    disable_response = client.post(
        f"/webhooks/subscriptions/{subscription_id}/disable",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
        },
    )

    assert disable_response.status_code == 200
    assert disable_response.json() == {
        "subscription_id": subscription_id,
        "enabled": False,
    }

    from app.database import SessionLocal
    from app.models import WebhookSubscription

    with SessionLocal() as db:
        subscription = db.get(WebhookSubscription, subscription_id)
        assert subscription is not None
        assert subscription.enabled is False

def test_webhook_subscription_disable_returns_404_for_unknown_subscription(client):
    response = client.post(
        "/webhooks/subscriptions/999999/disable",
        headers=HEADERS,
        json={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "webhook_subscription_not_found"


def test_webhook_subscription_disable_is_tenant_isolated(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "target_url": "https://example.com/webhook",
            "event_type": "access.decision",
            "signing_secret": "test-webhook-secret",
        },
    )
    assert response.status_code == 200
    subscription_id = response.json()["subscription_id"]

    response = client.post(
        f"/webhooks/subscriptions/{subscription_id}/disable",
        headers=HEADERS,
        json={"tenant_id": "tenant-other"},
    )

    assert response.status_code in (403, 404)


def test_webhook_subscription_disable_requires_client_authentication(client):
    response = client.post(
        "/webhooks/subscriptions/1/disable",
        json={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "missing_client_headers"


def test_webhook_subscription_disable_is_idempotent(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "target_url": "https://example.com/webhook",
            "event_type": "access.decision",
            "signing_secret": "test-webhook-secret",
        },
    )
    assert response.status_code == 200
    subscription_id = response.json()["subscription_id"]

    first = client.post(
        f"/webhooks/subscriptions/{subscription_id}/disable",
        headers=HEADERS,
        json={"tenant_id": "tenant-demo"},
    )
    second = client.post(
        f"/webhooks/subscriptions/{subscription_id}/disable",
        headers=HEADERS,
        json={"tenant_id": "tenant-demo"},
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["enabled"] is False
    assert second.json()["enabled"] is False


def test_webhook_subscription_disable_persists_state(client):
    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "target_url": "https://example.com/webhook",
            "event_type": "access.decision",
            "signing_secret": "test-webhook-secret",
        },
    )
    assert response.status_code == 200
    subscription_id = response.json()["subscription_id"]

    response = client.post(
        f"/webhooks/subscriptions/{subscription_id}/disable",
        headers=HEADERS,
        json={"tenant_id": "tenant-demo"},
    )
    assert response.status_code == 200

    with SessionLocal() as db:
        subscription = db.get(WebhookSubscription, subscription_id)
        assert subscription is not None
        assert subscription.enabled is False


def test_webhook_subscription_disable_commit_failure_rolls_back(client, monkeypatch):
    from sqlalchemy.orm import Session

    response = client.post(
        "/webhooks/subscriptions",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "target_url": "https://example.com/webhook",
            "event_type": "access.decision",
            "signing_secret": "test-webhook-secret",
        },
    )
    assert response.status_code == 200
    subscription_id = response.json()["subscription_id"]

    original_commit = Session.commit

    def broken_commit(self):
        raise SQLAlchemyError("forced_webhook_disable_failure")

    monkeypatch.setattr(Session, "commit", broken_commit)

    response = client.post(
        f"/webhooks/subscriptions/{subscription_id}/disable",
        headers=HEADERS,
        json={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "persistence_unavailable"

    monkeypatch.setattr(Session, "commit", original_commit)

    with SessionLocal() as db:
        subscription = db.get(WebhookSubscription, subscription_id)
        assert subscription.enabled is True
