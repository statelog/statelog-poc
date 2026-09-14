from datetime import timedelta
import json

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
import app.security as security_module

import app.services.webhook_service as webhook_service_module

from app.database import SessionLocal
from app.models import WebhookSubscription
from app.services.webhook_service import (
    _claim_webhook_for_reencryption,
    _release_webhook_reencrypt_claim,
    reencrypt_webhook_secrets,
)
from app.time_utils import utcnow_naive


def _create_subscription(
    *,
    tenant_id: str,
    claimed_by: str | None = None,
    claim_expires_at=None,
) -> int:
    with SessionLocal() as db:
        subscription = WebhookSubscription(
            tenant_id=tenant_id,
            target_url="https://example.com/claim-test",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            signing_secret_key_version="v1",
            signing_secret_key_version_verified=False,
            reencrypt_claimed_by=claimed_by,
            reencrypt_claim_expires_at=claim_expires_at,
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        return subscription.id


def test_reencrypt_claim_sets_owner_and_expiry():
    subscription_id = _create_subscription(
        tenant_id="claim-sets-owner",
    )
    now = utcnow_naive()

    with SessionLocal() as db:
        claim_token = _claim_webhook_for_reencryption(
            db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=60,
        )

    assert claim_token is not None

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.reencrypt_claimed_by == claim_token
        assert subscription.reencrypt_claim_expires_at == (
            now + timedelta(seconds=60)
        )


def test_reencrypt_active_claim_cannot_be_taken_twice():
    subscription_id = _create_subscription(
        tenant_id="claim-no-duplicate",
    )
    now = utcnow_naive()

    with SessionLocal() as first_db:
        first_token = _claim_webhook_for_reencryption(
            first_db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=60,
        )

    with SessionLocal() as second_db:
        second_token = _claim_webhook_for_reencryption(
            second_db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=60,
        )

    assert first_token is not None
    assert second_token is None


def test_reencrypt_expired_claim_can_be_reclaimed():
    now = utcnow_naive()
    subscription_id = _create_subscription(
        tenant_id="claim-expired",
        claimed_by="expired-owner",
        claim_expires_at=now - timedelta(seconds=1),
    )

    with SessionLocal() as db:
        new_token = _claim_webhook_for_reencryption(
            db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=60,
        )

    assert new_token is not None
    assert new_token != "expired-owner"

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.reencrypt_claimed_by == new_token


def test_reencrypt_claim_wrong_owner_cannot_release():
    subscription_id = _create_subscription(
        tenant_id="claim-wrong-release",
    )
    now = utcnow_naive()

    with SessionLocal() as db:
        claim_token = _claim_webhook_for_reencryption(
            db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=60,
        )

        released = _release_webhook_reencrypt_claim(
            db,
            subscription_id=subscription_id,
            claim_token="wrong-token",
        )

    assert claim_token is not None
    assert released is False

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.reencrypt_claimed_by == claim_token


def test_reencrypt_claim_owner_can_release():
    subscription_id = _create_subscription(
        tenant_id="claim-correct-release",
    )
    now = utcnow_naive()

    with SessionLocal() as db:
        claim_token = _claim_webhook_for_reencryption(
            db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=60,
        )

        assert claim_token is not None

        released = _release_webhook_reencrypt_claim(
            db,
            subscription_id=subscription_id,
            claim_token=claim_token,
        )

    assert released is True

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription is not None
        assert subscription.reencrypt_claimed_by is None
        assert subscription.reencrypt_claim_expires_at is None


def test_reencrypt_claim_without_expiry_is_recoverable():
    subscription_id = _create_subscription(
        tenant_id="claim-missing-expiry",
        claimed_by="orphaned-owner",
        claim_expires_at=None,
    )
    now = utcnow_naive()

    with SessionLocal() as db:
        claim_token = _claim_webhook_for_reencryption(
            db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=60,
        )

    assert claim_token is not None
    assert claim_token != "orphaned-owner"

def _configure_reencrypt_keys(monkeypatch):
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_keyring_json",
        json.dumps(
            {
                "v1": "old-webhook-encryption-key-123456",
                "v2": "new-webhook-encryption-key-123456",
            }
        ),
    )
    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v1",
    )


def _create_encrypted_subscription(
    *,
    tenant_id: str,
    secret: str,
) -> int:
    encrypted = security_module.encrypt_secret(secret)

    with SessionLocal() as db:
        subscription = WebhookSubscription(
            tenant_id=tenant_id,
            target_url=f"https://example.com/{tenant_id}",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted=encrypted,
            signing_secret_key_version="v1",
            signing_secret_key_version_verified=False,
        )
        db.add(subscription)
        db.commit()
        db.refresh(subscription)
        return subscription.id


def test_reencrypt_service_skips_active_claim_and_processes_next_row(
    monkeypatch,
):
    _configure_reencrypt_keys(monkeypatch)

    first_id = _create_encrypted_subscription(
        tenant_id="service-active-claim",
        secret="first-secret",
    )
    second_id = _create_encrypted_subscription(
        tenant_id="service-next-row",
        secret="second-secret",
    )

    now = utcnow_naive()

    with SessionLocal() as db:
        first = db.get(WebhookSubscription, first_id)
        first.reencrypt_claimed_by = "another-worker"
        first.reencrypt_claim_expires_at = now + timedelta(seconds=60)
        db.commit()

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    with SessionLocal() as db:
        reencrypted, remaining = reencrypt_webhook_secrets(
            db,
            limit=1,
        )

    assert reencrypted == 1
    assert remaining is False

    with SessionLocal() as db:
        first = db.get(WebhookSubscription, first_id)
        second = db.get(WebhookSubscription, second_id)

        assert first.signing_secret_key_version == "v1"
        assert first.reencrypt_claimed_by == "another-worker"

        assert second.signing_secret_key_version == "v2"
        assert second.signing_secret_key_version_verified is True
        assert second.reencrypt_claimed_by is None
        assert second.reencrypt_claim_expires_at is None


def test_reencrypt_service_success_clears_claim(
    monkeypatch,
):
    _configure_reencrypt_keys(monkeypatch)

    subscription_id = _create_encrypted_subscription(
        tenant_id="service-clears-claim",
        secret="claim-cleanup-secret",
    )

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    with SessionLocal() as db:
        reencrypted, remaining = reencrypt_webhook_secrets(
            db,
            limit=1,
        )

    assert reencrypted == 1
    assert remaining is False

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription.reencrypt_claimed_by is None
        assert subscription.reencrypt_claim_expires_at is None
        assert subscription.signing_secret_key_version == "v2"


def test_reencrypt_service_expired_claim_is_recovered(
    monkeypatch,
):
    _configure_reencrypt_keys(monkeypatch)

    subscription_id = _create_encrypted_subscription(
        tenant_id="service-expired-claim",
        secret="expired-claim-secret",
    )

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )
        subscription.reencrypt_claimed_by = "dead-worker"
        subscription.reencrypt_claim_expires_at = (
            utcnow_naive() - timedelta(seconds=1)
        )
        db.commit()

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    with SessionLocal() as db:
        reencrypted, remaining = reencrypt_webhook_secrets(
            db,
            limit=1,
        )

    assert reencrypted == 1
    assert remaining is False

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription.signing_secret_key_version == "v2"
        assert subscription.reencrypt_claimed_by is None
        assert subscription.reencrypt_claim_expires_at is None


def test_reencrypt_final_commit_failure_releases_claim_and_rolls_back(
    monkeypatch,
):
    _configure_reencrypt_keys(monkeypatch)

    subscription_id = _create_encrypted_subscription(
        tenant_id="service-final-commit-failure",
        secret="final-commit-failure-secret",
    )

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )
        original_ciphertext = subscription.signing_secret_encrypted

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    real_db = SessionLocal()

    class _FailSecondCommitSession:
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

            if self.commit_calls == 2:
                raise SQLAlchemyError("final_commit_failure")

            self.real_db.commit()

        def rollback(self):
            self.rollback_calls += 1
            self.real_db.rollback()

    session = _FailSecondCommitSession(real_db)

    try:
        with pytest.raises(
            SQLAlchemyError,
            match="final_commit_failure",
        ):
            reencrypt_webhook_secrets(
                session,
                limit=1,
            )
    finally:
        real_db.close()

    assert session.commit_calls == 3
    assert session.rollback_calls >= 1

    with SessionLocal() as db:
        subscription = db.get(
            WebhookSubscription,
            subscription_id,
        )

        assert subscription.signing_secret_key_version == "v1"
        assert subscription.signing_secret_encrypted == original_ciphertext
        assert subscription.reencrypt_claimed_by is None
        assert subscription.reencrypt_claim_expires_at is None

def test_reencrypt_service_fills_batch_after_losing_first_claim(
    monkeypatch,
):
    _configure_reencrypt_keys(monkeypatch)

    first_id = _create_encrypted_subscription(
        tenant_id="service-lost-first-claim",
        secret="first-race-secret",
    )
    second_id = _create_encrypted_subscription(
        tenant_id="service-race-next-row",
        secret="second-race-secret",
    )

    monkeypatch.setattr(
        security_module.settings,
        "secret_encryption_active_kid",
        "v2",
    )

    real_claim = (
        webhook_service_module._claim_webhook_for_reencryption
    )

    def _claim_with_first_race_loss(
        db,
        *,
        subscription_id,
        now,
        lease_seconds,
    ):
        if subscription_id == first_id:
            return None

        return real_claim(
            db,
            subscription_id=subscription_id,
            now=now,
            lease_seconds=lease_seconds,
        )

    monkeypatch.setattr(
        webhook_service_module,
        "_claim_webhook_for_reencryption",
        _claim_with_first_race_loss,
    )

    with SessionLocal() as db:
        reencrypted, remaining = (
            webhook_service_module.reencrypt_webhook_secrets(
                db,
                limit=1,
            )
        )

    assert reencrypted == 1
    assert remaining is True

    with SessionLocal() as db:
        first = db.get(WebhookSubscription, first_id)
        second = db.get(WebhookSubscription, second_id)

        assert first.signing_secret_key_version == "v1"
        assert second.signing_secret_key_version == "v2"
        assert second.signing_secret_key_version_verified is True
