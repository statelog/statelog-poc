from datetime import timedelta
from uuid import uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from ..config import settings
from ..time_utils import utcnow_naive

from ..models import WebhookSubscription
from ..security import (
    decrypt_secret_with_key_version,
    encrypt_secret,
    get_active_secret_encryption_key,
)

def _claim_webhook_for_reencryption(
    db: Session,
    *,
    subscription_id: int,
    now,
    lease_seconds: int,
) -> str | None:
    claim_token = uuid4().hex
    claim_expires_at = now + timedelta(seconds=lease_seconds)

    result = db.execute(
        update(WebhookSubscription)
        .where(
            WebhookSubscription.id == subscription_id,
            or_(
                WebhookSubscription.reencrypt_claimed_by.is_(None),
                WebhookSubscription.reencrypt_claim_expires_at.is_(None),
                WebhookSubscription.reencrypt_claim_expires_at <= now,
            ),
        )
        .values(
            reencrypt_claimed_by=claim_token,
            reencrypt_claim_expires_at=claim_expires_at,
        )
    )

    if result.rowcount != 1:
        db.rollback()
        return None

    db.commit()
    return claim_token


def _release_webhook_reencrypt_claim(
    db: Session,
    *,
    subscription_id: int,
    claim_token: str,
) -> bool:
    result = db.execute(
        update(WebhookSubscription)
        .where(
            WebhookSubscription.id == subscription_id,
            WebhookSubscription.reencrypt_claimed_by == claim_token,
        )
        .values(
            reencrypt_claimed_by=None,
            reencrypt_claim_expires_at=None,
        )
    )
    db.commit()
    return result.rowcount == 1

def reencrypt_webhook_secrets(
    db: Session,
    *,
    limit: int = 100,
) -> tuple[int, bool]:
    active_kid, _ = get_active_secret_encryption_key()
    now = utcnow_naive()

    candidate_ids = db.scalars(
        select(WebhookSubscription.id)
        .where(
            or_(
                WebhookSubscription.signing_secret_key_version != active_kid,
                WebhookSubscription.signing_secret_key_version_verified.is_(False),
            ),
            or_(
                WebhookSubscription.reencrypt_claimed_by.is_(None),
                WebhookSubscription.reencrypt_claim_expires_at.is_(None),
                WebhookSubscription.reencrypt_claim_expires_at <= now,
            ),
        )
        .order_by(WebhookSubscription.id)
        .limit(limit + 1)
    ).all()

    claimed: list[tuple[int, str]] = []

    try:
        for subscription_id in candidate_ids:
            if len(claimed) >= limit:
                break

            claim_token = _claim_webhook_for_reencryption(
                db,
                subscription_id=subscription_id,
                now=now,
                lease_seconds=settings.webhook_reencrypt_claim_lease_seconds,
            )

            if claim_token is not None:
                claimed.append((subscription_id, claim_token))

        reencrypted = 0

        for subscription_id, claim_token in claimed:
            subscription = db.get(
                WebhookSubscription,
                subscription_id,
            )

            if (
                subscription is None
                or subscription.reencrypt_claimed_by != claim_token
            ):
                continue

            secret, actual_kid = decrypt_secret_with_key_version(
                subscription.signing_secret_encrypted,
                key_version=subscription.signing_secret_key_version,
            )

            if actual_kid != active_kid:
                subscription.signing_secret_encrypted = encrypt_secret(secret)
                reencrypted += 1

            subscription.signing_secret_key_version = active_kid
            subscription.signing_secret_key_version_verified = True
            subscription.reencrypt_claimed_by = None
            subscription.reencrypt_claim_expires_at = None

        db.commit()

    except (ValueError, SQLAlchemyError):
        db.rollback()

        for subscription_id, claim_token in claimed:
            try:
                _release_webhook_reencrypt_claim(
                    db,
                    subscription_id=subscription_id,
                    claim_token=claim_token,
                )
            except SQLAlchemyError:
                db.rollback()

        raise

    remaining = len(candidate_ids) > limit

    return reencrypted, remaining
