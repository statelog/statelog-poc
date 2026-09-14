from sqlalchemy import or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..models import WebhookSubscription
from ..security import (
    decrypt_secret_with_key_version,
    encrypt_secret,
    get_active_secret_encryption_key,
)


def reencrypt_webhook_secrets(
    db: Session,
    *,
    limit: int = 100,
) -> tuple[int, bool]:
    active_kid, _ = get_active_secret_encryption_key()

    subscriptions = db.scalars(
        select(WebhookSubscription)
        .where(
            or_(
                WebhookSubscription.signing_secret_key_version != active_kid,
                WebhookSubscription.signing_secret_key_version_verified.is_(False),
            )
        )
        .order_by(WebhookSubscription.id)
        .limit(limit + 1)
    ).all()

    remaining = len(subscriptions) > limit
    subscriptions = subscriptions[:limit]

    reencrypted = 0

    try:
        for subscription in subscriptions:
            secret, actual_kid = decrypt_secret_with_key_version(
                subscription.signing_secret_encrypted,
                key_version=subscription.signing_secret_key_version,
            )

            if actual_kid != active_kid:
                subscription.signing_secret_encrypted = encrypt_secret(secret)
                reencrypted += 1

            subscription.signing_secret_key_version = active_kid
            subscription.signing_secret_key_version_verified = True

        db.commit()
    except (ValueError, SQLAlchemyError):
        db.rollback()
        raise

    return reencrypted, remaining