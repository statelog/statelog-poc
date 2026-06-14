from __future__ import annotations

import json
import logging
import time
from datetime import timedelta

import requests
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import settings
from .database import SessionLocal
from .models import OutboxEvent, WebhookDeliveryAttempt, WebhookSubscription
from .security import decrypt_secret, sign_webhook_payload
from .time_utils import utcnow_naive

logger = logging.getLogger(__name__)


def backoff_seconds(attempts: int) -> int:
    return min(2 ** max(attempts, 0), 300)


def _already_delivered(db: Session, *, event_id: int, subscription_id: int) -> bool:
    successful = db.scalar(
        select(func.count())
        .select_from(WebhookDeliveryAttempt)
        .where(
            WebhookDeliveryAttempt.event_id == event_id,
            WebhookDeliveryAttempt.subscription_id == subscription_id,
            WebhookDeliveryAttempt.successful.is_(True),
        )
    )
    return bool(successful)


def _record_attempt(
    db: Session,
    *,
    event_id: int,
    subscription_id: int,
    attempt_number: int,
    successful: bool,
    response_status_code: int | None,
    error_message: str | None,
) -> None:
    db.add(
        WebhookDeliveryAttempt(
            event_id=event_id,
            subscription_id=subscription_id,
            attempt_number=attempt_number,
            successful=successful,
            response_status_code=response_status_code,
            error_message=(error_message or '')[:500] or None,
            signature_version='v1',
        )
    )


def deliver_pending_events(db: Session, batch_size: int | None = None) -> int:
    now = utcnow_naive()
    size = batch_size or settings.outbox_batch_size
    events = list(
        db.scalars(
            select(OutboxEvent)
            .where(OutboxEvent.delivered.is_(False), OutboxEvent.dead_lettered.is_(False), OutboxEvent.next_attempt_at <= now)
            .order_by(OutboxEvent.created_at.asc())
            .limit(size)
        )
    )
    delivered_count = 0
    for event in events:
        subs = list(
            db.scalars(
                select(WebhookSubscription).where(
                    WebhookSubscription.tenant_id == event.tenant_id,
                    WebhookSubscription.event_type == event.event_type,
                    WebhookSubscription.enabled.is_(True),
                )
            )
        )
        if not subs:
            event.delivered = True
            event.delivered_at = utcnow_naive()
            delivered_count += 1
            continue

        payload = json.loads(event.payload)
        event.attempts += 1
        delivery_failed = False
        event.last_error = None

        for sub in subs:
            if _already_delivered(db, event_id=event.id, subscription_id=sub.id):
                continue

            timestamp = int(time.time())
            delivery_id = f"evt-{event.id}-sub-{sub.id}-try-{event.attempts}"
            try:
                secret = decrypt_secret(sub.signing_secret_encrypted)
                signature = sign_webhook_payload(secret=secret, payload=payload, timestamp=timestamp)
                response = requests.post(
                    sub.target_url,
                    json=payload,
                    timeout=settings.webhook_timeout_seconds,
                    headers={
                        settings.webhook_signature_header: signature,
                        settings.webhook_timestamp_header: str(timestamp),
                        settings.webhook_event_id_header: str(event.id),
                        settings.webhook_delivery_id_header: delivery_id,
                    },
                )
                if 200 <= response.status_code < 300:
                    _record_attempt(
                        db,
                        event_id=event.id,
                        subscription_id=sub.id,
                        attempt_number=event.attempts,
                        successful=True,
                        response_status_code=response.status_code,
                        error_message=None,
                    )
                else:
                    delivery_failed = True
                    event.last_error = f"webhook_http_{response.status_code}"
                    _record_attempt(
                        db,
                        event_id=event.id,
                        subscription_id=sub.id,
                        attempt_number=event.attempts,
                        successful=False,
                        response_status_code=response.status_code,
                        error_message=event.last_error,
                    )
            except Exception as exc:  # noqa: BLE001
                delivery_failed = True
                event.last_error = str(exc)[:500]
                _record_attempt(
                    db,
                    event_id=event.id,
                    subscription_id=sub.id,
                    attempt_number=event.attempts,
                    successful=False,
                    response_status_code=None,
                    error_message=event.last_error,
                )

        if delivery_failed:
            if event.attempts >= settings.webhook_max_attempts:
                event.dead_lettered = True
                event.next_attempt_at = utcnow_naive()
                logger.warning('outbox_event_dead_lettered', extra={'event_id': event.id})
            else:
                event.next_attempt_at = utcnow_naive() + timedelta(seconds=backoff_seconds(event.attempts))
        else:
            event.delivered = True
            event.delivered_at = utcnow_naive()
            event.last_error = None
            delivered_count += 1
    db.commit()
    return delivered_count


def run_worker() -> None:
    while True:
        with SessionLocal() as db:
            count = deliver_pending_events(db)
            if count:
                logger.info('outbox_delivery_cycle', extra={'event_type': 'delivery', 'status_code': 200})
        time.sleep(settings.outbox_poll_interval_seconds)


if __name__ == '__main__':
    run_worker()
