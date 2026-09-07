import json
from datetime import timedelta

from app.config import settings
from app.database import SessionLocal
from app.models import (
    OutboxEvent,
    WebhookDeliveryAttempt,
    WebhookSubscription,
)
from app.outbox_worker import (
    _already_delivered,
    _record_attempt,
    backoff_seconds,
    deliver_pending_events,
)
from app.time_utils import utcnow_naive


# #720
def test_outbox_backoff_first_attempt_is_two_seconds():
    assert backoff_seconds(1) == 2


# #721
def test_outbox_backoff_grows_exponentially():
    assert backoff_seconds(1) == 2
    assert backoff_seconds(2) == 4
    assert backoff_seconds(3) == 8
    assert backoff_seconds(4) == 16


# #722
def test_outbox_backoff_is_capped_at_300_seconds():
    assert backoff_seconds(9) == 300
    assert backoff_seconds(10) == 300
    assert backoff_seconds(100) == 300


# #723
def test_outbox_record_attempt_persists_success():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-720",
            event_type="decision.allowed",
            payload=json.dumps({"trace_id": "720"}),
            delivered=False,
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        sub = WebhookSubscription(
            tenant_id="outbox-720",
            target_url="https://example.com/720",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            enabled=True,
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)

        _record_attempt(
            db,
            event_id=event.id,
            subscription_id=sub.id,
            attempt_number=1,
            successful=True,
            response_status_code=204,
            error_message=None,
        )
        db.commit()

        attempt = (
            db.query(WebhookDeliveryAttempt)
            .filter_by(event_id=event.id, subscription_id=sub.id)
            .one()
        )

        assert attempt.attempt_number == 1
        assert attempt.successful is True
        assert attempt.response_status_code == 204
        assert attempt.error_message is None
        assert attempt.signature_version == "v1"


# #724
def test_outbox_record_attempt_persists_failure():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-724",
            event_type="decision.allowed",
            payload=json.dumps({"trace_id": "724"}),
            delivered=False,
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        sub = WebhookSubscription(
            tenant_id="outbox-724",
            target_url="https://example.com/724",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            enabled=True,
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)

        _record_attempt(
            db,
            event_id=event.id,
            subscription_id=sub.id,
            attempt_number=2,
            successful=False,
            response_status_code=503,
            error_message="service unavailable",
        )
        db.commit()

        attempt = (
            db.query(WebhookDeliveryAttempt)
            .filter_by(event_id=event.id, subscription_id=sub.id)
            .one()
        )

        assert attempt.attempt_number == 2
        assert attempt.successful is False
        assert attempt.response_status_code == 503
        assert attempt.error_message == "service unavailable"


# #725
def test_outbox_record_attempt_truncates_long_error_message():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-725",
            event_type="decision.allowed",
            payload=json.dumps({"trace_id": "725"}),
            delivered=False,
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        sub = WebhookSubscription(
            tenant_id="outbox-725",
            target_url="https://example.com/725",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            enabled=True,
        )
        db.add(sub)
        db.commit()
        db.refresh(sub)

        _record_attempt(
            db,
            event_id=event.id,
            subscription_id=sub.id,
            attempt_number=1,
            successful=False,
            response_status_code=None,
            error_message="x" * 700,
        )
        db.commit()

        attempt = (
            db.query(WebhookDeliveryAttempt)
            .filter_by(event_id=event.id, subscription_id=sub.id)
            .one()
        )

        assert attempt.error_message == "x" * 500


# #726
def test_outbox_already_delivered_false_without_attempt():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-726",
            event_type="decision.allowed",
            payload=json.dumps({"trace_id": "726"}),
            delivered=False,
        )
        sub = WebhookSubscription(
            tenant_id="outbox-726",
            target_url="https://example.com/726",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            enabled=True,
        )
        db.add_all([event, sub])
        db.commit()
        db.refresh(event)
        db.refresh(sub)

        assert (
            _already_delivered(
                db,
                event_id=event.id,
                subscription_id=sub.id,
            )
            is False
        )


# #727
def test_outbox_already_delivered_true_after_success():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-727",
            event_type="decision.allowed",
            payload=json.dumps({"trace_id": "727"}),
            delivered=False,
        )
        sub = WebhookSubscription(
            tenant_id="outbox-727",
            target_url="https://example.com/727",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            enabled=True,
        )
        db.add_all([event, sub])
        db.commit()
        db.refresh(event)
        db.refresh(sub)

        _record_attempt(
            db,
            event_id=event.id,
            subscription_id=sub.id,
            attempt_number=1,
            successful=True,
            response_status_code=200,
            error_message=None,
        )
        db.commit()

        assert (
            _already_delivered(
                db,
                event_id=event.id,
                subscription_id=sub.id,
            )
            is True
        )


# #728
def test_outbox_failed_attempt_does_not_count_as_delivered():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-728",
            event_type="decision.allowed",
            payload=json.dumps({"trace_id": "728"}),
            delivered=False,
        )
        sub = WebhookSubscription(
            tenant_id="outbox-728",
            target_url="https://example.com/728",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            enabled=True,
        )
        db.add_all([event, sub])
        db.commit()
        db.refresh(event)
        db.refresh(sub)

        _record_attempt(
            db,
            event_id=event.id,
            subscription_id=sub.id,
            attempt_number=1,
            successful=False,
            response_status_code=500,
            error_message="failed",
        )
        db.commit()

        assert (
            _already_delivered(
                db,
                event_id=event.id,
                subscription_id=sub.id,
            )
            is False
        )


# #729
def test_outbox_event_without_subscription_is_marked_delivered():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-729",
            event_type="no.subscription",
            payload=json.dumps({"trace_id": "729"}),
            delivered=False,
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        count = deliver_pending_events(db)

        db.refresh(event)

        assert count == 1
        assert event.delivered is True
        assert event.delivered_at is not None


# #730
def test_outbox_future_event_is_not_processed():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-730",
            event_type="future.event",
            payload=json.dumps({"trace_id": "730"}),
            delivered=False,
            next_attempt_at=utcnow_naive() + timedelta(hours=1),
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        count = deliver_pending_events(db)

        db.refresh(event)

        assert count == 0
        assert event.delivered is False


# #731
def test_outbox_dead_lettered_event_is_not_processed():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-731",
            event_type="dead.event",
            payload=json.dumps({"trace_id": "731"}),
            delivered=False,
            dead_lettered=True,
            next_attempt_at=utcnow_naive(),
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        count = deliver_pending_events(db)

        db.refresh(event)

        assert count == 0
        assert event.delivered is False
        assert event.dead_lettered is True


# #732
def test_outbox_already_delivered_event_is_not_processed():
    with SessionLocal() as db:
        event = OutboxEvent(
            tenant_id="outbox-732",
            event_type="delivered.event",
            payload=json.dumps({"trace_id": "732"}),
            delivered=True,
            delivered_at=utcnow_naive(),
            next_attempt_at=utcnow_naive(),
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        count = deliver_pending_events(db)

        assert count == 0


# #733
def test_outbox_batch_size_limits_processed_events():
    with SessionLocal() as db:
        for number in range(3):
            db.add(
                OutboxEvent(
                    tenant_id="outbox-733",
                    event_type="batch.no.subscription",
                    payload=json.dumps({"number": number}),
                    delivered=False,
                    next_attempt_at=utcnow_naive(),
                )
            )
        db.commit()

        count = deliver_pending_events(db, batch_size=2)

        delivered = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.tenant_id == "outbox-733",
                OutboxEvent.delivered.is_(True),
            )
            .count()
        )

        assert count == 2
        assert delivered == 2


# #734
def test_outbox_disabled_subscription_is_ignored():
    with SessionLocal() as db:
        sub = WebhookSubscription(
            tenant_id="outbox-734",
            target_url="https://example.com/734",
            event_type="decision.allowed",
            signing_secret_hash="unused",
            signing_secret_encrypted="unused",
            enabled=False,
        )
        event = OutboxEvent(
            tenant_id="outbox-734",
            event_type="decision.allowed",
            payload=json.dumps({"trace_id": "734"}),
            delivered=False,
            next_attempt_at=utcnow_naive(),
        )
        db.add_all([sub, event])
        db.commit()
        db.refresh(event)

        count = deliver_pending_events(db)

        db.refresh(event)

        attempts = (
            db.query(WebhookDeliveryAttempt)
            .filter(WebhookDeliveryAttempt.event_id == event.id)
            .count()
        )

        assert count == 1
        assert event.delivered is True
        assert attempts == 0