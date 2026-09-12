import json
import pytest
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
    _claim_outbox_event,
    _record_attempt,
    _release_outbox_claim,
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

def _make_outbox_event(
    db,
    *,
    tenant_id: str,
    event_type: str = "decision.allowed",
    payload: dict | None = None,
    attempts: int = 0,
    last_error: str | None = None,
    created_at=None,
):
    event = OutboxEvent(
        tenant_id=tenant_id,
        event_type=event_type,
        payload=json.dumps(payload or {"trace_id": tenant_id}),
        delivered=False,
        attempts=attempts,
        last_error=last_error,
        next_attempt_at=utcnow_naive(),
        **({"created_at": created_at} if created_at is not None else {}),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def _make_outbox_subscription(
    db,
    *,
    tenant_id: str,
    target_url: str,
    event_type: str = "decision.allowed",
    enabled: bool = True,
):
    sub = WebhookSubscription(
        tenant_id=tenant_id,
        target_url=target_url,
        event_type=event_type,
        signing_secret_hash="unused",
        signing_secret_encrypted="unused",
        enabled=enabled,
    )
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return sub


def _patch_outbox_secret(monkeypatch):
    monkeypatch.setattr(
        "app.outbox_worker.decrypt_secret",
        lambda value: "test-secret",
    )


class _OutboxResponse:
    def __init__(self, status_code):
        self.status_code = status_code


# #735
def test_outbox_http_200_marks_event_delivered(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(200),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-735",
            target_url="https://example.com/735",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-735",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        assert count == 1
        assert event.delivered is True
        assert event.delivered_at is not None
        assert event.last_error is None


# #736
def test_outbox_http_299_is_success(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(299),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-736",
            target_url="https://example.com/736",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-736",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        assert count == 1
        assert event.delivered is True


# #737
def test_outbox_http_300_is_failure(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(300),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-737",
            target_url="https://example.com/737",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-737",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        assert count == 0
        assert event.delivered is False
        assert event.last_error == "webhook_http_300"


# #738
def test_outbox_request_exception_records_failed_attempt(monkeypatch):
    _patch_outbox_secret(monkeypatch)

    def failing_post(*args, **kwargs):
        raise RuntimeError("network_down")

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        failing_post,
    )

    with SessionLocal() as db:
        sub = _make_outbox_subscription(
            db,
            tenant_id="outbox-738",
            target_url="https://example.com/738",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-738",
        )

        count = deliver_pending_events(db)

        attempt = (
            db.query(WebhookDeliveryAttempt)
            .filter_by(
                event_id=event.id,
                subscription_id=sub.id,
            )
            .one()
        )

        assert count == 0
        assert attempt.successful is False
        assert attempt.response_status_code is None
        assert attempt.error_message == "network_down"


# #739
def test_outbox_http_failure_records_status_code(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(503),
    )

    with SessionLocal() as db:
        sub = _make_outbox_subscription(
            db,
            tenant_id="outbox-739",
            target_url="https://example.com/739",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-739",
        )

        deliver_pending_events(db)

        attempt = (
            db.query(WebhookDeliveryAttempt)
            .filter_by(
                event_id=event.id,
                subscription_id=sub.id,
            )
            .one()
        )

        assert attempt.successful is False
        assert attempt.response_status_code == 503
        assert attempt.error_message == "webhook_http_503"


# #740
def test_outbox_delivery_increments_attempt_count(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(500),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-740",
            target_url="https://example.com/740",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-740",
            attempts=3,
        )

        deliver_pending_events(db)
        db.refresh(event)

        assert event.attempts == 4


# #741
def test_outbox_failure_schedules_future_retry(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(500),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-741",
            target_url="https://example.com/741",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-741",
        )

        before = utcnow_naive()
        deliver_pending_events(db)
        after = utcnow_naive()
        db.refresh(event)

        assert event.next_attempt_at > before
        assert event.next_attempt_at <= after + timedelta(seconds=3)


# #742
def test_outbox_failure_at_max_attempts_dead_letters(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(500),
    )

    old_max_attempts = settings.webhook_max_attempts
    settings.webhook_max_attempts = 2
    try:
        with SessionLocal() as db:
            _make_outbox_subscription(
                db,
                tenant_id="outbox-742",
                target_url="https://example.com/742",
            )
            event = _make_outbox_event(
                db,
                tenant_id="outbox-742",
                attempts=1,
            )

            count = deliver_pending_events(db)
            db.refresh(event)

            assert count == 0
            assert event.attempts == 2
            assert event.dead_lettered is True
    finally:
        settings.webhook_max_attempts = old_max_attempts


# #743
def test_outbox_multiple_subscriptions_all_succeed(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(200),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-743",
            target_url="https://example.com/743-a",
        )
        _make_outbox_subscription(
            db,
            tenant_id="outbox-743",
            target_url="https://example.com/743-b",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-743",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        attempts = (
            db.query(WebhookDeliveryAttempt)
            .filter(
                WebhookDeliveryAttempt.event_id == event.id
            )
            .all()
        )

        assert count == 1
        assert event.delivered is True
        assert len(attempts) == 2
        assert all(attempt.successful for attempt in attempts)


# #744
def test_outbox_one_failed_subscription_keeps_event_pending(monkeypatch):
    _patch_outbox_secret(monkeypatch)

    def fake_post(url, **kwargs):
        if url.endswith("/fail"):
            return _OutboxResponse(500)
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-744",
            target_url="https://example.com/success",
        )
        _make_outbox_subscription(
            db,
            tenant_id="outbox-744",
            target_url="https://example.com/fail",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-744",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        attempts = (
            db.query(WebhookDeliveryAttempt)
            .filter(
                WebhookDeliveryAttempt.event_id == event.id
            )
            .all()
        )

        assert count == 0
        assert event.delivered is False
        assert len(attempts) == 2
        assert sorted(
            attempt.successful for attempt in attempts
        ) == [False, True]

def test_outbox_worker_does_not_call_private_webhook_target(monkeypatch):
    _patch_outbox_secret(monkeypatch)

    post_called = False

    def fake_post(url, **kwargs):
        nonlocal post_called
        post_called = True
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-ssrf-private",
            target_url="http://127.0.0.1:8080/webhook",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-ssrf-private",
        )

        deliver_pending_events(db)

    assert post_called is False

def test_outbox_worker_does_not_call_hostname_resolving_to_private_ip(monkeypatch):
    _patch_outbox_secret(monkeypatch)

    post_called = False

    def fake_post(url, **kwargs):
        nonlocal post_called
        post_called = True
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    monkeypatch.setattr(
        "app.outbox_worker.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", ("127.0.0.1", 0)),
        ],
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-ssrf-dns",
            target_url="https://internal.example/webhook",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-ssrf-dns",
        )

        deliver_pending_events(db)

    assert post_called is False

# #745
def test_outbox_successful_subscription_is_not_redelivered(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        first_sub = _make_outbox_subscription(
            db,
            tenant_id="outbox-745",
            target_url="https://example.com/745-a",
        )
        _make_outbox_subscription(
            db,
            tenant_id="outbox-745",
            target_url="https://example.com/745-b",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-745",
        )

        _record_attempt(
            db,
            event_id=event.id,
            subscription_id=first_sub.id,
            attempt_number=1,
            successful=True,
            response_status_code=200,
            error_message=None,
        )
        db.commit()

        count = deliver_pending_events(db)
        db.refresh(event)

        assert count == 1
        assert event.delivered is True
        assert calls == ["https://example.com/745-b"]


# #746
def test_outbox_subscription_from_other_tenant_is_ignored(monkeypatch):
    calls = []

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: calls.append(args),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-746-other",
            target_url="https://example.com/746",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-746",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        assert count == 1
        assert event.delivered is True
        assert calls == []


# #747
def test_outbox_subscription_for_other_event_type_is_ignored(monkeypatch):
    calls = []

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: calls.append(args),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-747",
            target_url="https://example.com/747",
            event_type="decision.denied",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-747",
            event_type="decision.allowed",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        assert count == 1
        assert event.delivered is True
        assert calls == []


# #748
def test_outbox_enabled_subscription_used_when_disabled_also_exists(
    monkeypatch,
):
    _patch_outbox_secret(monkeypatch)
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-748",
            target_url="https://example.com/748-disabled",
            enabled=False,
        )
        _make_outbox_subscription(
            db,
            tenant_id="outbox-748",
            target_url="https://example.com/748-enabled",
            enabled=True,
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-748",
        )

        count = deliver_pending_events(db)

        assert count == 1
        assert calls == ["https://example.com/748-enabled"]


# #749
def test_outbox_payload_is_sent_unchanged(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    captured = {}

    def fake_post(url, json=None, **kwargs):
        captured["json"] = json
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-749",
            target_url="https://example.com/749",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-749",
            payload={
                "trace_id": "749",
                "allowed": True,
                "risk_score": 35,
            },
        )

        deliver_pending_events(db)

        assert captured["json"] == {
            "trace_id": "749",
            "allowed": True,
            "risk_score": 35,
        }


# #750
def test_outbox_request_uses_configured_timeout(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    captured = {}

    def fake_post(url, **kwargs):
        captured["timeout"] = kwargs["timeout"]
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-750",
            target_url="https://example.com/750",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-750",
        )

        deliver_pending_events(db)

        assert captured["timeout"] == settings.webhook_timeout_seconds


# #751
def test_outbox_request_contains_all_delivery_headers(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    captured = {}

    def fake_post(url, **kwargs):
        captured["headers"] = kwargs["headers"]
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-751",
            target_url="https://example.com/751",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-751",
        )

        deliver_pending_events(db)

        headers = captured["headers"]

        assert settings.webhook_signature_header in headers
        assert settings.webhook_timestamp_header in headers
        assert settings.webhook_event_id_header in headers
        assert settings.webhook_delivery_id_header in headers
        assert headers[settings.webhook_event_id_header] == str(event.id)


# #752
def test_outbox_multiple_subscriptions_share_attempt_number(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(200),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-752",
            target_url="https://example.com/752-a",
        )
        _make_outbox_subscription(
            db,
            tenant_id="outbox-752",
            target_url="https://example.com/752-b",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-752",
            attempts=4,
        )

        deliver_pending_events(db)

        attempts = (
            db.query(WebhookDeliveryAttempt)
            .filter(
                WebhookDeliveryAttempt.event_id == event.id
            )
            .all()
        )

        assert event.attempts == 5
        assert len(attempts) == 2
        assert {
            attempt.attempt_number
            for attempt in attempts
        } == {5}


# #753
def test_outbox_success_clears_previous_error(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(200),
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-753",
            target_url="https://example.com/753",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-753",
            attempts=1,
            last_error="old_failure",
        )

        count = deliver_pending_events(db)
        db.refresh(event)

        assert count == 1
        assert event.delivered is True
        assert event.last_error is None


# #754
def test_outbox_batch_processes_oldest_event_first():
    now = utcnow_naive()

    with SessionLocal() as db:
        older = _make_outbox_event(
            db,
            tenant_id="outbox-754-old",
            event_type="no.subscription",
            created_at=now - timedelta(minutes=10),
        )
        newer = _make_outbox_event(
            db,
            tenant_id="outbox-754-new",
            event_type="no.subscription",
            created_at=now - timedelta(minutes=5),
        )

        count = deliver_pending_events(db, batch_size=1)

        db.refresh(older)
        db.refresh(newer)

        assert count == 1
        assert older.delivered is True
        assert newer.delivered is False

# #755
def test_outbox_atomic_claim_rejects_second_session():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-755",
        )
        event_id = event.id

    now = utcnow_naive()

    with SessionLocal() as db_a:
        claim_a = _claim_outbox_event(
            db_a,
            event_id=event_id,
            now=now,
        )

    with SessionLocal() as db_b:
        claim_b = _claim_outbox_event(
            db_b,
            event_id=event_id,
            now=now,
        )

    assert claim_a is not None
    assert claim_b is None

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)

        assert event is not None
        assert event.claimed_by == claim_a
        assert event.claim_expires_at is not None
        assert event.claim_expires_at > now

# #756
def test_outbox_expired_claim_can_be_reclaimed():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-756",
        )
        event_id = event.id

    first_now = utcnow_naive()

    with SessionLocal() as db_a:
        claim_a = _claim_outbox_event(
            db_a,
            event_id=event_id,
            now=first_now,
            lease_seconds=1,
        )

    reclaim_now = first_now + timedelta(seconds=2)

    with SessionLocal() as db_b:
        claim_b = _claim_outbox_event(
            db_b,
            event_id=event_id,
            now=reclaim_now,
            lease_seconds=60,
        )

    assert claim_a is not None
    assert claim_b is not None
    assert claim_b != claim_a

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)

        assert event is not None
        assert event.claimed_by == claim_b
        assert event.claim_expires_at is not None
        assert event.claim_expires_at > reclaim_now

# #757
def test_outbox_worker_skips_event_with_active_claim(monkeypatch):
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-757",
        )
        event_id = event.id
        event.claimed_by = "other-worker"
        event.claim_expires_at = utcnow_naive() + timedelta(minutes=5)
        setup_db.commit()

    post_calls = []

    def fake_post(*args, **kwargs):
        post_calls.append((args, kwargs))
        return _OutboxResponse(200)

    monkeypatch.setattr("app.outbox_worker.requests.post", fake_post)

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 0
    assert post_calls == []

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.delivered is False
        assert event.claimed_by == "other-worker"


# #758
def test_outbox_worker_processes_event_after_claim_expires():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-758",
            event_type="no.subscription",
        )
        event_id = event.id
        event.claimed_by = "dead-worker"
        event.claim_expires_at = utcnow_naive() - timedelta(seconds=1)
        setup_db.commit()

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 1

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.delivered is True
        assert event.claimed_by is None
        assert event.claim_expires_at is None


# #759
def test_outbox_success_releases_claim(monkeypatch):
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-759",
        )
        event_id = event.id
        _make_outbox_subscription(
            setup_db,
            tenant_id="outbox-759",
            target_url="https://example.test/webhook",
        )
        
    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(200),
    )

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 1

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.delivered is True
        assert event.claimed_by is None
        assert event.claim_expires_at is None


# #760
def test_outbox_retry_failure_releases_claim(monkeypatch):
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-760",
        )
        event_id = event.id
        _make_outbox_subscription(
            setup_db,
            tenant_id="outbox-760",
            target_url="https://example.test/webhook",
        )

    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(500),
    )

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 0

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.delivered is False
        assert event.dead_lettered is False
        assert event.claimed_by is None
        assert event.claim_expires_at is None


# #761
def test_outbox_dead_letter_releases_claim(monkeypatch):
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-761",
        )
        event_id = event.id
        event.attempts = settings.webhook_max_attempts - 1
        _make_outbox_subscription(
            setup_db,
            tenant_id="outbox-761",
            target_url="https://example.test/webhook",
        )
        setup_db.commit()

    _patch_outbox_secret(monkeypatch)
    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(500),
    )

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 0

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.dead_lettered is True
        assert event.claimed_by is None
        assert event.claim_expires_at is None


# #762
def test_outbox_no_subscription_releases_claim():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-762",
            event_type="no.subscription",
        )
        event_id = event.id

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 1

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.delivered is True
        assert event.claimed_by is None
        assert event.claim_expires_at is None


# #763
def test_outbox_failed_claim_does_not_increment_attempts():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-763",
        )
        event_id = event.id
        event.claimed_by = "other-worker"
        event.claim_expires_at = utcnow_naive() + timedelta(minutes=5)
        setup_db.commit()

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 0

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.attempts == 0
        assert event.delivered is False


# #764
def test_outbox_expired_claim_is_replaced_with_new_token():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-764",
        )
        event_id = event.id
        event.claimed_by = "expired-token"
        event.claim_expires_at = utcnow_naive() - timedelta(seconds=1)
        setup_db.commit()

    with SessionLocal() as db:
        new_token = _claim_outbox_event(
            db,
            event_id=event_id,
            now=utcnow_naive(),
            lease_seconds=60,
        )

    assert new_token is not None
    assert new_token != "expired-token"

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.claimed_by == new_token


# #765
def test_outbox_claim_cannot_take_delivered_event():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-765",
        )
        event_id = event.id
        event.delivered = True
        event.delivered_at = utcnow_naive()
        setup_db.commit()

    with SessionLocal() as db:
        claim = _claim_outbox_event(
            db,
            event_id=event_id,
            now=utcnow_naive(),
            lease_seconds=60,
        )

    assert claim is None

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)
        assert event is not None
        assert event.delivered is True
        assert event.claimed_by is None
        assert event.claim_expires_at is None

# #766
def test_outbox_delivery_id_is_stable_across_retry(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    delivery_ids = []
    responses = iter([500, 200])

    def fake_post(url, **kwargs):
        delivery_ids.append(
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(next(responses))

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-766",
            target_url="https://example.com/766",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-766",
        )
        event_id = event.id

    with SessionLocal() as db:
        first_count = deliver_pending_events(db)

    assert first_count == 0

    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        event.next_attempt_at = utcnow_naive() - timedelta(seconds=1)
        db.commit()

    with SessionLocal() as db:
        second_count = deliver_pending_events(db)

    assert second_count == 1
    assert len(delivery_ids) == 2
    assert delivery_ids[0] == delivery_ids[1]


# #767
def test_outbox_delivery_id_does_not_include_attempt_number(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    captured = {}

    def fake_post(url, **kwargs):
        captured["delivery_id"] = (
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        sub = _make_outbox_subscription(
            db,
            tenant_id="outbox-767",
            target_url="https://example.com/767",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-767",
        )
        event.attempts = 4
        db.commit()
        event_id = event.id
        sub_id = sub.id

    with SessionLocal() as db:
        deliver_pending_events(db)

    assert captured["delivery_id"] == f"evt-{event_id}-sub-{sub_id}"
    assert "try-" not in captured["delivery_id"]


# #768
def test_outbox_different_subscriptions_get_different_delivery_ids(
    monkeypatch,
):
    _patch_outbox_secret(monkeypatch)
    delivery_ids = []

    def fake_post(url, **kwargs):
        delivery_ids.append(
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-768",
            target_url="https://example.com/768-a",
        )
        _make_outbox_subscription(
            db,
            tenant_id="outbox-768",
            target_url="https://example.com/768-b",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-768",
        )

    with SessionLocal() as db:
        deliver_pending_events(db)

    assert len(delivery_ids) == 2
    assert len(set(delivery_ids)) == 2


# #769
def test_outbox_different_events_get_different_delivery_ids(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    delivery_ids = []

    def fake_post(url, **kwargs):
        delivery_ids.append(
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-769",
            target_url="https://example.com/769",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-769",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-769",
        )

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 2
    assert len(delivery_ids) == 2
    assert len(set(delivery_ids)) == 2


# #770
def test_outbox_delivery_id_matches_event_and_subscription(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    captured = {}

    def fake_post(url, **kwargs):
        captured["delivery_id"] = (
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        sub = _make_outbox_subscription(
            db,
            tenant_id="outbox-770",
            target_url="https://example.com/770",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-770",
        )
        event_id = event.id
        sub_id = sub.id

    with SessionLocal() as db:
        deliver_pending_events(db)

    assert captured["delivery_id"] == f"evt-{event_id}-sub-{sub_id}"


# #771
def test_outbox_retry_increments_attempt_but_keeps_delivery_id(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    delivery_ids = []

    def fake_post(url, **kwargs):
        delivery_ids.append(
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(500)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-771",
            target_url="https://example.com/771",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-771",
        )
        event_id = event.id

    with SessionLocal() as db:
        deliver_pending_events(db)

    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        assert event.attempts == 1
        event.next_attempt_at = utcnow_naive() - timedelta(seconds=1)
        db.commit()

    with SessionLocal() as db:
        deliver_pending_events(db)

    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        assert event.attempts == 2

    assert len(delivery_ids) == 2
    assert delivery_ids[0] == delivery_ids[1]


# #772
def test_outbox_successful_subscription_is_not_redelivered(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        sub = _make_outbox_subscription(
            db,
            tenant_id="outbox-772",
            target_url="https://example.com/772",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-772",
        )

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

    with SessionLocal() as db:
        count = deliver_pending_events(db)

    assert count == 1
    assert calls == []


# #773
def test_outbox_delivery_id_is_stable_after_expired_claim(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    captured = {}

    def fake_post(url, **kwargs):
        captured["delivery_id"] = (
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        sub = _make_outbox_subscription(
            db,
            tenant_id="outbox-773",
            target_url="https://example.com/773",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-773",
        )
        event.claimed_by = "expired-worker"
        event.claim_expires_at = utcnow_naive() - timedelta(seconds=1)
        db.commit()
        event_id = event.id
        sub_id = sub.id

    with SessionLocal() as db:
        deliver_pending_events(db)

    assert captured["delivery_id"] == f"evt-{event_id}-sub-{sub_id}"


# #774
def test_outbox_delivery_id_header_value_is_string(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    captured = {}

    def fake_post(url, **kwargs):
        captured["delivery_id"] = (
            kwargs["headers"][settings.webhook_delivery_id_header]
        )
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-774",
            target_url="https://example.com/774",
        )
        _make_outbox_event(
            db,
            tenant_id="outbox-774",
        )

    with SessionLocal() as db:
        deliver_pending_events(db)

    assert isinstance(captured["delivery_id"], str)
    assert captured["delivery_id"]


# #775
def test_outbox_two_subscriptions_keep_stable_ids_across_retry(monkeypatch):
    _patch_outbox_secret(monkeypatch)
    first_ids = {}
    second_ids = {}
    phase = {"value": 1}

    def fake_post(url, **kwargs):
        delivery_id = kwargs["headers"][
            settings.webhook_delivery_id_header
        ]

        if phase["value"] == 1:
            first_ids[url] = delivery_id
            return _OutboxResponse(500)

        second_ids[url] = delivery_id
        return _OutboxResponse(200)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        fake_post,
    )

    with SessionLocal() as db:
        _make_outbox_subscription(
            db,
            tenant_id="outbox-775",
            target_url="https://example.com/775-a",
        )
        _make_outbox_subscription(
            db,
            tenant_id="outbox-775",
            target_url="https://example.com/775-b",
        )
        event = _make_outbox_event(
            db,
            tenant_id="outbox-775",
        )
        event_id = event.id

    with SessionLocal() as db:
        first_count = deliver_pending_events(db)

    assert first_count == 0

    with SessionLocal() as db:
        event = db.get(OutboxEvent, event_id)
        event.next_attempt_at = utcnow_naive() - timedelta(seconds=1)
        db.commit()

    phase["value"] = 2

    with SessionLocal() as db:
        second_count = deliver_pending_events(db)

    assert second_count == 1
    assert first_ids == second_ids
    assert len(first_ids) == 2
    assert len(set(first_ids.values())) == 2

# #893
def test_outbox_malformed_payload_releases_claim():
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-893",
        )
        event.payload = "{not-valid-json"
        setup_db.commit()
        event_id = event.id

        _make_outbox_subscription(
            setup_db,
            tenant_id="outbox-893",
            target_url="https://example.test/webhook",
        )

    with pytest.raises(json.JSONDecodeError):
        with SessionLocal() as db:
            deliver_pending_events(db)

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)

        assert event is not None
        assert event.delivered is False
        assert event.claimed_by is None
        assert event.claim_expires_at is None


# #894
def test_outbox_attempt_recording_failure_releases_claim(monkeypatch):
    import app.outbox_worker as worker_module

    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-894",
        )
        event_id = event.id

        _make_outbox_subscription(
            setup_db,
            tenant_id="outbox-894",
            target_url="https://example.test/webhook",
        )

    _patch_outbox_secret(monkeypatch)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(200),
    )

    def failing_record_attempt(*args, **kwargs):
        raise RuntimeError("attempt_recording_failed")

    monkeypatch.setattr(
        worker_module,
        "_record_attempt",
        failing_record_attempt,
    )

    with pytest.raises(
        RuntimeError,
        match="attempt_recording_failed",
    ):
        with SessionLocal() as db:
            deliver_pending_events(db)

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)

        assert event is not None
        assert event.delivered is False
        assert event.claimed_by is None
        assert event.claim_expires_at is None


# #895
def test_outbox_final_commit_failure_releases_claim(monkeypatch):
    with SessionLocal() as setup_db:
        event = _make_outbox_event(
            setup_db,
            tenant_id="outbox-895",
        )
        event_id = event.id

        _make_outbox_subscription(
            setup_db,
            tenant_id="outbox-895",
            target_url="https://example.test/webhook",
        )

    _patch_outbox_secret(monkeypatch)

    monkeypatch.setattr(
        "app.outbox_worker.requests.post",
        lambda *args, **kwargs: _OutboxResponse(200),
    )

    with SessionLocal() as db:
        original_commit = db.commit
        commit_calls = 0

        def failing_second_commit():
            nonlocal commit_calls
            commit_calls += 1

            if commit_calls == 2:
                raise RuntimeError("final_commit_failed")

            return original_commit()

        monkeypatch.setattr(
            db,
            "commit",
            failing_second_commit,
        )

        with pytest.raises(
            RuntimeError,
            match="final_commit_failed",
        ):
            deliver_pending_events(db)

        db.rollback()

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)

        assert event is not None
        assert event.delivered is False
        assert event.claimed_by is None
        assert event.claim_expires_at is None

# #896
def test_outbox_release_claim_cannot_release_another_workers_claim():
    with SessionLocal() as db:
        event = _make_outbox_event(
            db,
            tenant_id="outbox-896",
        )
        event_id = event.id

        claim_token = _claim_outbox_event(
            db,
            event_id=event_id,
            now=utcnow_naive(),
            lease_seconds=60,
        )

        assert claim_token is not None

        released = _release_outbox_claim(
            db,
            event_id=event_id,
            claim_token="different-worker-token",
        )

        assert released is False

    with SessionLocal() as verify_db:
        event = verify_db.get(OutboxEvent, event_id)

        assert event is not None
        assert event.claimed_by == claim_token
        assert event.claim_expires_at is not None