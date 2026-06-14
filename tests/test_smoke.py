import pytest
from fastapi import HTTPException
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.database import SessionLocal
from app.main import commit_or_409, rate_limiter, replay_store
from app.models import AccessRight, OutboxEvent, RequestLog, Tenant, WebhookDeliveryAttempt, WebhookSubscription
from app.outbox_worker import deliver_pending_events

ADMIN_HEADERS = {"X-Admin-Api-Key": "test-admin-key"}
HEADERS = {"X-Client-Id": "gateway-1", "X-API-Key": "super-secret", "X-Tenant-Id": "tenant-demo"}
OTHER_HEADERS = {"X-Client-Id": "gateway-2", "X-API-Key": "other-secret", "X-Tenant-Id": "tenant-other"}


def ensure_setup(client):
    client.post("/admin/tenants", headers=ADMIN_HEADERS, json={"tenant_id": "tenant-demo", "name": "Demo Tenant", "plan": "pro", "monthly_quota": 50})
    client.post("/admin/tenants", headers=ADMIN_HEADERS, json={"tenant_id": "tenant-other", "name": "Other Tenant", "plan": "pro", "monthly_quota": 50})
    client.post("/admin/clients", headers=ADMIN_HEADERS, json={"tenant_id": "tenant-demo", "client_id": "gateway-1", "api_key": "super-secret"})
    client.post("/admin/clients", headers=ADMIN_HEADERS, json={"tenant_id": "tenant-other", "client_id": "gateway-2", "api_key": "other-secret"})
    client.post("/admin/devices", headers=HEADERS, json={"tenant_id": "tenant-demo", "device_id": "gate-A1", "description": "Front gate"})
    client.post("/admin/devices", headers=OTHER_HEADERS, json={"tenant_id": "tenant-other", "device_id": "gate-X1", "description": "Other gate"})
    client.post("/rights/create", headers=HEADERS, json={"tenant_id": "tenant-demo", "right_id": "right-001", "owner_id": "user-123", "valid": True})
    client.post("/rights/create", headers=OTHER_HEADERS, json={"tenant_id": "tenant-other", "right_id": "right-777", "owner_id": "user-777", "valid": False})


def issue_token(client, scope="access", user_id="user-123"):
    token_resp = client.post(
        "/token/issue",
        headers=HEADERS,
        json={"tenant_id": "tenant-demo", "right_id": "right-001", "user_id": user_id, "device_id": "gate-A1", "scope": scope},
    )
    return token_resp


def access_request(client, token, **overrides):
    body = {"token": token, "request_type": "access", "device_id": "gate-A1", "ip_address": "10.0.0.10", "country_code": "EE"}
    body.update(overrides)
    return client.post("/request/access", headers=HEADERS, json=body)


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_admin_requires_auth(client):
    response = client.post("/admin/tenants", json={"tenant_id": "x", "name": "X"})
    assert response.status_code == 401


def test_access_flow(client):
    ensure_setup(client)
    token_resp = issue_token(client)
    assert token_resp.status_code == 200
    decision_resp = access_request(client, token_resp.json()["token"])
    assert decision_resp.status_code == 200
    body = decision_resp.json()
    assert isinstance(body["allow"], bool)
    assert body["allow"] is True
    assert body["decision_version"] == settings.request_decision_version
    assert "trace_id" in body
    assert "idempotency_key" in body


def test_create_device_rejects_other_tenant(client):
    ensure_setup(client)
    response = client.post(
        "/admin/devices",
        headers=HEADERS,
        json={"tenant_id": "tenant-other", "device_id": "gate-Z9", "description": "Wrong tenant"},
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


def test_token_issue_rejects_invalid_right(client):
    ensure_setup(client)
    response = client.post(
        "/token/issue",
        headers=OTHER_HEADERS,
        json={"tenant_id": "tenant-other", "right_id": "right-777", "user_id": "user-777", "device_id": "gate-X1", "scope": "access"},
    )
    assert response.status_code == 404


def test_token_issue_rejects_owner_mismatch(client):
    ensure_setup(client)
    response = issue_token(client, user_id="user-999")
    assert response.status_code == 403
    assert response.json()["detail"] == "owner_mismatch"


def test_duplicate_tenant_returns_409(client):
    response1 = client.post("/admin/tenants", headers=ADMIN_HEADERS, json={"tenant_id": "dup-tenant", "name": "Dup Tenant"})
    response2 = client.post("/admin/tenants", headers=ADMIN_HEADERS, json={"tenant_id": "dup-tenant", "name": "Dup Tenant"})
    assert response1.status_code == 200
    assert response2.status_code == 409


def test_access_rejects_owner_change_after_token_issue(client):
    ensure_setup(client)
    token = issue_token(client).json()["token"]
    with SessionLocal() as db:
        right = db.query(AccessRight).filter_by(tenant_id="tenant-demo", right_id="right-001").one()
        right.owner_id = "user-999"
        right.version += 1
        db.commit()
    response = access_request(client, token)
    assert response.status_code == 403
    assert response.json()["detail"] == "owner_mismatch"


def test_replay_same_token_returns_409(client):
    ensure_setup(client)
    token = issue_token(client).json()["token"]
    first = access_request(client, token)
    second = access_request(client, token)
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"] == "replay_detected"


def test_ownership_transfer_requires_rules(client):
    ensure_setup(client)
    token = issue_token(client, scope="ownership_transfer").json()["token"]
    missing = client.post(
        "/request/access",
        headers=HEADERS,
        json={"token": token, "request_type": "ownership_transfer", "device_id": "gate-A1", "ip_address": "10.0.0.10", "country_code": "EE"},
    )
    assert missing.status_code == 200 and missing.json()["allow"] is False


def test_ip_limit_is_tenant_isolated(client):
    ensure_setup(client)
    old_limit = settings.rate_limit_per_minute
    settings.rate_limit_per_minute = 1
    try:
        token_demo = issue_token(client).json()["token"]
        first = access_request(client, token_demo)
        assert first.status_code == 200
        second = client.post(
            "/token/issue",
            headers=OTHER_HEADERS,
            json={"tenant_id": "tenant-other", "right_id": "right-777", "user_id": "user-777", "device_id": "gate-X1", "scope": "access"},
        )
        assert second.status_code == 404  # invalid right blocks issuance, so make another valid right
        client.post("/rights/create", headers=OTHER_HEADERS, json={"tenant_id": "tenant-other", "right_id": "right-778", "owner_id": "user-777", "valid": True})
        token_other = client.post(
            "/token/issue",
            headers=OTHER_HEADERS,
            json={"tenant_id": "tenant-other", "right_id": "right-778", "user_id": "user-777", "device_id": "gate-X1", "scope": "access"},
        ).json()["token"]
        other = client.post(
            "/request/access",
            headers=OTHER_HEADERS,
            json={"token": token_other, "request_type": "access", "device_id": "gate-X1", "ip_address": "10.0.0.10", "country_code": "EE"},
        )
        assert other.status_code == 200
    finally:
        settings.rate_limit_per_minute = old_limit


def test_audit_log_stores_hashed_ip_only(client):
    ensure_setup(client)
    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200
    with SessionLocal() as db:
        log = db.query(RequestLog).filter_by(tenant_id="tenant-demo").one()
        assert log.ip_hash != "10.0.0.10"
        assert len(log.ip_hash) >= 32


def test_quota_exceeded_returns_429(client):
    ensure_setup(client)
    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 1
        db.commit()
    token = issue_token(client).json()["token"]
    first = access_request(client, token)
    assert first.status_code == 200
    next_token = issue_token(client).json()["token"]
    second = access_request(client, next_token, ip_address="10.0.0.11")
    assert second.status_code == 429
    assert second.json()["detail"] == "tenant_quota_exceeded"



def test_jwt_key_rotation_decode_legacy_token(monkeypatch, client):
    ensure_setup(client)
    monkeypatch.setenv('JWT_KEYRING_JSON', '{"legacy":"legacy-secret","v2":"current-secret"}')
    monkeypatch.setenv('JWT_ACTIVE_KID', 'legacy')
    import importlib
    import app.config as config_module
    import app.security as security_module
    importlib.reload(config_module)
    importlib.reload(security_module)
    token = security_module.issue_access_token(
        tenant_id='tenant-demo',
        right_id='right-001',
        user_id='user-123',
        device_id='gate-A1',
        scope='access',
    )
    decoded = security_module.decode_access_token(token)
    assert decoded['sub'] == 'user-123'
    assert decoded['kv'] == 'legacy'


def test_webhook_delivery_is_signed_and_tracked(client, monkeypatch):
    ensure_setup(client)
    sub_resp = client.post(
        '/webhooks/subscriptions',
        headers=HEADERS,
        json={'tenant_id': 'tenant-demo', 'target_url': 'https://example.com/hook', 'event_type': 'decision.allowed', 'signing_secret': 'whsec-123'},
    )
    assert sub_resp.status_code == 200

    captured = {}

    class Response:
        status_code = 202

    def fake_post(url, json=None, timeout=None, headers=None):
        captured['url'] = url
        captured['json'] = json
        captured['headers'] = headers
        return Response()

    monkeypatch.setattr('app.outbox_worker.requests.post', fake_post)
    with SessionLocal() as db:
        db.add(OutboxEvent(tenant_id='tenant-demo', event_type='decision.allowed', payload='{"trace_id":"t1"}', delivered=False))
        db.commit()
        count = deliver_pending_events(db)
        assert count == 1
        attempts = db.query(WebhookDeliveryAttempt).all()
        assert len(attempts) == 1
        assert attempts[0].successful is True
        sub = db.query(WebhookSubscription).one()
        assert sub.signing_secret_encrypted != 'whsec-123'

    assert captured['url'] == 'https://example.com/hook'
    assert 'X-Webhook-Signature' in captured['headers']
    assert 'X-Webhook-Event-Id' in captured['headers']
    assert 'X-Webhook-Delivery-Id' in captured['headers']


def test_webhook_dead_letters_after_max_attempts(client, monkeypatch):
    ensure_setup(client)
    client.post(
        '/webhooks/subscriptions',
        headers=HEADERS,
        json={'tenant_id': 'tenant-demo', 'target_url': 'https://example.com/fail', 'event_type': 'decision.allowed', 'signing_secret': 'whsec-123'},
    )

    def failing_post(*args, **kwargs):
        raise RuntimeError('network_down')

    monkeypatch.setattr('app.outbox_worker.requests.post', failing_post)
    old_attempts = settings.webhook_max_attempts
    settings.webhook_max_attempts = 2
    try:
        with SessionLocal() as db:
            db.add(OutboxEvent(tenant_id='tenant-demo', event_type='decision.allowed', payload='{"trace_id":"t1"}', delivered=False))
            db.commit()
            first = deliver_pending_events(db)
            assert first == 0
            event = db.query(OutboxEvent).one()
            assert event.dead_lettered is False
            event.next_attempt_at = event.next_attempt_at.replace(year=2000)
            db.commit()
            second = deliver_pending_events(db)
            assert second == 0
            event = db.query(OutboxEvent).one()
            assert event.dead_lettered is True
            attempts = db.query(WebhookDeliveryAttempt).all()
            assert len(attempts) == 2
    finally:
        settings.webhook_max_attempts = old_attempts


def test_rate_limit_fail_closed_returns_429(client, monkeypatch):
    ensure_setup(client)
    token = issue_token(client).json()["token"]

    class BrokenRedisLimiter:
        def allow(self, *args, **kwargs):
            raise RedisError("redis_down")

    original = rate_limiter.redis_limiter, rate_limiter.fail_closed
    rate_limiter.redis_limiter = BrokenRedisLimiter()
    rate_limiter.fail_closed = True
    try:
        response = access_request(client, token, ip_address="10.0.0.50")
        assert response.status_code == 429
        assert response.json()["detail"] == "rate_limited"
    finally:
        rate_limiter.redis_limiter, rate_limiter.fail_closed = original


def test_replay_store_fail_open_falls_back_to_memory(client):
    ensure_setup(client)
    token = issue_token(client).json()["token"]

    class BrokenRedisReplay:
        def mark_if_first_seen(self, *args, **kwargs):
            raise RedisError("redis_down")

    original = replay_store.redis_store, replay_store.fail_closed
    replay_store.redis_store = BrokenRedisReplay()
    replay_store.fail_closed = False
    try:
        first = access_request(client, token, ip_address="10.0.0.60")
        second = access_request(client, token, ip_address="10.0.0.60")
        assert first.status_code == 200
        assert second.status_code == 409
        assert second.json()["detail"] == "replay_detected"
    finally:
        replay_store.redis_store, replay_store.fail_closed = original


def test_replay_store_fail_closed_blocks_request(client):
    ensure_setup(client)
    token = issue_token(client).json()["token"]

    class BrokenRedisReplay:
        def mark_if_first_seen(self, *args, **kwargs):
            raise RedisError("redis_down")

    original = replay_store.redis_store, replay_store.fail_closed
    replay_store.redis_store = BrokenRedisReplay()
    replay_store.fail_closed = True
    try:
        response = access_request(client, token, ip_address="10.0.0.61")
        assert response.status_code == 409
        assert response.json()["detail"] == "replay_detected"
    finally:
        replay_store.redis_store, replay_store.fail_closed = original


def test_commit_or_409_returns_503_on_database_write_failure():
    class BrokenSession:
        def __init__(self):
            self.rolled_back = False

        def commit(self):
            raise SQLAlchemyError("db_down")

        def rollback(self):
            self.rolled_back = True

    session = BrokenSession()
    with pytest.raises(HTTPException) as exc_info:
        commit_or_409(session)
    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "persistence_unavailable"
    assert session.rolled_back is True


def test_webhook_delivery_commit_failure_bubbles_for_supervisor_visibility(client, monkeypatch):
    ensure_setup(client)
    client.post(
        '/webhooks/subscriptions',
        headers=HEADERS,
        json={'tenant_id': 'tenant-demo', 'target_url': 'https://example.com/hook', 'event_type': 'decision.allowed', 'signing_secret': 'whsec-123'},
    )

    class Response:
        status_code = 202

    def fake_post(*args, **kwargs):
        return Response()

    monkeypatch.setattr('app.outbox_worker.requests.post', fake_post)

    with SessionLocal() as db:
        db.add(OutboxEvent(tenant_id='tenant-demo', event_type='decision.allowed', payload='{"trace_id":"t2"}', delivered=False))
        db.commit()
        original_commit = db.commit

        def broken_commit():
            raise SQLAlchemyError('db_commit_failed')

        monkeypatch.setattr(db, 'commit', broken_commit)
        with pytest.raises(SQLAlchemyError):
            deliver_pending_events(db)
        db.commit = original_commit

