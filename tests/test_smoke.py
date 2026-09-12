import pytest
from fastapi import HTTPException
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.config import settings
from app.database import SessionLocal
from app.main import commit_or_409, rate_limiter, replay_store
from app.models import AccessRight, OutboxEvent, PolicyRecord, RequestLog, Tenant, WebhookDeliveryAttempt, WebhookSubscription, WorkflowConfigRecord
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


def test_ownership_transfer_changes_owner_and_invalidates_old_owner(client):
    ensure_setup(client)

    # Issue two tokens for the original owner.
    # One performs the transfer; the other must become invalid afterwards.
    transfer_token = issue_token(
        client,
        scope="ownership_transfer",
        user_id="user-123",
    ).json()["token"]

    old_owner_token = issue_token(
        client,
        scope="access",
        user_id="user-123",
    ).json()["token"]

    # Transfer ownership to a new owner.
    transfer_response = client.post(
        "/request/access",
        headers=HEADERS,
        json={
            "token": transfer_token,
            "request_type": "ownership_transfer",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.10",
            "country_code": "EE",
            "new_owner_id": "user-456",
        },
    )

    assert transfer_response.status_code == 200
    assert transfer_response.json()["allow"] is True

    # Token belonging to the previous owner must no longer work.
    old_owner_response = access_request(client, old_owner_token)

    assert old_owner_response.status_code == 403
    assert old_owner_response.json()["detail"] == "owner_mismatch"

    # The new owner must be able to obtain and use a new token.
    new_token_response = issue_token(
        client,
        scope="access",
        user_id="user-456",
    )

    assert new_token_response.status_code == 200

    new_owner_token = new_token_response.json()["token"]
    new_owner_response = access_request(client, new_owner_token)

    assert new_owner_response.status_code == 200
    assert new_owner_response.json()["allow"] is True


def test_revoke_right_invalidates_access(client):
    ensure_setup(client)

    # Two tokens are issued while the right is still valid.
    # The first proves access works before revocation.
    # The second remains unused until after revocation.
    before_token = issue_token(client).json()["token"]
    after_token = issue_token(client).json()["token"]

    before_revoke = access_request(client, before_token)
    assert before_revoke.status_code == 200
    assert before_revoke.json()["allow"] is True

    revoke_response = client.post(
        "/rights/revoke",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
        },
    )

    assert revoke_response.status_code == 200
    assert revoke_response.json()["right_id"] == "right-001"
    assert revoke_response.json()["valid"] is False
    assert revoke_response.json()["version"] == 2

    after_revoke = access_request(client, after_token)

    assert after_revoke.status_code == 404
    assert after_revoke.json()["detail"] == "access_right_invalid"


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
    monkeypatch.setenv("JWT_KEYRING_JSON", '{"legacy":"legacy-secret-key-for-statelog-tests-2026","v2":"current-secret-key-for-statelog-tests-2026"}')
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

def test_commit_or_409_returns_409_on_integrity_conflict():
    from sqlalchemy.exc import IntegrityError

    class BrokenSession:
        def __init__(self):
            self.rolled_back = False

        def commit(self):
            raise IntegrityError(
                "forced statement",
                {},
                Exception("forced_integrity_conflict"),
            )

        def rollback(self):
            self.rolled_back = True

    session = BrokenSession()

    with pytest.raises(HTTPException) as exc_info:
        commit_or_409(session, detail="workflow_config_conflict")

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "workflow_config_conflict"
    assert session.rolled_back is True

def test_commit_or_409_returns_409_on_stale_write_conflict():
    from sqlalchemy.orm.exc import StaleDataError

    class BrokenSession:
        def __init__(self):
            self.rolled_back = False

        def commit(self):
            raise StaleDataError("forced_stale_write")

        def rollback(self):
            self.rolled_back = True

    session = BrokenSession()

    with pytest.raises(HTTPException) as exc_info:
        commit_or_409(
            session,
            detail="policy_update_conflict",
            stale_detail="policy_version_conflict",
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "policy_version_conflict"
    assert session.rolled_back is True

def test_policy_record_optimistic_lock_rejects_stale_session(client):
    from sqlalchemy.orm.exc import StaleDataError

    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "optimistic-lock-race-policy",
            "effect": "allow",
            "priority": 50,
            "request_types": ["access"],
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    db_a = SessionLocal()
    db_b = SessionLocal()

    try:
        policy_a = db_a.get(PolicyRecord, policy_id)
        policy_b = db_b.get(PolicyRecord, policy_id)

        assert policy_a is not None
        assert policy_b is not None
        assert policy_a.version == policy_b.version

        original_version = policy_a.version

        policy_a.priority = 51
        policy_a.version = original_version + 1
        db_a.commit()

        policy_b.priority = 52
        policy_b.version = original_version + 1

        with pytest.raises(StaleDataError):
            db_b.commit()

        db_b.rollback()

        with SessionLocal() as verify_db:
            persisted = verify_db.get(PolicyRecord, policy_id)
            assert persisted is not None
            assert persisted.priority == 51
            assert persisted.version == original_version + 1
    finally:
        db_a.close()
        db_b.rollback()
        db_b.close()

def test_workflow_config_record_optimistic_lock_rejects_stale_session(client):
    from sqlalchemy.orm.exc import StaleDataError

    ensure_setup(client)

    initial = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert initial.status_code == 200

    db_a = SessionLocal()
    db_b = SessionLocal()

    try:
        workflow_a = db_a.get(WorkflowConfigRecord, "tenant-demo")
        workflow_b = db_b.get(WorkflowConfigRecord, "tenant-demo")

        assert workflow_a is not None
        assert workflow_b is not None
        assert workflow_a.version == workflow_b.version

        original_version = workflow_a.version

        workflow_a.execution_mode = "policy_first"
        workflow_a.version = original_version + 1
        db_a.commit()

        workflow_b.include_risk_step = False
        workflow_b.version = original_version + 1

        with pytest.raises(StaleDataError):
            db_b.commit()

        db_b.rollback()

        with SessionLocal() as verify_db:
            persisted = verify_db.get(
                WorkflowConfigRecord,
                "tenant-demo",
            )
            assert persisted is not None
            assert persisted.execution_mode == "policy_first"
            assert persisted.include_risk_step is True
            assert persisted.version == original_version + 1
    finally:
        db_a.close()
        db_b.rollback()
        db_b.close()

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
def test_expired_token_returns_401(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    import jwt
    from datetime import datetime, timedelta, timezone
    from app.security import get_active_signing_key

    payload = jwt.decode(
        token,
        options={
            "verify_signature": False,
            "verify_exp": False,
        },
        algorithms=[settings.jwt_algorithm],
    )

    payload["iat"] = int(
        (datetime.now(timezone.utc) - timedelta(minutes=10)).timestamp()
    )
    payload["exp"] = int(
        (datetime.now(timezone.utc) - timedelta(minutes=5)).timestamp()
    )

    kid, signing_key = get_active_signing_key()

    expired_token = jwt.encode(
        payload,
        signing_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": kid},
    )

    response = access_request(client, expired_token)

    assert response.status_code == 401
    assert response.json()["detail"] == "token_expired"


def test_invalid_token_returns_401(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    invalid_token = token + "X"

    response = access_request(client, invalid_token)

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_token"

# #891
def test_tenant_negative_monthly_quota_is_rejected(client):
    response = client.post(
        "/admin/tenants",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-negative-quota",
            "name": "Negative Quota Tenant",
            "plan": "pro",
            "monthly_quota": -1,
        },
    )

    assert response.status_code == 422

# #892
def test_tenant_zero_monthly_quota_is_rejected(client):
    response = client.post(
        "/admin/tenants",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-zero-quota",
            "name": "Zero Quota Tenant",
            "plan": "pro",
            "monthly_quota": 0,
        },
    )

    assert response.status_code == 422


# #893
def test_tenant_monthly_quota_one_is_allowed(client):
    response = client.post(
        "/admin/tenants",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-min-quota",
            "name": "Minimum Quota Tenant",
            "plan": "pro",
            "monthly_quota": 1,
        },
    )

    assert response.status_code == 200
    assert response.json()["tenant_id"] == "tenant-min-quota"


# #894
def test_tenant_default_monthly_quota_is_1000(client):
    response = client.post(
        "/admin/tenants",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-default-quota",
            "name": "Default Quota Tenant",
            "plan": "pro",
        },
    )

    assert response.status_code == 200

    with SessionLocal() as db:
        tenant = db.get(Tenant, "tenant-default-quota")
        assert tenant is not None
        assert tenant.monthly_quota == 1000


# #895
def test_tenant_monthly_quota_is_persisted(client):
    response = client.post(
        "/admin/tenants",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-custom-quota",
            "name": "Custom Quota Tenant",
            "plan": "pro",
            "monthly_quota": 2500,
        },
    )

    assert response.status_code == 200

    with SessionLocal() as db:
        tenant = db.get(Tenant, "tenant-custom-quota")
        assert tenant is not None
        assert tenant.monthly_quota == 2500

# #896
def test_quota_rejected_request_does_not_increment_usage_count(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 1
        tenant.usage_count = 0
        db.commit()

    token = issue_token(client).json()["token"]

    first = access_request(client, token)
    assert first.status_code == 200

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        assert tenant.usage_count == 1

    next_token = issue_token(client).json()["token"]
    rejected = access_request(
        client,
        next_token,
        ip_address="10.0.0.11",
    )

    assert rejected.status_code == 429
    assert rejected.json()["detail"] == "tenant_quota_exceeded"

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        assert tenant.usage_count == 1

# #900
def test_tenant_quota_is_isolated_between_tenants(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant_demo = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant_other = db.query(Tenant).filter_by(id="tenant-other").one()

        tenant_demo.monthly_quota = 1
        tenant_demo.usage_count = 1

        tenant_other.monthly_quota = 1
        tenant_other.usage_count = 0
        db.commit()

    demo_token = issue_token(client).json()["token"]

    demo_response = access_request(
        client,
        demo_token,
        ip_address="10.0.0.21",
    )

    assert demo_response.status_code == 429
    assert demo_response.json()["detail"] == "tenant_quota_exceeded"

    client.post(
        "/rights/create",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-quota-isolation",
            "owner_id": "user-777",
            "valid": True,
        },
    )

    other_token_response = client.post(
        "/token/issue",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-quota-isolation",
            "user_id": "user-777",
            "device_id": "gate-X1",
            "scope": "access",
        },
    )

    assert other_token_response.status_code == 200
    other_token = other_token_response.json()["token"]

    other_response = client.post(
        "/request/access",
        headers=OTHER_HEADERS,
        json={
            "token": other_token,
            "request_type": "access",
            "device_id": "gate-X1",
            "ip_address": "10.0.0.22",
            "country_code": "EE",
        },
    )

    assert other_response.status_code == 200

    with SessionLocal() as db:
        tenant_demo = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant_other = db.query(Tenant).filter_by(id="tenant-other").one()

        assert tenant_demo.usage_count == 1
        assert tenant_other.usage_count == 1

# #901
def test_same_idempotency_key_is_isolated_between_tenants(client):
    ensure_setup(client)

    shared_key = "shared-key-across-tenants"

    demo_token = issue_token(client).json()["token"]
    demo_response = client.post(
        "/request/access",
        headers={
            **HEADERS,
            "Idempotency-Key": shared_key,
        },
        json={
            "token": demo_token,
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.31",
            "country_code": "EE",
        },
    )

    assert demo_response.status_code == 200

    client.post(
        "/rights/create",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-idempotency-isolation",
            "owner_id": "user-777",
            "valid": True,
        },
    )

    other_token_response = client.post(
        "/token/issue",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-idempotency-isolation",
            "user_id": "user-777",
            "device_id": "gate-X1",
            "scope": "access",
        },
    )

    assert other_token_response.status_code == 200

    other_response = client.post(
        "/request/access",
        headers={
            **OTHER_HEADERS,
            "Idempotency-Key": shared_key,
        },
        json={
            "token": other_token_response.json()["token"],
            "request_type": "access",
            "device_id": "gate-X1",
            "ip_address": "10.0.0.32",
            "country_code": "EE",
        },
    )

    assert other_response.status_code == 200

    with SessionLocal() as db:
        logs = (
            db.query(RequestLog)
            .filter(RequestLog.idempotency_key == shared_key)
            .all()
        )

        assert len(logs) == 2
        assert {log.tenant_id for log in logs} == {
            "tenant-demo",
            "tenant-other",
        }

# #902
def test_tenant_usage_count_is_isolated_between_tenants(client):
    ensure_setup(client)

    with SessionLocal() as db:
        demo = db.query(Tenant).filter_by(id="tenant-demo").one()
        other = db.query(Tenant).filter_by(id="tenant-other").one()

        demo.monthly_quota = 10
        other.monthly_quota = 10
        demo.usage_count = 0
        other.usage_count = 0
        db.commit()

    demo_token = issue_token(client).json()["token"]
    demo_response = access_request(
        client,
        demo_token,
        ip_address="10.0.0.41",
    )
    assert demo_response.status_code == 200

    client.post(
        "/rights/create",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-usage-isolation",
            "owner_id": "user-777",
            "valid": True,
        },
    )

    other_token_response = client.post(
        "/token/issue",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-usage-isolation",
            "user_id": "user-777",
            "device_id": "gate-X1",
            "scope": "access",
        },
    )
    assert other_token_response.status_code == 200

    other_response = client.post(
        "/request/access",
        headers=OTHER_HEADERS,
        json={
            "token": other_token_response.json()["token"],
            "request_type": "access",
            "device_id": "gate-X1",
            "ip_address": "10.0.0.42",
            "country_code": "EE",
        },
    )
    assert other_response.status_code == 200

    with SessionLocal() as db:
        demo = db.query(Tenant).filter_by(id="tenant-demo").one()
        other = db.query(Tenant).filter_by(id="tenant-other").one()

        assert demo.usage_count == 1
        assert other.usage_count == 1

# #903
def test_idempotency_conflict_does_not_increment_usage_count(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 10
        tenant.usage_count = 0
        db.commit()

    token = issue_token(client).json()["token"]
    headers = {
        **HEADERS,
        "Idempotency-Key": "usage-idempotency-conflict",
    }

    first = client.post(
        "/request/access",
        headers=headers,
        json={
            "token": token,
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.51",
            "country_code": "EE",
        },
    )
    assert first.status_code == 200

    second = client.post(
        "/request/access",
        headers=headers,
        json={
            "token": token,
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.52",
            "country_code": "EE",
        },
    )
    assert second.status_code == 409
    assert second.json()["detail"] == "idempotency_key_conflict"

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        assert tenant.usage_count == 1


# #904
def test_invalid_token_does_not_increment_usage_count(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 10
        tenant.usage_count = 0
        db.commit()

    response = client.post(
        "/request/access",
        headers=HEADERS,
        json={
            "token": "not-a-valid-token",
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.53",
            "country_code": "EE",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_token"

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        assert tenant.usage_count == 0


# #905
def test_device_mismatch_does_not_increment_usage_count(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 10
        tenant.usage_count = 0
        db.commit()

    create_device = client.post(
        "/admin/devices",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "device_id": "gate-A2",
            "description": "Second demo gate",
        },
    )
    assert create_device.status_code == 200

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A2",
        ip_address="10.0.0.54",
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "device_mismatch"

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        assert tenant.usage_count == 0


# #906
def test_scope_mismatch_does_not_increment_usage_count(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 10
        tenant.usage_count = 0
        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        request_type="ownership_transfer",
        ip_address="10.0.0.55",
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "scope_mismatch"

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        assert tenant.usage_count == 0


# #907
def test_owner_mismatch_does_not_increment_usage_count(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 10
        tenant.usage_count = 0
        db.commit()

    token = issue_token(client).json()["token"]

    with SessionLocal() as db:
        right = (
            db.query(AccessRight)
            .filter_by(
                tenant_id="tenant-demo",
                right_id="right-001",
            )
            .one()
        )
        right.owner_id = "user-999"
        right.version += 1
        db.commit()

    response = access_request(
        client,
        token,
        ip_address="10.0.0.56",
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "owner_mismatch"

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        assert tenant.usage_count == 0

# #913
def test_idempotent_allowed_retry_emits_one_decision_event(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    headers = {
        **HEADERS,
        "Idempotency-Key": "outbox-allowed-retry",
    }
    payload = {
        "token": token,
        "request_type": "access",
        "device_id": "gate-A1",
        "ip_address": "10.0.0.61",
        "country_code": "EE",
    }

    first = client.post("/request/access", headers=headers, json=payload)
    second = client.post("/request/access", headers=headers, json=payload)

    assert first.status_code == 200
    assert second.status_code == 200

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter_by(
                tenant_id="tenant-demo",
                event_type="decision.allowed",
            )
            .all()
        )
        assert len(events) == 1


# #914
def test_idempotent_allowed_retry_emits_one_billing_event(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    headers = {
        **HEADERS,
        "Idempotency-Key": "outbox-billing-retry",
    }
    payload = {
        "token": token,
        "request_type": "access",
        "device_id": "gate-A1",
        "ip_address": "10.0.0.62",
        "country_code": "EE",
    }

    first = client.post("/request/access", headers=headers, json=payload)
    second = client.post("/request/access", headers=headers, json=payload)

    assert first.status_code == 200
    assert second.status_code == 200

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter_by(
                tenant_id="tenant-demo",
                event_type="billing.usage.incremented",
            )
            .all()
        )
        assert len(events) == 1


# #915
def test_idempotent_denied_retry_emits_one_decision_event(client):
    ensure_setup(client)

    token = issue_token(
        client,
        scope="ownership_transfer",
    ).json()["token"]

    headers = {
        **HEADERS,
        "Idempotency-Key": "outbox-denied-retry",
    }
    payload = {
        "token": token,
        "request_type": "ownership_transfer",
        "device_id": "gate-A1",
        "ip_address": "10.0.0.63",
        "country_code": "EE",
        "new_owner_id": "user-123",
    }

    first = client.post("/request/access", headers=headers, json=payload)
    second = client.post("/request/access", headers=headers, json=payload)

    assert first.status_code == 200
    assert first.json()["allow"] is False
    assert second.status_code == 200

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter_by(
                tenant_id="tenant-demo",
                event_type="decision.denied",
            )
            .all()
        )
        assert len(events) == 1


# #916
def test_idempotent_denied_retry_emits_one_billing_event(client):
    ensure_setup(client)

    token = issue_token(
        client,
        scope="ownership_transfer",
    ).json()["token"]

    headers = {
        **HEADERS,
        "Idempotency-Key": "outbox-denied-billing-retry",
    }
    payload = {
        "token": token,
        "request_type": "ownership_transfer",
        "device_id": "gate-A1",
        "ip_address": "10.0.0.64",
        "country_code": "EE",
        "new_owner_id": "user-123",
    }

    first = client.post("/request/access", headers=headers, json=payload)
    second = client.post("/request/access", headers=headers, json=payload)

    assert first.status_code == 200
    assert first.json()["allow"] is False
    assert second.status_code == 200

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter_by(
                tenant_id="tenant-demo",
                event_type="billing.usage.incremented",
            )
            .all()
        )
        assert len(events) == 1


# #917
def test_idempotency_conflict_does_not_emit_second_decision_event(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    headers = {
        **HEADERS,
        "Idempotency-Key": "outbox-conflict-decision",
    }

    first = client.post(
        "/request/access",
        headers=headers,
        json={
            "token": token,
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.65",
            "country_code": "EE",
        },
    )

    second = client.post(
        "/request/access",
        headers=headers,
        json={
            "token": token,
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.66",
            "country_code": "EE",
        },
    )

    assert first.status_code == 200
    assert second.status_code == 409

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter_by(
                tenant_id="tenant-demo",
                event_type="decision.allowed",
            )
            .all()
        )
        assert len(events) == 1


# #918
def test_idempotency_conflict_does_not_emit_second_billing_event(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    headers = {
        **HEADERS,
        "Idempotency-Key": "outbox-conflict-billing",
    }

    first = client.post(
        "/request/access",
        headers=headers,
        json={
            "token": token,
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.67",
            "country_code": "EE",
        },
    )

    second = client.post(
        "/request/access",
        headers=headers,
        json={
            "token": token,
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.68",
            "country_code": "EE",
        },
    )

    assert first.status_code == 200
    assert second.status_code == 409

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter_by(
                tenant_id="tenant-demo",
                event_type="billing.usage.incremented",
            )
            .all()
        )
        assert len(events) == 1


# #919
def test_quota_rejection_emits_no_decision_event(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 1
        tenant.usage_count = 1
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(
        client,
        token,
        ip_address="10.0.0.69",
    )

    assert response.status_code == 429

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.tenant_id == "tenant-demo",
                OutboxEvent.event_type.in_(
                    ["decision.allowed", "decision.denied"]
                ),
            )
            .all()
        )
        assert events == []


# #920
def test_quota_rejection_emits_no_billing_event(client):
    ensure_setup(client)

    with SessionLocal() as db:
        tenant = db.query(Tenant).filter_by(id="tenant-demo").one()
        tenant.monthly_quota = 1
        tenant.usage_count = 1
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(
        client,
        token,
        ip_address="10.0.0.70",
    )

    assert response.status_code == 429

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter_by(
                tenant_id="tenant-demo",
                event_type="billing.usage.incremented",
            )
            .all()
        )
        assert events == []


# #921
def test_invalid_token_emits_no_access_side_effect_events(client):
    ensure_setup(client)

    response = client.post(
        "/request/access",
        headers=HEADERS,
        json={
            "token": "invalid-token",
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.71",
            "country_code": "EE",
        },
    )

    assert response.status_code == 401

    with SessionLocal() as db:
        events = (
            db.query(OutboxEvent)
            .filter(
                OutboxEvent.tenant_id == "tenant-demo",
                OutboxEvent.event_type.in_(
                    [
                        "decision.allowed",
                        "decision.denied",
                        "billing.usage.incremented",
                    ]
                ),
            )
            .all()
        )
        assert events == []


# #922
def test_access_side_effect_events_are_tenant_isolated(client):
    ensure_setup(client)

    demo_token = issue_token(client).json()["token"]
    demo_response = access_request(
        client,
        demo_token,
        ip_address="10.0.0.72",
    )
    assert demo_response.status_code == 200

    client.post(
        "/rights/create",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-outbox-isolation",
            "owner_id": "user-777",
            "valid": True,
        },
    )

    other_token_response = client.post(
        "/token/issue",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-outbox-isolation",
            "user_id": "user-777",
            "device_id": "gate-X1",
            "scope": "access",
        },
    )
    assert other_token_response.status_code == 200

    other_response = client.post(
        "/request/access",
        headers=OTHER_HEADERS,
        json={
            "token": other_token_response.json()["token"],
            "request_type": "access",
            "device_id": "gate-X1",
            "ip_address": "10.0.0.73",
            "country_code": "EE",
        },
    )
    assert other_response.status_code == 200

    with SessionLocal() as db:
        demo_events = (
            db.query(OutboxEvent)
            .filter_by(tenant_id="tenant-demo")
            .all()
        )
        other_events = (
            db.query(OutboxEvent)
            .filter_by(tenant_id="tenant-other")
            .all()
        )

        assert len(demo_events) == 2
        assert len(other_events) == 2

        assert {event.event_type for event in demo_events} == {
            "decision.allowed",
            "billing.usage.incremented",
        }
        assert {event.event_type for event in other_events} == {
            "decision.allowed",
            "billing.usage.incremented",
        }

# #897
def test_create_right_rejects_other_tenant(client):
    ensure_setup(client)

    response = client.post(
        "/rights/create",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "cross-tenant-right",
            "owner_id": "user-777",
            "valid": True,
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


# #898
def test_revoke_right_rejects_other_tenant(client):
    ensure_setup(client)

    response = client.post(
        "/rights/revoke",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-777",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


# #899
def test_token_issue_rejects_other_tenant(client):
    ensure_setup(client)

    response = client.post(
        "/token/issue",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-777",
            "user_id": "user-777",
            "device_id": "gate-X1",
            "scope": "access",
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"


# #900
def test_tenant_dashboard_rejects_other_tenant(client):
    ensure_setup(client)

    response = client.get(
        "/tenant/tenant-other",
        headers=HEADERS,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "tenant_mismatch"

# #901
def test_client_auth_rejects_missing_tenant_header(client):
    ensure_setup(client)

    headers = {
        "X-Client-Id": "gateway-1",
        "X-API-Key": "super-secret",
    }

    response = client.post(
        "/token/issue",
        headers=headers,
        json={
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "user_id": "user-123",
            "device_id": "gate-A1",
            "scope": "access",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "missing_client_headers"


# #902
def test_client_auth_rejects_missing_client_id(client):
    ensure_setup(client)

    headers = {
        "X-API-Key": "super-secret",
        "X-Tenant-Id": "tenant-demo",
    }

    response = client.post(
        "/token/issue",
        headers=headers,
        json={
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "user_id": "user-123",
            "device_id": "gate-A1",
            "scope": "access",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "missing_client_headers"


# #903
def test_client_auth_rejects_missing_api_key(client):
    ensure_setup(client)

    headers = {
        "X-Client-Id": "gateway-1",
        "X-Tenant-Id": "tenant-demo",
    }

    response = client.post(
        "/token/issue",
        headers=headers,
        json={
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "user_id": "user-123",
            "device_id": "gate-A1",
            "scope": "access",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "missing_client_headers"


# #904
def test_client_auth_rejects_wrong_api_key(client):
    ensure_setup(client)

    headers = {
        "X-Client-Id": "gateway-1",
        "X-API-Key": "wrong-secret",
        "X-Tenant-Id": "tenant-demo",
    }

    response = client.post(
        "/token/issue",
        headers=headers,
        json={
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "user_id": "user-123",
            "device_id": "gate-A1",
            "scope": "access",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_client"


# #905
def test_client_auth_rejects_cross_tenant_credential_mix(client):
    ensure_setup(client)

    headers = {
        "X-Client-Id": "gateway-1",
        "X-API-Key": "super-secret",
        "X-Tenant-Id": "tenant-other",
    }

    response = client.post(
        "/token/issue",
        headers=headers,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-777",
            "user_id": "user-777",
            "device_id": "gate-X1",
            "scope": "access",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_client"


# #906
def test_client_auth_rejects_disabled_credential(client):
    ensure_setup(client)

    from app.database import SessionLocal
    from app.models import ClientCredential

    with SessionLocal() as db:
        credential = (
            db.query(ClientCredential)
            .filter_by(
                tenant_id="tenant-demo",
                client_id="gateway-1",
            )
            .one()
        )
        credential.enabled = False
        db.commit()

    response = client.post(
        "/token/issue",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "user_id": "user-123",
            "device_id": "gate-A1",
            "scope": "access",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_client"

def test_rate_limit_fail_open_falls_back_to_memory(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    class BrokenRedisLimiter:
        def allow(self, *args, **kwargs):
            raise RedisError("redis_down")

    original = rate_limiter.redis_limiter, rate_limiter.fail_closed
    rate_limiter.redis_limiter = BrokenRedisLimiter()
    rate_limiter.fail_closed = False

    try:
        response = access_request(
            client,
            token,
            ip_address="10.0.0.80",
        )

        assert response.status_code == 200
    finally:
        rate_limiter.redis_limiter, rate_limiter.fail_closed = original

def test_invalid_client_auth_does_not_reach_rate_limiter(client, monkeypatch):
    ensure_setup(client)

    def should_not_be_called(*args, **kwargs):
        raise AssertionError("rate_limiter_should_not_be_called")

    monkeypatch.setattr(rate_limiter, "allow", should_not_be_called)

    headers = {
        "X-Client-Id": "gateway-1",
        "X-API-Key": "wrong-secret",
        "X-Tenant-Id": "tenant-demo",
    }

    response = client.post(
        "/request/access",
        headers=headers,
        json={
            "token": "irrelevant-token",
            "request_type": "access",
            "device_id": "gate-A1",
            "ip_address": "10.0.0.81",
            "country_code": "EE",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_client"

def test_client_rate_limit_cannot_be_bypassed_with_different_ip(client):
    ensure_setup(client)

    old_limit = settings.rate_limit_per_minute
    settings.rate_limit_per_minute = 1

    try:
        first_token = issue_token(client).json()["token"]
        first = access_request(
            client,
            first_token,
            ip_address="10.0.0.82",
        )

        assert first.status_code == 200

        second_token = issue_token(client).json()["token"]
        second = access_request(
            client,
            second_token,
            ip_address="10.0.0.83",
        )

        assert second.status_code == 429
        assert second.json()["detail"] == "rate_limited"
    finally:
        settings.rate_limit_per_minute = old_limit

def test_large_streamed_request_without_content_length_is_rejected(client):
    ensure_setup(client)

    body = (
        '{"tenant_id":"tenant-demo",'
        '"right_id":"right-001",'
        '"user_id":"user-123",'
        '"device_id":"gate-A1",'
        '"scope":"access",'
        '"padding":"'
        + ("x" * (1024 * 1024))
        + '"}'
    ).encode()

    response = client.post(
        "/token/issue",
        headers={
            **HEADERS,
            "Content-Type": "application/json",
        },
        content=iter([body]),
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "request_too_large"

def test_small_streamed_request_without_content_length_is_allowed(client):
    ensure_setup(client)

    body = (
        '{"tenant_id":"tenant-demo",'
        '"right_id":"right-001",'
        '"user_id":"user-123",'
        '"device_id":"gate-A1",'
        '"scope":"access"}'
    ).encode()

    response = client.post(
        "/token/issue",
        headers={
            **HEADERS,
            "Content-Type": "application/json",
        },
        content=iter([body]),
    )

    assert response.status_code == 200


def test_oversized_content_length_is_rejected_before_endpoint(client):
    response = client.post(
        "/token/issue",
        headers={
            **HEADERS,
            "Content-Type": "application/json",
            "Content-Length": str((1024 * 1024) + 1),
        },
        content=b"{}",
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "request_too_large"


def test_negative_content_length_is_rejected(client):
    response = client.post(
        "/token/issue",
        headers={
            **HEADERS,
            "Content-Type": "application/json",
            "Content-Length": "-1",
        },
        content=b"{}",
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "invalid_content_length"

def test_atomic_quota_reservation_rejects_stale_session(client):
    ensure_setup(client)

    from app.main import reserve_tenant_quota

    with SessionLocal() as setup_db:
        tenant = setup_db.get(Tenant, "tenant-demo")
        tenant.monthly_quota = 1
        tenant.usage_count = 0
        setup_db.commit()

    db_a = SessionLocal()
    db_b = SessionLocal()

    try:
        tenant_a = db_a.get(Tenant, "tenant-demo")
        tenant_b = db_b.get(Tenant, "tenant-demo")

        assert tenant_a.usage_count == 0
        assert tenant_b.usage_count == 0

        usage_count = reserve_tenant_quota(db_a, "tenant-demo")
        assert usage_count == 1
        db_a.commit()

        # db_b still has a stale ORM snapshot showing usage_count == 0.
        assert tenant_b.usage_count == 0

        with pytest.raises(HTTPException) as exc_info:
            reserve_tenant_quota(db_b, "tenant-demo")

        assert exc_info.value.status_code == 429
        assert exc_info.value.detail == "tenant_quota_exceeded"

        db_b.rollback()

    finally:
        db_a.close()
        db_b.close()

    with SessionLocal() as verify_db:
        tenant = verify_db.get(Tenant, "tenant-demo")
        assert tenant.usage_count == 1

def test_atomic_quota_reservation_rolls_back_with_transaction(client):
    ensure_setup(client)

    from app.main import reserve_tenant_quota

    with SessionLocal() as setup_db:
        tenant = setup_db.get(Tenant, "tenant-demo")
        tenant.monthly_quota = 10
        tenant.usage_count = 0
        setup_db.commit()

    with SessionLocal() as db:
        usage_count = reserve_tenant_quota(db, "tenant-demo")

        assert usage_count == 1

        db.rollback()

    with SessionLocal() as verify_db:
        tenant = verify_db.get(Tenant, "tenant-demo")
        assert tenant.usage_count == 0