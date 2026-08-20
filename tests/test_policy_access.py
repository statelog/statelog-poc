from datetime import datetime
from app.models import PolicyRecord, RequestLog
from app.models import PolicyRecord

from tests.test_smoke import HEADERS, ensure_setup, issue_token, access_request


def test_access_without_policy_uses_risk_decision(client):
    ensure_setup(client)
    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()

    assert body["allow"] is True
    assert not body["reason"].startswith("policy_")


def test_matching_deny_policy_overrides_access(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="test-deny",
                effect="deny",
                priority=10,
                request_types="access",
                countries="EE",
                device_ids="",
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()

    assert body["allow"] is False
    assert body["reason"] == "policy_deny:test-deny"


def test_matching_allow_policy_overrides_access(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="test-allow",
                effect="allow",
                priority=10,
                request_types="access",
                countries="EE",
                device_ids="",
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()

    assert body["allow"] is True
    assert body["reason"] == "policy_allow:test-allow"

from app.database import SessionLocal
from app.models import RequestLog


def test_matching_policy_is_written_to_request_log(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="audit-deny",
                effect="deny",
                priority=5,
                request_types="access",
                countries="EE",
                device_ids="",
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200
    assert response.json()["allow"] is False
    assert response.json()["reason"] == "policy_deny:audit-deny"

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .order_by(RequestLog.id.desc())
            .first()
        )

        assert log is not None
        assert log.policy_matched is True
        assert log.policy_name == "audit-deny"
        assert log.reason == "policy_deny:audit-deny"

def test_policy_explainability_in_response(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="explain-deny",
                effect="deny",
                priority=5,
                request_types="access",
                countries="EE",
                device_ids="",
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["allow"] is False
    assert body["policy_matched"] is True
    assert body["policy_name"] == "explain-deny"
    assert body["reason"] == "policy_deny:explain-deny"


def test_no_policy_explainability_in_response(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["policy_matched"] is False
    assert body["policy_name"] is None

def test_policy_isolation_between_tenants(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-other",
                name="other-tenant-deny",
                effect="deny",
                priority=1,
                request_types="access",
                countries="EE",
                device_ids="",
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["allow"] is True
    assert body["policy_matched"] is False
    assert body["policy_name"] is None

def test_risk_deny_cannot_be_overridden_by_allow_policy(client):
    ensure_setup(client)

    # Create a second valid device so the RiskEngine can detect "new_device".
    device_response = client.post(
        "/admin/devices",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "device_id": "gate-Z9",
            "description": "Risk test device",
        },
    )
    assert device_response.status_code == 200

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="allow-high-risk",
                effect="allow",
                priority=1,
                request_types="access",
                countries="FI",
                device_ids="gate-Z9",
                enabled=True,
            )
        )

        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"old-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"old-trace-{i}",
                    idempotency_key=f"old-idem-{i}",
                    request_fingerprint=f"old-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                )
            )

        db.commit()

    token_response = client.post(
        "/token/issue",
        headers=HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "user_id": "user-123",
            "device_id": "gate-Z9",
            "scope": "access",
        },
    )

    assert token_response.status_code == 200
    token = token_response.json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-Z9",
        ip_address="10.10.10.99",
        country_code="FI",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["risk_score"] >= 70
    assert body["policy_matched"] is True
    assert body["policy_name"] == "allow-high-risk"

    # Deny wins: policy allow cannot override RiskEngine deny.
    assert body["allow"] is False

def test_future_policy_does_not_apply(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="future-deny",
                effect="deny",
                priority=1,
                request_types="access",
                countries="EE",
                device_ids="",
                enabled=True,
                valid_from=datetime(2099, 1, 1),
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is True

def test_expired_policy_does_not_apply(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="expired-deny",
                effect="deny",
                priority=1,
                request_types="access",
                countries="EE",
                device_ids="",
                enabled=True,
                expires_at=datetime(2020, 1, 1),
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()
    assert body["allow"] is True

def test_risk_signals_are_exposed_in_response(client):
    ensure_setup(client)

    with SessionLocal() as db:
        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"old-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"signal-trace-{i}",
                    idempotency_key=f"signal-idem-{i}",
                    request_fingerprint=f"signal-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        ip_address="10.10.10.99",
        country_code="FI",
    )

    assert response.status_code == 200

    body = response.json()

    assert "risk_signals" in body
    assert "failure_burst" in body["risk_signals"]
    assert "new_ip" in body["risk_signals"]
    assert "geo_change" in body["risk_signals"]

def test_risk_signals_are_written_to_request_log(client):
    ensure_setup(client)

    with SessionLocal() as db:
        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"old-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    risk_signals="failure_burst",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"audit-signal-trace-{i}",
                    idempotency_key=f"audit-signal-idem-{i}",
                    request_fingerprint=f"audit-signal-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        ip_address="10.10.10.99",
        country_code="FI",
    )

    assert response.status_code == 200

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .order_by(RequestLog.id.desc())
            .first()
        )

        assert log is not None
        assert "failure_burst" in log.risk_signals
        assert "new_ip" in log.risk_signals
        assert "geo_change" in log.risk_signals

def test_trust_score_is_exposed_in_response(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert "trust_score" in body
    assert 0 <= body["trust_score"] <= 100
    assert body["trust_score"] == max(
        0,
        min(100, 100 - body["risk_score"]),
    )

def test_min_trust_score_policy_in_access_flow(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="high-trust-access",
                effect="allow",
                priority=1,
                request_types="access",
                countries="EE",
                device_ids="",
                max_risk_score=None,
                min_trust_score=90,
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()

    assert body["trust_score"] >= 90
    assert body["policy_matched"] is True
    assert body["policy_name"] == "high-trust-access"

def test_min_trust_score_policy_does_not_match_low_trust(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="high-trust-only",
                effect="allow",
                priority=1,
                request_types="access",
                countries="FI",
                device_ids="gate-A1",
                max_risk_score=None,
                min_trust_score=90,
                enabled=True,
            )
        )

        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"low-trust-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    risk_signals="failure_burst",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"low-trust-trace-{i}",
                    idempotency_key=f"low-trust-idem-{i}",
                    request_fingerprint=f"low-trust-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        device_ids="gate-A1",
        ip_address="10.10.10.99",
        country_code="FI",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["trust_score"] < 90
    assert body["policy_name"] != "high-trust-only"

def test_policy_version_is_written_to_request_log(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="version-audit-policy",
            effect="deny",
            priority=1,
            version=2,
            request_types="access",
            countries="EE",
            device_ids="",
            max_risk_score=None,
            min_trust_score=None,
            enabled=True,
        )
        db.add(policy)
        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200
    assert response.json()["allow"] is False

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .order_by(RequestLog.id.desc())
            .first()
        )

        assert log is not None
        assert log.policy_name == "version-audit-policy"
        assert log.policy_version == 2