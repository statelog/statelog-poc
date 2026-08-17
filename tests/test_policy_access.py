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