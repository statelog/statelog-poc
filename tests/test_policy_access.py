from datetime import datetime, timedelta
from app.time_utils import utcnow_naive
from app.services.privacy_service import pseudonymize_ip
from app.models import PolicyRecord, RequestLog
from app.models import PolicyRecord

from tests.test_smoke import ADMIN_HEADERS, HEADERS, ensure_setup, issue_token, access_request


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
    assert body["explanation"]["final"]["allow"] is False
    assert body["explanation"]["final"]["decision_source"] == "risk"

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

    token = issue_token(
        client,
        scope="ownership_transfer",
    ).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="10.10.10.99",
        country_code="FI",
        request_type="ownership_transfer",
        new_owner_id="user-456",
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
        device_id="gate-A1",
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

def test_access_response_exposes_structured_explanation(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert "explanation" in body

    explanation = body["explanation"]

    assert "risk" in explanation
    assert "policy" in explanation
    assert "final" in explanation

    assert explanation["risk"]["score"] == body["risk_score"]
    assert explanation["risk"]["trust_score"] == body["trust_score"]
    assert explanation["risk"]["signals"] == body["risk_signals"]

    assert explanation["policy"]["matched"] == body["policy_matched"]
    assert explanation["policy"]["name"] == body["policy_name"]

    assert explanation["final"]["allow"] == body["allow"]
    assert explanation["final"]["reason"] == body["reason"]

def test_explanation_decision_source_is_risk_without_policy(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["policy_matched"] is False
    assert body["explanation"]["final"]["decision_source"] == "risk"


def test_explanation_decision_source_is_policy_when_policy_matches(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="source-deny-policy",
                effect="deny",
                priority=1,
                request_types="access",
                countries="EE",
                device_ids="",
                max_risk_score=None,
                min_trust_score=None,
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["policy_matched"] is True
    assert body["policy_name"] == "source-deny-policy"
    assert body["explanation"]["final"]["decision_source"] == "policy"

def test_explanation_decision_path_without_policy(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()
    path = body["explanation"]["final"]["decision_path"]

    assert path == [
        "risk_evaluated",
        "policy_checked",
        "no_policy_match",
        "final_allow",
    ]


def test_explanation_decision_path_with_deny_policy(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="decision-path-deny",
                effect="deny",
                priority=1,
                request_types="access",
                countries="EE",
                device_ids="",
                max_risk_score=None,
                min_trust_score=None,
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()
    path = body["explanation"]["final"]["decision_path"]

    assert path == [
        "risk_evaluated",
        "policy_checked",
        "policy_matched",
        "final_deny",
    ]

def test_explanation_includes_policy_version(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="explain-version-policy",
                effect="deny",
                priority=1,
                version=3,
                request_types="access",
                countries="EE",
                device_ids="",
                max_risk_score=None,
                min_trust_score=None,
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["policy_name"] == "explain-version-policy"
    assert body["explanation"]["policy"]["name"] == "explain-version-policy"
    assert body["explanation"]["policy"]["version"] == 3

def test_explanation_shows_risk_as_final_source_when_risk_denies(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="allow-high-risk-explanation",
                effect="allow",
                priority=1,
                request_types="ownership_transfer",
                countries="FI",
                device_ids="gate-A1",
                max_risk_score=None,
                min_trust_score=None,
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
                    ip_hash=f"explain-risk-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    risk_signals="failure_burst",
                    policy_matched=False,
                    policy_name=None,
                    policy_version=None,
                    trace_id=f"explain-risk-trace-{i}",
                    idempotency_key=f"explain-risk-idem-{i}",
                    request_fingerprint=f"explain-risk-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                )
            )

        db.commit()

    token = issue_token(
        client,
        scope="ownership_transfer",
    ).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="10.10.10.99",
        country_code="FI",
        request_type="ownership_transfer",
        new_owner_id="user-456",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["risk_score"] >= 70
    assert body["policy_matched"] is True
    assert body["policy_name"] == "allow-high-risk-explanation"
    assert body["allow"] is False
    assert body["explanation"]["final"]["decision_source"] == "risk"

def test_explanation_risk_signals_match_top_level(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["explanation"]["risk"]["signals"] == body["risk_signals"]

def test_explanation_risk_contributors_show_signal_scores(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()
    contributors = body["explanation"]["risk"]["contributors"]

    expected_scores = {
        "failure_burst": 35,
        "new_device": 15,
        "new_ip": 10,
        "geo_change": 15,
        "transfer_velocity": 30,
        "sensitive_action": 10,
    }

    for contributor in contributors:
        assert contributor["signal"] in expected_scores
        assert contributor["score"] == expected_scores[contributor["signal"]]

def test_explanation_risk_total_contribution_matches_contributors(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()
    risk = body["explanation"]["risk"]

    expected_total = sum(
        contributor["score"]
        for contributor in risk["contributors"]
    )

    assert risk["total_contribution"] == expected_total

def test_explanation_risk_score_matches_top_level(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["explanation"]["risk"]["score"] == body["risk_score"]

def test_explanation_trust_score_matches_top_level(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert (
        body["explanation"]["risk"]["trust_score"]
        == body["trust_score"]
    )

def test_explanation_total_contribution_covers_risk_score(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()
    risk = body["explanation"]["risk"]

    assert risk["total_contribution"] >= risk["score"]

def test_explanation_policy_fields_match_top_level(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="explanation-consistency-policy",
                effect="deny",
                priority=1,
                request_types="access",
                countries="EE",
                device_ids="",
                max_risk_score=None,
                min_trust_score=None,
                enabled=True,
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["explanation"]["policy"]["matched"] == body["policy_matched"]
    assert body["explanation"]["policy"]["name"] == body["policy_name"]

def test_end_to_end_policy_risk_explainability_and_audit(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="e2e-deny-policy",
                effect="deny",
                priority=1,
                version=4,
                request_types="access",
                countries="EE",
                device_ids="",
                max_risk_score=None,
                min_trust_score=None,
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
    assert body["policy_name"] == "e2e-deny-policy"

    assert body["explanation"]["policy"]["name"] == "e2e-deny-policy"
    assert body["explanation"]["policy"]["version"] == 4
    assert body["explanation"]["final"]["decision_source"] == "policy"

    assert body["explanation"]["risk"]["score"] == body["risk_score"]
    assert body["explanation"]["risk"]["trust_score"] == body["trust_score"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .order_by(RequestLog.id.desc())
            .first()
        )

        assert log is not None
        assert log.policy_name == "e2e-deny-policy"
        assert log.policy_version == 4
        assert log.allowed is False

def test_access_request_respects_transaction_amount_policy(client):
    ensure_setup(client)

    create = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "transaction-limit-policy",
            "effect": "allow",
            "priority": 1,
            "request_types": ["ownership_transfer"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_risk_score": None,
            "min_trust_score": None,
            "max_transaction_amount": 10000,
            "allowed_start_hour": None,
            "allowed_end_hour": None,
            "enabled": True,
        },
    )

    assert create.status_code == 200

    token = issue_token(
        client,
        scope="ownership_transfer",
    ).json()["token"]

    response = access_request(
        client,
        token,
        request_type="ownership_transfer",
        device_id="gate-A1",
        country_code="EE",
        transaction_amount=15000,
        new_owner_id="user-456",
    )

    assert response.status_code == 200

    body = response.json()

    assert body["policy_matched"] is False
def test_transfer_velocity_survives_more_than_fifty_newer_unrelated_logs(client):
    ensure_setup(client)

    now = utcnow_naive()

    with SessionLocal() as db:
        for i in range(2):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"transfer-history-ip-{i}",
                    country_code="EE",
                    request_type="ownership_transfer",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"transfer-history-trace-{i}",
                    idempotency_key=f"transfer-history-idem-{i}",
                    request_fingerprint=f"transfer-history-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=50 + i),
                )
            )

        for i in range(50):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"noise-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"noise-trace-{i}",
                    idempotency_key=f"noise-idem-{i}",
                    request_fingerprint=f"noise-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(seconds=i),
                )
            )

        db.commit()

    token = issue_token(
        client,
        scope="ownership_transfer",
    ).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="current-ip",
        country_code="EE",
        request_type="ownership_transfer",
        new_owner_id="user-456",
    )

    assert response.status_code == 200

    body = response.json()

    assert "transfer_velocity" in body["risk_signals"]

def test_live_access_transfer_velocity_survives_high_traffic_history(client):
    ensure_setup(client)

    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    with SessionLocal() as db:
        # Two ownership transfers inside the one-hour risk window.
        for i in range(2):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"high-traffic-transfer-ip-{i}",
                    country_code="EE",
                    request_type="ownership_transfer",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"high-traffic-transfer-trace-{i}",
                    idempotency_key=f"high-traffic-transfer-idem-{i}",
                    request_fingerprint=f"high-traffic-transfer-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=50 + i),
                )
            )

        # More than 50 newer ordinary access logs.
        # The old limit(50) implementation would lose the transfers above.
        for i in range(60):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"high-traffic-access-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"high-traffic-access-trace-{i}",
                    idempotency_key=f"high-traffic-access-idem-{i}",
                    request_fingerprint=f"high-traffic-access-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=i % 40),
                )
            )

        db.commit()

    token = issue_token(
        client,
        scope="ownership_transfer",
        user_id="user-123",
    ).json()["token"]

    response = access_request(
        client,
        token,
        request_type="ownership_transfer",
        new_owner_id="user-456",
    )

    assert response.status_code == 200

    body = response.json()

    assert "transfer_velocity" in body["risk_signals"]

def test_live_access_failure_burst_survives_high_traffic_history(client):
    ensure_setup(client)

    from app.time_utils import utcnow_naive
    from app.services.privacy_service import pseudonymize_ip

    now = utcnow_naive()
    same_ip_hash = pseudonymize_ip("same-live-ip")

    with SessionLocal() as db:
        # Three failures still inside the 15-minute failure-burst window.
        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"high-traffic-failure-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"high-traffic-failure-trace-{i}",
                    idempotency_key=f"high-traffic-failure-idem-{i}",
                    request_fingerprint=f"high-traffic-failure-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=14, seconds=i),
                )
            )

        # More than 50 newer successful requests.
        for i in range(60):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"high-traffic-success-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"high-traffic-success-trace-{i}",
                    idempotency_key=f"high-traffic-success-idem-{i}",
                    request_fingerprint=f"high-traffic-success-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=i % 10),
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="10.10.10.10",
        country_code="EE",
    )

    assert response.status_code == 200

    body = response.json()

    assert "failure_burst" in body["risk_signals"]

def test_live_access_new_ip_uses_only_five_most_recent_logs(client):
    ensure_setup(client)

    from app.time_utils import utcnow_naive
    from app.services.privacy_service import pseudonymize_ip

    now = utcnow_naive()
    same_ip_hash = pseudonymize_ip("same-live-ip")

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash=same_ip_hash,
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                trace_id="live-new-ip-old-same",
                idempotency_key="live-new-ip-old-same-idem",
                request_fingerprint="live-new-ip-old-same-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=now - timedelta(minutes=6),
            )
        )

        for i in range(5):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=pseudonymize_ip(f"different-live-ip-{i}"),
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"live-new-ip-recent-{i}",
                    idempotency_key=f"live-new-ip-recent-idem-{i}",
                    request_fingerprint=f"live-new-ip-recent-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=5 - i),
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="same-live-ip",
        country_code="EE",
    )

    assert response.status_code == 200

    body = response.json()

    assert "new_ip" in body["risk_signals"]

def test_live_access_new_ip_does_not_trigger_when_seen_in_five_most_recent_logs(client):
    ensure_setup(client)

    from app.time_utils import utcnow_naive
    from app.services.privacy_service import pseudonymize_ip

    now = utcnow_naive()
    same_ip_hash = pseudonymize_ip("same-live-ip")

    with SessionLocal() as db:
        for i in range(5):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=same_ip_hash if i == 4 else pseudonymize_ip(f"other-live-ip-{i}"),
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"live-new-ip-seen-{i}",
                    idempotency_key=f"live-new-ip-seen-idem-{i}",
                    request_fingerprint=f"live-new-ip-seen-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=5 - i),
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="same-live-ip",
        country_code="EE",
    )

    assert response.status_code == 200

    body = response.json()

    assert "new_ip" not in body["risk_signals"]

def test_live_access_new_device_uses_only_five_most_recent_logs(client):
    ensure_setup(client)

    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash="old-device-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                trace_id="live-new-device-old-same",
                idempotency_key="live-new-device-old-same-idem",
                request_fingerprint="live-new-device-old-same-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=now - timedelta(minutes=6),
            )
        )

        for i in range(5):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id=f"other-device-{i}",
                    user_id="user-123",
                    ip_hash=f"recent-device-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"live-new-device-recent-{i}",
                    idempotency_key=f"live-new-device-recent-idem-{i}",
                    request_fingerprint=f"live-new-device-recent-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=5 - i),
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="10.0.0.10",
        country_code="EE",
    )

    assert response.status_code == 200

    body = response.json()

    assert "new_device" in body["risk_signals"]

def test_live_access_new_device_does_not_trigger_when_seen_in_five_most_recent_logs(client):
    ensure_setup(client)

    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    with SessionLocal() as db:
        for i in range(5):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1" if i == 4 else f"other-device-{i}",
                    user_id="user-123",
                    ip_hash=f"live-device-seen-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"live-new-device-seen-{i}",
                    idempotency_key=f"live-new-device-seen-idem-{i}",
                    request_fingerprint=f"live-new-device-seen-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(minutes=5 - i),
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    response = access_request(
        client,
        token,
        device_id="gate-A1",
        ip_address="10.0.0.10",
        country_code="EE",
    )

    assert response.status_code == 200

    body = response.json()

    assert "new_device" not in body["risk_signals"]