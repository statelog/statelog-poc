from datetime import timedelta

from app.models import RequestLog
from app.risk_engine import RiskEngine
from app.time_utils import utcnow_naive


def test_risk_decision_exposes_signals():
    now = utcnow_naive()

    logs = [
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
            trace_id=f"trace-{i}",
            idempotency_key=f"idem-{i}",
            request_fingerprint=f"fingerprint-{i}",
            user_agent="pytest",
            decision_version="test",
            created_at=now - timedelta(minutes=5),
        )
        for i in range(3)
    ]

    engine = RiskEngine()

    decision = engine.evaluate(
        request_type="access",
        device_id="gate-Z9",
        ip_address="new-ip",
        country_code="FI",
        historical_logs=logs,
    )

    assert decision.allow is False
    assert decision.risk_score >= 70
    assert "failure_burst" in decision.signals
    assert "new_device" in decision.signals
    assert "new_ip" in decision.signals
    assert "geo_change" in decision.signals

def test_trust_score_is_inverse_of_risk_score():
    engine = RiskEngine()

    decision = engine.evaluate(
        request_type="access",
        device_id="gate-A1",
        ip_address="127.0.0.1",
        country_code="EE",
        historical_logs=[],
    )

    assert 0 <= decision.trust_score <= 100
    assert decision.trust_score == 100 - decision.risk_score

def test_new_ip_uses_only_five_most_recent_logs():
    now = utcnow_naive()

    logs = [
        RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash="current-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            policy_matched=False,
            policy_name=None,
            trace_id="old-same-ip",
            idempotency_key="old-same-ip-idem",
            request_fingerprint="old-same-ip-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=now - timedelta(minutes=6),
        )
    ]

    for i in range(5):
        logs.append(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash=f"different-ip-{i}",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                policy_matched=False,
                policy_name=None,
                trace_id=f"recent-trace-{i}",
                idempotency_key=f"recent-idem-{i}",
                request_fingerprint=f"recent-fingerprint-{i}",
                user_agent="pytest",
                decision_version="test",
                created_at=now - timedelta(minutes=5 - i),
            )
        )

    engine = RiskEngine()

    decision = engine.evaluate(
        request_type="access",
        device_id="gate-A1",
        ip_address="current-ip",
        country_code="EE",
        historical_logs=logs,
        now=now,
    )

    assert "new_ip" in decision.signals

def test_new_ip_does_not_trigger_when_seen_in_five_most_recent_logs():
    now = utcnow_naive()

    logs = []

    for i in range(5):
        logs.append(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash="current-ip" if i == 0 else f"different-ip-{i}",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                policy_matched=False,
                policy_name=None,
                trace_id=f"recent-five-trace-{i}",
                idempotency_key=f"recent-five-idem-{i}",
                request_fingerprint=f"recent-five-fingerprint-{i}",
                user_agent="pytest",
                decision_version="test",
                created_at=now - timedelta(minutes=5 - i),
            )
        )

    engine = RiskEngine()

    decision = engine.evaluate(
        request_type="access",
        device_id="gate-A1",
        ip_address="current-ip",
        country_code="EE",
        historical_logs=logs,
        now=now,
    )

    assert "new_ip" not in decision.signals