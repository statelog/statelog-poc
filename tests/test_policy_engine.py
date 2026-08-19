from datetime import datetime, timedelta
from app.policy_engine import Policy, PolicyEngine


def test_no_policy_match():
    engine = PolicyEngine()

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
    )

    assert decision.matched is False
    assert decision.allow is None
    assert decision.reason == "no_policy_match"


def test_allow_policy_matches():
    engine = PolicyEngine([
        Policy(
            name="allow-estonia-access",
            effect="allow",
            countries=("EE",),
            request_types=("access",),
        )
    ])

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "allow-estonia-access"


def test_deny_policy_matches():
    engine = PolicyEngine([
        Policy(
            name="deny-transfer",
            effect="deny",
            request_types=("ownership_transfer",),
        )
    ])

    decision = engine.evaluate(
        request_type="ownership_transfer",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
    )

    assert decision.matched is True
    assert decision.allow is False
    assert decision.policy_name == "deny-transfer"


def test_priority_wins():
    engine = PolicyEngine([
        Policy(
            name="general-allow",
            effect="allow",
            priority=100,
            request_types=("access",),
        ),
        Policy(
            name="priority-deny",
            effect="deny",
            priority=10,
            request_types=("access",),
            countries=("EE",),
        ),
    ])

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
    )

    assert decision.matched is True
    assert decision.allow is False
    assert decision.policy_name == "priority-deny"

def test_higher_priority_policy_wins():
    engine = PolicyEngine(
        [
            Policy(
                name="low-priority-allow",
                effect="allow",
                priority=100,
                request_types=("access",),
                countries=("EE",),
            ),
            Policy(
                name="high-priority-deny",
                effect="deny",
                priority=10,
                request_types=("access",),
                countries=("EE",),
            ),
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
    )

    assert decision.matched is True
    assert decision.allow is False
    assert decision.policy_name == "high-priority-deny"
    assert decision.reason == "policy_deny:high-priority-deny"


def test_higher_priority_allow_wins_over_lower_priority_deny():
    engine = PolicyEngine(
        [
            Policy(
                name="low-priority-deny",
                effect="deny",
                priority=100,
                request_types=("access",),
                countries=("EE",),
            ),
            Policy(
                name="high-priority-allow",
                effect="allow",
                priority=5,
                request_types=("access",),
                countries=("EE",),
            ),
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "high-priority-allow"
    assert decision.reason == "policy_allow:high-priority-allow"

def test_policy_not_active_before_valid_from():
    now = datetime(2026, 8, 19, 12, 0, 0)

    engine = PolicyEngine(
        [
            Policy(
                name="future-policy",
                effect="deny",
                priority=10,
                request_types=("access",),
                valid_from=now + timedelta(hours=1),
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        context={"now": now},
    )

    assert decision.matched is False
    assert decision.reason == "no_policy_match"


def test_policy_not_active_after_expires_at():
    now = datetime(2026, 8, 19, 12, 0, 0)

    engine = PolicyEngine(
        [
            Policy(
                name="expired-policy",
                effect="deny",
                priority=10,
                request_types=("access",),
                expires_at=now - timedelta(minutes=1),
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        context={"now": now},
    )

    assert decision.matched is False
    assert decision.reason == "no_policy_match"