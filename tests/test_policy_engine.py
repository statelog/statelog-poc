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