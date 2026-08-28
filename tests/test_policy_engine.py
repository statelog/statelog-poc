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

def test_min_trust_score_policy_matching():
    engine = PolicyEngine(
        [
            Policy(
                name="high-trust-only",
                effect="allow",
                priority=10,
                request_types=("access",),
                min_trust_score=70,
            )
        ]
    )

    low_trust = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=40,
        trust_score=60,
    )

    high_trust = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=20,
        trust_score=80,
    )

    assert low_trust.matched is False
    assert low_trust.reason == "no_policy_match"

    assert high_trust.matched is True
    assert high_trust.allow is True
    assert high_trust.policy_name == "high-trust-only"

def test_policy_simulation_reports_matching_policy():
    engine = PolicyEngine(
        [
            Policy(
                name="simulation-deny",
                effect="deny",
                priority=1,
                version=3,
                request_types=("access",),
                countries=("EE",),
                device_ids=("gate-A1",),
            )
        ]
    )

    simulation = engine.simulate(
        request_type="access",
        device_id="gate-A1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
    )

    assert simulation.matched is True
    assert simulation.policy_name == "simulation-deny"
    assert simulation.policy_version == 3
    assert simulation.evaluated_policies == 1
    assert simulation.decision.allow is False

def test_policy_simulation_reports_no_match():
    engine = PolicyEngine(
        [
            Policy(
                name="simulation-fi-only",
                effect="deny",
                priority=1,
                version=2,
                request_types=("access",),
                countries=("FI",),
                device_ids=("gate-A1",),
            )
        ]
    )

    simulation = engine.simulate(
        request_type="access",
        device_id="gate-A1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
    )

    assert simulation.matched is False
    assert simulation.policy_name is None
    assert simulation.policy_version is None
    assert simulation.evaluated_policies == 1
    assert simulation.decision.allow is None
    assert simulation.decision.reason == "no_policy_match"

def test_policy_simulation_is_repeatable_and_side_effect_free():
    engine = PolicyEngine(
        [
            Policy(
                name="repeatable-deny",
                effect="deny",
                priority=1,
                version=4,
                request_types=("access",),
                countries=("FI",),
            )
        ]
    )

    first = engine.simulate(
        request_type="access",
        device_id="gate-A1",
        country_code="FI",
        risk_score=20,
        trust_score=80,
    )

    second = engine.simulate(
        request_type="access",
        device_id="gate-A1",
        country_code="FI",
        risk_score=20,
        trust_score=80,
    )

    assert first == second
    assert len(engine.policies) == 1
    assert engine.policies[0].name == "repeatable-deny"

def test_policy_max_transaction_amount_matches_context():
    engine = PolicyEngine(
        [
            Policy(
                name="transaction-limit",
                effect="deny",
                priority=1,
                request_types=("access",),
                max_transaction_amount=10000,
            )
        ]
    )

    below_limit = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"transaction_amount": 5000},
    )

    above_limit = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"transaction_amount": 15000},
    )

    assert below_limit.matched is True
    assert below_limit.allow is False

    assert above_limit.matched is False
    assert above_limit.reason == "no_policy_match"

def test_policy_max_transaction_amount_requires_context_value():
    engine = PolicyEngine(
        [
            Policy(
                name="transaction-limit",
                effect="deny",
                priority=1,
                request_types=("access",),
                max_transaction_amount=10000,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={},
    )

    assert decision.matched is False
    assert decision.reason == "no_policy_match"

def test_policy_allowed_business_hours_matches_context():
    engine = PolicyEngine(
        [
            Policy(
                name="business-hours-only",
                effect="deny",
                priority=1,
                request_types=("access",),
                allowed_start_hour=8,
                allowed_end_hour=18,
            )
        ]
    )

    during_hours = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 12},
    )

    outside_hours = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 20},
    )

    assert during_hours.matched is True
    assert during_hours.allow is False

    assert outside_hours.matched is False
    assert outside_hours.reason == "no_policy_match"

def test_policy_business_hours_requires_context_hour():
    engine = PolicyEngine(
        [
            Policy(
                name="business-hours-only",
                effect="deny",
                priority=1,
                request_types=("access",),
                allowed_start_hour=8,
                allowed_end_hour=18,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={},
    )

    assert decision.matched is False
    assert decision.reason == "no_policy_match"

def test_policy_combines_dynamic_business_rules():
    engine = PolicyEngine(
        [
            Policy(
                name="high-value-business-hours",
                effect="allow",
                priority=1,
                request_types=("ownership_transfer",),
                countries=("EE",),
                max_risk_score=40,
                min_trust_score=60,
                max_transaction_amount=10000,
                allowed_start_hour=8,
                allowed_end_hour=18,
            )
        ]
    )

    valid_request = engine.evaluate(
        request_type="ownership_transfer",
        device_id="device-1",
        country_code="EE",
        risk_score=25,
        trust_score=75,
        context={
            "transaction_amount": 7500,
            "hour": 14,
        },
    )

    invalid_request = engine.evaluate(
        request_type="ownership_transfer",
        device_id="device-1",
        country_code="EE",
        risk_score=25,
        trust_score=75,
        context={
            "transaction_amount": 7500,
            "hour": 21,
        },
    )

    assert valid_request.matched is True
    assert valid_request.allow is True
    assert valid_request.policy_name == "high-value-business-hours"

    assert invalid_request.matched is False
    assert invalid_request.reason == "no_policy_match"

def test_policy_dynamic_rule_boundaries():
    engine = PolicyEngine(
        [
            Policy(
                name="boundary-rule",
                effect="deny",
                priority=1,
                request_types=("ownership_transfer",),
                max_transaction_amount=10000,
                allowed_start_hour=8,
                allowed_end_hour=18,
            )
        ]
    )

    at_start = engine.evaluate(
        request_type="ownership_transfer",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={
            "transaction_amount": 10000,
            "hour": 8,
        },
    )

    at_end = engine.evaluate(
        request_type="ownership_transfer",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={
            "transaction_amount": 10000,
            "hour": 18,
        },
    )

    above_amount = engine.evaluate(
        request_type="ownership_transfer",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={
            "transaction_amount": 10000.01,
            "hour": 8,
        },
    )

    assert at_start.matched is True
    assert at_start.allow is False

    assert at_end.matched is False
    assert at_end.reason == "no_policy_match"

    assert above_amount.matched is False
    assert above_amount.reason == "no_policy_match"

def test_equal_priority_deny_wins_independent_of_input_order():
    allow_policy = Policy(
        name="equal-priority-allow",
        effect="allow",
        priority=10,
        request_types=("access",),
    )
    deny_policy = Policy(
        name="equal-priority-deny",
        effect="deny",
        priority=10,
        request_types=("access",),
    )

    def evaluate(policies):
        engine = PolicyEngine(policies)
        return engine.evaluate(
            request_type="access",
            device_id="device-1",
            country_code="EE",
            risk_score=10,
            trust_score=90,
        )

    allow_first = evaluate([allow_policy, deny_policy])
    deny_first = evaluate([deny_policy, allow_policy])

    assert allow_first.matched is True
    assert allow_first.allow is False
    assert allow_first.policy_name == "equal-priority-deny"

    assert deny_first.matched is True
    assert deny_first.allow is False
    assert deny_first.policy_name == "equal-priority-deny"

    assert allow_first == deny_first