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

def test_equal_priority_equal_effect_is_independent_of_input_order():
    alpha = Policy(
        name="alpha-deny",
        effect="deny",
        priority=10,
        request_types=("access",),
    )
    beta = Policy(
        name="beta-deny",
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

    alpha_first = evaluate([alpha, beta])
    beta_first = evaluate([beta, alpha])

    assert alpha_first.matched is True
    assert beta_first.matched is True

    assert alpha_first.policy_name == "alpha-deny"
    assert beta_first.policy_name == "alpha-deny"

    assert alpha_first == beta_first

def test_equal_priority_effect_and_name_is_independent_of_input_order():
    older = Policy(
        name="same-policy",
        effect="deny",
        policy_id=10,
        priority=10,
        version=1,
        request_types=("access",),
    )
    newer = Policy(
        name="same-policy",
        effect="deny",
        policy_id=20,
        priority=10,
        version=2,
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

    first = evaluate([older, newer])
    second = evaluate([newer, older])

    assert first.matched is True
    assert second.matched is True
    assert first.policy_id == second.policy_id
    assert first.policy_version == second.policy_version

def test_policy_time_window_allows_hour_at_start_boundary():
    policy = Policy(
        name="day-window",
        effect="allow",
        allowed_start_hour=8,
        allowed_end_hour=18,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 8},
    ) is True

def test_policy_time_window_rejects_hour_at_end_boundary():
    policy = Policy(
        name="day-window",
        effect="allow",
        allowed_start_hour=8,
        allowed_end_hour=18,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 18},
    ) is False

def test_policy_overnight_window_allows_hour_after_start():
    policy = Policy(
        name="overnight-window",
        effect="allow",
        allowed_start_hour=22,
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 23},
    ) is True

def test_policy_overnight_window_allows_hour_before_end():
    policy = Policy(
        name="overnight-window",
        effect="allow",
        allowed_start_hour=22,
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 5},
    ) is True

def test_policy_overnight_window_rejects_hour_outside_window():
    policy = Policy(
        name="overnight-window",
        effect="allow",
        allowed_start_hour=22,
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 12},
    ) is False

def test_policy_overnight_window_allows_exact_start_hour():
    policy = Policy(
        name="overnight-start-boundary",
        effect="allow",
        allowed_start_hour=22,
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 22},
    ) is True


def test_policy_overnight_window_rejects_exact_end_hour():
    policy = Policy(
        name="overnight-end-boundary",
        effect="allow",
        allowed_start_hour=22,
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 6},
    ) is False


def test_policy_start_only_allows_hour_at_start():
    policy = Policy(
        name="start-only",
        effect="allow",
        allowed_start_hour=22,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 22},
    ) is True


def test_policy_start_only_rejects_hour_before_start():
    policy = Policy(
        name="start-only",
        effect="allow",
        allowed_start_hour=22,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 21},
    ) is False


def test_policy_end_only_rejects_hour_at_end():
    policy = Policy(
        name="end-only",
        effect="allow",
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 6},
    ) is False

def test_policy_equal_time_window_allows_exact_hour():
    policy = Policy(
        name="full-day-window",
        effect="allow",
        allowed_start_hour=8,
        allowed_end_hour=8,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 8},
    ) is True


def test_policy_equal_time_window_allows_midnight():
    policy = Policy(
        name="full-day-window",
        effect="allow",
        allowed_start_hour=8,
        allowed_end_hour=8,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 0},
    ) is True


def test_policy_equal_time_window_allows_hour_before_start():
    policy = Policy(
        name="full-day-window",
        effect="allow",
        allowed_start_hour=8,
        allowed_end_hour=8,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 23},
    ) is True


def test_policy_end_only_allows_hour_before_end():
    policy = Policy(
        name="end-only",
        effect="allow",
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 5},
    ) is True


def test_policy_end_only_allows_midnight():
    policy = Policy(
        name="end-only",
        effect="allow",
        allowed_end_hour=6,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"hour": 0},
    ) is True

def test_policy_max_risk_score_allows_exact_boundary():
    policy = Policy(
        name="risk-boundary",
        effect="allow",
        max_risk_score=50,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=50,
        trust_score=90,
        context={},
    ) is True


def test_policy_max_risk_score_rejects_above_boundary():
    policy = Policy(
        name="risk-boundary",
        effect="allow",
        max_risk_score=50,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=51,
        trust_score=90,
        context={},
    ) is False


def test_policy_min_trust_score_allows_exact_boundary():
    policy = Policy(
        name="trust-boundary",
        effect="allow",
        min_trust_score=60,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=60,
        context={},
    ) is True


def test_policy_min_trust_score_rejects_below_boundary():
    policy = Policy(
        name="trust-boundary",
        effect="allow",
        min_trust_score=60,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=59,
        context={},
    ) is False


def test_policy_combined_risk_and_trust_boundaries_match():
    policy = Policy(
        name="risk-trust-boundary",
        effect="allow",
        max_risk_score=50,
        min_trust_score=60,
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=50,
        trust_score=60,
        context={},
    ) is True

def test_policy_request_types_matches_second_allowed_value():
    policy = Policy(
        name="multi-request-type",
        effect="allow",
        request_types=("access", "ownership_transfer"),
    )

    assert PolicyEngine._matches(
        policy,
        request_type="ownership_transfer",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={},
    ) is True


def test_policy_device_ids_matches_second_allowed_value():
    policy = Policy(
        name="multi-device",
        effect="allow",
        device_ids=("gate-A1", "gate-B2"),
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="gate-B2",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={},
    ) is True


def test_policy_countries_matches_second_allowed_value():
    policy = Policy(
        name="multi-country",
        effect="allow",
        countries=("EE", "FI"),
    )

    assert PolicyEngine._matches(
        policy,
        request_type="access",
        device_id="device-1",
        country_code="FI",
        risk_score=10,
        trust_score=90,
        context={},
    ) is True


def test_policy_multiple_filters_match_when_all_values_allowed():
    policy = Policy(
        name="multi-filter",
        effect="allow",
        request_types=("access", "ownership_transfer"),
        device_ids=("gate-A1", "gate-B2"),
        countries=("EE", "FI"),
    )

    assert PolicyEngine._matches(
        policy,
        request_type="ownership_transfer",
        device_id="gate-B2",
        country_code="FI",
        risk_score=10,
        trust_score=90,
        context={},
    ) is True


def test_policy_multiple_filters_reject_when_one_value_not_allowed():
    policy = Policy(
        name="multi-filter",
        effect="allow",
        request_types=("access", "ownership_transfer"),
        device_ids=("gate-A1", "gate-B2"),
        countries=("EE", "FI"),
    )

    assert PolicyEngine._matches(
        policy,
        request_type="ownership_transfer",
        device_id="gate-B2",
        country_code="SE",
        risk_score=10,
        trust_score=90,
        context={},
    ) is False

def test_policy_active_exactly_at_valid_from():
    now = datetime(2026, 9, 1, 12, 0, 0)

    engine = PolicyEngine(
        [
            Policy(
                name="starts-now",
                effect="allow",
                priority=10,
                request_types=("access",),
                valid_from=now,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"now": now},
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "starts-now"


def test_policy_active_exactly_at_expires_at():
    now = datetime(2026, 9, 1, 12, 0, 0)

    engine = PolicyEngine(
        [
            Policy(
                name="expires-now",
                effect="allow",
                priority=10,
                request_types=("access",),
                expires_at=now,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"now": now},
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "expires-now"


def test_future_higher_priority_policy_is_skipped_for_active_lower_priority():
    now = datetime(2026, 9, 1, 12, 0, 0)

    engine = PolicyEngine(
        [
            Policy(
                name="future-high-priority",
                effect="deny",
                priority=100,
                request_types=("access",),
                valid_from=now + timedelta(minutes=1),
            ),
            Policy(
                name="active-lower-priority",
                effect="allow",
                priority=10,
                request_types=("access",),
            ),
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"now": now},
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "active-lower-priority"


def test_expired_higher_priority_policy_is_skipped_for_active_lower_priority():
    now = datetime(2026, 9, 1, 12, 0, 0)

    engine = PolicyEngine(
        [
            Policy(
                name="expired-high-priority",
                effect="deny",
                priority=100,
                request_types=("access",),
                expires_at=now - timedelta(seconds=1),
            ),
            Policy(
                name="active-lower-priority",
                effect="allow",
                priority=10,
                request_types=("access",),
            ),
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"now": now},
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "active-lower-priority"


def test_policy_active_when_valid_from_and_expires_at_equal_now():
    now = datetime(2026, 9, 1, 12, 0, 0)

    engine = PolicyEngine(
        [
            Policy(
                name="single-instant-policy",
                effect="allow",
                priority=10,
                request_types=("access",),
                valid_from=now,
                expires_at=now,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=10,
        trust_score=90,
        context={"now": now},
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "single-instant-policy"

def test_policy_derives_trust_score_when_missing():
    engine = PolicyEngine(
        [
            Policy(
                name="derived-trust",
                effect="allow",
                request_types=("access",),
                min_trust_score=60,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=40,
        trust_score=None,
    )

    assert decision.matched is True
    assert decision.allow is True


def test_policy_derived_trust_score_rejects_below_minimum():
    engine = PolicyEngine(
        [
            Policy(
                name="derived-trust",
                effect="allow",
                request_types=("access",),
                min_trust_score=60,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=41,
        trust_score=None,
    )

    assert decision.matched is False
    assert decision.reason == "no_policy_match"


def test_policy_derived_trust_score_allows_exact_boundary():
    engine = PolicyEngine(
        [
            Policy(
                name="derived-trust-boundary",
                effect="allow",
                request_types=("access",),
                min_trust_score=1,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=99,
        trust_score=None,
    )

    assert decision.matched is True
    assert decision.allow is True


def test_policy_derived_trust_score_clamps_to_zero():
    engine = PolicyEngine(
        [
            Policy(
                name="zero-trust",
                effect="allow",
                request_types=("access",),
                min_trust_score=1,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=150,
        trust_score=None,
    )

    assert decision.matched is False
    assert decision.reason == "no_policy_match"


def test_explicit_trust_score_overrides_derived_value():
    engine = PolicyEngine(
        [
            Policy(
                name="explicit-trust",
                effect="allow",
                request_types=("access",),
                min_trust_score=80,
            )
        ]
    )

    decision = engine.evaluate(
        request_type="access",
        device_id="device-1",
        country_code="EE",
        risk_score=90,
        trust_score=90,
    )

    assert decision.matched is True
    assert decision.allow is True
    assert decision.policy_name == "explicit-trust"