from app.workflow_engine import WorkflowEngine


def test_workflow_engine_policy_match_allow():
    engine = WorkflowEngine()

    decision = engine.evaluate(
        risk_allowed=True,
        policy_matched=True,
        policy_allowed=True,
        final_allowed=True,
    )

    assert decision.decision_source == "policy"
    assert decision.decision_path == (
        "risk_evaluated",
        "policy_checked",
        "policy_matched",
        "final_allow",
    )

def test_workflow_engine_risk_deny_wins():
    engine = WorkflowEngine()

    decision = engine.evaluate(
        risk_allowed=False,
        policy_matched=True,
        policy_allowed=True,
        final_allowed=False,
    )

    assert decision.decision_source == "risk"
    assert decision.decision_path == (
        "risk_evaluated",
        "policy_checked",
        "policy_matched",
        "final_deny",
    )