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

def test_workflow_config_defaults_enable_all_steps():
    from app.workflow_engine import WorkflowConfig

    config = WorkflowConfig()

    assert config.include_risk_step is True
    assert config.include_policy_step is True

def test_workflow_config_can_disable_policy_step():
    from app.workflow_engine import WorkflowConfig

    engine = WorkflowEngine(
        WorkflowConfig(
            include_risk_step=True,
            include_policy_step=False,
        )
    )

    decision = engine.evaluate(
        risk_allowed=True,
        policy_matched=True,
        policy_allowed=True,
        final_allowed=True,
    )

    assert decision.decision_source == "policy"
    assert decision.decision_path == (
        "risk_evaluated",
        "final_allow",
    )

def test_workflow_config_can_disable_risk_step():
    from app.workflow_engine import WorkflowConfig

    engine = WorkflowEngine(
        WorkflowConfig(
            include_risk_step=False,
            include_policy_step=True,
        )
    )

    decision = engine.evaluate(
        risk_allowed=True,
        policy_matched=False,
        policy_allowed=None,
        final_allowed=True,
    )

    assert decision.decision_source == "risk"
    assert decision.decision_path == (
        "policy_checked",
        "no_policy_match",
        "final_allow",
    )