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

from app.database import SessionLocal
from app.models import WorkflowConfigRecord


def test_workflow_config_record_can_be_persisted():
    with SessionLocal() as db:
        record = WorkflowConfigRecord(
            tenant_id="tenant-demo",
            include_risk_step=False,
            include_policy_step=True,
        )

        db.add(record)
        db.commit()

        saved = db.get(WorkflowConfigRecord, "tenant-demo")

        assert saved is not None
        assert saved.include_risk_step is False
        assert saved.include_policy_step is True

from tests.test_smoke import ADMIN_HEADERS, ensure_setup, issue_token, access_request


def test_admin_can_create_and_update_workflow_config(client):
    ensure_setup(client)

    create_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
        },
    )

    assert create_response.status_code == 200

    created = create_response.json()

    assert created["tenant_id"] == "tenant-demo"
    assert created["include_risk_step"] is False
    assert created["include_policy_step"] is True

    update_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
        },
    )

    assert update_response.status_code == 200

    updated = update_response.json()

    assert updated["include_risk_step"] is True
    assert updated["include_policy_step"] is False

def test_access_flow_uses_tenant_workflow_config(client):
    ensure_setup(client)

    config_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
        },
    )

    assert config_response.status_code == 200

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()
    path = body["explanation"]["final"]["decision_path"]

    assert "risk_evaluated" in path
    assert "policy_checked" not in path
    assert "policy_matched" not in path
    assert "no_policy_match" not in path