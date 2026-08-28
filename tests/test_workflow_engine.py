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
            "execution_mode": "policy_first",
        },
    )

    assert create_response.status_code == 200

    created = create_response.json()

    assert created["tenant_id"] == "tenant-demo"
    assert created["include_risk_step"] is False
    assert created["include_policy_step"] is True
    assert created["execution_mode"] == "policy_first"
    assert created["version"] == 1

    update_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert update_response.status_code == 200

    updated = update_response.json()

    assert updated["include_risk_step"] is True
    assert updated["include_policy_step"] is False
    assert updated["execution_mode"] == "risk_first"
    assert updated["version"] == 2

    get_response = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )

    assert get_response.status_code == 200

    body = get_response.json()

    assert body["version"] == 2

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

def test_admin_can_read_workflow_config(client):
    ensure_setup(client)

    update_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert update_response.status_code == 200

    get_response = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )

    assert get_response.status_code == 200

    body = get_response.json()

    assert body["tenant_id"] == "tenant-demo"
    assert body["include_risk_step"] is False
    assert body["include_policy_step"] is True
    assert body["execution_mode"] == "policy_first"

def test_admin_reads_default_workflow_config_when_none_exists(client):
    ensure_setup(client)

    with SessionLocal() as db:
        record = db.get(WorkflowConfigRecord, "tenant-demo")
        if record is not None:
            db.delete(record)
            db.commit()

    response = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["tenant_id"] == "tenant-demo"
    assert body["include_risk_step"] is True
    assert body["include_policy_step"] is True

def test_admin_workflow_config_unknown_tenant_returns_404(client):
    ensure_setup(client)

    response = client.get(
        "/admin/workflow-config/tenant-that-does-not-exist",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "tenant_not_found"

def test_admin_cannot_update_workflow_config_for_unknown_tenant(client):
    ensure_setup(client)

    response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-that-does-not-exist",
            "include_risk_step": False,
            "include_policy_step": False,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "tenant_not_found"

def test_workflow_config_defaults_to_risk_first():
    from app.workflow_engine import WorkflowConfig

    config = WorkflowConfig()

    assert config.execution_mode == "risk_first"

def test_workflow_policy_first_changes_decision_path_order():
    from app.workflow_engine import WorkflowConfig

    engine = WorkflowEngine(
        WorkflowConfig(
            include_risk_step=True,
            include_policy_step=True,
            execution_mode="policy_first",
        )
    )

    decision = engine.evaluate(
        risk_allowed=True,
        policy_matched=True,
        policy_allowed=True,
        final_allowed=True,
    )

    assert decision.decision_path == (
        "policy_checked",
        "policy_matched",
        "risk_evaluated",
        "final_allow",
    )

def test_access_flow_uses_policy_first_execution_mode(client):
    ensure_setup(client)

    config_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert config_response.status_code == 200

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()
    path = body["explanation"]["final"]["decision_path"]

    assert path[0] == "policy_checked"
    assert path[1] in ("policy_matched", "no_policy_match")
    assert path[2] == "risk_evaluated"
    assert path[-1] in ("final_allow", "final_deny")

def test_admin_rejects_invalid_workflow_execution_mode(client):
    ensure_setup(client)

    response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "banana",
        },
    )

    assert response.status_code == 422

def test_risk_deny_cannot_be_overridden_by_policy_allow():
    from app.workflow_engine import WorkflowConfig
 
    engine = WorkflowEngine(
        WorkflowConfig(
            include_risk_step=True,
            include_policy_step=True,
            execution_mode="policy_first",
        )
    )

    decision = engine.evaluate(
        risk_allowed=False,
        policy_matched=True,
        policy_allowed=True,
        final_allowed=False,
    )

    assert decision.decision_source == "risk"
    assert decision.decision_path == (
        "policy_checked",
        "policy_matched",
        "risk_evaluated",
        "final_deny",
    )

def test_policy_deny_cannot_be_overridden_by_risk_allow():
    from app.workflow_engine import WorkflowConfig

    engine = WorkflowEngine(
        WorkflowConfig(
            include_risk_step=True,
            include_policy_step=True,
            execution_mode="risk_first",
        )
    )

    decision = engine.evaluate(
        risk_allowed=True,
        policy_matched=True,
        policy_allowed=False,
        final_allowed=False,
    )

    assert decision.decision_source == "policy"
    assert decision.decision_path == (
        "risk_evaluated",
        "policy_checked",
        "policy_matched",
        "final_deny",
    )

def test_workflow_resolve_allowed_enforces_deny_wins():
    assert WorkflowEngine.resolve_allowed(
        risk_allowed=True,
        policy_matched=False,
        policy_allowed=None,
    ) is True

    assert WorkflowEngine.resolve_allowed(
        risk_allowed=True,
        policy_matched=True,
        policy_allowed=True,
    ) is True

    assert WorkflowEngine.resolve_allowed(
        risk_allowed=False,
        policy_matched=True,
        policy_allowed=True,
    ) is False

    assert WorkflowEngine.resolve_allowed(
        risk_allowed=True,
        policy_matched=True,
        policy_allowed=False,
    ) is False

def test_default_workflow_config_has_version_one(client):
    ensure_setup(client)

    response = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["tenant_id"] == "tenant-demo"
    assert body["version"] == 1

def test_access_response_explanation_matches_workflow_version(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    body = response.json()

    assert body["workflow_version"] == body["explanation"]["final"]["workflow_version"]

def test_workflow_config_update_preserves_previous_version_history(client):
    ensure_setup(client)

    create_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert create_response.status_code == 200
    assert create_response.json()["version"] == 1

    update_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert update_response.status_code == 200
    assert update_response.json()["version"] == 2

    from app.database import SessionLocal
    from app.models import WorkflowConfigHistory

    with SessionLocal() as db:
        history = (
            db.query(WorkflowConfigHistory)
            .filter_by(tenant_id="tenant-demo")
            .order_by(WorkflowConfigHistory.version.desc())
            .first()
        )

        assert history is not None
        assert history.version == 1
        assert history.include_risk_step is True
        assert history.include_policy_step is True
        assert history.execution_mode == "risk_first"

def test_workflow_config_history_endpoint_returns_previous_version(client):
    ensure_setup(client)

    create_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert create_response.status_code == 200
    assert create_response.json()["version"] == 1

    update_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert update_response.status_code == 200
    assert update_response.json()["version"] == 2

    history_response = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history_response.status_code == 200

    history = history_response.json()

    assert len(history) == 1
    assert history[0]["tenant_id"] == "tenant-demo"
    assert history[0]["version"] == 1
    assert history[0]["include_risk_step"] is True
    assert history[0]["include_policy_step"] is True
    assert history[0]["execution_mode"] == "risk_first"

def test_load_workflow_config_version_restores_history_and_active_version(client):
    ensure_setup(client)

    create_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert create_response.status_code == 200
    assert create_response.json()["version"] == 1

    update_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert update_response.status_code == 200
    assert update_response.json()["version"] == 2

    from app.database import SessionLocal
    from app.main import load_workflow_config_version

    with SessionLocal() as db:
        version_1 = load_workflow_config_version(
            db,
            "tenant-demo",
            1,
        )
        version_2 = load_workflow_config_version(
            db,
            "tenant-demo",
            2,
        )

    assert version_1 is not None
    assert version_1.include_risk_step is True
    assert version_1.include_policy_step is True
    assert version_1.execution_mode == "risk_first"

    assert version_2 is not None
    assert version_2.include_risk_step is False
    assert version_2.include_policy_step is True
    assert version_2.execution_mode == "policy_first"

def test_workflow_config_multiple_versions_remain_replayable(client):
    ensure_setup(client)

    version_1_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert version_1_response.status_code == 200
    assert version_1_response.json()["version"] == 1

    version_2_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert version_2_response.status_code == 200
    assert version_2_response.json()["version"] == 2

    version_3_response = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert version_3_response.status_code == 200
    assert version_3_response.json()["version"] == 3

    from app.database import SessionLocal
    from app.main import load_workflow_config_version

    with SessionLocal() as db:
        version_1 = load_workflow_config_version(
            db,
            "tenant-demo",
            1,
        )
        version_2 = load_workflow_config_version(
            db,
            "tenant-demo",
            2,
        )
        version_3 = load_workflow_config_version(
            db,
            "tenant-demo",
            3,
        )

    assert version_1 is not None
    assert version_1.include_risk_step is True
    assert version_1.include_policy_step is True
    assert version_1.execution_mode == "risk_first"

    assert version_2 is not None
    assert version_2.include_risk_step is False
    assert version_2.include_policy_step is True
    assert version_2.execution_mode == "policy_first"

    assert version_3 is not None
    assert version_3.include_risk_step is True
    assert version_3.include_policy_step is False
    assert version_3.execution_mode == "risk_first"

def test_load_workflow_config_version_isolates_tenants(client):
    ensure_setup(client)

    created = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert created.status_code == 200

    updated = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert updated.status_code == 200

    from app.database import SessionLocal
    from app.main import load_workflow_config_version

    with SessionLocal() as db:
        correct_tenant = load_workflow_config_version(
            db,
            "tenant-demo",
            1,
        )

        wrong_tenant = load_workflow_config_version(
            db,
            "tenant-other",
            1,
        )

    assert correct_tenant is not None
    assert correct_tenant.include_risk_step is True
    assert correct_tenant.include_policy_step is True

    assert wrong_tenant is None