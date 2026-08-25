from tests.test_smoke import ADMIN_HEADERS, ensure_setup, issue_token, access_request
from app.database import SessionLocal
from app.models import PolicyRecord, RequestLog

def test_create_policy(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "deny-ee-access",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": [],
            "max_risk_score": None,
            "enabled": True,
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["tenant_id"] == "tenant-demo"
    assert body["name"] == "deny-ee-access"
    assert body["effect"] == "deny"
    assert body["priority"] == 10
    assert body["request_types"] == ["access"]
    assert body["countries"] == ["EE"]
    assert body["enabled"] is True
    assert "id" in body


def test_list_policies(client):
    ensure_setup(client)

    client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "allow-access",
            "effect": "allow",
            "priority": 20,
            "request_types": ["access"],
            "countries": ["EE", "FI"],
            "device_ids": ["gate-A1"],
            "enabled": True,
        },
    )

    response = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 200

    policies = response.json()

    assert len(policies) == 1
    assert policies[0]["name"] == "allow-access"
    assert policies[0]["request_types"] == ["access"]
    assert policies[0]["countries"] == ["EE", "FI"]
    assert policies[0]["device_ids"] == ["gate-A1"]


def test_delete_policy(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "temporary-policy",
            "effect": "deny",
            "priority": 50,
            "request_types": ["access"],
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    deleted = client.delete(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
    )

    assert deleted.status_code == 200
    assert deleted.json() == {
        "deleted": True,
        "policy_id": policy_id,
    }

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert listed.status_code == 200
    assert listed.json() == []


def test_duplicate_policy_returns_409(client):
    ensure_setup(client)

    payload = {
        "tenant_id": "tenant-demo",
        "name": "duplicate-policy",
        "effect": "deny",
        "priority": 10,
        "request_types": ["access"],
    }

    first = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json=payload,
    )

    second = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json=payload,
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"] == "policy_exists"


def test_create_policy_rejects_unknown_tenant(client):
    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "missing-tenant",
            "name": "test-policy",
            "effect": "deny",
            "request_types": ["access"],
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "tenant_not_found"

def test_update_policy(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-me",
            "effect": "deny",
            "priority": 50,
            "request_types": ["access"],
            "countries": ["EE"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "effect": "allow",
            "priority": 5,
            "countries": ["FI"],
        },
    )

    assert response.status_code == 200
    body = response.json()

    assert body["effect"] == "allow"
    assert body["priority"] == 5
    assert body["countries"] == ["FI"]
    assert body["request_types"] == ["access"]


def test_disable_policy(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "disable-me",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
            "countries": ["EE"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"enabled": False},
    )

    assert response.status_code == 200
    assert response.json()["enabled"] is False


def test_update_missing_policy_returns_404(client):
    response = client.patch(
        "/admin/policies/999999",
        headers=ADMIN_HEADERS,
        json={"enabled": False},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "policy_not_found"

def test_policy_update_increments_version(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "versioned-policy",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
            "countries": ["EE"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    assert created.json()["version"] == 1

    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 5,
        },
    )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2

def test_policy_update_creates_history_snapshot(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-policy",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
            "countries": ["EE"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]
    assert created.json()["version"] == 1

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 5,
        },
    )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    from app.database import SessionLocal
    from app.models import PolicyHistory, PolicyRecord

    with SessionLocal() as db:
        history = (
            db.query(PolicyHistory)
            .filter_by(policy_id=policy_id)
            .order_by(PolicyHistory.id.desc())
            .first()
        )

        active_policy = db.get(PolicyRecord, policy_id)

        assert history is not None
        assert history.version == 1
        assert history.priority == 10

        assert active_policy is not None
        assert active_policy.version == 2

def test_policy_history_endpoint_returns_snapshots(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-api-policy",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
            "countries": ["EE"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 5,
        },
    )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    history = client.get(
        f"/admin/policies/{policy_id}/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert len(items) == 1
    assert items[0]["policy_id"] == policy_id
    assert items[0]["policy_name"] == "history-api-policy"
    assert items[0]["version"] == 1
    assert items[0]["priority"] == 10

def test_policy_history_unknown_policy_returns_404(client):
    response = client.get(
        "/admin/policies/999999/history",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "policy_not_found"


def test_policy_history_keeps_multiple_versions(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "multi-history-policy",
            "effect": "deny",
            "priority": 30,
            "request_types": ["access"],
            "countries": ["EE"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    first_update = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"priority": 20},
    )
    assert first_update.status_code == 200
    assert first_update.json()["version"] == 2

    second_update = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"priority": 10},
    )
    assert second_update.status_code == 200
    assert second_update.json()["version"] == 3

    history = client.get(
        f"/admin/policies/{policy_id}/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert [item["version"] for item in items] == [1, 2]
    assert [item["priority"] for item in items] == [30, 20]

def test_admin_audit_logs_returns_request_logs(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1

    latest = items[0]

    assert latest["tenant_id"] == "tenant-demo"
    assert latest["right_id"] == "right-001"
    assert latest["request_type"] == "access"
    assert isinstance(latest["allowed"], bool)
    assert "risk_score" in latest
    assert "risk_signals" in latest
    assert "trace_id" in latest

def test_admin_audit_log_records_workflow_version(client):
    ensure_setup(client)

    create_config = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert create_config.status_code == 200

    update_config = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )
    assert update_config.status_code == 200
    assert update_config.json()["version"] == 2

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    response_body = response.json()
    assert response_body["workflow_version"] == 2

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert audit.status_code == 200

    items = audit.json()
    assert len(items) >= 1

    trace_id = response.json()["trace_id"]

    matching = [
        item
        for item in items
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    assert matching[0]["workflow_version"] == 2
    assert matching[0]["workflow_version"] == response_body["workflow_version"]

def test_admin_audit_logs_can_filter_denied_requests(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="audit-deny-policy",
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

    response = access_request(client, token)
    assert response.status_code == 200
    assert response.json()["allow"] is False

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "allowed": "false",
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1
    assert all(item["allowed"] is False for item in items)

def test_admin_audit_logs_can_filter_by_policy_name(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="audit-policy-filter",
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

    response = access_request(client, token)

    assert response.status_code == 200
    assert response.json()["allow"] is False

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_name": "audit-policy-filter",
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1
    assert all(
        item["policy_name"] == "audit-policy-filter"
        for item in items
    )

def test_admin_audit_logs_can_filter_by_policy_version(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="audit-version-policy",
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
        )
        db.commit()

    response = access_request(client, token)

    assert response.status_code == 200
    assert response.json()["allow"] is False

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 2,
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1
    assert all(item["policy_version"] == 2 for item in items)

def test_admin_audit_logs_can_filter_by_min_risk_score(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "min_risk_score": 0,
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1
    assert all(item["risk_score"] >= 0 for item in items)

def test_admin_audit_logs_can_filter_by_risk_signal(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

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
                    ip_hash=f"signal-filter-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    risk_signals="failure_burst,new_ip",
                    policy_matched=False,
                    policy_name=None,
                    policy_version=None,
                    trace_id=f"signal-filter-trace-{i}",
                    idempotency_key=f"signal-filter-idem-{i}",
                    request_fingerprint=f"signal-filter-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                )
            )
        db.commit()

    response = access_request(
        client,
        token,
        ip_address="10.10.10.99",
        country_code="FI",
    )
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "failure_burst",
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1
    assert all("failure_burst" in item["risk_signals"] for item in items)

def test_admin_audit_logs_can_filter_by_from_time(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2020-01-01T00:00:00",
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1

def test_admin_audit_logs_can_filter_by_to_time(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "to_time": "2099-01-01T00:00:00",
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) >= 1

def test_admin_audit_logs_respects_limit(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    first = access_request(client, token)
    assert first.status_code == 200

    second_token = issue_token(client).json()["token"]
    second = access_request(
        client,
        second_token,
        ip_address="10.0.0.11",
    )
    assert second.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 1,
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) == 1

def test_admin_audit_logs_caps_limit_at_500(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 10000,
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) <= 500

def test_admin_audit_logs_respects_offset(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    first = access_request(client, token)
    assert first.status_code == 200

    second_token = issue_token(client).json()["token"]
    second = access_request(
        client,
        second_token,
        ip_address="10.0.0.22",
    )
    assert second.status_code == 200

    first_page = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 1,
            "offset": 0,
        },
    )

    second_page = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 1,
            "offset": 1,
        },
    )

    assert first_page.status_code == 200
    assert second_page.status_code == 200

    first_items = first_page.json()
    second_items = second_page.json()

    assert len(first_items) == 1
    assert len(second_items) == 1
    assert first_items[0]["id"] != second_items[0]["id"]

def test_admin_audit_log_count_returns_total(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    first = access_request(client, token)
    assert first.status_code == 200

    second_token = issue_token(client).json()["token"]
    second = access_request(
        client,
        second_token,
        ip_address="10.0.0.33",
    )
    assert second.status_code == 200

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
        },
    )

    assert count.status_code == 200

    body = count.json()

    assert "total" in body
    assert body["total"] >= 2

def test_admin_audit_log_count_respects_allowed_filter(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-demo",
                name="count-deny-policy",
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

    response = access_request(client, token)
    assert response.status_code == 200
    assert response.json()["allow"] is False

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "allowed": "false",
        },
    )

    assert count.status_code == 200

    body = count.json()

    assert body["total"] >= 1

def test_admin_can_simulate_matching_policy(client):
    ensure_setup(client)

    create = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "simulation-api-deny",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_risk_score": None,
            "min_trust_score": None,
            "enabled": True,
        },
    )

    assert create.status_code == 200

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "trust_score": 90,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["matched"] is True
    assert body["allow"] is False
    assert body["policy_name"] == "simulation-api-deny"
    assert body["evaluated_policies"] >= 1

def test_admin_policy_simulation_reports_no_match(client):
    ensure_setup(client)

    create = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "simulation-fi-only",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["FI"],
            "device_ids": ["gate-A1"],
            "max_risk_score": None,
            "min_trust_score": None,
            "enabled": True,
        },
    )

    assert create.status_code == 200

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "trust_score": 90,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["matched"] is False
    assert body["allow"] is None
    assert body["reason"] == "no_policy_match"
    assert body["policy_name"] is None
    assert body["policy_version"] is None
    assert body["evaluated_policies"] >= 1

def test_admin_dynamic_business_rule_create_list_update_flow(client):
    ensure_setup(client)

    create_response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "dynamic-business-rule",
            "effect": "allow",
            "priority": 5,
            "request_types": ["ownership_transfer"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_risk_score": 40,
            "min_trust_score": 60,
            "max_transaction_amount": 10000,
            "allowed_start_hour": 8,
            "allowed_end_hour": 18,
            "enabled": True,
        },
    )

    assert create_response.status_code == 200

    created = create_response.json()
    policy_id = created["id"]

    assert created["max_transaction_amount"] == 10000
    assert created["allowed_start_hour"] == 8
    assert created["allowed_end_hour"] == 18

    list_response = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert list_response.status_code == 200

    policies = list_response.json()
    policy = next(
        item
        for item in policies
        if item["id"] == policy_id
    )

    assert policy["max_transaction_amount"] == 10000
    assert policy["allowed_start_hour"] == 8
    assert policy["allowed_end_hour"] == 18

    update_response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "max_transaction_amount": 15000,
            "allowed_start_hour": 9,
            "allowed_end_hour": 17,
        },
    )

    assert update_response.status_code == 200

    updated = update_response.json()

    assert updated["max_transaction_amount"] == 15000
    assert updated["allowed_start_hour"] == 9
    assert updated["allowed_end_hour"] == 17

def test_policy_history_preserves_dynamic_business_rules(client):
    ensure_setup(client)

    create_response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-dynamic-rule",
            "effect": "allow",
            "priority": 5,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_risk_score": 40,
            "min_trust_score": 60,
            "max_transaction_amount": 10000,
            "allowed_start_hour": 8,
            "allowed_end_hour": 18,
            "enabled": True,
        },
    )

    assert create_response.status_code == 200

    policy_id = create_response.json()["id"]

    update_response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "max_transaction_amount": 15000,
            "allowed_start_hour": 9,
            "allowed_end_hour": 17,
        },
    )

    assert update_response.status_code == 200

    history_response = client.get(
        f"/admin/policies/{policy_id}/history",
        headers=ADMIN_HEADERS,
    )

    assert history_response.status_code == 200

    history = history_response.json()

    assert len(history) >= 1

    previous = history[0]

    assert previous["max_transaction_amount"] == 10000
    assert previous["allowed_start_hour"] == 8
    assert previous["allowed_end_hour"] == 18

def test_audit_log_preserves_new_owner_id(client):
    ensure_setup(client)

    token = issue_token(
        client,
        scope="ownership_transfer",
    ).json()["token"]

    response = access_request(
        client,
        token,
        request_type="ownership_transfer",
        new_owner_id="user-456",
    )

    assert response.status_code == 200

    trace_id = response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert audit.status_code == 200

    items = audit.json()

    matching = [
        item
        for item in items
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    assert matching[0]["new_owner_id"] == "user-456"

def test_audit_log_records_policy_id_and_version(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "audit-policy-identity",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_risk_score": None,
            "min_trust_score": None,
            "max_transaction_amount": None,
            "allowed_start_hour": None,
            "allowed_end_hour": None,
            "enabled": True,
        },
    )

    assert created.status_code == 200

    policy = created.json()
    policy_id = policy["id"]
    policy_version = policy["version"]

    token = issue_token(client).json()["token"]

    response = access_request(client, token)

    assert response.status_code == 200
    assert response.json()["allow"] is False

    trace_id = response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_name": "audit-policy-identity",
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    matching = [
        item
        for item in items
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    assert matching[0]["policy_id"] == policy_id
    assert matching[0]["policy_version"] == policy_version

def test_load_policy_version_restores_history_and_active_version(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "replay-version-policy",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
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

    assert created.status_code == 200
    policy_id = created.json()["id"]
    assert created.json()["version"] == 1

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 5,
            "max_transaction_amount": 15000,
        },
    )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    from app.database import SessionLocal
    from app.main import load_policy_version

    with SessionLocal() as db:
        version_1 = load_policy_version(
            db,
            "tenant-demo",
            policy_id,
            1,
        )
        version_2 = load_policy_version(
            db,
            "tenant-demo",
            policy_id,
            2,
        )

    assert version_1 is not None
    assert version_1.policy_id == policy_id
    assert version_1.version == 1
    assert version_1.priority == 10
    assert version_1.max_transaction_amount == 10000

    assert version_2 is not None
    assert version_2.policy_id == policy_id
    assert version_2.version == 2
    assert version_2.priority == 5
    assert version_2.max_transaction_amount == 15000

def test_replay_restores_historical_policy_and_workflow_versions(client):
    ensure_setup(client)

    workflow_v1 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert workflow_v1.status_code == 200
    assert workflow_v1.json()["version"] == 1

    policy_v1 = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "replay-history-policy",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_risk_score": None,
            "min_trust_score": None,
            "max_transaction_amount": None,
            "allowed_start_hour": None,
            "allowed_end_hour": None,
            "enabled": True,
        },
    )

    assert policy_v1.status_code == 200

    policy_id = policy_v1.json()["id"]
    assert policy_v1.json()["version"] == 1

    token = issue_token(client).json()["token"]
    decision = access_request(client, token)

    assert decision.status_code == 200
    assert decision.json()["allow"] is False

    trace_id = decision.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_name": "replay-history-policy",
        },
    )

    assert audit.status_code == 200

    matching = [
        item
        for item in audit.json()
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    log_id = matching[0]["id"]

    workflow_v2 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert workflow_v2.status_code == 200
    assert workflow_v2.json()["version"] == 2

    policy_v2 = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 5,
            "max_transaction_amount": 15000,
        },
    )

    assert policy_v2.status_code == 200
    assert policy_v2.json()["version"] == 2

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["trace_id"] == trace_id
    assert body["workflow"]["version"] == 1
    assert body["workflow"]["include_risk_step"] is True
    assert body["workflow"]["include_policy_step"] is True
    assert body["workflow"]["execution_mode"] == "risk_first"

    assert body["policy"]["policy_id"] == policy_id
    assert body["policy"]["version"] == 1
    assert body["policy"]["priority"] == 10
    assert body["policy"]["max_transaction_amount"] is None

def test_replay_re_evaluates_original_decision(client):
    ensure_setup(client)

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert workflow.status_code == 200

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "replay-evaluation-policy",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "enabled": True,
        },
    )
    assert policy.status_code == 200

    token = issue_token(client).json()["token"]

    original = access_request(client, token)

    assert original.status_code == 200
    assert original.json()["allow"] is False

    trace_id = original.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert audit.status_code == 200

    matching = [
        item
        for item in audit.json()
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    log_id = matching[0]["id"]

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["original"]["allow"] is False

    assert "replayed" in body
    assert body["replayed"]["allow"] is False
    assert body["replayed"]["risk_score"] == body["original"]["risk_score"]
    assert body["replayed"]["policy_matched"] is True

    assert body["comparison"]["decision_match"] is True
    assert body["comparison"]["risk_score_match"] is True

def test_replay_ignores_future_request_logs(client):
    ensure_setup(client)

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert workflow.status_code == 200

    token = issue_token(client).json()["token"]

    original = access_request(client, token)

    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert audit.status_code == 200

    matching = [
        item
        for item in audit.json()
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    log_id = matching[0]["id"]

    replay_before = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay_before.status_code == 200

    before = replay_before.json()

    for index in range(5):
        future_token = issue_token(client).json()["token"]

        future = access_request(
            client,
            future_token,
            ip_address=f"10.99.0.{index + 1}",
            country_code="FI",
        )

        assert future.status_code == 200

    replay_after = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay_after.status_code == 200

    after = replay_after.json()

    assert after["replayed"]["allow"] == before["replayed"]["allow"]
    assert after["replayed"]["risk_score"] == before["replayed"]["risk_score"]
    assert after["replayed"]["risk_signals"] == before["replayed"]["risk_signals"]

    assert after["comparison"]["decision_match"] is True
    assert after["comparison"]["risk_score_match"] is True

def test_replay_re_evaluates_ownership_transfer(client):
    ensure_setup(client)

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert workflow.status_code == 200

    token = issue_token(
        client,
        scope="ownership_transfer",
        user_id="user-123",
    ).json()["token"]

    original = access_request(
        client,
        token,
        request_type="ownership_transfer",
        new_owner_id="user-456",
    )

    assert original.status_code == 200
    assert original.json()["allow"] is True

    trace_id = original.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert audit.status_code == 200

    matching = [
        item
        for item in audit.json()
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    log_id = matching[0]["id"]

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["request"]["request_type"] == "ownership_transfer"
    assert body["request"]["new_owner_id"] == "user-456"

    assert body["original"]["allow"] is True
    assert body["replayed"]["allow"] is True

    assert body["comparison"]["decision_match"] is True
    assert body["comparison"]["risk_score_match"] is True

def test_replay_survives_policy_deletion(client):
    ensure_setup(client)

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert workflow.status_code == 200

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "deleted-replay-policy",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "enabled": True,
        },
    )
    assert policy.status_code == 200

    policy_id = policy.json()["id"]
    policy_version = policy.json()["version"]

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200
    assert original.json()["allow"] is False

    trace_id = original.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert audit.status_code == 200

    matching = [
        item
        for item in audit.json()
        if item["trace_id"] == trace_id
    ]

    assert len(matching) == 1
    log_id = matching[0]["id"]

    deleted = client.delete(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
    )

    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["original"]["allow"] is False
    assert body["policy"] is not None
    assert body["policy"]["policy_id"] == policy_id
    assert body["policy"]["version"] == policy_version
    assert body["policy"]["name"] == "deleted-replay-policy"

    assert body["replayed"]["allow"] is False
    assert body["comparison"]["decision_match"] is True
    assert body["comparison"]["risk_score_match"] is True

def test_policy_multiple_versions_remain_replayable(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "multi-version-policy",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
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

    assert created.status_code == 200
    policy_id = created.json()["id"]
    assert created.json()["version"] == 1

    version_2_response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 5,
            "max_transaction_amount": 15000,
        },
    )

    assert version_2_response.status_code == 200
    assert version_2_response.json()["version"] == 2

    version_3_response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 1,
            "max_transaction_amount": 20000,
        },
    )

    assert version_3_response.status_code == 200
    assert version_3_response.json()["version"] == 3

    from app.database import SessionLocal
    from app.main import load_policy_version

    with SessionLocal() as db:
        version_1 = load_policy_version(
            db,
            "tenant-demo",
            policy_id,
            1,
        )
        version_2 = load_policy_version(
            db,
            "tenant-demo",
            policy_id,
            2,
        )
        version_3 = load_policy_version(
            db,
            "tenant-demo",
            policy_id,
            3,
        )

    assert version_1 is not None
    assert version_1.policy_id == policy_id
    assert version_1.version == 1
    assert version_1.priority == 10
    assert version_1.max_transaction_amount == 10000

    assert version_2 is not None
    assert version_2.policy_id == policy_id
    assert version_2.version == 2
    assert version_2.priority == 5
    assert version_2.max_transaction_amount == 15000

    assert version_3 is not None
    assert version_3.policy_id == policy_id
    assert version_3.version == 3
    assert version_3.priority == 1
    assert version_3.max_transaction_amount == 20000

def test_replay_returns_409_when_historical_workflow_is_missing(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )
        log.workflow_version = 999
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 409
    assert replay.json()["detail"] == "historical_workflow_version_not_found"

def test_replay_returns_409_when_historical_policy_is_missing(client):
    ensure_setup(client)

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "missing-history-policy",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "enabled": True,
        },
    )

    assert policy.status_code == 200

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200
    assert original.json()["allow"] is False

    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        assert log.policy_id is not None
        assert log.policy_version is not None

        log.workflow_version = None
        log.policy_version = 999
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 409
    assert replay.json()["detail"] == "historical_policy_version_not_found"
def test_replay_returns_404_when_request_log_not_found(client):
    ensure_setup(client)

    replay = client.get(
        "/admin/audit/logs/999999/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 404
    assert replay.json()["detail"] == "request_log_not_found"