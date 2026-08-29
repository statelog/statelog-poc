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
    assert body["policy_version"] == 1
    assert body["reason"] == "policy_deny:simulation-api-deny"

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

def test_admin_policy_simulation_does_not_create_request_log(client):
    ensure_setup(client)

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        before_count = db.query(RequestLog).count()

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

    with SessionLocal() as db:
        after_count = db.query(RequestLog).count()

    assert after_count == before_count

def test_admin_policy_simulation_supports_transaction_amount(client):
    ensure_setup(client)

    create = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "simulation-transaction-limit",
            "effect": "deny",
            "priority": 1,
            "request_types": ["ownership_transfer"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_transaction_amount": 10000,
            "enabled": True,
        },
    )

    assert create.status_code == 200

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "ownership_transfer",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "trust_score": 90,
            "transaction_amount": 5000,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["matched"] is True
    assert body["allow"] is False
    assert body["policy_name"] == "simulation-transaction-limit"

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

    print("REPLAY STATUS:", replay.status_code)
    print("REPLAY BODY:", replay.json())

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

    print("REPLAY STATUS:", replay.status_code)
    print("REPLAY BODY:", replay.json())

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

def test_replay_returns_409_when_historical_policy_reference_is_incomplete(client):
    ensure_setup(client)

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "incomplete-reference-policy",
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
        log.policy_version = None
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 409
    assert replay.json()["detail"] == "historical_policy_reference_incomplete"

def test_replay_detects_risk_score_mismatch(client):
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

        log.workflow_version = None
        log.risk_score = log.risk_score + 1
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["replayed"]["risk_score"] != body["original"]["risk_score"]
    assert body["comparison"]["risk_score_match"] is False

def test_replay_detects_decision_mismatch(client):
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

        log.workflow_version = None
        log.allowed = not log.allowed
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["replayed"]["allow"] != body["original"]["allow"]
    assert body["comparison"]["decision_match"] is False

def test_replay_preserves_original_decision_version(client):
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

        log.workflow_version = None
        log.decision_version = "historical-test-version"
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["original_decision"]["decision_version"] == "historical-test-version"
    assert body["original"]["decision_version"] == "historical-test-version"

def test_replay_preserves_decision_version_after_runtime_change(client, monkeypatch):
    ensure_setup(client)

    from app.main import settings

    monkeypatch.setattr(settings, "request_decision_version", "historical-v1")

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200
    assert original.json()["decision_version"] == "historical-v1"

    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        assert log.decision_version == "historical-v1"

        log.workflow_version = None
        db.commit()
        log_id = log.id

    monkeypatch.setattr(settings, "request_decision_version", "current-v2")

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["original_decision"]["decision_version"] == "historical-v1"
    assert body["original"]["decision_version"] == "historical-v1"

def test_replay_preserves_original_request_context(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]

    original = access_request(
        client,
        token,
        ip_address="10.20.30.40",
        country_code="EE",
    )

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

        expected_request_type = log.request_type
        expected_device_id = log.device_id
        expected_country_code = log.country_code
        expected_transaction_amount = log.transaction_amount
        expected_new_owner_id = log.new_owner_id

        log.workflow_version = None
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["request"]["request_type"] == expected_request_type
    assert body["request"]["device_id"] == expected_device_id
    assert body["request"]["country_code"] == expected_country_code
    assert body["request"]["transaction_amount"] == expected_transaction_amount
    assert body["request"]["new_owner_id"] == expected_new_owner_id

def test_replay_preserves_decision_reason(client):
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

        log.workflow_version = None
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["replayed"]["reason"] == body["original"]["reason"]
    assert body["comparison"]["reason_match"] is True
    assert body["comparison"]["all_match"] is True

def test_replay_detects_decision_reason_mismatch(client):
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

        log.workflow_version = None
        log.reason = "historical-reason-that-does-not-match"
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["replayed"]["reason"] != body["original"]["reason"]
    assert body["comparison"]["reason_match"] is False
    assert body["comparison"]["all_match"] is False

def test_replay_reports_matching_risk_signals(client):
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

        log.workflow_version = None
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["comparison"]["risk_signals_match"] is True

def test_replay_detects_risk_signals_mismatch(client):
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

        log.workflow_version = None
        log.risk_signals = "historical_signal_that_does_not_match"
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["comparison"]["risk_signals_match"] is False
    assert body["comparison"]["all_match"] is False

def test_replay_reports_matching_policy(client):
    ensure_setup(client)

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "replay-policy-match",
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

        log.workflow_version = None
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["replayed"]["policy_matched"] is True
    assert body["comparison"]["policy_match"] is True

def test_replay_detects_policy_mismatch(client):
    ensure_setup(client)

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "replay-policy-mismatch",
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
        log.country_code = "FI"
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["workflow"] is None
    assert body["replayed"]["policy_matched"] is False
    assert body["comparison"]["policy_match"] is False
    assert body["comparison"]["all_match"] is False

def test_replay_reports_matching_policy_version(client):
    ensure_setup(client)

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "replay-policy-version-match",
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
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert body["comparison"]["policy_match"] is True
    assert body["comparison"]["policy_version_match"] is True
    assert body["comparison"]["all_match"] is True

def test_replay_ignores_request_logs_with_same_timestamp(client):
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

        log.workflow_version = None
        db.commit()

        log_id = log.id
        original_created_at = log.created_at

    replay_before = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay_before.status_code == 200
    before = replay_before.json()

    with SessionLocal() as db:
        original_log = db.get(RequestLog, log_id)

        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id=original_log.tenant_id,
                    right_id=original_log.right_id,
                    client_id=original_log.client_id,
                    source_client=original_log.source_client,
                    device_id=original_log.device_id,
                    user_id=original_log.user_id,
                    ip_hash=f"same-time-ip-{i}",
                    country_code=original_log.country_code,
                    request_type=original_log.request_type,
                    transaction_amount=original_log.transaction_amount,
                    new_owner_id=original_log.new_owner_id,
                    allowed=False,
                    risk_score=80,
                    reason="same_timestamp_denial",
                    risk_signals="failure_burst",
                    policy_matched=False,
                    policy_name=None,
                    policy_id=None,
                    policy_version=None,
                    trace_id=f"same-time-trace-{i}",
                    idempotency_key=f"same-time-idem-{i}",
                    token_jti=None,
                    request_fingerprint=f"same-time-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    workflow_version=None,
                    created_at=original_created_at,
                )
            )

        db.commit()

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

def test_replay_includes_failures_exactly_15_minutes_old(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    from datetime import timedelta

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        log.workflow_version = None
        db.commit()

        log_id = log.id
        original_created_at = log.created_at

    replay_before = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay_before.status_code == 200
    before = replay_before.json()

    with SessionLocal() as db:
        original_log = db.get(RequestLog, log_id)

        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id=original_log.tenant_id,
                    right_id=original_log.right_id,
                    client_id=original_log.client_id,
                    source_client=original_log.source_client,
                    device_id=original_log.device_id,
                    user_id=original_log.user_id,
                    ip_hash=original_log.ip_hash,
                    country_code=original_log.country_code,
                    request_type=original_log.request_type,
                    transaction_amount=original_log.transaction_amount,
                    new_owner_id=original_log.new_owner_id,
                    allowed=False,
                    risk_score=80,
                    reason="boundary_failure",
                    risk_signals="failure_burst",
                    policy_matched=False,
                    policy_name=None,
                    policy_id=None,
                    policy_version=None,
                    trace_id=f"boundary-15m-trace-{i}",
                    idempotency_key=f"boundary-15m-idem-{i}",
                    token_jti=None,
                    request_fingerprint=f"boundary-15m-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    workflow_version=None,
                    created_at=original_created_at - timedelta(minutes=15),
                )
            )

        db.commit()

    replay_after = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay_after.status_code == 200
    after = replay_after.json()

    assert "failure_burst" in after["replayed"]["risk_signals"]
    assert after["replayed"]["risk_score"] >= before["replayed"]["risk_score"]

def test_replay_excludes_failures_older_than_15_minutes(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    from datetime import timedelta

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        log.workflow_version = None
        db.commit()

        log_id = log.id
        original_created_at = log.created_at

    replay_before = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay_before.status_code == 200
    before = replay_before.json()

    with SessionLocal() as db:
        original_log = db.get(RequestLog, log_id)

        for i in range(3):
            db.add(
                RequestLog(
                    tenant_id=original_log.tenant_id,
                    right_id=original_log.right_id,
                    client_id=original_log.client_id,
                    source_client=original_log.source_client,
                    device_id=original_log.device_id,
                    user_id=original_log.user_id,
                    ip_hash=original_log.ip_hash,
                    country_code=original_log.country_code,
                    request_type=original_log.request_type,
                    transaction_amount=original_log.transaction_amount,
                    new_owner_id=original_log.new_owner_id,
                    allowed=False,
                    risk_score=80,
                    reason="older_boundary_failure",
                    risk_signals="failure_burst",
                    policy_matched=False,
                    policy_name=None,
                    policy_id=None,
                    policy_version=None,
                    trace_id=f"boundary-over-15m-trace-{i}",
                    idempotency_key=f"boundary-over-15m-idem-{i}",
                    token_jti=None,
                    request_fingerprint=f"boundary-over-15m-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    workflow_version=None,
                    created_at=original_created_at - timedelta(minutes=15, seconds=1),
                )
            )

        db.commit()

    replay_after = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay_after.status_code == 200
    after = replay_after.json()

    assert after["replayed"]["risk_score"] == before["replayed"]["risk_score"]
    assert after["replayed"]["risk_signals"] == before["replayed"]["risk_signals"]

def test_replay_includes_transfers_exactly_one_hour_old(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    with SessionLocal() as db:
        for i in range(2):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"replay-transfer-ip-{i}",
                    country_code="EE",
                    request_type="ownership_transfer",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"replay-transfer-trace-{i}",
                    idempotency_key=f"replay-transfer-idem-{i}",
                    request_fingerprint=f"replay-transfer-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=now - timedelta(hours=1),
                )
            )

        db.commit()

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

    trace_id = original.json()["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        log.created_at = now
        log.workflow_version = None
        log_id = log.id
        db.commit()

    with SessionLocal() as db:
        persisted_log = db.get(RequestLog, log_id)
        assert persisted_log is not None
        assert persisted_log.workflow_version is None

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200, replay.json()

    body = replay.json()

    assert "transfer_velocity" in body["replayed"]["risk_signals"]

def test_replay_includes_old_log_when_in_latest_ten(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash="old-latest-ten-ip",
                country_code="FI",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                trace_id="old-latest-ten-trace",
                idempotency_key="old-latest-ten-idem",
                request_fingerprint="old-latest-ten-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=now - timedelta(hours=2),
            )
        )
        db.commit()

    token = issue_token(client).json()["token"]

    original = access_request(
        client,
        token,
        ip_address="10.10.10.99",
        country_code="FI",
    )

    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        log.created_at = now
        log.workflow_version = None
        log_id = log.id
        db.commit()

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200, replay.json()

    body = replay.json()

    assert "new_ip" in body["replayed"]["risk_signals"]

def test_load_risk_history_deduplicates_overlapping_logs(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    with SessionLocal() as db:
        log = RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash="dedup-history-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id="dedup-history-trace",
            idempotency_key="dedup-history-idem",
            request_fingerprint="dedup-history-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=now,
        )
        db.add(log)
        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=now + timedelta(seconds=1),
        )

        matching = [
            item
            for item in history
            if item.trace_id == "dedup-history-trace"
        ]

        assert len(matching) == 1

def test_load_risk_history_excludes_log_at_before_boundary(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    before = utcnow_naive()

    with SessionLocal() as db:
        older = RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash="boundary-older-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id="boundary-older-trace",
            idempotency_key="boundary-older-idem",
            request_fingerprint="boundary-older-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=before - timedelta(seconds=1),
        )

        boundary = RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash="boundary-exact-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id="boundary-exact-trace",
            idempotency_key="boundary-exact-idem",
            request_fingerprint="boundary-exact-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=before,
        )

        db.add_all([older, boundary])
        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=before,
        )

        trace_ids = {item.trace_id for item in history}

        assert "boundary-older-trace" in trace_ids
        assert "boundary-exact-trace" not in trace_ids

def test_load_risk_history_includes_log_exactly_one_hour_old(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()

    with SessionLocal() as db:
        log = RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash="hour-boundary-ip",
            country_code="EE",
            request_type="ownership_transfer",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id="hour-boundary-trace",
            idempotency_key="hour-boundary-idem",
            request_fingerprint="hour-boundary-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=reference_time - timedelta(hours=1),
        )

        db.add(log)
        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=reference_time,
        )

        trace_ids = {item.trace_id for item in history}

        assert "hour-boundary-trace" in trace_ids

def test_load_risk_history_excludes_old_log_outside_latest_ten(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()

    with SessionLocal() as db:
        old_log = RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash="outside-latest-ten-old-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id="outside-latest-ten-old-trace",
            idempotency_key="outside-latest-ten-old-idem",
            request_fingerprint="outside-latest-ten-old-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=reference_time - timedelta(hours=2),
        )
        db.add(old_log)

        for i in range(10):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"outside-latest-ten-new-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"outside-latest-ten-new-trace-{i}",
                    idempotency_key=f"outside-latest-ten-new-idem-{i}",
                    request_fingerprint=f"outside-latest-ten-new-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=reference_time - timedelta(minutes=i + 1),
                )
            )

        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=reference_time,
        )

        trace_ids = {item.trace_id for item in history}

        assert "outside-latest-ten-old-trace" not in trace_ids

def test_load_risk_history_isolates_tenant_and_right(client):
    ensure_setup(client)

    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    def make_log(tenant_id, right_id, trace_id):
        return RequestLog(
            tenant_id=tenant_id,
            right_id=right_id,
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=now,
        )

    with SessionLocal() as db:
        db.add_all(
            [
                make_log(
                    "tenant-demo",
                    "right-001",
                    "history-isolation-target",
                ),
                make_log(
                    "tenant-demo",
                    "right-777",
                    "history-isolation-other-right",
                ),
                make_log(
                    "tenant-other",
                    "right-001",
                    "history-isolation-other-tenant",
                ),
            ]
        )
        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        trace_ids = {item.trace_id for item in history}

        assert "history-isolation-target" in trace_ids
        assert "history-isolation-other-right" not in trace_ids
        assert "history-isolation-other-tenant" not in trace_ids

def test_load_risk_history_same_timestamp_latest_ten_is_deterministic(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()
    same_time = reference_time - timedelta(hours=2)

    with SessionLocal() as db:
        inserted = []

        for i in range(12):
            log = RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash=f"same-time-latest-ip-{i}",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                trace_id=f"same-time-latest-trace-{i}",
                idempotency_key=f"same-time-latest-idem-{i}",
                request_fingerprint=f"same-time-latest-fingerprint-{i}",
                user_agent="pytest",
                decision_version="test",
                created_at=same_time,
            )
            db.add(log)
            inserted.append(log)

        db.commit()

        inserted_ids = sorted(log.id for log in inserted)
        expected_ids = set(inserted_ids[-10:])

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=reference_time,
        )

        returned_ids = {log.id for log in history if log.id in inserted_ids}

    assert returned_ids == expected_ids

def test_replay_same_timestamp_latest_ten_is_deterministic(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()
    same_time = reference_time - timedelta(hours=2)

    with SessionLocal() as db:
        for i in range(12):
            db.add(
                RequestLog(
                    tenant_id="tenant-demo",
                    right_id="right-001",
                    client_id="gateway-1",
                    source_client="gateway-1",
                    device_id="gate-A1",
                    user_id="user-123",
                    ip_hash=f"replay-deterministic-ip-{i}",
                    country_code="EE" if i < 2 else "FI",
                    request_type="access",
                    allowed=True,
                    risk_score=0,
                    reason="allowed",
                    risk_signals="",
                    policy_matched=False,
                    policy_name=None,
                    trace_id=f"replay-deterministic-trace-{i}",
                    idempotency_key=f"replay-deterministic-idem-{i}",
                    request_fingerprint=f"replay-deterministic-fingerprint-{i}",
                    user_agent="pytest",
                    decision_version="test",
                    created_at=same_time,
                )
            )

        db.commit()

    token = issue_token(client).json()["token"]

    original = access_request(
        client,
        token,
        ip_address="current-ip",
        country_code="EE",
    )

    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        log.workflow_version = None
        log_id = log.id
        db.commit()

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200, replay.json()

    body = replay.json()

    assert "geo_change" in body["replayed"]["risk_signals"]

def test_load_risk_history_same_timestamp_returns_deterministic_order(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()
    same_time = reference_time - timedelta(hours=2)

    with SessionLocal() as db:
        inserted = []

        for i in range(12):
            log = RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash=f"order-deterministic-ip-{i}",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                trace_id=f"order-deterministic-trace-{i}",
                idempotency_key=f"order-deterministic-idem-{i}",
                request_fingerprint=f"order-deterministic-fingerprint-{i}",
                user_agent="pytest",
                decision_version="test",
                created_at=same_time,
            )
            db.add(log)
            inserted.append(log)

        db.commit()

        inserted_ids = sorted(log.id for log in inserted)
        expected_ids = list(reversed(inserted_ids[-10:]))

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=reference_time,
        )

        returned_ids = [
            log.id
            for log in history
            if log.id in inserted_ids
        ]

    assert returned_ids == expected_ids

def test_load_risk_history_same_timestamp_limit_boundary_prefers_higher_id(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()
    same_time = reference_time - timedelta(hours=2)

    with SessionLocal() as db:
        inserted = []

        for i in range(11):
            log = RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="gate-A1",
                user_id="user-123",
                ip_hash=f"limit-boundary-ip-{i}",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                trace_id=f"limit-boundary-trace-{i}",
                idempotency_key=f"limit-boundary-idem-{i}",
                request_fingerprint=f"limit-boundary-fingerprint-{i}",
                user_agent="pytest",
                decision_version="test",
                created_at=same_time,
            )
            db.add(log)
            inserted.append(log)

        db.commit()

        inserted_ids = sorted(log.id for log in inserted)

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=reference_time,
        )

        returned_ids = {
            log.id
            for log in history
            if log.id in inserted_ids
        }

    assert inserted_ids[0] not in returned_ids
    assert set(inserted_ids[1:]) == returned_ids

def test_load_risk_history_filters_tenant_and_right_before_limit(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()

    def make_log(tenant_id, right_id, trace_id, created_at):
        return RequestLog(
            tenant_id=tenant_id,
            right_id=right_id,
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=created_at,
        )

    with SessionLocal() as db:
        target = make_log(
            "tenant-demo",
            "right-001",
            "filter-before-limit-target",
            reference_time - timedelta(minutes=30),
        )
        db.add(target)

        for i in range(12):
            db.add(
                make_log(
                    "tenant-other",
                    "right-001",
                    f"filter-before-limit-other-tenant-{i}",
                    reference_time - timedelta(minutes=i),
                )
            )

        for i in range(12):
            db.add(
                make_log(
                    "tenant-demo",
                    "right-777",
                    f"filter-before-limit-other-right-{i}",
                    reference_time - timedelta(minutes=i),
                )
            )

        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=reference_time,
        )

        trace_ids = {log.trace_id for log in history}

    assert "filter-before-limit-target" in trace_ids
    assert not any(
        trace_id.startswith("filter-before-limit-other-tenant")
        for trace_id in trace_ids
    )
    assert not any(
        trace_id.startswith("filter-before-limit-other-right")
        for trace_id in trace_ids
    )

def test_load_risk_history_filters_before_timestamp_before_limit(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    reference_time = utcnow_naive()
    before = reference_time - timedelta(hours=1)

    def make_log(trace_id, created_at):
        return RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=created_at,
        )

    with SessionLocal() as db:
        target = make_log(
            "before-limit-target",
            before - timedelta(minutes=1),
        )
        db.add(target)

        for i in range(12):
            db.add(
                make_log(
                    f"before-limit-future-{i}",
                    before + timedelta(minutes=i + 1),
                )
            )

        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
            before=before,
        )

        trace_ids = {log.trace_id for log in history}

    assert "before-limit-target" in trace_ids
    assert not any(
        trace_id.startswith("before-limit-future-")
        for trace_id in trace_ids
    )

def test_load_risk_history_without_before_uses_current_one_hour_window(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    def make_log(trace_id, created_at):
        return RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=created_at,
        )

    with SessionLocal() as db:
        db.add(
            make_log(
                "no-before-old",
                now - timedelta(hours=1, minutes=5),
            )
        )

        for i in range(10):
            db.add(
                make_log(
                    f"no-before-recent-{i}",
                    now - timedelta(minutes=i + 1),
                )
            )

        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        trace_ids = {log.trace_id for log in history}

    assert "no-before-recent-0" in trace_ids
    assert "no-before-old" not in trace_ids

def test_admin_policy_simulation_supports_business_hours(client):
    ensure_setup(client)

    create = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "simulation-business-hours",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "allowed_start_hour": 8,
            "allowed_end_hour": 18,
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
            "hour": 12,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["matched"] is True
    assert body["allow"] is False
    assert body["policy_name"] == "simulation-business-hours"

def test_admin_policy_simulation_returns_404_for_unknown_tenant(client):
    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-does-not-exist",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "trust_score": 90,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "tenant_not_found"

def test_admin_policy_simulation_has_no_persistence_side_effects(client):
    ensure_setup(client)

    from app.database import SessionLocal
    from app.models import (
        OutboxEvent,
        PolicyHistory,
        RequestLog,
        WorkflowConfigHistory,
    )

    with SessionLocal() as db:
        before = {
            "request_logs": db.query(RequestLog).count(),
            "outbox_events": db.query(OutboxEvent).count(),
            "policy_history": db.query(PolicyHistory).count(),
            "workflow_history": db.query(WorkflowConfigHistory).count(),
        }

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

    with SessionLocal() as db:
        after = {
            "request_logs": db.query(RequestLog).count(),
            "outbox_events": db.query(OutboxEvent).count(),
            "policy_history": db.query(PolicyHistory).count(),
            "workflow_history": db.query(WorkflowConfigHistory).count(),
        }

    assert after == before

def test_admin_policy_simulation_does_not_modify_active_configuration(client):
    ensure_setup(client)

    create = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "simulation-immutable-policy",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "max_risk_score": 50,
            "min_trust_score": 50,
            "enabled": True,
        },
    )

    assert create.status_code == 200

    from app.database import SessionLocal
    from app.models import PolicyRecord, WorkflowConfigRecord

    with SessionLocal() as db:
        policy = (
            db.query(PolicyRecord)
            .filter_by(
                tenant_id="tenant-demo",
                name="simulation-immutable-policy",
            )
            .first()
        )
        workflow = db.get(WorkflowConfigRecord, "tenant-demo")

        assert policy is not None

        policy_before = {
            "id": policy.id,
            "name": policy.name,
            "effect": policy.effect,
            "priority": policy.priority,
            "version": policy.version,
            "request_types": policy.request_types,
            "countries": policy.countries,
            "device_ids": policy.device_ids,
            "max_risk_score": policy.max_risk_score,
            "min_trust_score": policy.min_trust_score,
            "max_transaction_amount": policy.max_transaction_amount,
            "allowed_start_hour": policy.allowed_start_hour,
            "allowed_end_hour": policy.allowed_end_hour,
            "enabled": policy.enabled,
            "updated_at": policy.updated_at,
        }

        workflow_before = None
        if workflow is not None:
            workflow_before = {
                "version": workflow.version,
                "include_risk_step": workflow.include_risk_step,
                "include_policy_step": workflow.include_policy_step,
                "execution_mode": workflow.execution_mode,
            }

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

    with SessionLocal() as db:
        policy = db.get(PolicyRecord, policy_before["id"])
        workflow = db.get(WorkflowConfigRecord, "tenant-demo")

        policy_after = {
            "id": policy.id,
            "name": policy.name,
            "effect": policy.effect,
            "priority": policy.priority,
            "version": policy.version,
            "request_types": policy.request_types,
            "countries": policy.countries,
            "device_ids": policy.device_ids,
            "max_risk_score": policy.max_risk_score,
            "min_trust_score": policy.min_trust_score,
            "max_transaction_amount": policy.max_transaction_amount,
            "allowed_start_hour": policy.allowed_start_hour,
            "allowed_end_hour": policy.allowed_end_hour,
            "enabled": policy.enabled,
            "updated_at": policy.updated_at,
        }

        workflow_after = None
        if workflow is not None:
            workflow_after = {
                "version": workflow.version,
                "include_risk_step": workflow.include_risk_step,
                "include_policy_step": workflow.include_policy_step,
                "execution_mode": workflow.execution_mode,
            }

    assert policy_after == policy_before
    assert workflow_after == workflow_before

def test_admin_policy_simulation_isolates_tenant_policies(client):
    ensure_setup(client)

    create = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "name": "other-tenant-deny",
            "effect": "deny",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
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

def test_list_policies_orders_equal_priority_by_id(client):
    ensure_setup(client)

    first = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "equal-priority-first",
            "effect": "allow",
            "priority": 42,
        },
    )
    second = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "equal-priority-second",
            "effect": "deny",
            "priority": 42,
        },
    )

    assert first.status_code == 200
    assert second.status_code == 200

    response = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 200

    policies = [
        policy
        for policy in response.json()
        if policy["name"] in {
            "equal-priority-first",
            "equal-priority-second",
        }
    ]

    assert [policy["name"] for policy in policies] == [
        "equal-priority-first",
        "equal-priority-second",
    ]
    assert policies[0]["id"] < policies[1]["id"]

def test_load_policy_version_isolates_tenants(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "tenant-isolated-history",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
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

    from app.database import SessionLocal
    from app.main import load_policy_version

    with SessionLocal() as db:
        correct_tenant = load_policy_version(
            db,
            "tenant-demo",
            policy_id,
            1,
        )

        wrong_tenant = load_policy_version(
            db,
            "tenant-other",
            policy_id,
            1,
        )

    assert correct_tenant is not None
    assert correct_tenant.policy_id == policy_id
    assert correct_tenant.version == 1

    assert wrong_tenant is None

def test_replay_does_not_load_policy_version_from_other_tenant(client):
    ensure_setup(client)

    policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "cross-tenant-replay-policy",
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
        log.tenant_id = "tenant-other"
        db.commit()

        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 409
    assert replay.json()["detail"] == "historical_policy_version_not_found"

def test_replay_does_not_load_workflow_version_from_other_tenant(client):
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

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        assert log.workflow_version is not None

        log.policy_id = None
        log.policy_version = None
        log.tenant_id = "tenant-other"
        db.commit()

        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 409
    assert replay.json()["detail"] == "historical_workflow_version_not_found"

def test_replay_rejects_request_log_with_unknown_tenant(client):
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

        log.workflow_version = None
        log.policy_id = None
        log.policy_version = None
        log.tenant_id = "tenant-does-not-exist"

        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 409
    assert replay.json()["detail"] == "historical_tenant_not_found"

def test_audit_logs_same_timestamp_order_by_id_desc(client):
    ensure_setup(client)

    first_token = issue_token(client).json()["token"]
    second_token = issue_token(client).json()["token"]

    first = access_request(client, first_token)
    second = access_request(
        client,
        second_token,
        ip_address="10.0.0.11",
    )

    assert first.status_code == 200
    assert second.status_code == 200

    from datetime import datetime
    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        first_log = (
            db.query(RequestLog)
            .filter_by(trace_id=first.json()["trace_id"])
            .one()
        )
        second_log = (
            db.query(RequestLog)
            .filter_by(trace_id=second.json()["trace_id"])
            .one()
        )

        same_time = datetime(2026, 1, 1, 12, 0, 0)

        first_log.created_at = same_time
        second_log.created_at = same_time
        db.commit()

        first_id = first_log.id
        second_id = second_log.id

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 500,
        },
    )

    assert response.status_code == 200

    ids = [
        item["id"]
        for item in response.json()
        if item["id"] in {first_id, second_id}
    ]

    assert ids == [max(first_id, second_id), min(first_id, second_id)]

def test_tenant_dashboard_same_timestamp_orders_logs_by_id_desc(client):
    ensure_setup(client)

    from tests.test_smoke import HEADERS

    first_token = issue_token(client).json()["token"]
    second_token = issue_token(client).json()["token"]

    first = access_request(client, first_token)
    second = access_request(
        client,
        second_token,
        ip_address="10.0.0.11",
    )

    assert first.status_code == 200
    assert second.status_code == 200

    from datetime import datetime
    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        first_log = (
            db.query(RequestLog)
            .filter_by(trace_id=first.json()["trace_id"])
            .one()
        )
        second_log = (
            db.query(RequestLog)
            .filter_by(trace_id=second.json()["trace_id"])
            .one()
        )

        same_time = datetime(2026, 1, 1, 12, 0, 0)

        first_log.created_at = same_time
        second_log.created_at = same_time
        first_log.reason = "dashboard-first-log"
        second_log.reason = "dashboard-second-log"

        db.commit()

        assert second_log.id > first_log.id

    response = client.get(
        "/tenant/tenant-demo",
        headers=HEADERS,
    )

    assert response.status_code == 200

    html = response.text

    assert "dashboard-first-log" in html
    assert "dashboard-second-log" in html
    assert html.index("dashboard-second-log") < html.index("dashboard-first-log")

def test_load_risk_history_without_before_excludes_future_logs(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    def make_log(trace_id, created_at):
        return RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=created_at,
        )

    with SessionLocal() as db:
        recent = make_log(
            "no-before-recent",
            now - timedelta(minutes=5),
        )
        future = make_log(
            "no-before-future",
            now + timedelta(hours=1),
        )

        db.add_all([recent, future])
        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        trace_ids = {log.trace_id for log in history}

    assert "no-before-recent" in trace_ids
    assert "no-before-future" not in trace_ids

def test_load_risk_history_filters_future_logs_before_latest_ten_limit(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    def make_log(trace_id, created_at):
        return RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=created_at,
        )

    with SessionLocal() as db:
        target = make_log(
            "future-limit-target",
            now - timedelta(hours=2),
        )
        db.add(target)

        for i in range(10):
            db.add(
                make_log(
                    f"future-limit-old-{i}",
                    now - timedelta(hours=3, minutes=i),
                )
            )

        for i in range(12):
            db.add(
                make_log(
                    f"future-limit-future-{i}",
                    now + timedelta(hours=1, minutes=i),
                )
            )

        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        trace_ids = {log.trace_id for log in history}

    assert "future-limit-target" in trace_ids
    assert not any(
        trace_id.startswith("future-limit-future-")
        for trace_id in trace_ids
    )

def test_load_risk_history_without_before_filters_tenant_and_right_before_limit(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    def make_log(tenant_id, right_id, trace_id, created_at):
        return RequestLog(
            tenant_id=tenant_id,
            right_id=right_id,
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=created_at,
        )

    with SessionLocal() as db:
        target = make_log(
            "tenant-demo",
            "right-001",
            "live-filter-before-limit-target",
            now - timedelta(hours=2),
        )
        db.add(target)

        for i in range(12):
            db.add(
                make_log(
                    "tenant-other",
                    "right-001",
                    f"live-filter-other-tenant-{i}",
                    now - timedelta(minutes=i + 1),
                )
            )

        for i in range(12):
            db.add(
                make_log(
                    "tenant-demo",
                    "right-other",
                    f"live-filter-other-right-{i}",
                    now - timedelta(minutes=i + 1),
                )
            )

        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        trace_ids = {log.trace_id for log in history}

    assert "live-filter-before-limit-target" in trace_ids
    assert not any(
        trace_id.startswith("live-filter-other-tenant-")
        for trace_id in trace_ids
    )
    assert not any(
        trace_id.startswith("live-filter-other-right-")
        for trace_id in trace_ids
    )

def test_load_risk_history_without_before_same_timestamp_latest_ten_is_deterministic(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()
    same_time = now - timedelta(hours=2)

    def make_log(trace_id):
        return RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=same_time,
        )

    with SessionLocal() as db:
        logs = []

        for i in range(12):
            log = make_log(f"live-same-time-{i}")
            db.add(log)
            logs.append(log)

        db.commit()

        ids = [log.id for log in logs]

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        history_ids = {log.id for log in history}

    expected_ids = set(sorted(ids, reverse=True)[:10])

    assert history_ids == expected_ids
    assert min(ids) not in history_ids
    assert sorted(ids)[1] not in history_ids

def test_load_risk_history_without_before_deduplicates_overlapping_logs(client):
    ensure_setup(client)

    from datetime import timedelta
    from app.database import SessionLocal
    from app.main import load_risk_history
    from app.models import RequestLog
    from app.time_utils import utcnow_naive

    now = utcnow_naive()

    def make_log(trace_id, created_at):
        return RequestLog(
            tenant_id="tenant-demo",
            right_id="right-001",
            client_id="gateway-1",
            source_client="gateway-1",
            device_id="gate-A1",
            user_id="user-123",
            ip_hash=f"{trace_id}-ip",
            country_code="EE",
            request_type="access",
            allowed=True,
            risk_score=0,
            reason="allowed",
            risk_signals="",
            policy_matched=False,
            policy_name=None,
            trace_id=trace_id,
            idempotency_key=f"{trace_id}-idem",
            request_fingerprint=f"{trace_id}-fingerprint",
            user_agent="pytest",
            decision_version="test",
            created_at=created_at,
        )

    with SessionLocal() as db:
        overlap = make_log(
            "live-dedup-overlap",
            now - timedelta(minutes=5),
        )
        db.add(overlap)
        db.commit()

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        matching = [
            log
            for log in history
            if log.trace_id == "live-dedup-overlap"
        ]

    assert len(matching) == 1