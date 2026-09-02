import json
from datetime import datetime, timedelta
from tests.test_smoke import ADMIN_HEADERS, ensure_setup, issue_token, access_request
from app.database import SessionLocal
from app.models import PolicyHistory
from app.main import (
    PolicyRecord,
    RequestLog,
    load_tenant_policies,
    load_policy_version,
    save_policy_history,
)
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

def test_load_risk_history_without_before_respects_one_hour_boundary(client):
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
                "live-boundary-59-minutes",
                now - timedelta(minutes=59),
            )
        )
        db.add(
            make_log(
                "live-boundary-61-minutes",
                now - timedelta(minutes=61),
            )
        )

        # Push the 61-minute-old log outside latest_ten.
        for i in range(10):
            db.add(
                make_log(
                    f"live-boundary-recent-{i}",
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

    assert "live-boundary-59-minutes" in trace_ids
    assert "live-boundary-61-minutes" not in trace_ids

def test_load_risk_history_future_logs_do_not_displace_latest_ten(client):
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
        historical = []

        # These are older than one hour, so they can only enter
        # through the latest_ten branch.
        for i in range(10):
            log = make_log(
                f"future-pressure-history-{i}",
                now - timedelta(hours=2, minutes=i),
            )
            db.add(log)
            historical.append(log)

        # Future logs must neither be returned nor consume
        # positions in latest_ten.
        for i in range(12):
            db.add(
                make_log(
                    f"future-pressure-future-{i}",
                    now + timedelta(hours=1, minutes=i),
                )
            )

        db.commit()

        historical_ids = {log.id for log in historical}

        history = load_risk_history(
            db,
            tenant_id="tenant-demo",
            right_id="right-001",
        )

        history_ids = {log.id for log in history}
        trace_ids = {log.trace_id for log in history}

    assert historical_ids.issubset(history_ids)
    assert not any(
        trace_id.startswith("future-pressure-future-")
        for trace_id in trace_ids
    )

def test_workflow_multiple_versions_remain_replayable(client):
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

    workflow_v3 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert workflow_v3.status_code == 200
    assert workflow_v3.json()["version"] == 3

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

def test_workflow_history_returns_archived_versions_in_ascending_order(client):
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

    workflow_v3 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )
    assert workflow_v3.status_code == 200
    assert workflow_v3.json()["version"] == 3

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert [item["version"] for item in items] == [1, 2]


def test_workflow_history_snapshots_preserve_original_configuration(client):
    ensure_setup(client)

    workflow_v1 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )
    assert workflow_v1.status_code == 200

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

    workflow_v3 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert workflow_v3.status_code == 200

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()
    assert len(items) == 2

    assert items[0]["version"] == 1
    assert items[0]["include_risk_step"] is True
    assert items[0]["include_policy_step"] is False
    assert items[0]["execution_mode"] == "risk_first"

    assert items[1]["version"] == 2
    assert items[1]["include_risk_step"] is False
    assert items[1]["include_policy_step"] is True
    assert items[1]["execution_mode"] == "policy_first"


def test_workflow_history_endpoint_isolates_tenants(client):
    ensure_setup(client)

    demo_v1 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert demo_v1.status_code == 200

    demo_v2 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )
    assert demo_v2.status_code == 200

    other_v1 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "include_risk_step": False,
            "include_policy_step": False,
            "execution_mode": "policy_first",
        },
    )
    assert other_v1.status_code == 200

    other_v2 = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )
    assert other_v2.status_code == 200

    demo_history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )
    other_history = client.get(
        "/admin/workflow-config/tenant-other/history",
        headers=ADMIN_HEADERS,
    )

    assert demo_history.status_code == 200
    assert other_history.status_code == 200

    demo_items = demo_history.json()
    other_items = other_history.json()

    assert [item["version"] for item in demo_items] == [1]
    assert [item["version"] for item in other_items] == [1]

    assert all(item["tenant_id"] == "tenant-demo" for item in demo_items)
    assert all(item["tenant_id"] == "tenant-other" for item in other_items)


def test_workflow_active_config_is_latest_version_while_history_contains_previous_versions(client):
    ensure_setup(client)

    for payload in [
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    ]:
        response = client.put(
            "/admin/workflow-config",
            headers=ADMIN_HEADERS,
            json=payload,
        )
        assert response.status_code == 200

    active = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )
    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert active.status_code == 200
    assert history.status_code == 200

    active_body = active.json()
    history_items = history.json()

    assert active_body["version"] == 3
    assert active_body["include_risk_step"] is True
    assert active_body["include_policy_step"] is False
    assert active_body["execution_mode"] == "risk_first"

    assert [item["version"] for item in history_items] == [1, 2]
    assert 3 not in [item["version"] for item in history_items]

def test_workflow_history_returns_404_for_unknown_tenant(client):
    ensure_setup(client)

    response = client.get(
        "/admin/workflow-config/tenant-unknown/history",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "tenant_not_found"

def test_workflow_history_returns_empty_list_when_no_history_exists(client):
    ensure_setup(client)

    response = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 200
    assert response.json() == []

def test_workflow_history_is_empty_while_initial_version_is_active(client):
    ensure_setup(client)

    created = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert created.status_code == 200
    assert created.json()["version"] == 1

    active = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )
    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert active.status_code == 200
    assert active.json()["version"] == 1

    assert history.status_code == 200
    assert history.json() == []

def test_workflow_history_contains_only_previous_version_after_first_update(client):
    ensure_setup(client)

    created = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert created.status_code == 200
    assert created.json()["version"] == 1

    updated = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    active = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )
    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert active.status_code == 200
    assert history.status_code == 200

    active_body = active.json()
    history_items = history.json()

    assert active_body["version"] == 2
    assert active_body["include_risk_step"] is False
    assert active_body["include_policy_step"] is True
    assert active_body["execution_mode"] == "policy_first"

    assert len(history_items) == 1

    archived = history_items[0]

    assert archived["version"] == 1
    assert archived["include_risk_step"] is True
    assert archived["include_policy_step"] is False
    assert archived["execution_mode"] == "risk_first"

def test_workflow_history_snapshot_includes_created_at(client):
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
    assert created.json()["version"] == 1

    updated = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert len(items) == 1
    assert items[0]["version"] == 1
    assert items[0]["created_at"] is not None
    assert isinstance(items[0]["created_at"], str)
    assert items[0]["created_at"] != ""

def test_workflow_history_created_at_is_in_chronological_order(client):
    ensure_setup(client)

    from datetime import datetime

    payloads = [
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    ]

    for expected_version, payload in enumerate(payloads, start=1):
        response = client.put(
            "/admin/workflow-config",
            headers=ADMIN_HEADERS,
            json=payload,
        )

        assert response.status_code == 200
        assert response.json()["version"] == expected_version

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert [item["version"] for item in items] == [1, 2]

    created_at_values = [
        datetime.fromisoformat(item["created_at"])
        for item in items
    ]

    assert created_at_values == sorted(created_at_values)

def test_workflow_history_snapshots_have_unique_ids(client):
    ensure_setup(client)

    payloads = [
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    ]

    for expected_version, payload in enumerate(payloads, start=1):
        response = client.put(
            "/admin/workflow-config",
            headers=ADMIN_HEADERS,
            json=payload,
        )

        assert response.status_code == 200
        assert response.json()["version"] == expected_version

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert [item["version"] for item in items] == [1, 2]
    assert len(items) == 2

    ids = [item["id"] for item in items]

    assert all(item_id is not None for item_id in ids)
    assert len(set(ids)) == 2

def test_workflow_history_repeated_reads_preserve_snapshots(client):
    ensure_setup(client)

    payloads = [
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    ]

    for expected_version, payload in enumerate(payloads, start=1):
        response = client.put(
            "/admin/workflow-config",
            headers=ADMIN_HEADERS,
            json=payload,
        )

        assert response.status_code == 200
        assert response.json()["version"] == expected_version

    first = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )
    second = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    first_items = first.json()
    second_items = second.json()

    assert [item["version"] for item in first_items] == [1, 2]
    assert first_items == second_items

def test_workflow_active_reads_do_not_create_history(client):
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
    assert created.json()["version"] == 1

    first = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )
    second = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json() == second.json()
    assert first.json()["version"] == 1

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200
    assert history.json() == []

def test_workflow_history_adds_exactly_one_snapshot_per_update(client):
    ensure_setup(client)

    initial = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert initial.status_code == 200
    assert initial.json()["version"] == 1

    first_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert first_update.status_code == 200
    assert first_update.json()["version"] == 2

    history_after_first = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history_after_first.status_code == 200
    first_items = history_after_first.json()

    assert len(first_items) == 1
    assert [item["version"] for item in first_items] == [1]

    second_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert second_update.status_code == 200
    assert second_update.json()["version"] == 3

    history_after_second = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history_after_second.status_code == 200
    second_items = history_after_second.json()

    assert len(second_items) == 2
    assert [item["version"] for item in second_items] == [1, 2]

def test_workflow_history_snapshot_preserves_previous_configuration(client):
    ensure_setup(client)

    initial = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert initial.status_code == 200
    assert initial.json()["version"] == 1

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
    assert updated.json()["version"] == 2

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert len(items) == 1

    snapshot = items[0]

    assert snapshot["tenant_id"] == "tenant-demo"
    assert snapshot["version"] == 1
    assert snapshot["include_risk_step"] is False
    assert snapshot["include_policy_step"] is True
    assert snapshot["execution_mode"] == "policy_first"
    assert snapshot["created_at"] is not None

def test_workflow_history_preserves_each_version_configuration(client):
    ensure_setup(client)

    payloads = [
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    ]

    for expected_version, payload in enumerate(payloads, start=1):
        response = client.put(
            "/admin/workflow-config",
            headers=ADMIN_HEADERS,
            json=payload,
        )

        assert response.status_code == 200
        assert response.json()["version"] == expected_version

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert len(items) == 2

    v1 = items[0]
    v2 = items[1]

    assert v1["version"] == 1
    assert v1["include_risk_step"] is True
    assert v1["include_policy_step"] is False
    assert v1["execution_mode"] == "risk_first"

    assert v2["version"] == 2
    assert v2["include_risk_step"] is False
    assert v2["include_policy_step"] is True
    assert v2["execution_mode"] == "policy_first"

def test_workflow_history_versions_remain_consecutive_without_duplicates(client):
    ensure_setup(client)

    payloads = [
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
        {
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": False,
            "execution_mode": "policy_first",
        },
    ]

    for expected_version, payload in enumerate(payloads, start=1):
        response = client.put(
            "/admin/workflow-config",
            headers=ADMIN_HEADERS,
            json=payload,
        )

        assert response.status_code == 200
        assert response.json()["version"] == expected_version

    history = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()
    versions = [item["version"] for item in items]

    assert versions == [1, 2, 3]
    assert len(versions) == len(set(versions))

    active = client.get(
        "/admin/workflow-config/tenant-demo",
        headers=ADMIN_HEADERS,
    )

    assert active.status_code == 200
    assert active.json()["version"] == 4

def test_workflow_history_snapshot_remains_unchanged_after_later_updates(client):
    ensure_setup(client)

    initial = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert initial.status_code == 200
    assert initial.json()["version"] == 1

    first_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert first_update.status_code == 200
    assert first_update.json()["version"] == 2

    history_before = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history_before.status_code == 200
    before_items = history_before.json()
    assert len(before_items) == 1

    original_v1 = before_items[0].copy()

    second_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": False,
            "execution_mode": "policy_first",
        },
    )

    assert second_update.status_code == 200
    assert second_update.json()["version"] == 3

    third_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert third_update.status_code == 200
    assert third_update.json()["version"] == 4

    history_after = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history_after.status_code == 200
    after_items = history_after.json()

    v1_after = next(
        item for item in after_items
        if item["version"] == 1
    )

    assert v1_after == original_v1
    assert v1_after["created_at"] == original_v1["created_at"]

def test_workflow_history_snapshot_id_remains_stable_after_later_updates(client):
    ensure_setup(client)

    initial = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": False,
            "execution_mode": "risk_first",
        },
    )

    assert initial.status_code == 200
    assert initial.json()["version"] == 1

    first_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )

    assert first_update.status_code == 200
    assert first_update.json()["version"] == 2

    history_before = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history_before.status_code == 200

    v1_before = next(
        item for item in history_before.json()
        if item["version"] == 1
    )

    original_id = v1_before["id"]

    second_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )

    assert second_update.status_code == 200
    assert second_update.json()["version"] == 3

    third_update = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": False,
            "execution_mode": "policy_first",
        },
    )

    assert third_update.status_code == 200
    assert third_update.json()["version"] == 4

    history_after = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers=ADMIN_HEADERS,
    )

    assert history_after.status_code == 200

    v1_after = next(
        item for item in history_after.json()
        if item["version"] == 1
    )

    assert v1_after["id"] == original_id

def test_workflow_history_requires_admin_authentication(client):
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

    response = client.get(
        "/admin/workflow-config/tenant-demo/history",
    )

    assert response.status_code == 401

def test_workflow_history_rejects_invalid_admin_api_key(client):
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

    response = client.get(
        "/admin/workflow-config/tenant-demo/history",
        headers={"X-Admin-Api-Key": "wrong-admin-key"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"

def test_policy_history_requires_admin_authentication(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "policy-history-auth-test",
            "effect": "allow",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "enabled": True,
        },
    )

    assert created.status_code == 200

    policy_id = created.json()["id"]

    response = client.get(
        f"/admin/policies/{policy_id}/history",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"

def test_policy_history_exposes_temporal_fields(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "policy-history-temporal-fields",
            "effect": "allow",
            "priority": 1,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "enabled": True,
            "valid_from": "2026-08-01T00:00:00",
            "expires_at": "2026-12-31T23:59:59",
        },
    )

    assert created.status_code == 200

    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "priority": 2,
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

    snapshot = items[0]

    assert snapshot["version"] == 1
    assert snapshot["valid_from"] is not None
    assert snapshot["expires_at"] is not None
    assert snapshot["created_at"] is not None

def test_policy_history_remains_readable_after_policy_deletion(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "deleted-policy-history",
            "effect": "deny",
            "priority": 10,
            "request_types": ["access"],
            "countries": ["EE"],
            "device_ids": ["gate-A1"],
            "enabled": True,
        },
    )

    assert created.status_code == 200

    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"priority": 20},
    )

    assert updated.status_code == 200
    assert updated.json()["version"] == 2

    deleted = client.delete(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
    )

    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    history = client.get(
        f"/admin/policies/{policy_id}/history",
        headers=ADMIN_HEADERS,
    )

    assert history.status_code == 200

    items = history.json()

    assert [item["version"] for item in items] == [1, 2]
    assert items[0]["policy_id"] == policy_id
    assert items[1]["policy_id"] == policy_id
    assert items[0]["policy_name"] == "deleted-policy-history"
    assert items[1]["policy_name"] == "deleted-policy-history"

def test_admin_audit_logs_filter_tenant_before_limit(client):
    ensure_setup(client)

    from tests.test_smoke import OTHER_HEADERS

    tenant_demo_token = issue_token(client).json()["token"]
    demo_response = access_request(client, tenant_demo_token)

    assert demo_response.status_code == 200

    valid_right = client.post(
        "/rights/create",
        headers=OTHER_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "right_id": "right-778",
            "owner_id": "user-777",
            "valid": True,
        },
    )
    assert valid_right.status_code == 200

    for i in range(5):
        token_response = client.post(
            "/token/issue",
            headers=OTHER_HEADERS,
            json={
                "tenant_id": "tenant-other",
                "right_id": "right-778",
                "user_id": "user-777",
                "device_id": "gate-X1",
                "scope": "access",
            },
        )
        assert token_response.status_code == 200

        other_token = token_response.json()["token"]

        other_response = client.post(
            "/request/access",
            headers=OTHER_HEADERS,
            json={
                "token": other_token,
                "request_type": "access",
                "device_id": "gate-X1",
                "ip_address": f"10.0.1.{i + 1}",
                "country_code": "EE",
            },
        )
        assert other_response.status_code == 200
    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 1,
        },
    )

    assert response.status_code == 200

    items = response.json()

    assert len(items) == 1
    assert items[0]["tenant_id"] == "tenant-demo"

def test_admin_audit_logs_requires_admin_authentication(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"

def test_admin_audit_log_count_requires_admin_authentication(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"

def test_replay_requires_admin_authentication(client):
    ensure_setup(client)

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

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
    )

    assert replay.status_code == 401
    assert replay.json()["detail"] == "invalid_admin"

def test_replay_rejects_invalid_admin_api_key(client):
    ensure_setup(client)

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

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers={"X-Admin-Api-Key": "wrong-admin-key"},
    )

    assert replay.status_code == 401
    assert replay.json()["detail"] == "invalid_admin"

def test_replay_returns_404_for_zero_log_id(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/0/replay",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "request_log_not_found"


def test_replay_returns_404_for_negative_log_id(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/-1/replay",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "request_log_not_found"


def test_replay_rejects_non_integer_log_id(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/not-a-number/replay",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 422


def test_replay_rejects_post_method(client):
    ensure_setup(client)

    response = client.post(
        "/admin/audit/logs/1/replay",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 405


def test_replay_rejects_delete_method(client):
    ensure_setup(client)

    response = client.delete(
        "/admin/audit/logs/1/replay",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 405

def test_admin_audit_logs_normalizes_zero_limit_to_one(client):
    ensure_setup(client)

    for _ in range(2):
        token = issue_token(client).json()["token"]
        response = access_request(client, token)
        assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 0,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) == 1


def test_admin_audit_logs_normalizes_negative_limit_to_one(client):
    ensure_setup(client)

    for _ in range(2):
        token = issue_token(client).json()["token"]
        response = access_request(client, token)
        assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": -10,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) == 1


def test_admin_audit_logs_normalizes_negative_offset_to_zero(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    trace_id = response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": 1,
            "offset": -10,
        },
    )

    assert audit.status_code == 200

    items = audit.json()

    assert len(items) == 1
    assert items[0]["trace_id"] == trace_id


def test_admin_audit_logs_rejects_non_integer_limit(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "limit": "invalid",
        },
    )

    assert response.status_code == 422


def test_admin_audit_logs_rejects_non_integer_offset(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "offset": "invalid",
        },
    )

    assert response.status_code == 422

def test_admin_audit_log_count_filters_by_tenant(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] >= 1


def test_admin_audit_log_count_filters_by_policy_name(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_name": "policy-that-does-not-exist",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_admin_audit_log_count_filters_by_policy_version(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 999999,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_admin_audit_log_count_filters_by_min_risk_score(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "min_risk_score": 101,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_admin_audit_log_count_filters_by_risk_signal(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "signal-that-does-not-exist",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0

def test_admin_audit_log_count_filters_by_from_time(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2999-01-01T00:00:00",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_admin_audit_log_count_filters_by_to_time(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "to_time": "2000-01-01T00:00:00",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_admin_audit_log_count_filters_by_time_range(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2020-01-01T00:00:00",
            "to_time": "2999-01-01T00:00:00",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] >= 1


def test_admin_audit_log_count_combines_tenant_and_allowed_filters(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200

    expected_allowed = response.json()["allow"]

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "allowed": expected_allowed,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] >= 1


def test_admin_audit_log_count_combines_filters_with_no_match(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "allowed": True,
            "policy_name": "policy-that-does-not-exist",
            "min_risk_score": 101,
            "risk_signal": "signal-that-does-not-exist",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0

def test_admin_audit_log_count_rejects_invalid_allowed(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "allowed": "not-a-boolean",
        },
    )

    assert response.status_code == 422


def test_admin_audit_log_count_rejects_invalid_policy_version(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": "not-an-integer",
        },
    )

    assert response.status_code == 422


def test_admin_audit_log_count_rejects_invalid_min_risk_score(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "min_risk_score": "not-an-integer",
        },
    )

    assert response.status_code == 422


def test_admin_audit_log_count_rejects_invalid_from_time(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "not-a-datetime",
        },
    )

    assert response.status_code == 422


def test_admin_audit_log_count_rejects_invalid_to_time(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "to_time": "not-a-datetime",
        },
    )

    assert response.status_code == 422

def test_list_policies_requires_admin_authentication(client):
    ensure_setup(client)

    response = client.get(
        "/admin/policies",
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_list_policies_rejects_invalid_admin_api_key(client):
    ensure_setup(client)

    response = client.get(
        "/admin/policies",
        headers={"X-Admin-Api-Key": "wrong-admin-key"},
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_list_policies_isolates_tenants(client):
    ensure_setup(client)

    demo_policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "demo-isolation-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )
    assert demo_policy.status_code == 200

    other_policy = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-other",
            "name": "other-isolation-policy",
            "effect": "deny",
            "priority": 20,
            "request_types": ["access"],
            "enabled": True,
        },
    )
    assert other_policy.status_code == 200

    response = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 200

    items = response.json()
    names = [item["name"] for item in items]

    assert "demo-isolation-policy" in names
    assert "other-isolation-policy" not in names
    assert all(item["tenant_id"] == "tenant-demo" for item in items)


def test_list_policies_orders_by_priority_ascending(client):
    ensure_setup(client)

    high_priority = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "priority-80-policy",
            "effect": "allow",
            "priority": 80,
            "request_types": ["access"],
            "enabled": True,
        },
    )
    assert high_priority.status_code == 200

    low_priority = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "priority-10-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )
    assert low_priority.status_code == 200

    response = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 200

    relevant = [
        item
        for item in response.json()
        if item["name"] in {
            "priority-80-policy",
            "priority-10-policy",
        }
    ]

    assert [item["name"] for item in relevant] == [
        "priority-10-policy",
        "priority-80-policy",
    ]


def test_list_policies_excludes_deleted_policy(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "deleted-list-policy",
            "effect": "allow",
            "priority": 15,
            "request_types": ["access"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    deleted = client.delete(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
    )

    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    response = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )

    assert response.status_code == 200

    ids = [item["id"] for item in response.json()]

    assert policy_id not in ids

def test_create_policy_requires_admin_authentication(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        json={
            "tenant_id": "tenant-demo",
            "name": "unauthorized-create-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_create_policy_rejects_invalid_admin_api_key(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers={"X-Admin-Api-Key": "wrong-admin-key"},
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-admin-create-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_update_policy_requires_admin_authentication(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "unauthorized-update-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        json={"priority": 20},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_update_policy_rejects_invalid_admin_api_key(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-admin-update-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers={"X-Admin-Api-Key": "wrong-admin-key"},
        json={"priority": 20},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_delete_policy_requires_admin_authentication(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "unauthorized-delete-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.delete(
        f"/admin/policies/{policy_id}",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"

def test_delete_missing_policy_returns_404(client):
    ensure_setup(client)

    response = client.delete(
        "/admin/policies/999999",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "policy_not_found"


def test_update_policy_rejects_non_integer_policy_id(client):
    ensure_setup(client)

    response = client.patch(
        "/admin/policies/not-an-integer",
        headers=ADMIN_HEADERS,
        json={"enabled": False},
    )

    assert response.status_code == 422


def test_delete_policy_rejects_non_integer_policy_id(client):
    ensure_setup(client)

    response = client.delete(
        "/admin/policies/not-an-integer",
        headers=ADMIN_HEADERS,
    )

    assert response.status_code == 422


def test_delete_policy_rejects_invalid_admin_api_key(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-admin-delete-policy",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access"],
            "enabled": True,
        },
    )

    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.delete(
        f"/admin/policies/{policy_id}",
        headers={"X-Admin-Api-Key": "wrong-admin-key"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_delete_missing_policy_requires_admin_before_lookup(client):
    ensure_setup(client)

    response = client.delete(
        "/admin/policies/999999",
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"

def test_admin_policy_simulation_requires_admin_authentication(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_admin_policy_simulation_rejects_invalid_admin_api_key(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers={"X-Admin-Api-Key": "wrong-admin-key"},
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "invalid_admin"


def test_admin_policy_simulation_requires_tenant_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_requires_request_type(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_invalid_risk_score_type(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": "not-a-number",
        },
    )

    assert response.status_code == 422

def test_admin_policy_simulation_requires_device_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_requires_country_code(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_invalid_trust_score_type(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "trust_score": "not-a-number",
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_invalid_transaction_amount_type(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "transaction_amount": "not-a-number",
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_invalid_hour_type(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "hour": "not-a-number",
        },
    )

    assert response.status_code == 422

def test_admin_policy_simulation_rejects_negative_risk_score(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": -1,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_risk_score_above_one_hundred(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 101,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_negative_trust_score(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "trust_score": -1,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_trust_score_above_one_hundred(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "trust_score": 101,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_hour_above_twenty_three(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "hour": 24,
        },
    )

    assert response.status_code == 422

def test_admin_policy_simulation_rejects_negative_transaction_amount(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
            "transaction_amount": -1.0,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_empty_tenant_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_empty_request_type(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_empty_device_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_empty_country_code(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422

def test_admin_policy_simulation_rejects_whitespace_tenant_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "   ",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_whitespace_request_type(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "   ",
            "device_id": "gate-A1",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_whitespace_device_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "   ",
            "country_code": "EE",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_country_code_too_short(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "E",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422


def test_admin_policy_simulation_rejects_country_code_too_long(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies/simulate",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "request_type": "access",
            "device_id": "gate-A1",
            "country_code": "ABCDEFGHI",
            "risk_score": 10,
        },
    )

    assert response.status_code == 422

def test_create_policy_rejects_negative_max_risk_score(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-negative-risk",
            "effect": "allow",
            "max_risk_score": -1,
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_max_risk_score_above_one_hundred(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-high-risk",
            "effect": "allow",
            "max_risk_score": 101,
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_negative_min_trust_score(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-negative-trust",
            "effect": "allow",
            "min_trust_score": -1,
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_min_trust_score_above_one_hundred(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-high-trust",
            "effect": "allow",
            "min_trust_score": 101,
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_allowed_start_hour_above_twenty_three(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-start-hour",
            "effect": "allow",
            "allowed_start_hour": 24,
        },
    )

    assert response.status_code == 422

def test_create_policy_rejects_negative_allowed_start_hour(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "negative-start-hour-policy",
            "effect": "allow",
            "allowed_start_hour": -1,
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_negative_allowed_end_hour(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "negative-end-hour-policy",
            "effect": "allow",
            "allowed_end_hour": -1,
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_allowed_end_hour_above_twenty_three(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "high-end-hour-policy",
            "effect": "allow",
            "allowed_end_hour": 24,
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_negative_max_transaction_amount(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "negative-transaction-limit-policy",
            "effect": "allow",
            "max_transaction_amount": -1,
        },
    )

    assert response.status_code == 422


def test_create_policy_accepts_boundary_values(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "boundary-values-policy",
            "effect": "allow",
            "max_risk_score": 0,
            "min_trust_score": 100,
            "max_transaction_amount": 0,
            "allowed_start_hour": 0,
            "allowed_end_hour": 23,
        },
    )

    assert response.status_code == 200

    body = response.json()
    assert body["max_risk_score"] == 0
    assert body["min_trust_score"] == 100
    assert body["max_transaction_amount"] == 0
    assert body["allowed_start_hour"] == 0
    assert body["allowed_end_hour"] == 23

def test_update_policy_rejects_negative_max_risk_score(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-negative-risk-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"max_risk_score": -1},
    )

    assert response.status_code == 422


def test_update_policy_rejects_max_risk_score_above_one_hundred(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-high-risk-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"max_risk_score": 101},
    )

    assert response.status_code == 422


def test_update_policy_rejects_negative_min_trust_score(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-negative-trust-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"min_trust_score": -1},
    )

    assert response.status_code == 422


def test_update_policy_rejects_min_trust_score_above_one_hundred(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-high-trust-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"min_trust_score": 101},
    )

    assert response.status_code == 422


def test_update_policy_rejects_negative_max_transaction_amount(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-negative-transaction-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"max_transaction_amount": -1},
    )

    assert response.status_code == 422

def test_update_policy_rejects_negative_allowed_start_hour(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-negative-start-hour-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"allowed_start_hour": -1},
    )

    assert response.status_code == 422


def test_update_policy_rejects_allowed_start_hour_above_twenty_three(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-high-start-hour-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"allowed_start_hour": 24},
    )

    assert response.status_code == 422


def test_update_policy_rejects_negative_allowed_end_hour(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-negative-end-hour-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"allowed_end_hour": -1},
    )

    assert response.status_code == 422


def test_update_policy_rejects_allowed_end_hour_above_twenty_three(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-high-end-hour-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"allowed_end_hour": 24},
    )

    assert response.status_code == 422


def test_update_policy_accepts_boundary_values(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-boundary-values-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "max_risk_score": 0,
            "min_trust_score": 100,
            "max_transaction_amount": 0,
            "allowed_start_hour": 0,
            "allowed_end_hour": 23,
        },
    )

    assert response.status_code == 200

    body = response.json()
    assert body["max_risk_score"] == 0
    assert body["min_trust_score"] == 100
    assert body["max_transaction_amount"] == 0
    assert body["allowed_start_hour"] == 0
    assert body["allowed_end_hour"] == 23

def test_create_policy_rejects_empty_name(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "",
            "effect": "allow",
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_whitespace_name(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "   ",
            "effect": "allow",
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_empty_request_type_item(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-request-type-item",
            "effect": "allow",
            "request_types": [""],
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_whitespace_country_item(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-country-item",
            "effect": "allow",
            "countries": ["   "],
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_empty_device_id_item(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-device-item",
            "effect": "allow",
            "device_ids": [""],
        },
    )

    assert response.status_code == 422

def test_update_policy_rejects_empty_request_type_item(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-empty-request-type-item",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"request_types": [""]},
    )

    assert response.status_code == 422


def test_update_policy_rejects_whitespace_request_type_item(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-whitespace-request-type-item",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"request_types": ["   "]},
    )

    assert response.status_code == 422


def test_update_policy_rejects_empty_country_item(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-empty-country-item",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"countries": [""]},
    )

    assert response.status_code == 422


def test_update_policy_rejects_whitespace_country_item(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-whitespace-country-item",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"countries": ["   "]},
    )

    assert response.status_code == 422


def test_update_policy_rejects_empty_device_id_item(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-empty-device-id-item",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"device_ids": [""]},
    )

    assert response.status_code == 422

def test_create_policy_rejects_empty_tenant_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "",
            "name": "empty-tenant-policy",
            "effect": "allow",
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_whitespace_tenant_id(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "   ",
            "name": "whitespace-tenant-policy",
            "effect": "allow",
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_whitespace_request_type_item(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "whitespace-request-type-policy",
            "effect": "allow",
            "request_types": ["   "],
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_empty_country_item(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "empty-country-policy",
            "effect": "allow",
            "countries": [""],
        },
    )

    assert response.status_code == 422


def test_create_policy_rejects_whitespace_device_id_item(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "whitespace-device-policy",
            "effect": "allow",
            "device_ids": ["   "],
        },
    )

    assert response.status_code == 422

def test_create_policy_rejects_valid_from_after_expires_at(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "invalid-policy-window",
            "effect": "allow",
            "valid_from": "2026-09-02T12:00:00",
            "expires_at": "2026-09-01T12:00:00",
        },
    )

    assert response.status_code == 422


def test_create_policy_accepts_equal_valid_from_and_expires_at(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "equal-policy-window",
            "effect": "allow",
            "valid_from": "2026-09-01T12:00:00",
            "expires_at": "2026-09-01T12:00:00",
        },
    )

    assert response.status_code == 200


def test_update_policy_rejects_valid_from_after_existing_expires_at(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-invalid-valid-from-window",
            "effect": "allow",
            "valid_from": "2026-09-01T12:00:00",
            "expires_at": "2026-09-10T12:00:00",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-11T12:00:00",
        },
    )

    assert response.status_code == 422


def test_update_policy_rejects_expires_at_before_existing_valid_from(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-invalid-expires-window",
            "effect": "allow",
            "valid_from": "2026-09-05T12:00:00",
            "expires_at": "2026-09-10T12:00:00",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "expires_at": "2026-09-04T12:00:00",
        },
    )

    assert response.status_code == 422


def test_update_policy_accepts_equal_valid_from_and_expires_at(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-equal-policy-window",
            "effect": "allow",
            "valid_from": "2026-09-01T12:00:00",
            "expires_at": "2026-09-10T12:00:00",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-10T12:00:00",
        },
    )

    assert response.status_code == 200

def test_create_policy_normalizes_utc_z_valid_from_to_naive_utc(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "timezone-z-valid-from-policy",
            "effect": "allow",
            "valid_from": "2026-09-01T12:00:00Z",
        },
    )

    assert response.status_code == 200
    policy_id = response.json()["id"]

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert listed.status_code == 200

    policy = next(item for item in listed.json() if item["id"] == policy_id)
    assert policy["valid_from"] == "2026-09-01T12:00:00"


def test_create_policy_normalizes_positive_offset_valid_from_to_naive_utc(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "timezone-positive-offset-policy",
            "effect": "allow",
            "valid_from": "2026-09-01T15:00:00+03:00",
        },
    )

    assert response.status_code == 200
    policy_id = response.json()["id"]

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert listed.status_code == 200

    policy = next(item for item in listed.json() if item["id"] == policy_id)
    assert policy["valid_from"] == "2026-09-01T12:00:00"

def test_create_policy_normalizes_negative_offset_expires_at_to_naive_utc(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "timezone-negative-offset-policy",
            "effect": "allow",
            "expires_at": "2026-09-01T08:00:00-04:00",
        },
    )

    assert response.status_code == 200
    policy_id = response.json()["id"]

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert listed.status_code == 200

    policy = next(item for item in listed.json() if item["id"] == policy_id)
    assert policy["expires_at"] == "2026-09-01T12:00:00"


def test_create_policy_compares_mixed_timezone_window_after_normalization(client):
    ensure_setup(client)

    response = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "mixed-timezone-window-policy",
            "effect": "allow",
            "valid_from": "2026-09-01T15:00:00+03:00",
            "expires_at": "2026-09-01T12:30:00Z",
        },
    )

    assert response.status_code == 200
    policy_id = response.json()["id"]

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert listed.status_code == 200

    policy = next(item for item in listed.json() if item["id"] == policy_id)

    assert policy["valid_from"] == "2026-09-01T12:00:00"
    assert policy["expires_at"] == "2026-09-01T12:30:00"


def test_update_policy_normalizes_timezone_offset_to_naive_utc(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-timezone-policy",
            "effect": "allow",
            "valid_from": "2026-09-01T10:00:00",
            "expires_at": "2026-09-10T12:00:00",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-01T15:00:00+03:00",
        },
    )

    assert response.status_code == 200

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert listed.status_code == 200

    policy = next(item for item in listed.json() if item["id"] == policy_id)
    assert policy["valid_from"] == "2026-09-01T12:00:00"

def test_update_policy_normalizes_negative_timezone_offset_to_naive_utc(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-negative-offset-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"valid_from": "2026-09-01T09:00:00-03:00"},
    )
    assert response.status_code == 200

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert listed.status_code == 200

    policy = next(item for item in listed.json() if item["id"] == policy_id)
    assert policy["valid_from"] == "2026-09-01T12:00:00"


def test_update_policy_normalizes_utc_z_expires_at_to_naive_utc(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-z-expires-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"expires_at": "2026-09-10T12:00:00Z"},
    )
    assert response.status_code == 200

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert listed.status_code == 200

    policy = next(item for item in listed.json() if item["id"] == policy_id)
    assert policy["expires_at"] == "2026-09-10T12:00:00"


def test_update_policy_accepts_mixed_timezone_window_after_normalization(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-mixed-window-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-01T15:00:00+03:00",
            "expires_at": "2026-09-01T12:30:00Z",
        },
    )
    assert response.status_code == 200

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    policy = next(item for item in listed.json() if item["id"] == policy_id)

    assert policy["valid_from"] == "2026-09-01T12:00:00"
    assert policy["expires_at"] == "2026-09-01T12:30:00"


def test_update_policy_rejects_timezone_window_invalid_after_normalization(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-invalid-offset-window-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-01T15:00:00+03:00",
            "expires_at": "2026-09-01T11:59:59Z",
        },
    )

    assert response.status_code == 422


def test_update_policy_accepts_equal_instants_with_different_timezones(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "update-equal-offset-window-policy",
            "effect": "allow",
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    response = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-01T15:00:00+03:00",
            "expires_at": "2026-09-01T12:00:00Z",
        },
    )

    assert response.status_code == 200

    listed = client.get(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    policy = next(item for item in listed.json() if item["id"] == policy_id)

    assert policy["valid_from"] == "2026-09-01T12:00:00"
    assert policy["expires_at"] == "2026-09-01T12:00:00"

def test_load_tenant_policies_loads_only_enabled_policies():
    with SessionLocal() as db:
        enabled = PolicyRecord(
            tenant_id="tenant-loader-enabled",
            name="enabled-policy",
            effect="allow",
            priority=10,
            request_types="access",
            countries="EE",
            device_ids="gate-A1",
            enabled=True,
        )
        disabled = PolicyRecord(
            tenant_id="tenant-loader-enabled",
            name="disabled-policy",
            effect="deny",
            priority=100,
            request_types="access",
            countries="EE",
            device_ids="gate-A1",
            enabled=False,
        )
        db.add_all([enabled, disabled])
        db.commit()

        engine = load_tenant_policies(db, "tenant-loader-enabled")

        assert len(engine.policies) == 1
        assert engine.policies[0].name == "enabled-policy"


def test_load_tenant_policies_isolates_tenants():
    with SessionLocal() as db:
        db.add_all(
            [
                PolicyRecord(
                    tenant_id="tenant-loader-a",
                    name="tenant-a-policy",
                    effect="allow",
                    priority=10,
                    request_types="access",
                    countries="EE",
                    device_ids="",
                    enabled=True,
                ),
                PolicyRecord(
                    tenant_id="tenant-loader-b",
                    name="tenant-b-policy",
                    effect="deny",
                    priority=100,
                    request_types="access",
                    countries="EE",
                    device_ids="",
                    enabled=True,
                ),
            ]
        )
        db.commit()

        engine = load_tenant_policies(db, "tenant-loader-a")

        assert len(engine.policies) == 1
        assert engine.policies[0].name == "tenant-a-policy"


def test_load_tenant_policies_normalizes_csv_fields():
    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-loader-csv",
                name="csv-policy",
                effect="allow",
                priority=10,
                request_types=" access, ,ownership_transfer, ",
                countries=" EE, FI, ,",
                device_ids=" gate-A1, ,gate-B2 ",
                enabled=True,
            )
        )
        db.commit()

        engine = load_tenant_policies(db, "tenant-loader-csv")
        policy = engine.policies[0]

        assert policy.request_types == ("access", "ownership_transfer")
        assert policy.countries == ("EE", "FI")
        assert policy.device_ids == ("gate-A1", "gate-B2")


def test_load_tenant_policies_preserves_policy_constraints():
    with SessionLocal() as db:
        db.add(
            PolicyRecord(
                tenant_id="tenant-loader-constraints",
                name="constraint-policy",
                effect="deny",
                priority=42,
                version=3,
                request_types="ownership_transfer",
                countries="FI",
                device_ids="gate-Z9",
                max_risk_score=75,
                min_trust_score=25,
                max_transaction_amount=500.0,
                allowed_start_hour=8,
                allowed_end_hour=18,
                enabled=True,
            )
        )
        db.commit()

        engine = load_tenant_policies(db, "tenant-loader-constraints")
        policy = engine.policies[0]

        assert policy.effect == "deny"
        assert policy.priority == 42
        assert policy.version == 3
        assert policy.max_risk_score == 75
        assert policy.min_trust_score == 25
        assert policy.max_transaction_amount == 500.0
        assert policy.allowed_start_hour == 8
        assert policy.allowed_end_hour == 18


def test_load_tenant_policies_preserves_priority_order():
    with SessionLocal() as db:
        db.add_all(
            [
                PolicyRecord(
                    tenant_id="tenant-loader-order",
                    name="lower-priority",
                    effect="allow",
                    priority=100,
                    request_types="access",
                    countries="EE",
                    device_ids="",
                    enabled=True,
                ),
                PolicyRecord(
                    tenant_id="tenant-loader-order",
                    name="higher-priority",
                    effect="deny",
                    priority=10,
                    request_types="access",
                    countries="EE",
                    device_ids="",
                    enabled=True,
                ),
            ]
        )
        db.commit()

        engine = load_tenant_policies(db, "tenant-loader-order")

        assert [policy.name for policy in engine.policies] == [
            "higher-priority",
            "lower-priority",
        ]

def test_load_policy_version_restores_historical_request_types(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-request-types",
            "effect": "allow",
            "priority": 10,
            "request_types": ["access", "ownership_transfer"],
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"request_types": ["access"]},
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.request_types == ("access", "ownership_transfer")


def test_load_policy_version_restores_historical_countries(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-countries",
            "effect": "allow",
            "priority": 10,
            "countries": ["EE", "FI"],
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"countries": ["SE"]},
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.countries == ("EE", "FI")


def test_load_policy_version_restores_historical_device_ids(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-device-ids",
            "effect": "allow",
            "priority": 10,
            "device_ids": ["gate-A1", "gate-B2"],
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"device_ids": ["gate-C3"]},
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.device_ids == ("gate-A1", "gate-B2")


def test_load_policy_version_restores_historical_risk_and_trust_limits(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-risk-trust",
            "effect": "deny",
            "priority": 10,
            "max_risk_score": 60,
            "min_trust_score": 40,
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "max_risk_score": 80,
            "min_trust_score": 20,
        },
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.max_risk_score == 60
    assert version_1.min_trust_score == 40


def test_load_policy_version_restores_historical_business_hours(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-business-hours",
            "effect": "allow",
            "priority": 10,
            "allowed_start_hour": 8,
            "allowed_end_hour": 18,
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "allowed_start_hour": 22,
            "allowed_end_hour": 6,
        },
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.allowed_start_hour == 8
    assert version_1.allowed_end_hour == 18

def test_load_policy_version_restores_historical_effect(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-effect",
            "effect": "allow",
            "priority": 10,
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"effect": "deny"},
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)
        version_2 = load_policy_version(db, "tenant-demo", policy_id, 2)

    assert version_1 is not None
    assert version_2 is not None
    assert version_1.effect == "allow"
    assert version_2.effect == "deny"


def test_load_policy_version_restores_historical_valid_from(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-valid-from",
            "effect": "allow",
            "priority": 10,
            "valid_from": "2026-09-01T08:00:00Z",
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"valid_from": "2026-09-02T08:00:00Z"},
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.valid_from == datetime(2026, 9, 1, 8, 0, 0)


def test_load_policy_version_restores_historical_expires_at(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-expires-at",
            "effect": "allow",
            "priority": 10,
            "expires_at": "2026-09-10T18:00:00Z",
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={"expires_at": "2026-09-11T18:00:00Z"},
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.expires_at == datetime(2026, 9, 10, 18, 0, 0)


def test_load_policy_version_restores_historical_temporal_window(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-temporal-window",
            "effect": "allow",
            "priority": 10,
            "valid_from": "2026-09-01T08:00:00Z",
            "expires_at": "2026-09-10T18:00:00Z",
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-02T08:00:00Z",
            "expires_at": "2026-09-12T18:00:00Z",
        },
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        version_1 = load_policy_version(db, "tenant-demo", policy_id, 1)

    assert version_1 is not None
    assert version_1.valid_from == datetime(2026, 9, 1, 8, 0, 0)
    assert version_1.expires_at == datetime(2026, 9, 10, 18, 0, 0)


def test_load_policy_version_current_and_history_keep_separate_temporal_values(client):
    ensure_setup(client)

    created = client.post(
        "/admin/policies",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "name": "history-current-temporal-parity",
            "effect": "allow",
            "priority": 10,
            "valid_from": "2026-09-01T08:00:00Z",
            "expires_at": "2026-09-10T18:00:00Z",
            "enabled": True,
        },
    )
    assert created.status_code == 200
    policy_id = created.json()["id"]

    updated = client.patch(
        f"/admin/policies/{policy_id}",
        headers=ADMIN_HEADERS,
        json={
            "valid_from": "2026-09-03T09:00:00Z",
            "expires_at": "2026-09-15T20:00:00Z",
        },
    )
    assert updated.status_code == 200

    with SessionLocal() as db:
        historical = load_policy_version(db, "tenant-demo", policy_id, 1)
        current = load_policy_version(db, "tenant-demo", policy_id, 2)

    assert historical is not None
    assert current is not None

    assert historical.valid_from == datetime(2026, 9, 1, 8, 0, 0)
    assert historical.expires_at == datetime(2026, 9, 10, 18, 0, 0)

    assert current.valid_from == datetime(2026, 9, 3, 9, 0, 0)
    assert current.expires_at == datetime(2026, 9, 15, 20, 0, 0)

def test_load_policy_version_normalizes_historical_request_types(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyHistory(
                policy_id=475001,
                tenant_id="tenant-demo",
                policy_name="legacy-request-types",
                version=1,
                effect="allow",
                priority=10,
                request_types=" access, ,ownership_transfer, ",
                countries="",
                device_ids="",
            )
        )
        db.commit()

        policy = load_policy_version(db, "tenant-demo", 475001, 1)

    assert policy is not None
    assert policy.request_types == ("access", "ownership_transfer")


def test_load_policy_version_normalizes_historical_countries(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyHistory(
                policy_id=476001,
                tenant_id="tenant-demo",
                policy_name="legacy-countries",
                version=1,
                effect="allow",
                priority=10,
                request_types="",
                countries=" EE, FI, ,SE ",
                device_ids="",
            )
        )
        db.commit()

        policy = load_policy_version(db, "tenant-demo", 476001, 1)

    assert policy is not None
    assert policy.countries == ("EE", "FI", "SE")


def test_load_policy_version_normalizes_historical_device_ids(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyHistory(
                policy_id=477001,
                tenant_id="tenant-demo",
                policy_name="legacy-device-ids",
                version=1,
                effect="allow",
                priority=10,
                request_types="",
                countries="",
                device_ids=" gate-A1, ,gate-B2, ",
            )
        )
        db.commit()

        policy = load_policy_version(db, "tenant-demo", 477001, 1)

    assert policy is not None
    assert policy.device_ids == ("gate-A1", "gate-B2")


def test_load_policy_version_normalizes_all_historical_csv_fields(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyHistory(
                policy_id=478001,
                tenant_id="tenant-demo",
                policy_name="legacy-all-csv",
                version=1,
                effect="deny",
                priority=5,
                request_types=" access, ,ownership_transfer ",
                countries=" EE, ,FI ",
                device_ids=" gate-A1, ,gate-B2 ",
            )
        )
        db.commit()

        policy = load_policy_version(db, "tenant-demo", 478001, 1)

    assert policy is not None
    assert policy.request_types == ("access", "ownership_transfer")
    assert policy.countries == ("EE", "FI")
    assert policy.device_ids == ("gate-A1", "gate-B2")


def test_load_policy_version_historical_empty_csv_fields_become_empty_tuples(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            PolicyHistory(
                policy_id=479001,
                tenant_id="tenant-demo",
                policy_name="legacy-empty-csv",
                version=1,
                effect="allow",
                priority=10,
                request_types=" , , ",
                countries="",
                device_ids="   ",
            )
        )
        db.commit()

        policy = load_policy_version(db, "tenant-demo", 479001, 1)

    assert policy is not None
    assert policy.request_types == ()
    assert policy.countries == ()
    assert policy.device_ids == ()

def test_save_policy_history_preserves_identity_fields(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="snapshot-identity",
            effect="deny",
            priority=7,
            version=3,
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        history = (
            db.query(PolicyHistory)
            .filter_by(policy_id=policy_id, version=3)
            .one()
        )

        assert history.policy_id == policy_id
        assert history.tenant_id == "tenant-demo"
        assert history.policy_name == "snapshot-identity"
        assert history.version == 3
        assert history.effect == "deny"
        assert history.priority == 7


def test_save_policy_history_preserves_filter_fields(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="snapshot-filters",
            effect="allow",
            priority=10,
            request_types="access,ownership_transfer",
            countries="EE,FI",
            device_ids="gate-A1,gate-B2",
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        history = (
            db.query(PolicyHistory)
            .filter_by(policy_id=policy_id, version=1)
            .one()
        )

        assert history.request_types == "access,ownership_transfer"
        assert history.countries == "EE,FI"
        assert history.device_ids == "gate-A1,gate-B2"


def test_save_policy_history_preserves_risk_and_transaction_constraints(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="snapshot-constraints",
            effect="allow",
            priority=10,
            max_risk_score=70,
            min_trust_score=30,
            max_transaction_amount=12500.0,
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        history = (
            db.query(PolicyHistory)
            .filter_by(policy_id=policy_id, version=1)
            .one()
        )

        assert history.max_risk_score == 70
        assert history.min_trust_score == 30
        assert history.max_transaction_amount == 12500.0


def test_save_policy_history_preserves_business_hours_and_enabled(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="snapshot-hours",
            effect="allow",
            priority=10,
            allowed_start_hour=22,
            allowed_end_hour=6,
            enabled=False,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        history = (
            db.query(PolicyHistory)
            .filter_by(policy_id=policy_id, version=1)
            .one()
        )

        assert history.allowed_start_hour == 22
        assert history.allowed_end_hour == 6
        assert history.enabled is False


def test_save_policy_history_preserves_temporal_constraints(client):
    ensure_setup(client)

    valid_from = datetime(2026, 9, 1, 8, 0, 0)
    expires_at = datetime(2026, 9, 10, 18, 0, 0)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="snapshot-temporal",
            effect="allow",
            priority=10,
            valid_from=valid_from,
            expires_at=expires_at,
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        history = (
            db.query(PolicyHistory)
            .filter_by(policy_id=policy_id, version=1)
            .one()
        )

        assert history.valid_from == valid_from
        assert history.expires_at == expires_at

def test_policy_history_round_trip_preserves_identity_fields(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="round-trip-identity",
            effect="deny",
            priority=7,
            version=4,
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        restored = load_policy_version(
            db, "tenant-demo", policy_id, 4
        )

    assert restored is not None
    assert restored.policy_id == policy_id
    assert restored.name == "round-trip-identity"
    assert restored.effect == "deny"
    assert restored.priority == 7
    assert restored.version == 4


def test_policy_history_round_trip_preserves_filters(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="round-trip-filters",
            effect="allow",
            priority=10,
            version=2,
            request_types="access,ownership_transfer",
            countries="EE,FI",
            device_ids="gate-A1,gate-B2",
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        restored = load_policy_version(
            db, "tenant-demo", policy_id, 2
        )

    assert restored is not None
    assert restored.request_types == ("access", "ownership_transfer")
    assert restored.countries == ("EE", "FI")
    assert restored.device_ids == ("gate-A1", "gate-B2")


def test_policy_history_round_trip_preserves_numeric_constraints(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="round-trip-constraints",
            effect="allow",
            priority=10,
            version=2,
            max_risk_score=70,
            min_trust_score=30,
            max_transaction_amount=12500.0,
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        restored = load_policy_version(
            db, "tenant-demo", policy_id, 2
        )

    assert restored is not None
    assert restored.max_risk_score == 70
    assert restored.min_trust_score == 30
    assert restored.max_transaction_amount == 12500.0


def test_policy_history_round_trip_preserves_business_hours(client):
    ensure_setup(client)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="round-trip-hours",
            effect="allow",
            priority=10,
            version=2,
            allowed_start_hour=22,
            allowed_end_hour=6,
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        restored = load_policy_version(
            db, "tenant-demo", policy_id, 2
        )

    assert restored is not None
    assert restored.allowed_start_hour == 22
    assert restored.allowed_end_hour == 6


def test_policy_history_round_trip_preserves_temporal_constraints(client):
    ensure_setup(client)

    valid_from = datetime(2026, 9, 1, 8, 0, 0)
    expires_at = datetime(2026, 9, 10, 18, 0, 0)

    with SessionLocal() as db:
        policy = PolicyRecord(
            tenant_id="tenant-demo",
            name="round-trip-temporal",
            effect="allow",
            priority=10,
            version=2,
            valid_from=valid_from,
            expires_at=expires_at,
            enabled=True,
        )
        db.add(policy)
        db.flush()

        policy_id = policy.id
        save_policy_history(db, policy)
        db.commit()

        restored = load_policy_version(
            db, "tenant-demo", policy_id, 2
        )

    assert restored is not None
    assert restored.valid_from == valid_from
    assert restored.expires_at == expires_at

def test_replay_restores_workflow_decision_source(client):
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
    original_source = original.json()["explanation"]["final"]["decision_source"]

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

    replay = client.get(
        f"/admin/audit/logs/{matching[0]['id']}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["replayed"]["decision_source"] == original_source


def test_replay_restores_workflow_decision_path(client):
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
    original_path = original.json()["explanation"]["final"]["decision_path"]

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

    replay = client.get(
        f"/admin/audit/logs/{matching[0]['id']}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["replayed"]["decision_path"] == original_path


def test_replay_restores_policy_first_workflow_path(client):
    ensure_setup(client)

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )
    assert workflow.status_code == 200

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200
    trace_id = original.json()["trace_id"]
    original_final = original.json()["explanation"]["final"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert audit.status_code == 200

    log_id = next(
        item["id"]
        for item in audit.json()
        if item["trace_id"] == trace_id
    )

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    body = replay.json()

    assert body["replayed"]["decision_source"] == original_final["decision_source"]
    assert body["replayed"]["decision_path"] == original_final["decision_path"]


def test_replay_restores_workflow_path_with_risk_step_disabled(client):
    ensure_setup(client)

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "risk_first",
        },
    )
    assert workflow.status_code == 200

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200
    trace_id = original.json()["trace_id"]
    original_final = original.json()["explanation"]["final"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert audit.status_code == 200

    log_id = next(
        item["id"]
        for item in audit.json()
        if item["trace_id"] == trace_id
    )

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    body = replay.json()

    assert body["replayed"]["decision_source"] == original_final["decision_source"]
    assert body["replayed"]["decision_path"] == original_final["decision_path"]


def test_replay_uses_historical_workflow_for_explainability_after_config_change(client):
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

    token = issue_token(client).json()["token"]
    original = access_request(client, token)

    assert original.status_code == 200
    trace_id = original.json()["trace_id"]
    original_final = original.json()["explanation"]["final"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={"tenant_id": "tenant-demo"},
    )
    assert audit.status_code == 200

    log_id = next(
        item["id"]
        for item in audit.json()
        if item["trace_id"] == trace_id
    )

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

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    body = replay.json()

    assert body["workflow"]["version"] == 1
    assert body["workflow"]["execution_mode"] == "risk_first"
    assert body["replayed"]["decision_source"] == original_final["decision_source"]
    assert body["replayed"]["decision_path"] == original_final["decision_path"]

def test_replay_without_workflow_version_returns_no_historical_workflow(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

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
    assert replay.json()["workflow"] is None


def test_replay_without_workflow_version_uses_default_risk_first_path(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

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

    path = replay.json()["replayed"]["decision_path"]

    assert path[0] == "risk_evaluated"
    assert path[1] == "policy_checked"


def test_replay_without_workflow_version_includes_final_decision_in_path(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

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
    expected_final = (
        "final_allow"
        if body["replayed"]["allow"]
        else "final_deny"
    )

    assert body["replayed"]["decision_path"][-1] == expected_final

def test_replay_without_workflow_version_ignores_current_workflow_config(client):
    ensure_setup(client)

    current_workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )
    assert current_workflow.status_code == 200

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

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

    assert body["workflow"] is None
    assert body["replayed"]["decision_path"][0] == "risk_evaluated"
    assert body["replayed"]["decision_path"][1] == "policy_checked"


def test_replay_without_workflow_version_reconstructs_default_explainability(client):
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

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    original_final = original.json()["explanation"]["final"]
    trace_id = original.json()["trace_id"]

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

    assert body["workflow"] is None
    assert body["replayed"]["decision_source"] == original_final["decision_source"]
    assert body["replayed"]["decision_path"] == original_final["decision_path"]

def test_request_log_persists_workflow_decision_source(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    trace_id = response.json()["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        assert log.decision_source is not None
        assert log.decision_source in {"risk", "policy"}


def test_request_log_persists_workflow_decision_path(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    trace_id = response.json()["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        assert log.decision_path is not None

        path = json.loads(log.decision_path)

        assert isinstance(path, list)
        assert len(path) > 0


def test_request_log_workflow_decision_source_matches_response(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()
    trace_id = body["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        assert log.decision_source == body["explanation"]["final"]["decision_source"]


def test_request_log_workflow_decision_path_matches_response(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    body = response.json()
    trace_id = body["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        assert json.loads(log.decision_path) == body["explanation"]["final"]["decision_path"]


def test_request_log_workflow_decision_path_preserves_order(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    trace_id = response.json()["trace_id"]

    with SessionLocal() as db:
        log = (
            db.query(RequestLog)
            .filter_by(trace_id=trace_id)
            .one()
        )

        path = json.loads(log.decision_path)

        assert path[-1] in {"final_allow", "final_deny"}

def test_replay_comparison_includes_decision_source_match(client):
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

    replay = client.get(
        f"/admin/audit/logs/{matching[0]['id']}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_source_match"] is True


def test_replay_comparison_includes_decision_path_match(client):
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

    replay = client.get(
        f"/admin/audit/logs/{matching[0]['id']}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_path_match"] is True


def test_replay_comparison_detects_decision_source_mismatch(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_source = "tampered-source"
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_source_match"] is False


def test_replay_comparison_detects_decision_path_mismatch(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_path = json.dumps(["tampered", "final_deny"])
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_path_match"] is False


def test_replay_all_match_includes_workflow_explainability(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_source = "tampered-source"
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    comparison = replay.json()["comparison"]

    assert comparison["decision_source_match"] is False
    assert comparison["all_match"] is False

def test_replay_handles_missing_decision_source(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_source = None
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_source_match"] is False
    assert replay.json()["comparison"]["all_match"] is False


def test_replay_handles_missing_decision_path(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_path = None
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_path_match"] is False
    assert replay.json()["comparison"]["all_match"] is False


def test_replay_handles_malformed_decision_path_json(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_path = "{not-valid-json"
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_path_match"] is False
    assert replay.json()["comparison"]["all_match"] is False


def test_replay_rejects_non_list_decision_path_as_match(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_path = json.dumps(
            {
                "path": [
                    "risk_evaluated",
                    "policy_checked",
                    "no_policy_match",
                    "final_allow",
                ]
            }
        )
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_path_match"] is False
    assert replay.json()["comparison"]["all_match"] is False


def test_replay_rejects_non_string_decision_path_items_as_match(client):
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
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log.decision_path = json.dumps(
            ["risk_evaluated", 123, "final_allow"]
        )
        db.commit()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["comparison"]["decision_path_match"] is False
    assert replay.json()["comparison"]["all_match"] is False

def test_request_without_workflow_config_persists_no_workflow_version(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        assert log.workflow_version is None


def test_request_without_workflow_config_replay_succeeds_without_manual_patch(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200


def test_request_without_workflow_config_replay_reports_no_historical_workflow(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200
    assert replay.json()["workflow"] is None


def test_request_without_workflow_config_replay_uses_default_risk_first(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    path = replay.json()["replayed"]["decision_path"]

    assert path[0] == "risk_evaluated"
    assert path[1] == "policy_checked"


def test_request_without_workflow_config_replay_preserves_explainability(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    original = access_request(client, token)
    assert original.status_code == 200

    original_final = original.json()["explanation"]["final"]
    trace_id = original.json()["trace_id"]

    from app.database import SessionLocal
    from app.models import RequestLog

    with SessionLocal() as db:
        log = db.query(RequestLog).filter_by(trace_id=trace_id).one()
        log_id = log.id

    replay = client.get(
        f"/admin/audit/logs/{log_id}/replay",
        headers=ADMIN_HEADERS,
    )

    assert replay.status_code == 200

    body = replay.json()

    assert (
        body["replayed"]["decision_source"]
        == original_final["decision_source"]
    )
    assert (
        body["replayed"]["decision_path"]
        == original_final["decision_path"]
    )

def test_default_workflow_response_reports_version_one(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)

    assert response.status_code == 200
    assert response.json()["workflow_version"] == 1
    assert response.json()["explanation"]["final"]["workflow_version"] == 1


def test_default_workflow_audit_log_reports_no_persisted_version(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    trace_id = response.json()["trace_id"]

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
    assert matching[0]["workflow_version"] is None


def test_default_workflow_response_and_audit_distinguish_default_from_history(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    trace_id = response.json()["trace_id"]

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
    assert response.json()["workflow_version"] == 1
    assert matching[0]["workflow_version"] is None


def test_configured_workflow_persists_real_version_in_audit_log(client):
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
    assert workflow.json()["version"] == 1

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    trace_id = response.json()["trace_id"]

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
    assert matching[0]["workflow_version"] == 1


def test_configured_workflow_response_and_audit_versions_match(client):
    ensure_setup(client)

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )
    assert workflow.status_code == 200

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    trace_id = response.json()["trace_id"]

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
    assert response.json()["workflow_version"] == workflow.json()["version"]
    assert matching[0]["workflow_version"] == workflow.json()["version"]

def test_audit_logs_filter_by_workflow_version(client):
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
    assert workflow.json()["version"] == 1

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 1,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) >= 1
    assert all(item["workflow_version"] == 1 for item in audit.json())


def test_audit_logs_workflow_version_filter_excludes_other_versions(client):
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

    token = issue_token(client).json()["token"]
    request_v1 = access_request(client, token)
    assert request_v1.status_code == 200
    trace_v1 = request_v1.json()["trace_id"]

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

    token_v2 = issue_token(client).json()["token"]

    request_v2 = access_request(
        client,
        token_v2,
        ip_address="10.0.0.11",
    )
    assert request_v2.status_code == 200
    trace_v2 = request_v2.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 1,
        },
    )

    assert audit.status_code == 200

    trace_ids = {item["trace_id"] for item in audit.json()}

    assert trace_v1 in trace_ids
    assert trace_v2 not in trace_ids


def test_audit_logs_filter_by_second_workflow_version(client):
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

    token = issue_token(client).json()["token"]
    request_v1 = access_request(client, token)
    assert request_v1.status_code == 200
    trace_v1 = request_v1.json()["trace_id"]

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

    token_v2 = issue_token(client).json()["token"]

    request_v2 = access_request(
        client,
        token_v2,
        ip_address="10.0.0.11",
    )
    assert request_v2.status_code == 200
    trace_v2 = request_v2.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 2,
        },
    )

    assert audit.status_code == 200

    trace_ids = {item["trace_id"] for item in audit.json()}

    assert trace_v2 in trace_ids
    assert trace_v1 not in trace_ids
    assert all(item["workflow_version"] == 2 for item in audit.json())


def test_audit_logs_unknown_workflow_version_returns_empty_list(client):
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
    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 999,
        },
    )

    assert audit.status_code == 200
    assert audit.json() == []


def test_audit_logs_workflow_version_filter_preserves_tenant_isolation(client):
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
    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-other",
            "workflow_version": 1,
        },
    )

    assert audit.status_code == 200
    assert all(item["tenant_id"] == "tenant-other" for item in audit.json())

def test_audit_logs_filter_workflow_configured_false_returns_default_logs(client):
    ensure_setup(client)

    token_default = issue_token(client).json()["token"]
    default_response = access_request(client, token_default)
    assert default_response.status_code == 200
    default_trace = default_response.json()["trace_id"]

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

    token_configured = issue_token(client).json()["token"]
    configured_response = access_request(
        client,
        token_configured,
        ip_address="10.0.0.11",
    )
    assert configured_response.status_code == 200
    configured_trace = configured_response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": False,
        },
    )

    assert audit.status_code == 200

    trace_ids = {item["trace_id"] for item in audit.json()}

    assert default_trace in trace_ids
    assert configured_trace not in trace_ids
    assert all(item["workflow_version"] is None for item in audit.json())


def test_audit_logs_filter_workflow_configured_true_returns_configured_logs(client):
    ensure_setup(client)

    token_default = issue_token(client).json()["token"]
    default_response = access_request(client, token_default)
    assert default_response.status_code == 200
    default_trace = default_response.json()["trace_id"]

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

    token_configured = issue_token(client).json()["token"]
    configured_response = access_request(
        client,
        token_configured,
        ip_address="10.0.0.11",
    )
    assert configured_response.status_code == 200
    configured_trace = configured_response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
        },
    )

    assert audit.status_code == 200

    trace_ids = {item["trace_id"] for item in audit.json()}

    assert configured_trace in trace_ids
    assert default_trace not in trace_ids
    assert all(item["workflow_version"] is not None for item in audit.json())


def test_audit_logs_workflow_configured_false_excludes_versioned_logs(client):
    ensure_setup(client)

    token_default = issue_token(client).json()["token"]
    default_response = access_request(client, token_default)
    assert default_response.status_code == 200

    workflow = client.put(
        "/admin/workflow-config",
        headers=ADMIN_HEADERS,
        json={
            "tenant_id": "tenant-demo",
            "include_risk_step": False,
            "include_policy_step": True,
            "execution_mode": "policy_first",
        },
    )
    assert workflow.status_code == 200

    token_configured = issue_token(client).json()["token"]
    configured_response = access_request(
        client,
        token_configured,
        ip_address="10.0.0.11",
    )
    assert configured_response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": False,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) >= 1
    assert all(item["workflow_version"] is None for item in audit.json())


def test_audit_logs_workflow_configured_true_excludes_default_logs(client):
    ensure_setup(client)

    token_default = issue_token(client).json()["token"]
    default_response = access_request(client, token_default)
    assert default_response.status_code == 200

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

    token_configured = issue_token(client).json()["token"]
    configured_response = access_request(
        client,
        token_configured,
        ip_address="10.0.0.11",
    )
    assert configured_response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) >= 1
    assert all(item["workflow_version"] is not None for item in audit.json())


def test_audit_logs_workflow_configured_combines_with_workflow_version(client):
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

    token_v1 = issue_token(client).json()["token"]
    response_v1 = access_request(client, token_v1)
    assert response_v1.status_code == 200
    trace_v1 = response_v1.json()["trace_id"]

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

    token_v2 = issue_token(client).json()["token"]
    response_v2 = access_request(
        client,
        token_v2,
        ip_address="10.0.0.11",
    )
    assert response_v2.status_code == 200
    trace_v2 = response_v2.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
            "workflow_version": 2,
        },
    )

    assert audit.status_code == 200

    trace_ids = {item["trace_id"] for item in audit.json()}

    assert trace_v2 in trace_ids
    assert trace_v1 not in trace_ids
    assert all(item["workflow_version"] == 2 for item in audit.json())

def test_audit_logs_workflow_configured_true_combines_with_allowed(client):
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
    response = access_request(client, token)
    assert response.status_code == 200
    trace_id = response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
            "allowed": True,
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert trace_id in trace_ids
    assert all(item["workflow_version"] is not None for item in audit.json())
    assert all(item["allowed"] is True for item in audit.json())


def test_audit_logs_workflow_configured_false_combines_with_allowed(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200
    trace_id = response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": False,
            "allowed": True,
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert trace_id in trace_ids
    assert all(item["workflow_version"] is None for item in audit.json())
    assert all(item["allowed"] is True for item in audit.json())


def test_audit_logs_workflow_configured_true_combines_with_min_risk_score(client):
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
    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
            "min_risk_score": 0,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) >= 1
    assert all(item["workflow_version"] is not None for item in audit.json())
    assert all(item["risk_score"] >= 0 for item in audit.json())


def test_audit_logs_workflow_configured_and_version_conflict_returns_empty(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": False,
            "workflow_version": 1,
        },
    )

    assert audit.status_code == 200
    assert audit.json() == []


def test_audit_logs_workflow_configured_true_and_matching_version(client):
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
    assert workflow.json()["version"] == 1

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200
    trace_id = response.json()["trace_id"]

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
            "workflow_version": 1,
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert trace_id in trace_ids
    assert all(item["workflow_version"] == 1 for item in audit.json())

def test_audit_logs_workflow_configured_true_respects_limit(client):
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
            "workflow_configured": True,
            "limit": 1,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) == 1
    assert audit.json()[0]["workflow_version"] is not None


def test_audit_logs_workflow_configured_false_respects_limit(client):
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
            "workflow_configured": False,
            "limit": 1,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) == 1
    assert audit.json()[0]["workflow_version"] is None


def test_audit_logs_workflow_version_respects_limit(client):
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
    assert workflow.json()["version"] == 1

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
            "workflow_version": 1,
            "limit": 1,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) == 1
    assert audit.json()[0]["workflow_version"] == 1


def test_audit_logs_workflow_configured_true_respects_offset(client):
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

    token_1 = issue_token(client).json()["token"]
    first = access_request(client, token_1)
    assert first.status_code == 200

    token_2 = issue_token(client).json()["token"]
    second = access_request(
        client,
        token_2,
        ip_address="10.0.0.11",
    )
    assert second.status_code == 200

    first_page = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
            "limit": 1,
            "offset": 0,
        },
    )
    second_page = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
            "limit": 1,
            "offset": 1,
        },
    )

    assert first_page.status_code == 200
    assert second_page.status_code == 200
    assert len(first_page.json()) == 1
    assert len(second_page.json()) == 1
    assert first_page.json()[0]["id"] != second_page.json()[0]["id"]
    assert first_page.json()[0]["workflow_version"] is not None
    assert second_page.json()[0]["workflow_version"] is not None


def test_audit_logs_workflow_version_offset_stays_inside_filtered_results(client):
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

    token_1 = issue_token(client).json()["token"]
    request_v1 = access_request(client, token_1)
    assert request_v1.status_code == 200

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

    token_2 = issue_token(client).json()["token"]
    request_v2_a = access_request(
        client,
        token_2,
        ip_address="10.0.0.11",
    )
    assert request_v2_a.status_code == 200

    token_3 = issue_token(client).json()["token"]
    request_v2_b = access_request(
        client,
        token_3,
        ip_address="10.0.0.12",
    )
    assert request_v2_b.status_code == 200

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 2,
            "limit": 1,
            "offset": 1,
        },
    )

    assert audit.status_code == 200
    assert len(audit.json()) == 1
    assert audit.json()[0]["workflow_version"] == 2
    assert audit.json()[0]["trace_id"] != request_v1.json()["trace_id"]

def test_audit_logs_risk_signal_matches_exact_token_at_start(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-start-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="exact_start,other_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-start-trace",
                idempotency_key="risk-signal-start-idem",
                request_fingerprint="risk-signal-start-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "exact_start",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-start-trace" in trace_ids


def test_audit_logs_risk_signal_matches_exact_token_in_middle(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-middle-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,exact_middle,last_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-middle-trace",
                idempotency_key="risk-signal-middle-idem",
                request_fingerprint="risk-signal-middle-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "exact_middle",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-middle-trace" in trace_ids


def test_audit_logs_risk_signal_matches_exact_token_at_end(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-end-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,exact_end",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-end-trace",
                idempotency_key="risk-signal-end-idem",
                request_fingerprint="risk-signal-end-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "exact_end",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-end-trace" in trace_ids


def test_audit_logs_risk_signal_does_not_match_substring(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-substring-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="new_ip_extra",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-substring-trace",
                idempotency_key="risk-signal-substring-idem",
                request_fingerprint="risk-signal-substring-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "new_ip",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-substring-trace" not in trace_ids


def test_audit_log_count_risk_signal_does_not_match_substring(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-count-substring-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="count_exact_extra",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-count-substring-trace",
                idempotency_key="risk-signal-count-substring-idem",
                request_fingerprint="risk-signal-count-substring-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "count_exact",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0

def test_audit_logs_risk_signal_underscore_is_literal_at_start(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-like-start-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="newXip,other_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-like-start-trace",
                idempotency_key="risk-signal-like-start-idem",
                request_fingerprint="risk-signal-like-start-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "new_ip",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-like-start-trace" not in trace_ids


def test_audit_logs_risk_signal_underscore_is_literal_in_middle(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-like-middle-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,newXip,last_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-like-middle-trace",
                idempotency_key="risk-signal-like-middle-idem",
                request_fingerprint="risk-signal-like-middle-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "new_ip",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-like-middle-trace" not in trace_ids


def test_audit_logs_risk_signal_underscore_is_literal_at_end(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-like-end-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,newXip",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-like-end-trace",
                idempotency_key="risk-signal-like-end-idem",
                request_fingerprint="risk-signal-like-end-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "new_ip",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-like-end-trace" not in trace_ids


def test_audit_log_count_risk_signal_underscore_is_literal(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-like-count-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,newXip,last_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-like-count-trace",
                idempotency_key="risk-signal-like-count-idem",
                request_fingerprint="risk-signal-like-count-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "new_ip",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_audit_logs_risk_signal_underscore_exact_token_still_matches(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-like-exact-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,new_ip,last_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-like-exact-trace",
                idempotency_key="risk-signal-like-exact-idem",
                request_fingerprint="risk-signal-like-exact-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "new_ip",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-like-exact-trace" in trace_ids

def test_audit_logs_risk_signal_percent_is_literal_at_start(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-percent-start-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="riskXburst,other_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-percent-start-trace",
                idempotency_key="risk-signal-percent-start-idem",
                request_fingerprint="risk-signal-percent-start-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "risk%burst",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-percent-start-trace" not in trace_ids


def test_audit_logs_risk_signal_percent_is_literal_in_middle(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-percent-middle-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,riskXYZburst,last_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-percent-middle-trace",
                idempotency_key="risk-signal-percent-middle-idem",
                request_fingerprint="risk-signal-percent-middle-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "risk%burst",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-percent-middle-trace" not in trace_ids


def test_audit_logs_risk_signal_percent_is_literal_at_end(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-percent-end-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,risk123burst",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-percent-end-trace",
                idempotency_key="risk-signal-percent-end-idem",
                request_fingerprint="risk-signal-percent-end-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "risk%burst",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-percent-end-trace" not in trace_ids


def test_audit_log_count_risk_signal_percent_is_literal(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-percent-count-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,riskABCburst,last_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-percent-count-trace",
                idempotency_key="risk-signal-percent-count-idem",
                request_fingerprint="risk-signal-percent-count-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "risk%burst",
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_audit_logs_risk_signal_percent_exact_token_still_matches(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="risk-signal-percent-exact-ip",
                country_code="EE",
                request_type="access",
                allowed=False,
                risk_score=80,
                reason="test",
                risk_signals="first_signal,risk%burst,last_signal",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="risk-signal-percent-exact-trace",
                idempotency_key="risk-signal-percent-exact-idem",
                request_fingerprint="risk-signal-percent-exact-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    audit = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "risk_signal": "risk%burst",
        },
    )

    assert audit.status_code == 200
    trace_ids = {item["trace_id"] for item in audit.json()}
    assert "risk-signal-percent-exact-trace" in trace_ids

def test_admin_audit_logs_rejects_zero_workflow_version(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 0,
        },
    )

    assert response.status_code == 422


def test_admin_audit_logs_rejects_negative_workflow_version(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": -1,
        },
    )

    assert response.status_code == 422


def test_admin_audit_logs_rejects_negative_min_risk_score(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "min_risk_score": -1,
        },
    )

    assert response.status_code == 422


def test_admin_audit_logs_allows_min_risk_score_above_100(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "min_risk_score": 101,
        },
    )

    assert response.status_code == 200
    assert response.json() == []


def test_admin_audit_log_count_rejects_negative_min_risk_score(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "min_risk_score": -1,
        },
    )

    assert response.status_code == 422

def test_admin_audit_log_count_filters_by_workflow_version(client):
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
    assert workflow.json()["version"] == 1

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 1,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 1


def test_admin_audit_log_count_unknown_workflow_version_returns_zero(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 999,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 0


def test_admin_audit_log_count_filters_workflow_configured_false(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    response = access_request(client, token)
    assert response.status_code == 200

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": False,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 1


def test_admin_audit_log_count_filters_workflow_configured_true(client):
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
    response = access_request(client, token)
    assert response.status_code == 200

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_configured": True,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] == 1


def test_admin_audit_log_count_rejects_zero_workflow_version(client):
    ensure_setup(client)

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "workflow_version": 0,
        },
    )

    assert count.status_code == 422

def test_admin_audit_logs_rejects_reversed_time_range(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-02T00:00:00",
            "to_time": "2030-01-01T00:00:00",
        },
    )

    assert response.status_code == 422


def test_admin_audit_log_count_rejects_reversed_time_range(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-02T00:00:00",
            "to_time": "2030-01-01T00:00:00",
        },
    )

    assert response.status_code == 422


def test_admin_audit_logs_allows_equal_time_range(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T00:00:00",
            "to_time": "2030-01-01T00:00:00",
        },
    )

    assert response.status_code == 200


def test_admin_audit_log_count_allows_equal_time_range(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T00:00:00",
            "to_time": "2030-01-01T00:00:00",
        },
    )

    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_admin_audit_logs_and_count_agree_on_time_range(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    access = access_request(client, token)
    assert access.status_code == 200

    params = {
        "tenant_id": "tenant-demo",
        "from_time": "2020-01-01T00:00:00",
        "to_time": "2999-01-01T00:00:00",
    }

    logs = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params,
    )
    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params=params,
    )

    assert logs.status_code == 200
    assert count.status_code == 200
    assert count.json()["total"] == len(logs.json())

def test_admin_audit_logs_from_time_boundary_is_inclusive(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 12, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="time-from-boundary-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="time-from-boundary-trace",
                idempotency_key="time-from-boundary-idem",
                request_fingerprint="time-from-boundary-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": boundary.isoformat(),
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "time-from-boundary-trace" in trace_ids


def test_admin_audit_logs_to_time_boundary_is_inclusive(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 12, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="time-to-boundary-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="time-to-boundary-trace",
                idempotency_key="time-to-boundary-idem",
                request_fingerprint="time-to-boundary-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "to_time": boundary.isoformat(),
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "time-to-boundary-trace" in trace_ids


def test_admin_audit_logs_from_time_excludes_earlier_microsecond(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 12, 0, 0)
    before = boundary - timedelta(microseconds=1)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="time-before-boundary-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="time-before-boundary-trace",
                idempotency_key="time-before-boundary-idem",
                request_fingerprint="time-before-boundary-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=before,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": boundary.isoformat(),
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "time-before-boundary-trace" not in trace_ids


def test_admin_audit_logs_to_time_excludes_later_microsecond(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 12, 0, 0)
    after = boundary + timedelta(microseconds=1)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="time-after-boundary-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="time-after-boundary-trace",
                idempotency_key="time-after-boundary-idem",
                request_fingerprint="time-after-boundary-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=after,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "to_time": boundary.isoformat(),
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "time-after-boundary-trace" not in trace_ids


def test_admin_audit_logs_and_count_include_exact_time_boundary(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 12, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="time-exact-range-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="time-exact-range-trace",
                idempotency_key="time-exact-range-idem",
                request_fingerprint="time-exact-range-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    params = {
        "tenant_id": "tenant-demo",
        "from_time": boundary.isoformat(),
        "to_time": boundary.isoformat(),
    }

    logs = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params,
    )
    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params=params,
    )

    assert logs.status_code == 200
    assert count.status_code == 200

    trace_ids = {item["trace_id"] for item in logs.json()}
    assert "time-exact-range-trace" in trace_ids
    assert count.json()["total"] == len(logs.json())

def test_admin_audit_logs_from_time_normalizes_positive_offset(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 9, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="timezone-from-offset-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="timezone-from-offset-trace",
                idempotency_key="timezone-from-offset-idem",
                request_fingerprint="timezone-from-offset-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00+03:00",
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "timezone-from-offset-trace" in trace_ids


def test_admin_audit_logs_to_time_normalizes_positive_offset(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 9, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="timezone-to-offset-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="timezone-to-offset-trace",
                idempotency_key="timezone-to-offset-idem",
                request_fingerprint="timezone-to-offset-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "to_time": "2030-01-01T12:00:00+03:00",
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "timezone-to-offset-trace" in trace_ids


def test_admin_audit_logs_z_and_positive_offset_are_equivalent(client):
    ensure_setup(client)

    params_z = {
        "tenant_id": "tenant-demo",
        "from_time": "2030-01-01T09:00:00Z",
    }
    params_offset = {
        "tenant_id": "tenant-demo",
        "from_time": "2030-01-01T12:00:00+03:00",
    }

    response_z = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params_z,
    )
    response_offset = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params_offset,
    )

    assert response_z.status_code == 200
    assert response_offset.status_code == 200

    trace_ids_z = {item["trace_id"] for item in response_z.json()}
    trace_ids_offset = {item["trace_id"] for item in response_offset.json()}

    assert trace_ids_z == trace_ids_offset


def test_admin_audit_log_count_z_and_positive_offset_are_equivalent(client):
    ensure_setup(client)

    response_z = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2020-01-01T00:00:00Z",
        },
    )
    response_offset = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2020-01-01T03:00:00+03:00",
        },
    )

    assert response_z.status_code == 200
    assert response_offset.status_code == 200
    assert response_z.json()["total"] == response_offset.json()["total"]


def test_admin_audit_logs_normalizes_offsets_before_range_validation(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00+03:00",
            "to_time": "2030-01-01T09:00:00Z",
        },
    )

    assert response.status_code == 200

def test_admin_audit_logs_from_time_normalizes_negative_offset(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 17, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="timezone-negative-offset-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="timezone-negative-offset-trace",
                idempotency_key="timezone-negative-offset-idem",
                request_fingerprint="timezone-negative-offset-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00-05:00",
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "timezone-negative-offset-trace" in trace_ids


def test_admin_audit_logs_to_time_normalizes_negative_offset(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 17, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="timezone-negative-to-offset-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="timezone-negative-to-offset-trace",
                idempotency_key="timezone-negative-to-offset-idem",
                request_fingerprint="timezone-negative-to-offset-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "to_time": "2030-01-01T12:00:00-05:00",
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "timezone-negative-to-offset-trace" in trace_ids


def test_admin_audit_logs_positive_and_negative_offsets_are_equivalent(client):
    ensure_setup(client)

    positive = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T20:00:00+03:00",
        },
    )

    negative = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00-05:00",
        },
    )

    assert positive.status_code == 200
    assert negative.status_code == 200

    positive_trace_ids = {item["trace_id"] for item in positive.json()}
    negative_trace_ids = {item["trace_id"] for item in negative.json()}

    assert positive_trace_ids == negative_trace_ids


def test_admin_audit_log_count_positive_and_negative_offsets_are_equivalent(client):
    ensure_setup(client)

    positive = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2020-01-01T03:00:00+03:00",
        },
    )

    negative = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2019-12-31T19:00:00-05:00",
        },
    )

    assert positive.status_code == 200
    assert negative.status_code == 200
    assert positive.json()["total"] == negative.json()["total"]


def test_admin_audit_logs_rejects_range_reversed_only_after_timezone_normalization(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00-05:00",
            "to_time": "2030-01-01T18:00:00+03:00",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "invalid_time_range"

def test_admin_audit_log_count_from_time_normalizes_negative_offset(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 17, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="count-negative-offset-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="count-negative-offset-trace",
                idempotency_key="count-negative-offset-idem",
                request_fingerprint="count-negative-offset-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00-05:00",
        },
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_admin_audit_log_count_to_time_normalizes_negative_offset(client):
    ensure_setup(client)

    boundary = datetime(2030, 1, 1, 17, 0, 0)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="count-negative-to-offset-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=False,
                policy_name=None,
                policy_version=None,
                trace_id="count-negative-to-offset-trace",
                idempotency_key="count-negative-to-offset-idem",
                request_fingerprint="count-negative-to-offset-fingerprint",
                user_agent="pytest",
                decision_version="test",
                created_at=boundary,
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": boundary.isoformat(),
            "to_time": "2030-01-01T12:00:00-05:00",
        },
    )

    assert response.status_code == 200
    assert response.json()["total"] == 1


def test_admin_audit_log_count_allows_equal_instant_with_different_offsets(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00-05:00",
            "to_time": "2030-01-01T20:00:00+03:00",
        },
    )

    assert response.status_code == 200


def test_admin_audit_log_count_rejects_range_reversed_after_timezone_normalization(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "from_time": "2030-01-01T12:00:00-05:00",
            "to_time": "2030-01-01T18:00:00+03:00",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "invalid_time_range"


def test_admin_audit_logs_and_count_agree_with_mixed_timezone_range(client):
    ensure_setup(client)

    token = issue_token(client).json()["token"]
    access = access_request(client, token)
    assert access.status_code == 200

    params = {
        "tenant_id": "tenant-demo",
        "from_time": "2019-12-31T19:00:00-05:00",
        "to_time": "2999-01-01T03:00:00+03:00",
    }

    logs = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params,
    )
    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params=params,
    )

    assert logs.status_code == 200
    assert count.status_code == 200
    assert count.json()["total"] == len(logs.json())

def test_admin_audit_logs_rejects_zero_policy_version(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 0,
        },
    )

    assert response.status_code == 422


def test_admin_audit_logs_rejects_negative_policy_version(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": -1,
        },
    )

    assert response.status_code == 422


def test_admin_audit_log_count_rejects_zero_policy_version(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 0,
        },
    )

    assert response.status_code == 422


def test_admin_audit_log_count_rejects_negative_policy_version(client):
    ensure_setup(client)

    response = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": -1,
        },
    )

    assert response.status_code == 422


def test_admin_audit_logs_and_count_accept_policy_version_one(client):
    ensure_setup(client)

    params = {
        "tenant_id": "tenant-demo",
        "policy_version": 1,
    }

    logs = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params,
    )
    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params=params,
    )

    assert logs.status_code == 200
    assert count.status_code == 200
    assert count.json()["total"] == len(logs.json())

def test_admin_audit_logs_combines_policy_and_workflow_version_filters(client):
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
    assert workflow.json()["version"] == 1

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="policy-workflow-combo-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="combo-policy",
                policy_version=1,
                workflow_version=1,
                trace_id="policy-workflow-combo-trace",
                idempotency_key="policy-workflow-combo-idem",
                request_fingerprint="policy-workflow-combo-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_version": 1,
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "policy-workflow-combo-trace" in trace_ids
    assert all(item["policy_version"] == 1 for item in response.json())
    assert all(item["workflow_version"] == 1 for item in response.json())


def test_admin_audit_logs_policy_and_workflow_version_mismatch_returns_empty(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="policy-workflow-mismatch-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="mismatch-policy",
                policy_version=1,
                workflow_version=2,
                trace_id="policy-workflow-mismatch-trace",
                idempotency_key="policy-workflow-mismatch-idem",
                request_fingerprint="policy-workflow-mismatch-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_version": 1,
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "policy-workflow-mismatch-trace" not in trace_ids


def test_admin_audit_log_count_combines_policy_and_workflow_version_filters(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="policy-workflow-count-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="count-combo-policy",
                policy_version=1,
                workflow_version=1,
                trace_id="policy-workflow-count-trace",
                idempotency_key="policy-workflow-count-idem",
                request_fingerprint="policy-workflow-count-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_version": 1,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] >= 1


def test_admin_audit_logs_and_count_agree_for_policy_and_workflow_versions(client):
    ensure_setup(client)

    params = {
        "tenant_id": "tenant-demo",
        "policy_version": 1,
        "workflow_version": 1,
    }

    logs = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params,
    )
    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params=params,
    )

    assert logs.status_code == 200
    assert count.status_code == 200
    assert count.json()["total"] == len(logs.json())


def test_admin_audit_policy_and_workflow_version_filters_preserve_tenant_isolation(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="other-tenant",
                right_id="right-other",
                client_id="gateway-other",
                source_client="gateway-other",
                device_id="device-other",
                user_id="user-other",
                ip_hash="other-tenant-combo-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="other-policy",
                policy_version=1,
                workflow_version=1,
                trace_id="other-tenant-combo-trace",
                idempotency_key="other-tenant-combo-idem",
                request_fingerprint="other-tenant-combo-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_version": 1,
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "other-tenant-combo-trace" not in trace_ids

def test_admin_audit_logs_policy_version_with_workflow_configured_true(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="policy-configured-true-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="configured-policy",
                policy_version=1,
                workflow_version=1,
                trace_id="policy-configured-true-trace",
                idempotency_key="policy-configured-true-idem",
                request_fingerprint="policy-configured-true-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_configured": True,
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "policy-configured-true-trace" in trace_ids
    assert all(item["policy_version"] == 1 for item in response.json())
    assert all(item["workflow_version"] is not None for item in response.json())


def test_admin_audit_logs_policy_version_with_workflow_configured_false(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="policy-configured-false-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="default-workflow-policy",
                policy_version=1,
                workflow_version=None,
                trace_id="policy-configured-false-trace",
                idempotency_key="policy-configured-false-idem",
                request_fingerprint="policy-configured-false-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_configured": False,
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "policy-configured-false-trace" in trace_ids
    assert all(item["policy_version"] == 1 for item in response.json())
    assert all(item["workflow_version"] is None for item in response.json())


def test_admin_audit_logs_policy_version_excludes_wrong_workflow_configured_state(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="policy-configured-exclusion-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="configured-exclusion-policy",
                policy_version=1,
                workflow_version=1,
                trace_id="policy-configured-exclusion-trace",
                idempotency_key="policy-configured-exclusion-idem",
                request_fingerprint="policy-configured-exclusion-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    response = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_configured": False,
        },
    )

    assert response.status_code == 200
    trace_ids = {item["trace_id"] for item in response.json()}
    assert "policy-configured-exclusion-trace" not in trace_ids


def test_admin_audit_log_count_policy_version_with_workflow_configured(client):
    ensure_setup(client)

    with SessionLocal() as db:
        db.add(
            RequestLog(
                tenant_id="tenant-demo",
                right_id="right-001",
                client_id="gateway-1",
                source_client="gateway-1",
                device_id="device-A1",
                user_id="user-123",
                ip_hash="policy-configured-count-ip",
                country_code="EE",
                request_type="access",
                allowed=True,
                risk_score=0,
                reason="allowed",
                risk_signals="",
                policy_matched=True,
                policy_name="configured-count-policy",
                policy_version=1,
                workflow_version=1,
                trace_id="policy-configured-count-trace",
                idempotency_key="policy-configured-count-idem",
                request_fingerprint="policy-configured-count-fingerprint",
                user_agent="pytest",
                decision_version="test",
            )
        )
        db.commit()

    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params={
            "tenant_id": "tenant-demo",
            "policy_version": 1,
            "workflow_configured": True,
        },
    )

    assert count.status_code == 200
    assert count.json()["total"] >= 1


def test_admin_audit_logs_and_count_agree_for_policy_version_and_workflow_configured(client):
    ensure_setup(client)

    params = {
        "tenant_id": "tenant-demo",
        "policy_version": 1,
        "workflow_configured": False,
    }

    logs = client.get(
        "/admin/audit/logs",
        headers=ADMIN_HEADERS,
        params=params,
    )
    count = client.get(
        "/admin/audit/logs/count",
        headers=ADMIN_HEADERS,
        params=params,
    )

    assert logs.status_code == 200
    assert count.status_code == 200
    assert count.json()["total"] == len(logs.json())