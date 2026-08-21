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