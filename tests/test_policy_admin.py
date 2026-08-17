from tests.test_smoke import ADMIN_HEADERS, ensure_setup


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