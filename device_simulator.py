import os

import requests

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")
TENANT_ID = os.getenv("TENANT_ID", "tenant-demo")
CLIENT_ID = os.getenv("CLIENT_ID", "gateway-1")
API_KEY = os.getenv("API_KEY", "super-secret")

HEADERS = {
    "X-Client-Id": CLIENT_ID,
    "X-API-Key": API_KEY,
    "X-Tenant-Id": TENANT_ID,
}


def post(path: str, payload: dict):
    response = requests.post(f"{BASE_URL}{path}", json=payload, headers=HEADERS, timeout=10)
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    print("1) create device")
    print(post("/admin/devices", {"tenant_id": TENANT_ID, "device_id": "gate-A1", "description": "Front gate"}))

    print("2) create access right")
    print(post("/rights/create", {"tenant_id": TENANT_ID, "right_id": "right-001", "owner_id": "user-123", "valid": True}))

    print("3) issue token")
    token_resp = post("/token/issue", {"tenant_id": TENANT_ID, "right_id": "right-001", "user_id": "user-123", "device_id": "gate-A1", "scope": "access"})
    print(token_resp)

    print("4) request access")
    print(post("/request/access", {"token": token_resp["token"], "request_type": "access", "device_id": "gate-A1", "ip_address": "10.0.0.10", "country_code": "EE"}))
