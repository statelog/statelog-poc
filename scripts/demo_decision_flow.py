import os
from datetime import datetime, timezone

# Isolated demo environment.
# These must be set BEFORE importing app modules.
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JWT_SECRET"] = "demo-secret-key-for-statelog-poc-2026"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["REDIS_URL"] = "redis://localhost:6399/0"
os.environ["ENVIRONMENT"] = "test"
os.environ["TRUSTED_HOSTS"] = "testserver,localhost,127.0.0.1"

from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app, decision_cache, rate_limiter, replay_store
from app.models import RequestLog
from tests.test_smoke import ensure_setup, issue_token, access_request


def reset_demo_environment():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    decision_cache.clear()
    rate_limiter.memory._buckets.clear()
    replay_store.memory._seen.clear()


def print_decision(title, body):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    print("\n--- FINAL DECISION ---")
    print(f"Allowed:          {body['allow']}")
    print(f"Reason:           {body['reason']}")
    print(f"Risk score:       {body['risk_score']}")
    print(f"Trust score:      {body['trust_score']}")
    print(f"Policy matched:   {body['policy_matched']}")
    print(f"Policy name:      {body['policy_name']}")
    print(
        f"Decision source:  "
        f"{body['explanation']['final']['decision_source']}"
    )

    print("\n--- RISK EXPLAINABILITY ---")
    print(
        f"Total contribution: "
        f"{body['explanation']['risk']['total_contribution']}"
    )

    contributors = body["explanation"]["risk"]["contributors"]

    if contributors:
        for contributor in contributors:
            print(
                f"- {contributor['signal']}: "
                f"+{contributor['score']}"
            )
    else:
        print("- No risk signals detected")

    print("\n--- DECISION PATH ---")
    for step in body["explanation"]["final"]["decision_path"]:
        print(f"- {step}")

    print("\n--- TRACEABILITY ---")
    print(f"Trace ID:          {body['trace_id']}")
    print(f"Decision version:  {body['decision_version']}")


def create_risk_history():
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
                    ip_hash=f"demo-old-ip-{i}",
                    country_code="EE",
                    request_type="access",
                    allowed=False,
                    risk_score=80,
                    reason="previous_denial",
                    risk_signals="failure_burst",
                    policy_matched=False,
                    policy_name=None,
                    policy_version=None,
                    trace_id=f"demo-risk-trace-{i}",
                    idempotency_key=f"demo-risk-idem-{i}",
                    request_fingerprint=f"demo-risk-fingerprint-{i}",
                    user_agent="statelog-demo",
                    decision_version="demo",
                    created_at=datetime.now(timezone.utc),
                )
            )

        db.commit()


def main():
    reset_demo_environment()

    with TestClient(app) as client:
        print("=" * 60)
        print("STATELOG PoC - END-TO-END DECISION DEMO")
        print("=" * 60)

        print("\nPreparing isolated demo environment...")
        ensure_setup(client)

        # ---------------------------------------------------------
        # SCENARIO A: NORMAL ACCESS
        # ---------------------------------------------------------

        token_response = issue_token(client)

        if token_response.status_code != 200:
            raise RuntimeError(
                f"Token issuance failed: "
                f"{token_response.status_code} {token_response.text}"
            )

        token = token_response.json()["token"]

        normal_response = access_request(client, token)

        if normal_response.status_code != 200:
            raise RuntimeError(
                f"Normal access failed: "
                f"{normal_response.status_code} "
                f"{normal_response.text}"
            )

        print_decision(
            "SCENARIO A - NORMAL ACCESS",
            normal_response.json(),
        )

        # ---------------------------------------------------------
        # SCENARIO B: HIGH-RISK ACCESS
        # ---------------------------------------------------------

        create_risk_history()

        risk_token_response = issue_token(client, scope="ownership_transfer")

        if risk_token_response.status_code != 200:
            raise RuntimeError(
                f"Risk token issuance failed: "
                f"{risk_token_response.status_code} "
                f"{risk_token_response.text}"
            )

        risk_token = risk_token_response.json()["token"]

        risky_response = access_request(
            client,
            risk_token,
            device_id="gate-A1",
            ip_address="10.10.10.99",
            country_code="FI",
            request_type="ownership_transfer",
            new_owner_id="user-456",
        )

        if risky_response.status_code != 200:
            raise RuntimeError(
                f"Risk access failed: "
                f"{risky_response.status_code} "
                f"{risky_response.text}"
            )

        print_decision(
            "SCENARIO B - HIGH-RISK OWNERSHIP TRANSFER",
            risky_response.json(),
        )

        print("\n" + "=" * 60)
        print("DEMO SUMMARY")
        print("=" * 60)
        print("Scenario A: normal behaviour -> ALLOW")
        print("Scenario B: accumulated risk -> DENY")
        print("Both decisions include explainability and traceability.")
        print("=" * 60)


if __name__ == "__main__":
    main()