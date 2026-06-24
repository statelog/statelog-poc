# Production Readiness Checklist (v9.1)

This checklist summarizes the recommended steps before deploying Statelog to a production or pilot environment.

---

# Secrets & Configuration

Before deployment:

* Replace all development secrets with production-grade values:

  * `ADMIN_API_KEY`
  * `JWT_KEYRING_JSON`
  * `SECRET_ENCRYPTION_KEY`
  * `IP_HASH_PEPPER`
  * `WEBHOOK_SECRET_PEPPER`
* Store all secrets in a secure secret management solution or orchestration platform. Do **not** commit secrets to `.env` files.
* Verify that `JWT_ACTIVE_KID` references a valid signing key in the configured keyring.
* Set the deployment environment:

```text
ENVIRONMENT=prod
```

* Confirm that all database migrations complete successfully:

```bash
alembic upgrade head
```

---

# Network Security

* Restrict PostgreSQL and Redis to private network access only.
* Deploy the API behind a reverse proxy with:

  * TLS termination
  * Request size limits
  * Appropriate security headers
* Protect administrative endpoints using network policies, API gateways or equivalent access controls.

---

# Runtime Hardening

* Run all containers as non-root users.
* Use read-only filesystems wherever practical.
* Mount temporary storage using `tmpfs`.
* Enable `no-new-privileges`.
* Remove unnecessary Linux capabilities.
* Configure appropriate restart policies for all services.

---

# Observability

Configure centralized monitoring and logging.

Recommended configuration:

* Forward structured logs to a centralized logging platform.
* Export Prometheus metrics from `/metrics`.
* Configure alerting for:

  * Increased HTTP 5xx responses
  * Replay attack detections
  * Dead-lettered webhook events
  * Redis or PostgreSQL availability issues
  * Elevated p95/p99 request latency

---

# Data Protection

* Store only `ip_hash` values within audit logs.
* Never retain raw client IP addresses.
* Define data retention policies for:

  * `RequestLog`
  * `OutboxEvent`
  * `WebhookDeliveryAttempt`
* Document webhook secret rotation and delivery retention policies.

---

# Release Validation

Before every production deployment:

Run automated tests:

```bash
pytest -q
```

Execute a latency benchmark:

```bash
python load/latency_probe.py \
  --base-url http://127.0.0.1:8000 \
  --path /healthz \
  --requests 200 \
  --concurrency 20
```

Verify that:

* The Outbox Worker processes queued events successfully.
* Dead-letter handling has been validated.
* Webhook retries behave as expected.
* JWT signing key rotation has a tested rollback procedure.
* Previous signing keys remain available for token verification until all previously issued tokens have expired.

---

# Production Readiness Goal

Before entering production, Statelog should demonstrate:

* Secure secret management
* Hardened runtime environment
* Reliable observability
* Automated deployment validation
* Verified disaster recovery procedures
* Stable authorization performance under expected production workloads
* Secure cryptographic key lifecycle management
