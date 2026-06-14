# Access PoC v8

See versioon tugevdab v7 MVP-d päris kasutuse poole: admin-auth, tenant-boundary kontrollid, Redis-põhine rate limiting, idempotentsus, parem audit-logi, Alembic migratsioonid ja webhook/outbox worker.

## Mis v8-s uut on

- admin endpointid on kaitstud `X-Admin-Api-Key` headeriga
- tenant mismatch kontroll seadme ja õiguse loomisel
- parem decision cache key
- duplicate protection / idempotency `Idempotency-Key` headeri või request fingerprinti alusel
- `allow` on nüüd boolean
- access tokenit ei väljastata invaliidsele õigusele
- ownership transfer kontrollib puuduva/sama omaniku ja current owner reegleid
- Redis-põhine rate limiter koos fallbackiga
- audit-logis talletatakse `user_agent`, `source_client`, `decision_version`, `token_jti`, `request_fingerprint`
- Alembic migratsioonide scaffold
- structured logging
- webhook/outbox delivery worker retry/backoffiga
- config-põhine headerite lugemine

## Kiire käivitamine lokaalselt

Rakendus ei loo enam DB skeemi käivitumisel automaatselt. Enne starti rakenda migratsioonid.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Admin header demo jaoks:

```bash
export ADMIN_API_KEY=admin-dev-key
```

## Docker Compose

```bash
docker compose up --build
```

## Testid

```bash
pytest -q
```

## Worker

```bash
python -m app.outbox_worker
```

## Alembic

```bash
alembic upgrade head
```


## Additional security hardening in v8.1
- Token issuance is bound to the current access-right owner.
- Access requests are rejected if the token subject no longer matches the current right owner.
- Tokens are single-use within their validity window via replay protection on JWT `jti`.
- IP-based rate limiting is tenant-isolated and uses pseudonymized IP hashes.
- Audit logs store `ip_hash` instead of raw IP addresses.


## v8.2 operational notes
- JWT signing now supports key rotation via `JWT_ACTIVE_KID` and `JWT_KEYRING_JSON`.
- Webhook signing secrets are encrypted at rest with `SECRET_ENCRYPTION_KEY`.
- Outbox worker records each delivery attempt and dead-letters events after max retries.


## Latency probe

Run a quick p50/p95/p99 probe against a running instance:

```bash
python load/latency_probe.py --base-url http://127.0.0.1:8000 --path /healthz --requests 500 --concurrency 50
```


## vol 9.1 deploy hardening

Lisatud failid:
- `.env.example`
- `.dockerignore`
- `docker-compose.prod.yml`
- `deploy/docker-entrypoint.sh`
- `deploy/worker-entrypoint.sh`
- `deploy/wait_for_services.py`
- `PRODUCTION_CHECKLIST_VOL9_1.md`

### Soovitatud production käivitus

```bash
cp .env.example .env
# muuda secretid ja võtmed ära
docker compose -f docker-compose.prod.yml up --build -d
```

See variant:
- ootab DB ja Redise valmisolekut
- rakendab migratsioonid startupis
- käivitab appi ja workeri eraldi
- kasutab non-root konteinerit
- lisab healthcheckid ja restart policy
- väldib Postgresi/Redise host-portide avalikku avamist

## CI/CD migration + test gate

Lisatud GitHub Actions workflow:
- `.github/workflows/ci.yml`
- `scripts/run_migration_gate.sh`

Pipeline teeb järjekorras:
1. käivitab Postgresi ja Redise service-containerid
2. ootab sõltuvuste valmisolekut
3. rakendab `alembic upgrade head`
4. kontrollib, et andmebaas oleks päriselt `head` peal
5. käivitab `pytest -q`

See tähendab, et PR/commit kukub läbi, kui:
- migratsioon ei rakendu puhtale Postgresile
- andmebaas ei jõua head revisjonini
- testid ei läbi

## Päris /request/access flow latency probe

Lisatud fail:
- `load/access_flow_probe.py`

See probe:
- bootstrapib tenandi, kliendid, seadme ja õiguse automaatselt
- väljastab iga iteratsiooni jaoks uue tokeni
- teeb päris `/token/issue` + `/request/access` flow
- mõõdab eraldi `token_issue`, `request_access` ja `end_to_end` latentsust
- väljastab `avg`, `p50`, `p95`, `p99`, `max` ning status code kokkuvõtte

Näide:

```bash
python load/access_flow_probe.py --base-url http://127.0.0.1:8000 --requests 500 --concurrency 50 --client-shards 32 --admin-api-key admin-dev-key
```

Märkus:
- replay protection tõttu kasutab probe igal iteratsioonil uut tokenit
- client-side rate limiting vältimiseks kasutab probe mitut client credentialit (`--client-shards`)


## Release workflow

A GitHub Actions release workflow is included in `.github/workflows/release.yml`.

Typical flow:

```bash
git tag v9.3.0
git push origin v9.3.0
```

That workflow:

- reuses the CI migration/test gate
- builds a release zip
- generates SHA256 checksums
- publishes a GitHub release

Recommended branch and tag protection settings are documented in `docs/BRANCH_PROTECTION.md`.

## Soak testing and latency reports

For a repeated access-flow soak test with report files:

```bash
python scripts/soak_report.py \
  --base-url http://127.0.0.1:8000 \
  --duration-seconds 300 \
  --round-requests 250 \
  --concurrency 25 \
  --client-shards 32
```

Artifacts:

- `load/reports/soak_report.json`
- `load/reports/soak_report.csv`

For a single-run JSON summary from the real `/request/access` flow:

```bash
python load/access_flow_probe.py \
  --base-url http://127.0.0.1:8000 \
  --requests 500 \
  --concurrency 50 \
  --client-shards 32 \
  --json-output load/reports/access_probe.json
```

## Warning cleanup

- Bumped `fastapi` from `0.115.0` to `0.115.5`, which includes compatibility updates around `python-multipart` imports.
- Added a targeted pytest warning filter for the legacy `python_multipart` PendingDeprecationWarning emitted by third-party packages in older toolchains. This keeps CI/test output clean while runtime dependencies move to the newer import path.
