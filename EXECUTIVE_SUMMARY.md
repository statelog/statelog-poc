# Deployment guide

## Eeldused
- Docker ja Docker Compose
- Postgres
- Redis
- vajalikud secrets väärtused `.env` põhjal

## Kohalik kontroll
```bash
cp .env.example .env
bash scripts/run_migration_gate.sh
pytest -q
```

## Production-lähedane käivitus
```bash
docker compose -f docker-compose.prod.yml up --build
```

## Soovituslik kontroll enne demo või piloteerimist
- kinnita, et Alembic on `head`
- kinnita, et `SECRET_ENCRYPTION_KEY` ja JWT keyring on seadistatud
- kontrolli worker health'i ja webhook retry'd
- tee vähemalt üks `load/access_flow_probe.py` jooks
