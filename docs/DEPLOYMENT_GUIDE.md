# Deployment Guide

## Prerequisites

Before deploying Statelog, ensure the following components are available:

* Docker
* Docker Compose
* PostgreSQL
* Redis
* Environment variables configured according to `.env.example`

---

## Local Validation

Run the following commands to prepare and validate the environment:

```bash
cp .env.example .env
bash scripts/run_migration_gate.sh
pytest -q
```

---

## Production Deployment

Start the production environment using Docker Compose:

```bash
docker compose -f docker-compose.prod.yml up --build
```

---

## Pre-Deployment Checklist

Before running a demonstration or deploying to a pilot environment, verify the following:

* Confirm that all Alembic migrations are applied (`head`)
* Verify that `SECRET_ENCRYPTION_KEY` is configured
* Verify that the JWT keyring is configured correctly
* Confirm that the Outbox Worker is healthy
* Verify webhook retry functionality
* Run at least one end-to-end authorization benchmark using:

```bash
python load/access_flow_probe.py
```
