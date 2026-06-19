# Statelog Access Engine

**Real-Time Stateful Authorization Infrastructure**

Statelog is a proof-of-concept authorization platform that makes access decisions based on the current state of ownership, rights and risk rather than identity alone.

Unlike traditional IAM systems that answer **"Who are you?"**, Statelog answers:

> **"Should this action be allowed right now?"**

---

# Key Features

* JWT-based authentication
* Stateful authorization engine
* Real-time ownership validation
* Digital rights management
* Risk-aware access decisions
* Tenant isolation
* Redis-backed rate limiting
* Replay protection
* Idempotent request processing
* Immutable audit trail
* Structured logging
* Webhook / Outbox event delivery
* Alembic database migrations
* Docker deployment
* Multi-tenant architecture

---

# Architecture

Statelog evaluates every access request using multiple real-time validation layers.

Decision inputs include:

* Identity
* Digital rights
* Current ownership
* Device context
* Risk signals
* Business rules

The authorization engine produces either:

* ALLOW
* DENY

Every decision can be recorded in the immutable audit log.

---

# Project Structure

```
app/
alembic/
deploy/
docs/
evidence/
load/
scripts/
tests/
```

---

# Quick Start

Clone repository

```
git clone https://github.com/statelog/statelog-poc.git
cd statelog-poc
```

Create virtual environment

```
python -m venv .venv
```

Activate

Linux / macOS

```
source .venv/bin/activate
```

Windows

```
.venv\Scripts\activate
```

Install dependencies

```
pip install -r requirements.txt
```

Run database migrations

```
alembic upgrade head
```

Start API

```
uvicorn app.main:app --reload
```

---

# Docker

Development

```
docker compose up --build
```

Production

```
cp .env.example .env
docker compose -f docker-compose.prod.yml up --build -d
```

---

# Testing

Run unit tests

```
pytest -q
```

Latency probe

```
python load/latency_probe.py
```

Real authorization flow benchmark

```
python load/access_flow_probe.py
```

Soak test

```
python scripts/soak_report.py
```

---

# Security

Implemented protections include:

* Tenant boundary enforcement
* Ownership validation
* JWT replay protection
* Key rotation support
* Redis rate limiting
* Encrypted webhook secrets
* Token binding to current owner
* IP hash anonymization
* Immutable audit logging

---

# Current Status

Current maturity:

* Public Proof of Concept
* Active development
* Production-oriented architecture
* CI/CD pipeline
* Docker deployment
* Migration gate
* Automated testing

Statelog is currently seeking design partners and pilot projects.

---

# Documentation

Additional documentation is available in the `docs/` directory.

Topics include:

* Deployment
* Validation
* Executive summary
* Production checklist
* Platform overview

---

# License

Copyright © Statelog.

Source code is proprietary.

See the LICENSE file for details.
