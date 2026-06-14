# Statelog

## Real-Time Digital Rights Infrastructure

Statelog is a platform for creating, validating and managing digital rights as stateful server-side objects.

Unlike traditional access control systems that validate identity only at login, Statelog evaluates every access request in real time and determines whether an action should be allowed or denied based on the current state of a digital right.

---

## The Problem

Most systems answer a single question:

**Who are you?**

Authentication alone is often insufficient when:

* ownership changes over time
* devices are replaced
* permissions must be revoked immediately
* access decisions require context
* actions must be auditable

Modern systems need to answer a different question:

**Should this action be allowed right now?**

---

## The Statelog Approach

Statelog treats a digital right as a stateful object managed by a centralized decision engine.

Each digital right may contain:

* ownership information
* validity status
* transfer history
* access history
* risk indicators
* decision metadata

Every request is evaluated against the current state of the right before access is granted.

---

## Decision Flow

```text
User / Device
      ↓
Access Request
      ↓
Token Validation
      ↓
Digital Right Lookup
      ↓
Risk Signal Analysis
      ↓
Decision Engine
      ↓
ALLOW / DENY
      ↓
State Update
      ↓
Audit Log
```

---

## Demonstrated Capabilities

* JWT token issuance
* JWT token validation
* Multi-tenant architecture
* Device registration
* Ownership tracking
* Digital rights management
* Replay attack protection
* Access decision engine
* Audit-ready logging
* Browser-based demonstration interface

---

## Example Decision

```text
allow: true
reason: allowed
risk_score: 0
decision_version: v8.2
```

---

## Technology Stack

Backend

* Python
* FastAPI
* PostgreSQL
* Redis

Infrastructure

* Docker
* Docker Compose

Documentation

* OpenAPI / Swagger

---

## Running Locally

Start the platform:

```bash
docker compose up --build
```

Frontend Demo:

```text
http://localhost:8080
```

API Documentation:

```text
http://localhost:8001/docs
```

---

## Current Status

Working Proof of Concept.

Successfully demonstrated:

* tenant creation
* client creation
* device registration
* digital right creation
* JWT issuance
* JWT validation
* access request processing
* real-time access decisions

---

## Potential Applications

* Digital identity systems
* Access control platforms
* Electronic ticketing
* Government services
* Industrial systems
* SaaS platforms
* Financial workflows
* Critical infrastructure

---

## Vision

Statelog aims to become a universal authorization layer for systems requiring secure, auditable and context-aware access decisions.

The long-term vision is a platform where digital rights, ownership, state and risk signals can be evaluated in real time before any action is executed.

---
## Demo result

Demo completed successfully: JWT token issued, access right validated, decision returned allow=true.

© Statelog. All Rights Reserved.
