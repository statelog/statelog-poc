from __future__ import annotations

import json
import logging
import time
import uuid
import jwt
from typing import Optional
from datetime import datetime, timedelta

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import desc, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from .risk_engine import RiskEngine, RISK_SIGNAL_SCORES
from .policy_engine import Policy, PolicyEngine

from .config import settings
from .database import get_db
from .logging_setup import configure_logging
from .metrics import (
    AUTH_FAILURE_COUNTER,
    CACHE_COUNTER,
    LATENCY_HISTOGRAM,
    OUTBOX_DEAD_LETTER_GAUGE,
    OUTBOX_PENDING_GAUGE,
    RATE_LIMIT_COUNTER,
    REQUEST_COUNTER,
    RISK_SCORE_HISTOGRAM,
    metrics_response,
)
from .models import AccessRight, ClientCredential, Device, OutboxEvent, RequestLog, Tenant, WebhookDeliveryAttempt, WebhookSubscription, PolicyRecord, PolicyHistory, WorkflowConfigRecord, WorkflowConfigHistory
from .rate_limit import HybridRateLimiter
from .replay_protection import HybridReplayStore
from .risk_engine import RiskEngine
from .workflow_engine import WorkflowConfig, WorkflowEngine
from .schemas import (
    AccessRequest,
    AccessRightCreate,
    AccessRightRevoke, 
    ClientCreate,
    DecisionResponse,
    DeviceCreate,
    TenantCreate,
    TokenIssueRequest,
    WebhookCreate,
    PolicyCreate,
    PolicySimulationRequest,
    PolicyUpdate,
    WorkflowConfigUpdate,
)
from .security import build_request_fingerprint, constant_time_equals, decode_access_token, encrypt_secret, get_active_signing_key, hash_secret, hash_with_pepper, issue_access_token
from .services.auth_service import enforce_right_owner
from .services.decision_service import build_cache_key
from .services.privacy_service import pseudonymize_ip
from .services.token_service import validate_token_issue_inputs
from .time_utils import utcnow_naive

configure_logging()
logger = logging.getLogger(__name__)

templates = Jinja2Templates(directory="app/templates")
risk_engine = RiskEngine()
workflow_engine = WorkflowEngine()
policy_engine = PolicyEngine()
decision_cache: dict[str, tuple[float, dict]] = {}

def load_tenant_policies(db: Session, tenant_id: str) -> PolicyEngine:
    records = (
        db.query(PolicyRecord)
        .filter_by(tenant_id=tenant_id, enabled=True)
        .order_by(PolicyRecord.priority.asc())
        .all()
    )

    policies = [
        Policy(
            name=record.name,
            effect=record.effect,
            policy_id=record.id,
            priority=record.priority,
            request_types=tuple(
                value.strip()
                for value in record.request_types.split(",")
                if value.strip()
            ),
            countries=tuple(
                value.strip()
                for value in record.countries.split(",")
                if value.strip()
            ),
            device_ids=tuple(
                value.strip()
                for value in record.device_ids.split(",")
                if value.strip()
            ),
        max_risk_score=record.max_risk_score,
        min_trust_score=record.min_trust_score,
        max_transaction_amount=record.max_transaction_amount,
        allowed_start_hour=record.allowed_start_hour,
        allowed_end_hour=record.allowed_end_hour,
        version=record.version,
        valid_from=record.valid_from,
        expires_at=record.expires_at,
        )
        for record in records
    ]

    return PolicyEngine(policies)


def save_policy_history(db: Session, policy: PolicyRecord) -> None:
    history = PolicyHistory(
        policy_id=policy.id,
        tenant_id=policy.tenant_id,
        policy_name=policy.name,
        version=policy.version,
        effect=policy.effect,
        priority=policy.priority,
        request_types=policy.request_types,
        countries=policy.countries,
        device_ids=policy.device_ids,
        max_risk_score=policy.max_risk_score,
        min_trust_score=policy.min_trust_score,
        max_transaction_amount=policy.max_transaction_amount,
        allowed_start_hour=policy.allowed_start_hour,
        allowed_end_hour=policy.allowed_end_hour,
        enabled=policy.enabled,
        valid_from=policy.valid_from,
        expires_at=policy.expires_at,
    )
    db.add(history)

def save_workflow_config_history(
    db: Session,
    record: WorkflowConfigRecord,
) -> None:
    history = WorkflowConfigHistory(
        tenant_id=record.tenant_id,
        version=record.version,
        include_risk_step=record.include_risk_step,
        include_policy_step=record.include_policy_step,
        execution_mode=record.execution_mode,
    )
    db.add(history)
def load_workflow_config_version(
    db: Session,
    tenant_id: str,
    version: int,
) -> WorkflowConfig | None:
    record = db.get(WorkflowConfigRecord, tenant_id)

    if record is not None and record.version == version:
        return WorkflowConfig(
            include_risk_step=record.include_risk_step,
            include_policy_step=record.include_policy_step,
            execution_mode=record.execution_mode,
        )

    history = (
        db.query(WorkflowConfigHistory)
        .filter_by(
            tenant_id=tenant_id,
            version=version,
        )
        .first()
    )

    if history is None:
        return None

    return WorkflowConfig(
        include_risk_step=history.include_risk_step,
        include_policy_step=history.include_policy_step,
        execution_mode=history.execution_mode,
    )

def load_policy_version(
    db: Session,
    tenant_id: str,
    policy_id: int,
    version: int,
) -> Policy | None:
    record = db.get(PolicyRecord, policy_id)

    if (
        record is not None
        and record.tenant_id == tenant_id
        and record.version == version
    ):
        return Policy(
            name=record.name,
            effect=record.effect,
            policy_id=record.id,
            priority=record.priority,
            version=record.version,
            request_types=tuple(
                value.strip()
                for value in record.request_types.split(",")
                if value.strip()
            ),
            countries=tuple(
                value.strip()
                for value in record.countries.split(",")
                if value.strip()
            ),
            device_ids=tuple(
                value.strip()
                for value in record.device_ids.split(",")
                if value.strip()
            ),
            max_risk_score=record.max_risk_score,
            min_trust_score=record.min_trust_score,
            max_transaction_amount=record.max_transaction_amount,
            allowed_start_hour=record.allowed_start_hour,
            allowed_end_hour=record.allowed_end_hour,
            valid_from=record.valid_from,
            expires_at=record.expires_at,
        )

    history = (
        db.query(PolicyHistory)
        .filter_by(
            tenant_id=tenant_id,
            policy_id=policy_id,
            version=version,
        )
        .first()
    )

    if history is None:
        return None

    return Policy(
        name=history.policy_name,
        effect=history.effect,
        policy_id=history.policy_id,
        priority=history.priority,
        version=history.version,
        request_types=tuple(
            value.strip()
            for value in history.request_types.split(",")
            if value.strip()
        ),
        countries=tuple(
            value.strip()
            for value in history.countries.split(",")
            if value.strip()
        ),
        device_ids=tuple(
            value.strip()
            for value in history.device_ids.split(",")
            if value.strip()
        ),
        max_risk_score=history.max_risk_score,
        min_trust_score=history.min_trust_score,
        max_transaction_amount=history.max_transaction_amount,
        allowed_start_hour=history.allowed_start_hour,
        allowed_end_hour=history.allowed_end_hour,
        valid_from=history.valid_from,
        expires_at=history.expires_at,
    )

try:
    redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    redis_client.ping()
except RedisError:
    redis_client = None
    logger.warning("redis_unavailable_startup")
rate_limiter = HybridRateLimiter(redis_client=redis_client, fail_closed=settings.fail_closed)
replay_store = HybridReplayStore(redis_client=redis_client, fail_closed=settings.fail_closed)


app = FastAPI(
    title=settings.app_name,
    docs_url=None if settings.environment.lower() == "prod" else "/docs",
    redoc_url=None if settings.environment.lower() == "prod" else "/redoc",
    openapi_url=None if settings.environment.lower() == "prod" else "/openapi.json",
)

trusted_hosts = [
    host.strip()
    for host in settings.trusted_hosts.split(",")
    if host.strip()
]

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=trusted_hosts,
)

MAX_REQUEST_BODY_BYTES = 1024 * 1024  # 1 MiB


@app.middleware("http")
async def limit_request_body_size(request: Request, call_next):
    content_length = request.headers.get("content-length")

    if content_length:
        try:
            body_size = int(content_length)
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "invalid_content_length"},
            )

        if body_size > MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "request_too_large"},
            )

    return await call_next(request)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if settings.environment.lower() == "prod":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def trace_id() -> str:
    return uuid.uuid4().hex


def _header_value(request: Request, configured_name: str) -> Optional[str]:
    return request.headers.get(configured_name)


def cache_get(key: str) -> Optional[dict]:
    hit = decision_cache.get(key)
    if not hit:
        CACHE_COUNTER.labels(result="miss").inc()
        return None
    expires_at, value = hit
    if time.time() > expires_at:
        decision_cache.pop(key, None)
        CACHE_COUNTER.labels(result="expired").inc()
        return None
    CACHE_COUNTER.labels(result="hit").inc()
    return value


def cache_set(key: str, value: dict) -> None:
    decision_cache[key] = (time.time() + settings.request_cache_ttl_seconds, value)


def get_client(request: Request, db: Session = Depends(get_db)) -> ClientCredential:
    x_client_id = _header_value(request, settings.client_id_header)
    x_api_key = _header_value(request, settings.api_key_header)
    x_tenant_id = _header_value(request, settings.tenant_id_header)
    if not x_client_id or not x_api_key or not x_tenant_id:
        AUTH_FAILURE_COUNTER.labels(reason="missing_headers").inc()
        raise HTTPException(status_code=401, detail="missing_client_headers")
    stmt = select(ClientCredential).where(
        ClientCredential.tenant_id == x_tenant_id,
        ClientCredential.client_id == x_client_id,
        ClientCredential.enabled.is_(True),
    )
    client = db.scalar(stmt)
    hashed = hash_secret(x_api_key)
    if not client or not constant_time_equals(client.api_key_hash, hashed):
        AUTH_FAILURE_COUNTER.labels(reason="invalid_client").inc()
        raise HTTPException(status_code=401, detail="invalid_client")
    return client


def get_admin(request: Request) -> str:
    admin_key = _header_value(request, settings.admin_api_key_header)
    if not admin_key or not constant_time_equals(hash_secret(admin_key), hash_secret(settings.admin_api_key)):
        AUTH_FAILURE_COUNTER.labels(reason="invalid_admin").inc()
        raise HTTPException(status_code=401, detail="invalid_admin")
    return admin_key


def enforce_tenant_quota(tenant: Tenant) -> None:
    if tenant.usage_count >= tenant.monthly_quota:
        raise HTTPException(status_code=429, detail="tenant_quota_exceeded")


def emit_event(db: Session, tenant_id: str, event_type: str, payload: dict) -> None:
    db.add(OutboxEvent(tenant_id=tenant_id, event_type=event_type, payload=json.dumps(payload), delivered=False))


def commit_or_409(db: Session, detail: str = "already_exists") -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        logger.info("integrity_conflict", extra={"status_code": 409})
        raise HTTPException(status_code=409, detail=detail) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        logger.exception("database_write_unavailable", extra={"status_code": 503})
        raise HTTPException(status_code=503, detail="persistence_unavailable") from exc



@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok", "app": settings.app_name}


@app.get("/readyz")
def readyz(db: Session = Depends(get_db)) -> dict:
    db.execute(select(Tenant).limit(1))
    redis_ok = False
    if redis_client:
        try:
            redis_ok = bool(redis_client.ping())
        except RedisError:
            redis_ok = False
    return {"status": "ready", "redis": redis_ok, "database": True}


@app.get("/metrics")
def metrics_endpoint(
    request: Request,
    db: Session = Depends(get_db),
):
    if settings.environment.lower() == "prod":
        supplied_key = request.headers.get("X-Metrics-API-Key", "")
        if not settings.metrics_api_key or not constant_time_equals(
            hash_secret(supplied_key),
            hash_secret(settings.metrics_api_key),
        ):
            raise HTTPException(status_code=401, detail="invalid_metrics_key")

    pending_count = db.scalar(
        select(func.count())
        .select_from(OutboxEvent)
        .where(
            OutboxEvent.delivered.is_(False),
            OutboxEvent.dead_lettered.is_(False),
        )
    )

    dead_letter_count = db.scalar(
        select(func.count())
        .select_from(OutboxEvent)
        .where(OutboxEvent.dead_lettered.is_(True))
    )

    OUTBOX_PENDING_GAUGE.set(pending_count or 0)
    OUTBOX_DEAD_LETTER_GAUGE.set(dead_letter_count or 0)

    return metrics_response()


@app.post("/admin/tenants")
def create_tenant(payload: TenantCreate, _: str = Depends(get_admin), db: Session = Depends(get_db)):
    tenant = Tenant(id=payload.tenant_id, name=payload.name, plan=payload.plan, monthly_quota=payload.monthly_quota)
    db.add(tenant)
    commit_or_409(db, detail="tenant_exists")
    return {"tenant_id": tenant.id, "plan": tenant.plan}


@app.post("/admin/clients")
def create_client(payload: ClientCreate, _: str = Depends(get_admin), db: Session = Depends(get_db)):
    if not db.get(Tenant, payload.tenant_id):
        raise HTTPException(status_code=404, detail="tenant_not_found")
    client = ClientCredential(tenant_id=payload.tenant_id, client_id=payload.client_id, api_key_hash=hash_secret(payload.api_key))
    db.add(client)
    commit_or_409(db, detail="client_exists")
    return {"tenant_id": payload.tenant_id, "client_id": payload.client_id}

@app.post("/admin/policies/simulate")
def simulate_policy(
    payload: PolicySimulationRequest,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    if not db.get(Tenant, payload.tenant_id):
        raise HTTPException(
            status_code=404,
            detail="tenant_not_found",
        )

    engine = load_tenant_policies(
        db,
        payload.tenant_id,
    )

    simulation = engine.simulate(
        request_type=payload.request_type,
        device_id=payload.device_id,
        country_code=payload.country_code,
        risk_score=payload.risk_score,
        trust_score=payload.trust_score,
    )

    return {
        "matched": simulation.matched,
        "allow": simulation.decision.allow,
        "reason": simulation.decision.reason,
        "policy_name": simulation.policy_name,
        "policy_version": simulation.policy_version,
        "evaluated_policies": simulation.evaluated_policies,
    }

@app.put("/admin/workflow-config")
def update_workflow_config(
    payload: WorkflowConfigUpdate,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    if not db.get(Tenant, payload.tenant_id):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    record = db.get(WorkflowConfigRecord, payload.tenant_id)

    if record is None:
        record = WorkflowConfigRecord(
            tenant_id=payload.tenant_id,
            include_risk_step=payload.include_risk_step,
            include_policy_step=payload.include_policy_step,
            execution_mode=payload.execution_mode,
        )
        db.add(record)
    else:

        save_workflow_config_history(db, record)
        record.include_risk_step = payload.include_risk_step
        record.include_policy_step = payload.include_policy_step
        record.execution_mode = payload.execution_mode
        record.version += 1

    db.commit()
    db.refresh(record)

    return {
        "tenant_id": record.tenant_id,
        "include_risk_step": record.include_risk_step,
        "include_policy_step": record.include_policy_step,
        "execution_mode": record.execution_mode,
        "version": record.version,
    }

@app.get("/admin/workflow-config/{tenant_id}")
def get_workflow_config(
    tenant_id: str,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    if not db.get(Tenant, tenant_id):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    record = db.get(WorkflowConfigRecord, tenant_id)

    if record is None:
        return {
            "tenant_id": tenant_id,
            "include_risk_step": True,
            "include_policy_step": True,
            "execution_mode": "risk_first",
            "version": 1,
        }

    return {
        "tenant_id": record.tenant_id,
        "include_risk_step": record.include_risk_step,
        "include_policy_step": record.include_policy_step,
        "execution_mode": record.execution_mode,
        "version": record.version,
    }

@app.get("/admin/workflow-config/{tenant_id}/history")
def get_workflow_config_history(
    tenant_id: str,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    if not db.get(Tenant, tenant_id):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    history = (
        db.query(WorkflowConfigHistory)
        .filter_by(tenant_id=tenant_id)
        .order_by(WorkflowConfigHistory.version.asc())
        .all()
    )

    return [
        {
            "id": item.id,
            "tenant_id": item.tenant_id,
            "version": item.version,
            "include_risk_step": item.include_risk_step,
            "include_policy_step": item.include_policy_step,
            "execution_mode": item.execution_mode,
            "created_at": item.created_at,
        }
        for item in history
    ]

@app.post("/admin/policies")
def create_policy(
    payload: PolicyCreate,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    if not db.get(Tenant, payload.tenant_id):
        raise HTTPException(status_code=404, detail="tenant_not_found")

    policy = PolicyRecord(
        tenant_id=payload.tenant_id,
        name=payload.name,
        effect=payload.effect,
        priority=payload.priority,
        request_types=",".join(payload.request_types),
        countries=",".join(payload.countries),
        device_ids=",".join(payload.device_ids),
        max_risk_score=payload.max_risk_score,
        min_trust_score=payload.min_trust_score,
        max_transaction_amount=payload.max_transaction_amount,
        allowed_start_hour=payload.allowed_start_hour,
        allowed_end_hour=payload.allowed_end_hour,
        enabled=payload.enabled,
        valid_from=payload.valid_from,
        expires_at=payload.expires_at,
    )

    db.add(policy)
    commit_or_409(db, detail="policy_exists")

    return {
        "id": policy.id,
        "tenant_id": policy.tenant_id,
        "name": policy.name,
        "effect": policy.effect,
        "priority": policy.priority,
        "version": policy.version,
        "request_types": payload.request_types,
        "countries": payload.countries,
        "device_ids": payload.device_ids,
        "max_risk_score": policy.max_risk_score,
        "min_trust_score": policy.min_trust_score,
        "max_transaction_amount": policy.max_transaction_amount,
        "allowed_start_hour": policy.allowed_start_hour,
        "allowed_end_hour": policy.allowed_end_hour,
        "enabled": policy.enabled,
    }

@app.patch("/admin/policies/{policy_id}")
def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    policy = db.get(PolicyRecord, policy_id)

    if not policy:
        raise HTTPException(status_code=404, detail="policy_not_found")
    
    save_policy_history(db, policy)

    if payload.effect is not None:
        policy.effect = payload.effect

    if payload.priority is not None:
        policy.priority = payload.priority

    if payload.request_types is not None:
        policy.request_types = ",".join(payload.request_types)

    if payload.countries is not None:
        policy.countries = ",".join(payload.countries)

    if payload.device_ids is not None:
        policy.device_ids = ",".join(payload.device_ids)

    if payload.max_risk_score is not None:
        policy.max_risk_score = payload.max_risk_score

    if payload.min_trust_score is not None:
        policy.min_trust_score = payload.min_trust_score
    
    if payload.max_transaction_amount is not None:
        policy.max_transaction_amount = payload.max_transaction_amount

    if payload.allowed_start_hour is not None:
        policy.allowed_start_hour = payload.allowed_start_hour

    if payload.allowed_end_hour is not None:
        policy.allowed_end_hour = payload.allowed_end_hour

    if payload.enabled is not None:
        policy.enabled = payload.enabled

    if payload.valid_from is not None:
        policy.valid_from = payload.valid_from

    if payload.expires_at is not None:
        policy.expires_at = payload.expires_at

    policy.version += 1

    db.commit()
    db.refresh(policy)

    return {
        "id": policy.id,
        "tenant_id": policy.tenant_id,
        "name": policy.name,
        "effect": policy.effect,
        "priority": policy.priority,
        "version": policy.version,
        "request_types": [
            value.strip()
            for value in policy.request_types.split(",")
            if value.strip()
        ],
        "countries": [
            value.strip()
            for value in policy.countries.split(",")
            if value.strip()
        ],
        "device_ids": [
            value.strip()
            for value in policy.device_ids.split(",")
            if value.strip()
        ],
        "max_risk_score": policy.max_risk_score,
        "min_trust_score": policy.min_trust_score,
        "max_transaction_amount": policy.max_transaction_amount,
        "allowed_start_hour": policy.allowed_start_hour,
        "allowed_end_hour": policy.allowed_end_hour,
        "enabled": policy.enabled,
    }

@app.get("/admin/policies")
def list_policies(
    tenant_id: str,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    policies = (
        db.query(PolicyRecord)
        .filter_by(tenant_id=tenant_id)
        .order_by(PolicyRecord.priority.asc(), PolicyRecord.id.asc())
        .all()
    )

    return [
        {
            "id": policy.id,
            "tenant_id": policy.tenant_id,
            "name": policy.name,
            "effect": policy.effect,
            "priority": policy.priority,
            "version": policy.version,
            "request_types": [
                value.strip()
                for value in policy.request_types.split(",")
                if value.strip()
            ],
            "countries": [
                value.strip()
                for value in policy.countries.split(",")
                if value.strip()
            ],
            "device_ids": [
                value.strip()
                for value in policy.device_ids.split(",")
                if value.strip()
            ],
            "max_risk_score": policy.max_risk_score,
            "min_trust_score": policy.min_trust_score,
            "max_transaction_amount": policy.max_transaction_amount,
            "allowed_start_hour": policy.allowed_start_hour,
            "allowed_end_hour": policy.allowed_end_hour,
            "enabled": policy.enabled,
            "valid_from": policy.valid_from,
            "expires_at": policy.expires_at,
        }
        for policy in policies
    ]


@app.delete("/admin/policies/{policy_id}")
def delete_policy(
    policy_id: int,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    policy = db.get(PolicyRecord, policy_id)

    if not policy:
        raise HTTPException(status_code=404, detail="policy_not_found")

    save_policy_history(db, policy)  
    db.delete(policy)
    db.commit()

    return {
        "deleted": True,
        "policy_id": policy_id,
    }
@app.get("/admin/policies/{policy_id}/history")
def get_policy_history(
    policy_id: int,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    policy = db.get(PolicyRecord, policy_id)

    if not policy:
        raise HTTPException(status_code=404, detail="policy_not_found")

    history = (
        db.query(PolicyHistory)
        .filter_by(policy_id=policy_id)
        .order_by(PolicyHistory.version.asc())
        .all()
    )

    return [
        {
            "id": item.id,
            "policy_id": item.policy_id,
            "tenant_id": item.tenant_id,
            "policy_name": item.policy_name,
            "version": item.version,
            "effect": item.effect,
            "priority": item.priority,
            "request_types": [
                value.strip()
                for value in item.request_types.split(",")
                if value.strip()
            ],
            "countries": [
                value.strip()
                for value in item.countries.split(",")
                if value.strip()
            ],
            "device_ids": [
                value.strip()
                for value in item.device_ids.split(",")
                if value.strip()
            ],
            "max_risk_score": item.max_risk_score,
            "min_trust_score": item.min_trust_score,
            "max_transaction_amount": item.max_transaction_amount,
            "allowed_start_hour": item.allowed_start_hour,
            "allowed_end_hour": item.allowed_end_hour,
            "enabled": item.enabled,
        }
        for item in history
    ]
def load_risk_history(
    db: Session,
    tenant_id: str,
    right_id: str,
    *,
    before: datetime | None = None,
) -> list[RequestLog]:
    reference_time = before or utcnow_naive()
    one_hour_ago = reference_time - timedelta(hours=1)

    conditions = [
        RequestLog.tenant_id == tenant_id,
        RequestLog.right_id == right_id,
    ]

    if before is not None:
        conditions.append(RequestLog.created_at < before)

    recent_by_time = list(
        db.scalars(
            select(RequestLog)
            .where(
                *conditions,
                RequestLog.created_at >= one_hour_ago,
            )
            .order_by(
                desc(RequestLog.created_at),
                desc(RequestLog.id),
            )
        )
    )

    latest_ten = list(
        db.scalars(
            select(RequestLog)
            .where(*conditions)
            .order_by(
                desc(RequestLog.created_at),
                desc(RequestLog.id),
            )
            .limit(10)
        )
    )

    logs_by_id = {log.id: log for log in recent_by_time}
    for log in latest_ten:
        logs_by_id[log.id] = log

    return list(logs_by_id.values())

@app.post("/admin/devices")
def create_device(payload: DeviceCreate, db: Session = Depends(get_db), client: ClientCredential = Depends(get_client)):
    if client.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    if not db.get(Tenant, payload.tenant_id):
        raise HTTPException(status_code=404, detail="tenant_not_found")
    device = Device(tenant_id=payload.tenant_id, device_id=payload.device_id, description=payload.description)
    db.add(device)
    commit_or_409(db, detail="device_exists")
    return {"device_id": payload.device_id}


@app.post("/rights/create")
def create_right(payload: AccessRightCreate, db: Session = Depends(get_db), client: ClientCredential = Depends(get_client)):
    if client.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    if not db.get(Tenant, payload.tenant_id):
        raise HTTPException(status_code=404, detail="tenant_not_found")
    right = AccessRight(tenant_id=payload.tenant_id, right_id=payload.right_id, owner_id=payload.owner_id, valid=payload.valid)
    db.add(right)
    commit_or_409(db, detail="right_exists")
    return {"right_id": payload.right_id, "owner_id": payload.owner_id, "valid": payload.valid}


@app.post("/rights/revoke")
def revoke_right(
    payload: AccessRightRevoke,
    db: Session = Depends(get_db),
    client: ClientCredential = Depends(get_client),
):
    if client.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    right = db.scalar(
        select(AccessRight).where(
            AccessRight.tenant_id == payload.tenant_id,
            AccessRight.right_id == payload.right_id,
        )
    )

    if not right:
        raise HTTPException(status_code=404, detail="right_not_found")

    if not right.valid:
        return {
            "right_id": right.right_id,
            "valid": False,
            "version": right.version,
        }

    right.valid = False
    right.version += 1

    emit_event(
        db,
        payload.tenant_id,
        "right.revoked",
        {
            "right_id": right.right_id,
            "owner_id": right.owner_id,
            "version": right.version,
        },
    )

    commit_or_409(db, detail="right_revoke_failed")

    return {
        "right_id": right.right_id,
        "valid": right.valid,
        "version": right.version,
    }

@app.post("/token/issue")
def token_issue(payload: TokenIssueRequest, db: Session = Depends(get_db), client: ClientCredential = Depends(get_client)):
    if client.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    device = db.scalar(select(Device).where(Device.tenant_id == payload.tenant_id, Device.device_id == payload.device_id))
    if not device:
        raise HTTPException(status_code=404, detail="device_not_found")
    right = db.scalar(select(AccessRight).where(AccessRight.tenant_id == payload.tenant_id, AccessRight.right_id == payload.right_id))
    validate_token_issue_inputs(device=device, right=right, requested_user_id=payload.user_id)
    enforce_right_owner(right, payload.user_id)
    token = issue_access_token(
        tenant_id=payload.tenant_id,
        right_id=payload.right_id,
        user_id=payload.user_id,
        device_id=payload.device_id,
        scope=payload.scope,
    )
    return {"token": token}

@app.post("/request/access", response_model=DecisionResponse)
def request_access(payload: AccessRequest, request: Request, db: Session = Depends(get_db), client: ClientCredential = Depends(get_client)):
    started = time.perf_counter()
    trace = trace_id()
    user_agent = request.headers.get("user-agent", "")[:512]

    pseudonymized_ip = pseudonymize_ip(payload.ip_address)

    if not rate_limiter.allow(f"client:{client.tenant_id}:{client.client_id}", settings.rate_limit_per_minute):
        RATE_LIMIT_COUNTER.labels(scope="client").inc()
        raise HTTPException(status_code=429, detail="rate_limited")
    if not rate_limiter.allow(f"rl:tenant:{client.tenant_id}:ip:{pseudonymized_ip}", settings.rate_limit_per_minute):
        RATE_LIMIT_COUNTER.labels(scope="ip").inc()
        raise HTTPException(status_code=429, detail="rate_limited")

    device = db.scalar(
        select(Device).where(
            Device.tenant_id == client.tenant_id,
            Device.device_id == payload.device_id,
        )
    )

    if not device:
        raise HTTPException(status_code=404, detail="device_not_found")

    try:
       claims = decode_access_token(payload.token)
    except jwt.ExpiredSignatureError as exc:
        AUTH_FAILURE_COUNTER.labels(reason="token_expired").inc()
        raise HTTPException(status_code=401, detail="token_expired") from exc
    except jwt.InvalidTokenError as exc:
        AUTH_FAILURE_COUNTER.labels(reason="invalid_token").inc()
        raise HTTPException(status_code=401, detail="invalid_token") from exc

    if claims["tenant_id"] != client.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")

    if claims["device_id"] != payload.device_id:
        raise HTTPException(status_code=403, detail="device_mismatch")

    if claims["scope"] != payload.request_type:
        raise HTTPException(status_code=403, detail="scope_mismatch")

    replay_ttl = max(int(claims.get("exp", 0)) - int(time.time()), 1)
    replay_jti = claims.get("jti") or "missing-jti"
    if not replay_store.mark_if_first_seen(tenant_id=claims["tenant_id"], jti=replay_jti, ttl_seconds=replay_ttl):
        raise HTTPException(status_code=409, detail="replay_detected")

    tenant = db.get(Tenant, claims["tenant_id"])
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    enforce_tenant_quota(tenant)

    right = db.scalar(select(AccessRight).where(AccessRight.tenant_id == tenant.id, AccessRight.right_id == claims["right_id"]))
    if not right or not right.valid:
        raise HTTPException(status_code=404, detail="access_right_invalid")
    enforce_right_owner(right, claims["sub"])

    fingerprint = build_request_fingerprint(
        {
            "tenant_id": tenant.id,
            "right_id": claims["right_id"],
            "request_type": payload.request_type,
            "device_id": payload.device_id,
            "ip_address": pseudonymized_ip,
            "country_code": payload.country_code,
            "new_owner_id": payload.new_owner_id,
            "token_jti": claims.get("jti"),
        }
    )
    idempotency_key = request.headers.get("Idempotency-Key") or fingerprint

    existing_log = db.scalar(select(RequestLog).where(RequestLog.tenant_id == tenant.id, RequestLog.idempotency_key == idempotency_key))
    if existing_log:
        return DecisionResponse(
            allow=existing_log.allowed,
            reason=existing_log.reason,
            risk_score=existing_log.risk_score,
            trace_id=existing_log.trace_id,
            decision_version=existing_log.decision_version,
            idempotency_key=existing_log.idempotency_key,
        )

    cache_payload = payload.model_copy(update={"ip_address": pseudonymized_ip})
    cache_key = build_cache_key(client.tenant_id, cache_payload, right.version)
    if payload.request_type == "access":
        cached = cache_get(cache_key)
        if cached:
            return DecisionResponse(**cached)

    history = load_risk_history(
        db,
        tenant.id,
        right.right_id,
    )
    decision = risk_engine.evaluate(
        request_type=payload.request_type,
        device_id=payload.device_id,
        ip_address=pseudonymized_ip,
        country_code=payload.country_code,
        historical_logs=history,
    )

    allowed = decision.allow
    reason = decision.reason

    tenant_policy_engine = load_tenant_policies(db, tenant.id)

    policy_decision = tenant_policy_engine.evaluate(
        request_type=payload.request_type,
        device_id=payload.device_id,
        country_code=payload.country_code,
        risk_score=decision.risk_score,
        trust_score=decision.trust_score,
        context={
            "now": utcnow_naive(),
            "hour": utcnow_naive().hour,
            "transaction_amount": payload.transaction_amount,
        },
    )

    allowed = workflow_engine.resolve_allowed(
        risk_allowed=decision.allow,
        policy_matched=policy_decision.matched,
        policy_allowed=policy_decision.allow,
    )

    if policy_decision.matched:
        if not decision.allow:
            reason = decision.reason
        else:
            reason = policy_decision.reason

    if payload.request_type == "ownership_transfer":
        if not payload.new_owner_id:
            allowed = False
            reason = "missing_new_owner_id"
        elif payload.new_owner_id == right.owner_id:
            allowed = False
            reason = "same_owner"

    if allowed:
        right.last_used_at = utcnow_naive()
        if payload.request_type == "ownership_transfer":
            right.owner_id = payload.new_owner_id or right.owner_id
            right.owner_change_count += 1
            right.version += 1

    workflow_config_record = db.get(WorkflowConfigRecord, tenant.id)
    
    log = RequestLog(
        tenant_id=tenant.id,
        right_id=right.right_id,
        client_id=client.client_id,
        source_client=client.client_id,
        device_id=payload.device_id,
        user_id=claims["sub"],
        ip_hash=pseudonymized_ip,
        country_code=payload.country_code,
        request_type=payload.request_type,
        transaction_amount=payload.transaction_amount,
        new_owner_id=payload.new_owner_id,
        allowed=allowed,
        risk_score=decision.risk_score,
        reason=reason,
        risk_signals=",".join(decision.signals),
        policy_matched=policy_decision.matched,
        policy_name=policy_decision.policy_name,
        policy_id=policy_decision.policy_id,
        policy_version=policy_decision.policy_version,
        trace_id=trace,
        idempotency_key=idempotency_key,
        token_jti=claims.get("jti"),
        request_fingerprint=fingerprint,
        user_agent=user_agent,
        decision_version=settings.request_decision_version,
        workflow_version=workflow_config_record.version if workflow_config_record is not None else 1,
    )

    tenant.usage_count += 1
    db.add(log)


    emit_event(
        db,
        tenant.id,
        "decision.allowed" if allowed else "decision.denied",
        {
            "trace_id": trace,
            "right_id": right.right_id,
            "risk_score": decision.risk_score,
            "allowed": allowed,
        },
    )

    emit_event(
        db,
        tenant.id,
        "billing.usage.incremented",
        {
            "tenant_id": tenant.id,
            "usage_count": tenant.usage_count,
        },
    )

    commit_or_409(db, detail="duplicate_request")

    REQUEST_COUNTER.labels(
        tenant_id=tenant.id,
        result="allow" if allowed else "deny",
        request_type=payload.request_type,
    ).inc()

    RISK_SCORE_HISTOGRAM.observe(decision.risk_score)
    LATENCY_HISTOGRAM.observe(time.perf_counter() - started)
    
    workflow_config_record = db.get(WorkflowConfigRecord, tenant.id)

    if workflow_config_record is not None:
        request_workflow_engine = WorkflowEngine(
            WorkflowConfig(
                include_risk_step=workflow_config_record.include_risk_step,
                include_policy_step=workflow_config_record.include_policy_step,
                execution_mode=workflow_config_record.execution_mode,
            )
        )
    else:
        request_workflow_engine = workflow_engine

    workflow_decision = request_workflow_engine.evaluate(
        risk_allowed=decision.allow,
        policy_matched=policy_decision.matched,
        policy_allowed=policy_decision.allow,
        final_allowed=allowed,
    )

    response = {
        "allow": allowed,
        "reason": reason,
        "risk_score": decision.risk_score,
        "trust_score": decision.trust_score,
        "risk_signals": list(decision.signals),
        "explanation": {
        "risk": {
            "score": decision.risk_score,
            "trust_score": decision.trust_score,
            "signals": list(decision.signals),
            "total_contribution": sum(RISK_SIGNAL_SCORES.get(signal, 0) for signal in decision.signals),
            "contributors": [
                {
                    "signal": signal,
                    "score": RISK_SIGNAL_SCORES.get(signal, 0),
                }
                for signal in decision.signals    
            ],
            "reason": decision.reason,
        },
        "policy": {
                "matched": policy_decision.matched,
                "name": policy_decision.policy_name,
                "version": policy_decision.policy_version,
                "reason": policy_decision.reason,
            },

    "final": {
        "allow": allowed,
        "reason": reason,
        "decision_source": workflow_decision.decision_source,
        "decision_path": list(workflow_decision.decision_path),
        "workflow_version": workflow_config_record.version if workflow_config_record is not None else 1,
    },
  
        },
        "trace_id": trace,
        "decision_version": settings.request_decision_version,
        "workflow_version": workflow_config_record.version if workflow_config_record is not None else 1,
        "idempotency_key": idempotency_key,
        "policy_matched": policy_decision.matched,
        "policy_name": policy_decision.policy_name,
    }

    if payload.request_type == "access" and allowed:
        cache_set(cache_key, response)

    return DecisionResponse(**response)


@app.post("/webhooks/subscriptions")
def create_webhook(payload: WebhookCreate, db: Session = Depends(get_db), client: ClientCredential = Depends(get_client)):
    if client.tenant_id != payload.tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    active_kid, _ = get_active_signing_key()
    sub = WebhookSubscription(
        tenant_id=payload.tenant_id,
        target_url=str(payload.target_url),
        event_type=payload.event_type,
        signing_secret_hash=hash_with_pepper(payload.signing_secret, settings.webhook_secret_pepper),
        signing_secret_encrypted=encrypt_secret(payload.signing_secret),
        signing_secret_key_version=active_kid,
    )
    db.add(sub)
    db.commit()
    return {"subscription_id": sub.id}


@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, _: str = Depends(get_admin), db: Session = Depends(get_db)):
    tenants = list(db.scalars(select(Tenant).order_by(Tenant.created_at.desc())))
    events = list(db.scalars(select(OutboxEvent).order_by(OutboxEvent.created_at.desc()).limit(20)))
    return templates.TemplateResponse("admin.html", {"request": request, "tenants": tenants, "events": events})


@app.get("/tenant/{tenant_id}", response_class=HTMLResponse)
def tenant_dashboard(tenant_id: str, request: Request, db: Session = Depends(get_db), client: ClientCredential = Depends(get_client)):
    if client.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="tenant_mismatch")
    tenant = db.get(Tenant, tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="tenant_not_found")
    rights = list(db.scalars(select(AccessRight).where(AccessRight.tenant_id == tenant_id).order_by(AccessRight.created_at.desc())))
    logs = list(db.scalars(select(RequestLog).where(RequestLog.tenant_id == tenant_id).order_by(RequestLog.created_at.desc()).limit(20)))
    return templates.TemplateResponse("tenant.html", {"request": request, "tenant": tenant, "rights": rights, "logs": logs})

def build_audit_log_query(
    tenant_id: str,
    allowed: bool | None = None,
    policy_name: str | None = None,
    policy_version: int | None = None,
    min_risk_score: int | None = None,
    risk_signal: str | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
):
    query = select(RequestLog).where(
        RequestLog.tenant_id == tenant_id
    )

    if policy_version is not None:
        query = query.where(
            RequestLog.policy_version == policy_version
        )

    if allowed is not None:
        query = query.where(
            RequestLog.allowed == allowed
        )

    if policy_name is not None:
        query = query.where(
            RequestLog.policy_name == policy_name
        )

    if min_risk_score is not None:
        query = query.where(
            RequestLog.risk_score >= min_risk_score
        )

    if risk_signal is not None:
        query = query.where(
            RequestLog.risk_signals.contains(risk_signal)
        )

    if from_time is not None:
        query = query.where(
            RequestLog.created_at >= from_time
        )

    if to_time is not None:
        query = query.where(
            RequestLog.created_at <= to_time
        )

    return query

@app.get("/admin/audit/logs")
def get_audit_logs(
    tenant_id: str,
    allowed: bool | None = None,
    policy_name: str | None = None,
    policy_version: int | None = None,
    min_risk_score: int | None = None,
    risk_signal: str | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
    limit: int = 100,
    offset: int = 0,
):
    limit = max(1, min(limit, 500))
    offset = max(0, offset)

    query = build_audit_log_query(
        tenant_id=tenant_id,
        allowed=allowed,
        policy_name=policy_name,
        policy_version=policy_version,
        min_risk_score=min_risk_score,
        risk_signal=risk_signal,
        from_time=from_time,
        to_time=to_time,
    )

    query = (
        query
        .order_by(RequestLog.created_at.desc())
        .offset(offset)
        .limit(limit)
    )

    logs = list(db.scalars(query))

    return [
        {
            "id": log.id,
            "tenant_id": log.tenant_id,
            "right_id": log.right_id,
            "device_id": log.device_id,
            "request_type": log.request_type,
            "transaction_amount": log.transaction_amount,
            "new_owner_id": log.new_owner_id,
            "allowed": log.allowed,
            "risk_score": log.risk_score,
            "risk_signals": log.risk_signals,
            "reason": log.reason,
            "policy_matched": log.policy_matched,
            "policy_name": log.policy_name,
            "policy_id": log.policy_id,
            "policy_version": log.policy_version,
            "workflow_version": log.workflow_version,
            "trace_id": log.trace_id,
            "created_at": log.created_at,
        }
        for log in logs
    ]

@app.get("/admin/audit/logs/{log_id}/replay")
def replay_audit_log(
    log_id: int,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    log = db.get(RequestLog, log_id)

    if log is None:
        raise HTTPException(status_code=404, detail="request_log_not_found")

    workflow = None
    if log.workflow_version is not None:
        workflow = load_workflow_config_version(
            db,
            log.tenant_id,
            log.workflow_version,
        )
        if workflow is None:
            raise HTTPException(
                status_code=409,
                detail="historical_workflow_version_not_found",
            )

    policy = None

    if (log.policy_id is None) != (log.policy_version is None):
        raise HTTPException(
            status_code=409,
            detail="historical_policy_reference_incomplete",
        )

    if log.policy_id is not None and log.policy_version is not None:
        policy = load_policy_version(
            db,
            log.tenant_id,
            log.policy_id,
            log.policy_version,
        )
        if policy is None:
            raise HTTPException(
                status_code=409,
                detail="historical_policy_version_not_found",
            )
    historical_logs = load_risk_history(
        db,
        log.tenant_id,
        log.right_id,
        before=log.created_at,
    )

    replay_risk = risk_engine.evaluate(
        request_type=log.request_type,
        device_id=log.device_id,
        ip_address=log.ip_hash,
        country_code=log.country_code,
        historical_logs=historical_logs,
        now=log.created_at,
    )

    replay_policy_engine = PolicyEngine(
        [policy] if policy is not None else []
    )

    replay_policy = replay_policy_engine.evaluate(
        request_type=log.request_type,
        device_id=log.device_id,
        country_code=log.country_code,
        risk_score=replay_risk.risk_score,
        trust_score=replay_risk.trust_score,
        context={
            "now": log.created_at,
            "hour": log.created_at.hour,
            "transaction_amount": log.transaction_amount,
        },
    )

    replay_workflow_engine = WorkflowEngine(
        workflow or WorkflowConfig()
    )

    replay_allowed = replay_workflow_engine.resolve_allowed(
        risk_allowed=replay_risk.allow,
        policy_matched=replay_policy.matched,
        policy_allowed=replay_policy.allow,
    )

    replay_reason = replay_risk.reason

    if replay_policy.matched:
        if not replay_risk.allow:
            replay_reason = replay_risk.reason
        else:
            replay_reason = replay_policy.reason

    return {
        "log_id": log.id,
        "trace_id": log.trace_id,
        "tenant_id": log.tenant_id,
        "request": {
            "request_type": log.request_type,
            "device_id": log.device_id,
            "country_code": log.country_code,
            "transaction_amount": log.transaction_amount,
            "new_owner_id": log.new_owner_id,
        },
        "original_decision": {
            "allowed": log.allowed,
            "reason": log.reason,
            "risk_score": log.risk_score,
            "risk_signals": log.risk_signals,
            "decision_version": log.decision_version,
        },
        "original": {
            "allow": log.allowed,
            "reason": log.reason,
            "risk_score": log.risk_score,
            "risk_signals": log.risk_signals,
            "decision_version": log.decision_version,
        },
        "replayed": {
            "allow": replay_allowed,
            "reason": replay_reason,
            "risk_score": replay_risk.risk_score,
            "risk_signals": list(replay_risk.signals),
            "policy_matched": replay_policy.matched,
            "policy_id": replay_policy.policy_id,
            "policy_version": replay_policy.policy_version,
        },
        "comparison": {
            "decision_match": replay_allowed == log.allowed,
            "risk_score_match": replay_risk.risk_score == log.risk_score,
            "reason_match": replay_reason == log.reason,
            "risk_signals_match": list(replay_risk.signals)
            == [signal for signal in log.risk_signals.split(",") if signal],
            "policy_match": replay_policy.policy_id == log.policy_id,
            "policy_version_match": replay_policy.policy_version == log.policy_version,
          "all_match": (
              replay_allowed == log.allowed
              and replay_risk.risk_score == log.risk_score
              and replay_reason == log.reason
              and list(replay_risk.signals)
              == [signal for signal in log.risk_signals.split(",") if signal]
              and replay_policy.policy_id == log.policy_id
              and replay_policy.policy_version == log.policy_version
            ),
        },

        "workflow": None if workflow is None else {
            "version": log.workflow_version,
            "include_risk_step": workflow.include_risk_step,
            "include_policy_step": workflow.include_policy_step,
            "execution_mode": workflow.execution_mode,
        },
        "policy": None if policy is None else {
            "policy_id": policy.policy_id,
            "version": policy.version,
            "name": policy.name,
            "effect": policy.effect,
            "priority": policy.priority,
            "request_types": list(policy.request_types),
            "countries": list(policy.countries),
            "device_ids": list(policy.device_ids),
            "max_risk_score": policy.max_risk_score,
            "min_trust_score": policy.min_trust_score,
            "max_transaction_amount": policy.max_transaction_amount,
            "allowed_start_hour": policy.allowed_start_hour,
            "allowed_end_hour": policy.allowed_end_hour,
        },
    }

@app.get("/admin/audit/logs/count")
def get_audit_log_count(
    tenant_id: str,
    allowed: bool | None = None,
    policy_name: str | None = None,
    policy_version: int | None = None,
    min_risk_score: int | None = None,
    risk_signal: str | None = None,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    _: str = Depends(get_admin),
    db: Session = Depends(get_db),
):
    query = build_audit_log_query(
        tenant_id=tenant_id,
        allowed=allowed,
        policy_name=policy_name,
        policy_version=policy_version,
        min_risk_score=min_risk_score,
        risk_signal=risk_signal,
        from_time=from_time,
        to_time=to_time,
    )

    total = db.scalar(
        select(func.count()).select_from(query.subquery())
    )

    return {"total": total or 0}

@app.get("/")
def root():
    return JSONResponse({"name": settings.app_name, "status": "ok"})
