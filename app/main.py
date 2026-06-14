from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from starlette.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .logging_setup import configure_logging
from .metrics import (
    AUTH_FAILURE_COUNTER,
    CACHE_COUNTER,
    LATENCY_HISTOGRAM,
    RATE_LIMIT_COUNTER,
    REQUEST_COUNTER,
    RISK_SCORE_HISTOGRAM,
    metrics_response,
)
from .models import AccessRight, ClientCredential, Device, OutboxEvent, RequestLog, Tenant, WebhookDeliveryAttempt, WebhookSubscription
from .rate_limit import HybridRateLimiter
from .replay_protection import HybridReplayStore
from .risk_engine import RiskEngine
from .schemas import (
    AccessRequest,
    AccessRightCreate,
    ClientCreate,
    DecisionResponse,
    DeviceCreate,
    TenantCreate,
    TokenIssueRequest,
    WebhookCreate,
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
decision_cache: dict[str, tuple[float, dict]] = {}

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
def metrics_endpoint(request: Request):
    if settings.environment.lower() == "prod":
        supplied_key = request.headers.get("X-Metrics-API-Key", "")
        if not settings.metrics_api_key or not constant_time_equals(hash_secret(supplied_key), hash_secret(settings.metrics_api_key)):
            raise HTTPException(status_code=401, detail="invalid_metrics_key")
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

    claims = decode_access_token(payload.token)

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

    history = list(
        db.scalars(
            select(RequestLog)
            .where(RequestLog.tenant_id == tenant.id, RequestLog.right_id == right.right_id)
            .order_by(desc(RequestLog.created_at))
            .limit(50)
        )
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
        allowed=allowed,
        risk_score=decision.risk_score,
        reason=reason,
        trace_id=trace,
        idempotency_key=idempotency_key,
        token_jti=claims.get("jti"),
        request_fingerprint=fingerprint,
        user_agent=user_agent,
        decision_version=settings.request_decision_version,
    )
    tenant.usage_count += 1
    db.add(log)
    emit_event(
        db,
        tenant.id,
        "decision.allowed" if allowed else "decision.denied",
        {"trace_id": trace, "right_id": right.right_id, "risk_score": decision.risk_score, "allowed": allowed},
    )
    emit_event(db, tenant.id, "billing.usage.incremented", {"tenant_id": tenant.id, "usage_count": tenant.usage_count})
    commit_or_409(db, detail="duplicate_request")

    REQUEST_COUNTER.labels(tenant_id=tenant.id, result="allow" if allowed else "deny", request_type=payload.request_type).inc()
    RISK_SCORE_HISTOGRAM.observe(decision.risk_score)
    LATENCY_HISTOGRAM.observe(time.perf_counter() - started)

    response = {
        "allow": allowed,
        "reason": reason,
        "risk_score": decision.risk_score,
        "trace_id": trace,
        "decision_version": settings.request_decision_version,
        "idempotency_key": idempotency_key,
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


@app.get("/")
def root():
    return JSONResponse({"name": settings.app_name, "status": "ok"})
