from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings


ROOT = Path(__file__).resolve().parents[1]

STRONG_SECRET = "s" * 32


def production_settings(**overrides):
    values = {
        "ENVIRONMENT": "prod",
        "DATABASE_URL": "postgresql://statelog:strong-db-password@db/statelog",
        "ADMIN_API_KEY": STRONG_SECRET,
        "SECRET_ENCRYPTION_KEY": STRONG_SECRET,
        "IP_HASH_PEPPER": STRONG_SECRET,
        "WEBHOOK_SECRET_PEPPER": STRONG_SECRET,
        "METRICS_API_KEY": STRONG_SECRET,
        "JWT_SECRET": STRONG_SECRET,
        "JWT_ACTIVE_KID": "v1",
        "JWT_KEYRING_JSON": "",
        "TRUSTED_HOSTS": "api.example.com",
        "FORWARDED_ALLOW_IPS": "10.0.0.10",
    }
    values.update(overrides)
    return Settings(**values)


def test_production_compose_binds_api_to_loopback_only():
    compose = (ROOT / "docker-compose.prod.yml").read_text(
        encoding="utf-8"
    )

    assert '"127.0.0.1:8000:8000"' in compose


def test_production_compose_does_not_publish_postgres():
    compose = (ROOT / "docker-compose.prod.yml").read_text(
        encoding="utf-8"
    )

    postgres_block = compose.split("postgres:", 1)[1].split(
        "redis:", 1
    )[0]

    assert "ports:" not in postgres_block


def test_production_compose_does_not_publish_redis():
    compose = (ROOT / "docker-compose.prod.yml").read_text(
        encoding="utf-8"
    )

    redis_block = compose.split("redis:", 1)[1]

    assert "ports:" not in redis_block


def test_api_entrypoint_enables_proxy_headers():
    entrypoint = (
        ROOT / "deploy" / "docker-entrypoint.sh"
    ).read_text(encoding="utf-8")

    assert "--proxy-headers" in entrypoint


def test_api_entrypoint_uses_configured_forwarded_allow_ips():
    entrypoint = (
        ROOT / "deploy" / "docker-entrypoint.sh"
    ).read_text(encoding="utf-8")

    assert "--forwarded-allow-ips=" in entrypoint
    assert "FORWARDED_ALLOW_IPS" in entrypoint


def test_production_rejects_empty_forwarded_allow_ips():
    with pytest.raises(
        ValidationError,
        match="FORWARDED_ALLOW_IPS must contain at least one trusted proxy in production",
    ):
        production_settings(
            FORWARDED_ALLOW_IPS="",
        )


def test_production_rejects_forwarded_allow_ips_wildcard():
    with pytest.raises(
        ValidationError,
        match="FORWARDED_ALLOW_IPS wildcard is not allowed in production",
    ):
        production_settings(
            FORWARDED_ALLOW_IPS="*",
        )

def test_dockerfile_copies_application_once():
    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert dockerfile.count("COPY . .") == 1


def test_dockerfile_sets_non_root_user_once():
    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert dockerfile.count("USER app") == 1


def test_dockerfile_has_single_default_command():
    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert dockerfile.count('CMD ["/app/deploy/docker-entrypoint.sh"]') == 1


def test_dockerfile_runs_as_non_root_user():
    dockerfile = (ROOT / "deploy" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "USER app" in dockerfile
    assert "USER root" not in dockerfile


def test_api_entrypoint_runs_database_migrations():
    entrypoint = (
        ROOT / "deploy" / "docker-entrypoint.sh"
    ).read_text(encoding="utf-8")

    assert "alembic upgrade head" in entrypoint


def test_worker_entrypoint_does_not_run_database_migrations():
    entrypoint = (
        ROOT / "deploy" / "worker-entrypoint.sh"
    ).read_text(encoding="utf-8")

    assert "alembic upgrade head" not in entrypoint


def test_worker_entrypoint_runs_outbox_worker():
    entrypoint = (
        ROOT / "deploy" / "worker-entrypoint.sh"
    ).read_text(encoding="utf-8")

    assert "exec python -m app.outbox_worker" in entrypoint


def test_app_and_worker_keep_runtime_hardening():
    compose = (ROOT / "docker-compose.prod.yml").read_text(
        encoding="utf-8"
    )

    assert compose.count("read_only: true") >= 2
    assert compose.count("no-new-privileges:true") >= 2
    assert compose.count("cap_drop:") >= 2
    assert compose.count("- ALL") >= 2

def test_worker_waits_for_app_health_before_starting():
    compose = (ROOT / "docker-compose.prod.yml").read_text(
        encoding="utf-8"
    )

    worker_block = compose.split("worker:", 1)[1].split(
        "postgres:",
        1,
    )[0]

    assert "app:" in worker_block
    assert "condition: service_healthy" in worker_block