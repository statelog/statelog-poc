from unittest.mock import MagicMock

import pytest
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from app.main import app, redis_client
from deploy.wait_for_services import wait_for_db, wait_for_redis


def test_healthz_reports_ok(client):
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_readyz_reports_ready_when_dependencies_are_available(client, monkeypatch):
    class RedisOk:
        def ping(self):
            return True

    monkeypatch.setattr("app.main.redis_client", RedisOk())

    response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "redis": True,
        "database": True,
    }


def test_readyz_is_not_ready_when_redis_is_unavailable(client, monkeypatch):
    class RedisBroken:
        def ping(self):
            raise RedisError("redis_down")

    monkeypatch.setattr("app.main.redis_client", RedisBroken())

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["redis"] is False
    assert response.json()["database"] is True


def test_readyz_is_not_ready_when_redis_client_is_missing(client, monkeypatch):
    monkeypatch.setattr("app.main.redis_client", None)

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["redis"] is False


def test_wait_for_db_returns_when_database_is_ready(monkeypatch):
    connection = MagicMock()
    context = MagicMock()
    context.__enter__.return_value = connection
    context.__exit__.return_value = False

    engine = MagicMock()
    engine.connect.return_value = context

    monkeypatch.setattr(
        "deploy.wait_for_services.create_engine",
        lambda *args, **kwargs: engine,
    )

    wait_for_db(max_wait=1)

    connection.execute.assert_called_once()


def test_wait_for_db_raises_after_timeout(monkeypatch):
    monkeypatch.setattr(
        "deploy.wait_for_services.create_engine",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            SQLAlchemyError("db_down")
        ),
    )

    monkeypatch.setattr(
        "deploy.wait_for_services.time.sleep",
        lambda *_: None,
    )

    times = iter([0, 0, 2])

    monkeypatch.setattr(
        "deploy.wait_for_services.time.time",
        lambda: next(times, 2),
    )

    with pytest.raises(
        RuntimeError,
        match="database not ready",
    ):
        wait_for_db(max_wait=1)


def test_wait_for_redis_returns_when_redis_is_ready(monkeypatch):
    client = MagicMock()
    client.ping.return_value = True

    monkeypatch.setattr(
        "deploy.wait_for_services.Redis.from_url",
        lambda *args, **kwargs: client,
    )

    wait_for_redis(max_wait=1)

    client.ping.assert_called_once()


def test_wait_for_redis_raises_after_timeout(monkeypatch):
    client = MagicMock()
    client.ping.side_effect = RedisError("redis_down")

    monkeypatch.setattr(
        "deploy.wait_for_services.Redis.from_url",
        lambda *args, **kwargs: client,
    )

    monkeypatch.setattr(
        "deploy.wait_for_services.time.sleep",
        lambda *_: None,
    )

    times = iter([0, 0, 2])

    monkeypatch.setattr(
        "deploy.wait_for_services.time.time",
        lambda: next(times, 2),
    )

    with pytest.raises(
        RuntimeError,
        match="redis not ready",
    ):
        wait_for_redis(max_wait=1)

def test_readyz_returns_503_when_database_is_unavailable(client, monkeypatch):
    from app.database import get_db

    class BrokenDb:
        def execute(self, *args, **kwargs):
            raise SQLAlchemyError("database_down")

    def override_get_db():
        yield BrokenDb()

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.get("/readyz")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["database"] is False


def test_readyz_database_failure_does_not_claim_redis_failure(client, monkeypatch):
    from app.database import get_db

    class BrokenDb:
        def execute(self, *args, **kwargs):
            raise SQLAlchemyError("database_down")

    class RedisOk:
        def ping(self):
            return True

    monkeypatch.setattr("app.main.redis_client", RedisOk())

    def override_get_db():
        yield BrokenDb()

    app.dependency_overrides[get_db] = override_get_db

    try:
        response = client.get("/readyz")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 503
    assert response.json()["database"] is False
    assert response.json()["redis"] is True


def test_healthz_remains_available_when_redis_is_unavailable(client, monkeypatch):
    class RedisBroken:
        def ping(self):
            raise RedisError("redis_down")

    monkeypatch.setattr("app.main.redis_client", RedisBroken())

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_healthz_does_not_probe_redis(client, monkeypatch):
    class RedisMustNotBeCalled:
        def ping(self):
            raise AssertionError("healthz must not probe redis")

    monkeypatch.setattr(
        "app.main.redis_client",
        RedisMustNotBeCalled(),
    )

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_wait_for_db_retries_then_succeeds(monkeypatch):
    attempts = {"count": 0}
    engines = []

    def fake_create_engine(*args, **kwargs):
        attempts["count"] += 1

        engine = MagicMock()
        context = MagicMock()

        if attempts["count"] < 3:
            context.__enter__.side_effect = SQLAlchemyError("db_down")
        else:
            connection = MagicMock()
            context.__enter__.return_value = connection

        context.__exit__.return_value = False
        engine.connect.return_value = context
        engines.append(engine)
        return engine

    monkeypatch.setattr(
        "deploy.wait_for_services.create_engine",
        fake_create_engine,
    )
    monkeypatch.setattr(
        "deploy.wait_for_services.time.sleep",
        lambda *_: None,
    )

    times = iter([0, 0, 0, 0, 0, 0])

    monkeypatch.setattr(
        "deploy.wait_for_services.time.time",
        lambda: next(times, 0),
    )

    wait_for_db(max_wait=1)

    assert attempts["count"] == 3


def test_wait_for_db_disposes_engine_after_success(monkeypatch):
    engine = MagicMock()
    context = MagicMock()
    connection = MagicMock()

    context.__enter__.return_value = connection
    context.__exit__.return_value = False
    engine.connect.return_value = context

    monkeypatch.setattr(
        "deploy.wait_for_services.create_engine",
        lambda *args, **kwargs: engine,
    )

    wait_for_db(max_wait=1)

    engine.dispose.assert_called_once()


def test_wait_for_db_disposes_failed_engine_before_retry(monkeypatch):
    engines = []

    def fake_create_engine(*args, **kwargs):
        engine = MagicMock()
        context = MagicMock()

        if not engines:
            context.__enter__.side_effect = SQLAlchemyError("db_down")
        else:
            connection = MagicMock()
            context.__enter__.return_value = connection

        context.__exit__.return_value = False
        engine.connect.return_value = context
        engines.append(engine)
        return engine

    monkeypatch.setattr(
        "deploy.wait_for_services.create_engine",
        fake_create_engine,
    )
    monkeypatch.setattr(
        "deploy.wait_for_services.time.sleep",
        lambda *_: None,
    )

    times = iter([0, 0, 0, 0])

    monkeypatch.setattr(
        "deploy.wait_for_services.time.time",
        lambda: next(times, 0),
    )

    wait_for_db(max_wait=1)

    assert len(engines) == 2
    engines[0].dispose.assert_called_once()
    engines[1].dispose.assert_called_once()


def test_wait_for_db_timeout_reports_last_error(monkeypatch):
    monkeypatch.setattr(
        "deploy.wait_for_services.create_engine",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            SQLAlchemyError("final-db-error")
        ),
    )
    monkeypatch.setattr(
        "deploy.wait_for_services.time.sleep",
        lambda *_: None,
    )

    times = iter([0, 0, 2])

    monkeypatch.setattr(
        "deploy.wait_for_services.time.time",
        lambda: next(times, 2),
    )

    with pytest.raises(
        RuntimeError,
        match="final-db-error",
    ):
        wait_for_db(max_wait=1)


def test_wait_for_redis_retries_then_succeeds(monkeypatch):
    client = MagicMock()
    client.ping.side_effect = [
        RedisError("redis_down"),
        RedisError("redis_down"),
        True,
    ]

    monkeypatch.setattr(
        "deploy.wait_for_services.Redis.from_url",
        lambda *args, **kwargs: client,
    )
    monkeypatch.setattr(
        "deploy.wait_for_services.time.sleep",
        lambda *_: None,
    )

    times = iter([0, 0, 0, 0, 0, 0])

    monkeypatch.setattr(
        "deploy.wait_for_services.time.time",
        lambda: next(times, 0),
    )

    wait_for_redis(max_wait=1)

    assert client.ping.call_count == 3


def test_wait_for_redis_timeout_reports_last_error(monkeypatch):
    client = MagicMock()
    client.ping.side_effect = RedisError("final-redis-error")

    monkeypatch.setattr(
        "deploy.wait_for_services.Redis.from_url",
        lambda *args, **kwargs: client,
    )
    monkeypatch.setattr(
        "deploy.wait_for_services.time.sleep",
        lambda *_: None,
    )

    times = iter([0, 0, 2])

    monkeypatch.setattr(
        "deploy.wait_for_services.time.time",
        lambda: next(times, 2),
    )

    with pytest.raises(
        RuntimeError,
        match="final-redis-error",
    ):
        wait_for_redis(max_wait=1)