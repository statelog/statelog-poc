import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JWT_SECRET"] = "test-secret"
os.environ["ADMIN_API_KEY"] = "test-admin-key"
os.environ["REDIS_URL"] = "redis://localhost:6399/0"
os.environ["ENVIRONMENT"] = "test"

from fastapi.testclient import TestClient
import pytest

from app.database import Base, engine
from app.main import app, decision_cache, rate_limiter, replay_store


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    decision_cache.clear()
    rate_limiter.memory._buckets.clear()
    replay_store.memory._seen.clear()
    yield
    Base.metadata.drop_all(bind=engine)
    decision_cache.clear()
    rate_limiter.memory._buckets.clear()
    replay_store.memory._seen.clear()


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client
