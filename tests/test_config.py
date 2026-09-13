import json

import pytest
from pydantic import ValidationError

from app.config import Settings


STRONG_SECRET = "s" * 32
STRONG_SECRET_2 = "t" * 32


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
    }
    values.update(overrides)
    return Settings(**values)


def test_production_accepts_strong_legacy_jwt_secret():
    settings = production_settings()

    assert settings.jwt_secret == STRONG_SECRET


def test_production_rejects_weak_legacy_jwt_secret():
    with pytest.raises(
        ValidationError,
        match="JWT_KEYRING_JSON or JWT_SECRET must contain a strong production signing secret",
    ):
        production_settings(
            JWT_SECRET="short",
        )


def test_production_accepts_strong_jwt_keyring():
    settings = production_settings(
        JWT_KEYRING_JSON=json.dumps(
            {
                "v1": STRONG_SECRET,
                "v2": STRONG_SECRET_2,
            }
        ),
        JWT_ACTIVE_KID="v2",
    )

    assert settings.jwt_active_kid == "v2"


def test_production_rejects_weak_key_in_jwt_keyring():
    with pytest.raises(ValidationError):
        production_settings(
            JWT_KEYRING_JSON=json.dumps(
                {
                    "v1": STRONG_SECRET,
                    "legacy": "short",
                }
            ),
        )


def test_production_rejects_empty_jwt_keyring_object():
    with pytest.raises(ValidationError):
        production_settings(
            JWT_KEYRING_JSON="{}",
        )


def test_production_rejects_non_object_jwt_keyring():
    with pytest.raises(ValidationError):
        production_settings(
            JWT_KEYRING_JSON=json.dumps(
                [
                    STRONG_SECRET,
                ]
            ),
        )


def test_production_rejects_missing_active_kid_from_keyring():
    with pytest.raises(ValidationError):
        production_settings(
            JWT_KEYRING_JSON=json.dumps(
                {
                    "legacy": STRONG_SECRET,
                }
            ),
            JWT_ACTIVE_KID="v2",
        )


def test_non_production_allows_development_jwt_secret():
    settings = Settings(
        ENVIRONMENT="test",
        JWT_SECRET="dev-secret-change-me",
        JWT_KEYRING_JSON="",
    )

    assert settings.environment == "test"