import hashlib
import hmac
import json

import jwt
import pytest

from app.config import settings
from app.security import (
    build_request_fingerprint,
    constant_time_equals,
    decrypt_secret,
    encrypt_secret,
    get_active_signing_key,
    get_jwt_keyring,
    hash_secret,
    hash_with_pepper,
    sign_webhook_payload,
    decode_access_token,
)


# #755
def test_hash_secret_is_deterministic():
    assert hash_secret("statelog-secret") == hash_secret("statelog-secret")


# #756
def test_hash_secret_changes_when_value_changes():
    assert hash_secret("secret-a") != hash_secret("secret-b")


# #757
def test_hash_secret_supports_unicode():
    value = "saladus-õäöü-🔐"

    expected = hashlib.sha256(value.encode("utf-8")).hexdigest()

    assert hash_secret(value) == expected


# #758
def test_hash_with_pepper_is_deterministic():
    assert hash_with_pepper(
        "value",
        "pepper",
    ) == hash_with_pepper(
        "value",
        "pepper",
    )


# #759
def test_hash_with_pepper_changes_when_pepper_changes():
    assert hash_with_pepper(
        "value",
        "pepper-a",
    ) != hash_with_pepper(
        "value",
        "pepper-b",
    )


# #760
def test_constant_time_equals_returns_true_for_equal_values():
    assert constant_time_equals("same-value", "same-value") is True


# #761
def test_constant_time_equals_returns_false_for_different_values():
    assert constant_time_equals("value-a", "value-b") is False


# #762
def test_get_jwt_keyring_falls_back_to_legacy_secret(monkeypatch):
    monkeypatch.setattr(settings, "jwt_keyring_json", "")
    monkeypatch.setattr(settings, "jwt_active_kid", "legacy")
    monkeypatch.setattr(settings, "jwt_secret", "legacy-secret")

    assert get_jwt_keyring() == {
        "legacy": "legacy-secret",
    }


# #763
def test_get_jwt_keyring_parses_configured_json(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": "secret-one",
                "v2": "secret-two",
            }
        ),
    )

    assert get_jwt_keyring() == {
        "v1": "secret-one",
        "v2": "secret-two",
    }


# #764
def test_get_jwt_keyring_rejects_non_object_json(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(["secret-one"]),
    )

    with pytest.raises(
        ValueError,
        match="JWT_KEYRING_JSON must be a non-empty JSON object",
    ):
        get_jwt_keyring()


# #765
def test_get_jwt_keyring_rejects_empty_object(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        "{}",
    )

    with pytest.raises(
        ValueError,
        match="JWT_KEYRING_JSON must be a non-empty JSON object",
    ):
        get_jwt_keyring()


# #766
def test_get_active_signing_key_returns_configured_key(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "legacy": "old-secret",
                "v2": "current-secret",
            }
        ),
    )
    monkeypatch.setattr(settings, "jwt_active_kid", "v2")

    assert get_active_signing_key() == (
        "v2",
        "current-secret",
    )


# #767
def test_get_active_signing_key_rejects_missing_active_kid(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "legacy": "old-secret",
            }
        ),
    )
    monkeypatch.setattr(settings, "jwt_active_kid", "missing")

    with pytest.raises(
        ValueError,
        match="JWT active kid missing from keyring",
    ):
        get_active_signing_key()


# #768
def test_encrypt_decrypt_secret_round_trip():
    plaintext = "webhook-secret-768"

    encrypted = encrypt_secret(plaintext)

    assert encrypted != plaintext
    assert decrypt_secret(encrypted) == plaintext


# #769
def test_encrypt_secret_uses_randomized_ciphertext():
    plaintext = "same-secret-value"

    first = encrypt_secret(plaintext)
    second = encrypt_secret(plaintext)

    assert first != second
    assert decrypt_secret(first) == plaintext
    assert decrypt_secret(second) == plaintext


# #770
def test_decrypt_secret_rejects_invalid_ciphertext():
    with pytest.raises(
        ValueError,
        match="secret_decryption_failed",
    ):
        decrypt_secret("not-valid-fernet-ciphertext")


# #771
def test_request_fingerprint_is_independent_of_dict_order():
    first = {
        "tenant_id": "tenant-demo",
        "right_id": "right-001",
        "device_id": "gate-A1",
    }

    second = {
        "device_id": "gate-A1",
        "tenant_id": "tenant-demo",
        "right_id": "right-001",
    }

    assert build_request_fingerprint(first) == build_request_fingerprint(
        second
    )


# #772
def test_request_fingerprint_changes_when_payload_changes():
    first = {
        "tenant_id": "tenant-demo",
        "allowed": True,
    }
    second = {
        "tenant_id": "tenant-demo",
        "allowed": False,
    }

    assert build_request_fingerprint(first) != build_request_fingerprint(
        second
    )


# #773
def test_request_fingerprint_matches_canonical_json_sha256():
    payload = {
        "b": 2,
        "a": 1,
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )
    expected = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()

    assert build_request_fingerprint(payload) == expected


# #774
def test_sign_webhook_payload_matches_expected_hmac():
    secret = "webhook-secret"
    timestamp = 1700000000
    payload = {
        "trace_id": "trace-774",
        "allowed": True,
        "risk_score": 35,
    }

    body = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )
    message = f"{timestamp}.{body}".encode("utf-8")
    expected_digest = hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()

    signature = sign_webhook_payload(
        secret=secret,
        payload=payload,
        timestamp=timestamp,
    )

    assert signature == f"v1={expected_digest}"

def test_decode_access_token_rejects_missing_exp(monkeypatch):
    signing_key = "jwt-required-claims-test-secret-2026"

    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": signing_key,
            }
        ),
    )
    monkeypatch.setattr(settings, "jwt_active_kid", "v1")

    token = jwt.encode(
        {
            "iss": settings.app_name,
            "sub": "user-123",
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "device_id": "gate-A1",
            "scope": "access",
            "jti": "missing-exp-test-jti",
            "iat": 1_700_000_000,
            "kid": "v1",
            "kv": "v1",
        },
        signing_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": "v1"},
    )

    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(token)


def test_decode_access_token_rejects_wrong_issuer(monkeypatch):
    signing_key = "jwt-required-claims-test-secret-2026"

    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": signing_key,
            }
        ),
    )
    monkeypatch.setattr(settings, "jwt_active_kid", "v1")

    token = jwt.encode(
        {
            "iss": "evil-issuer",
            "sub": "user-123",
            "tenant_id": "tenant-demo",
            "right_id": "right-001",
            "device_id": "gate-A1",
            "scope": "access",
            "jti": "wrong-issuer-test-jti",
            "iat": 1_700_000_000,
            "exp": 4_102_444_800,
            "kid": "v1",
            "kv": "v1",
        },
        signing_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": "v1"},
    )

    with pytest.raises(jwt.InvalidIssuerError):
        decode_access_token(token)

def test_decode_access_token_rejects_missing_tenant_id(monkeypatch):
    signing_key = "jwt-required-claims-test-secret-2026"

    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": signing_key,
            }
        ),
    )
    monkeypatch.setattr(settings, "jwt_active_kid", "v1")

    token = jwt.encode(
        {
            "iss": settings.app_name,
            "sub": "user-123",
            "right_id": "right-001",
            "device_id": "gate-A1",
            "scope": "access",
            "jti": "missing-tenant-test-jti",
            "iat": 1_700_000_000,
            "exp": 4_102_444_800,
            "kid": "v1",
            "kv": "v1",
        },
        signing_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": "v1"},
    )

    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(token)

@pytest.mark.parametrize(
    "missing_claim",
    [
        "iat",
        "sub",
        "right_id",
        "device_id",
        "scope",
        "jti",
    ],
)
def test_decode_access_token_rejects_missing_required_claim(
    monkeypatch,
    missing_claim,
):
    signing_key = "jwt-required-claims-test-secret-2026"

    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": signing_key,
            }
        ),
    )
    monkeypatch.setattr(settings, "jwt_active_kid", "v1")

    payload = {
        "iss": settings.app_name,
        "sub": "user-123",
        "tenant_id": "tenant-demo",
        "right_id": "right-001",
        "device_id": "gate-A1",
        "scope": "access",
        "jti": "required-claims-test-jti",
        "iat": 1_700_000_000,
        "exp": 4_102_444_800,
        "kid": "v1",
        "kv": "v1",
    }

    payload.pop(missing_claim)

    token = jwt.encode(
        payload,
        signing_key,
        algorithm=settings.jwt_algorithm,
        headers={"kid": "v1"},
    )

    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(token)

def _jwt_rotation_payload():
    return {
        "iss": settings.app_name,
        "sub": "user-123",
        "tenant_id": "tenant-demo",
        "right_id": "right-001",
        "device_id": "gate-A1",
        "scope": "access",
        "jti": "rotation-test-jti",
        "iat": 1_700_000_000,
        "exp": 4_102_444_800,
        "kid": "v1",
        "kv": "v1",
    }


def test_decode_access_token_uses_matching_kid(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": "rotation-secret-v1-2026",
                "v2": "rotation-secret-v2-2026",
            }
        ),
    )

    token = jwt.encode(
        _jwt_rotation_payload(),
        "rotation-secret-v1-2026",
        algorithm=settings.jwt_algorithm,
        headers={"kid": "v1"},
    )

    decoded = decode_access_token(token)

    assert decoded["sub"] == "user-123"


def test_decode_access_token_accepts_legacy_token_without_kid(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "legacy": "rotation-legacy-secret-2026",
                "v2": "rotation-current-secret-2026",
            }
        ),
    )

    payload = _jwt_rotation_payload()
    payload["kid"] = "legacy"
    payload["kv"] = "legacy"

    token = jwt.encode(
        payload,
        "rotation-legacy-secret-2026",
        algorithm=settings.jwt_algorithm,
        headers={},
    )

    decoded = decode_access_token(token)

    assert decoded["sub"] == "user-123"


def test_decode_access_token_rejects_unknown_kid(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": "rotation-secret-v1-2026",
                "v2": "rotation-secret-v2-2026",
            }
        ),
    )

    token = jwt.encode(
        _jwt_rotation_payload(),
        "rotation-secret-v1-2026",
        algorithm=settings.jwt_algorithm,
        headers={"kid": "unknown"},
    )

    with pytest.raises(jwt.InvalidTokenError):
        decode_access_token(token)


def test_decode_access_token_rejects_signature_from_wrong_key(monkeypatch):
    monkeypatch.setattr(
        settings,
        "jwt_keyring_json",
        json.dumps(
            {
                "v1": "rotation-secret-v1-2026",
                "v2": "rotation-secret-v2-2026",
            }
        ),
    )

    token = jwt.encode(
        _jwt_rotation_payload(),
        "attacker-secret-not-in-keyring-2026",
        algorithm=settings.jwt_algorithm,
        headers={"kid": "v1"},
    )

    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(token)