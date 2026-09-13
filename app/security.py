from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json
import secrets
from typing import Any, Dict

from cryptography.fernet import Fernet, InvalidToken
import jwt

from .config import settings

UTC = timezone.utc


def now_utc() -> datetime:
    return datetime.now(UTC)


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_with_pepper(value: str, pepper: str) -> str:
    return hashlib.sha256(f"{value}:{pepper}".encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left, right)


def get_jwt_keyring() -> dict[str, str]:
    if settings.jwt_keyring_json.strip():
        parsed = json.loads(settings.jwt_keyring_json)
        if not isinstance(parsed, dict) or not parsed:
            raise ValueError('JWT_KEYRING_JSON must be a non-empty JSON object')
        return {str(k): str(v) for k, v in parsed.items()}
    return {settings.jwt_active_kid: settings.jwt_secret}


def get_active_signing_key() -> tuple[str, str]:
    keyring = get_jwt_keyring()
    active_kid = settings.jwt_active_kid
    if active_kid not in keyring:
        raise ValueError('JWT active kid missing from keyring')
    return active_kid, keyring[active_kid]


def get_secret_encryption_keyring() -> dict[str, str]:
    if settings.secret_encryption_keyring_json.strip():
        parsed = json.loads(settings.secret_encryption_keyring_json)

        if not isinstance(parsed, dict) or not parsed:
            raise ValueError(
                "SECRET_ENCRYPTION_KEYRING_JSON must be a non-empty JSON object"
            )

        return {
            str(k): str(v)
            for k, v in parsed.items()
        }

    return {
        settings.secret_encryption_active_kid:
            settings.secret_encryption_key
    }


def get_active_secret_encryption_key() -> tuple[str, str]:
    keyring = get_secret_encryption_keyring()
    active_kid = settings.secret_encryption_active_kid

    if active_kid not in keyring:
        raise ValueError(
            "Secret encryption active kid missing from keyring"
        )

    return active_kid, keyring[active_kid]


def _fernet_for_key(secret_key: str) -> Fernet:
    key_material = hashlib.sha256(
        secret_key.encode("utf-8")
    ).digest()

    return Fernet(
        base64.urlsafe_b64encode(key_material)
    )


def encrypt_secret(value: str) -> str:
    _, encryption_key = get_active_secret_encryption_key()

    return (
        _fernet_for_key(encryption_key)
        .encrypt(value.encode("utf-8"))
        .decode("utf-8")
    )


def decrypt_secret(
    value: str,
    *,
    key_version: str | None = None,
) -> str:
    keyring = get_secret_encryption_keyring()

    candidate_keys: list[str] = []

    if key_version and key_version in keyring:
        candidate_keys.append(keyring[key_version])

    candidate_keys.extend(
        encryption_key
        for kid, encryption_key in keyring.items()
        if not (
            key_version
            and key_version in keyring
            and kid == key_version
        )
    )

    for encryption_key in candidate_keys:
        try:
            return (
                _fernet_for_key(encryption_key)
                .decrypt(value.encode("utf-8"))
                .decode("utf-8")
            )
        except InvalidToken:
            continue

    raise ValueError("secret_decryption_failed")


def issue_access_token(*, tenant_id: str, right_id: str, user_id: str, device_id: str, scope: str) -> str:
    kid, signing_key = get_active_signing_key()
    payload: Dict[str, Any] = {
        'iss': settings.app_name,
        'aud': settings.jwt_audience,
        'sub': user_id,
        'tenant_id': tenant_id,
        'right_id': right_id,
        'device_id': device_id,
        'scope': scope,
        'jti': secrets.token_hex(12),
        'iat': int(now_utc().timestamp()),
        'exp': int((now_utc() + timedelta(seconds=settings.access_token_ttl_seconds)).timestamp()),
        'kid': kid,
        'kv': kid,
    }
    return jwt.encode(payload, signing_key, algorithm=settings.jwt_algorithm, headers={'kid': kid})


def decode_access_token(token: str) -> Dict[str, Any]:
    keyring = get_jwt_keyring()
    header = jwt.get_unverified_header(token)
    token_kid = header.get('kid')
    if token_kid and token_kid in keyring:
        return jwt.decode(
            token,
            keyring[token_kid],
            algorithms=[settings.jwt_algorithm],
            issuer=settings.app_name,
            audience=settings.jwt_audience,
            options={
                "require": [
                    "exp",
                    "iss",
                    "aud",
                    "iat",
                    "sub",
                    "tenant_id",
                    "right_id",
                    "device_id",
                    "scope",
                    "jti",
                ]
            },
        )
    if token_kid:
        raise jwt.InvalidTokenError("unknown_kid")

    last_exc = None
    for signing_key in keyring.values():
        try:
            return jwt.decode(
                token,
                signing_key,
                algorithms=[settings.jwt_algorithm],
                issuer=settings.app_name,
                audience=settings.jwt_audience,
                options={
                    "require": [
                        "exp",
                        "iss",
                        "aud",
                        "iat",
                        "sub",
                        "tenant_id",
                        "right_id",
                        "device_id",
                        "scope",
                        "jti",
                   ]
                },
            )
        except jwt.InvalidTokenError as exc:
            last_exc = exc
    if last_exc:
        raise last_exc
    raise jwt.InvalidTokenError('no_signing_keys_configured')


def build_request_fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def sign_webhook_payload(*, secret: str, payload: dict[str, Any], timestamp: int) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    message = f"{timestamp}.{body}".encode('utf-8')
    digest = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).hexdigest()
    return f"v1={digest}"
