from __future__ import annotations

from app.schemas import AccessRequest


def build_cache_key(tenant_id: str, payload: AccessRequest, right_version: int | None = None) -> str:
    return ':'.join(
        [
            tenant_id,
            payload.token,
            payload.request_type,
            payload.device_id,
            payload.ip_address,
            payload.country_code,
            payload.new_owner_id or '-',
            str(right_version or 0),
        ]
    )
