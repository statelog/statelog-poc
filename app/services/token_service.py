from __future__ import annotations

from fastapi import HTTPException

from app.models import AccessRight, Device


def validate_token_issue_inputs(*, device: Device | None, right: AccessRight | None, requested_user_id: str) -> None:
    if not device:
        raise HTTPException(status_code=404, detail='device_missing')
    if not right or not right.valid:
        raise HTTPException(status_code=404, detail='access_right_invalid')
    if right.owner_id != requested_user_id:
        raise HTTPException(status_code=403, detail='owner_mismatch')
