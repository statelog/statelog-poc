from __future__ import annotations

from fastapi import HTTPException

from app.models import AccessRight


def enforce_right_owner(right: AccessRight, user_id: str, detail: str = 'owner_mismatch') -> None:
    if right.owner_id != user_id:
        raise HTTPException(status_code=403, detail=detail)
