from __future__ import annotations

from app.security import hash_with_pepper
from app.config import settings


def pseudonymize_ip(ip_address: str) -> str:
    return hash_with_pepper(ip_address, settings.ip_hash_pepper)
