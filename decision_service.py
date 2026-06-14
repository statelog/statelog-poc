from __future__ import annotations

import logging
import time
from typing import Protocol

from redis import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class ReplayStore(Protocol):
    def mark_if_first_seen(self, *, tenant_id: str, jti: str, ttl_seconds: int) -> bool: ...


class InMemoryReplayStore:
    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def mark_if_first_seen(self, *, tenant_id: str, jti: str, ttl_seconds: int) -> bool:
        now = time.time()
        expired = [key for key, expiry in self._seen.items() if expiry <= now]
        for key in expired:
            self._seen.pop(key, None)
        cache_key = f"replay:{tenant_id}:{jti}"
        if cache_key in self._seen:
            return False
        self._seen[cache_key] = now + ttl_seconds
        return True


class RedisReplayStore:
    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    def mark_if_first_seen(self, *, tenant_id: str, jti: str, ttl_seconds: int) -> bool:
        cache_key = f"replay:{tenant_id}:{jti}"
        try:
            return bool(self.redis.set(cache_key, '1', nx=True, ex=max(ttl_seconds, 1)))
        except RedisError:
            logger.exception('redis_replay_store_failed', extra={'cache_key': cache_key})
            raise


class HybridReplayStore:
    def __init__(self, redis_client: Redis | None = None, fail_closed: bool = True) -> None:
        self.memory = InMemoryReplayStore()
        self.redis_store = RedisReplayStore(redis_client) if redis_client else None
        self.fail_closed = fail_closed

    def mark_if_first_seen(self, *, tenant_id: str, jti: str, ttl_seconds: int) -> bool:
        if self.redis_store:
            try:
                return self.redis_store.mark_if_first_seen(tenant_id=tenant_id, jti=jti, ttl_seconds=ttl_seconds)
            except RedisError:
                if self.fail_closed:
                    return False
                return self.memory.mark_if_first_seen(tenant_id=tenant_id, jti=jti, ttl_seconds=ttl_seconds)
        return self.memory.mark_if_first_seen(tenant_id=tenant_id, jti=jti, ttl_seconds=ttl_seconds)
