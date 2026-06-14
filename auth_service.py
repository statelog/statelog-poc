from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Protocol

from redis import Redis
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)


class RateLimiter(Protocol):
    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool: ...


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.time()
        bucket = self._buckets[key]
        while bucket and bucket[0] <= now - window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            return False
        bucket.append(now)
        return True


class RedisRateLimiter:
    def __init__(self, redis_client: Redis) -> None:
        self.redis = redis_client

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = int(time.time())
        bucket_key = f"rate_limit:{key}:{now // window_seconds}"
        try:
            current = self.redis.incr(bucket_key)
            if current == 1:
                self.redis.expire(bucket_key, window_seconds + 1)
            return current <= limit
        except RedisError:
            logger.exception("redis_rate_limit_failed", extra={"bucket_key": bucket_key})
            raise


class HybridRateLimiter:
    def __init__(self, redis_client: Redis | None = None, fail_closed: bool = True) -> None:
        self.memory = InMemoryRateLimiter()
        self.redis_limiter = RedisRateLimiter(redis_client) if redis_client else None
        self.fail_closed = fail_closed

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        if self.redis_limiter:
            try:
                return self.redis_limiter.allow(key, limit, window_seconds)
            except RedisError:
                if self.fail_closed:
                    return False
                return self.memory.allow(key, limit, window_seconds)
        return self.memory.allow(key, limit, window_seconds)
