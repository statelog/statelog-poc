from __future__ import annotations

import sys
import time

from redis import Redis
from sqlalchemy import create_engine, text

from app.config import settings


def wait_for_db(max_wait: int = 60) -> None:
    deadline = time.time() + max_wait
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            engine = create_engine(settings.database_url, future=True)
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(1)
    raise RuntimeError(f"database not ready after {max_wait}s: {last_exc}")


def wait_for_redis(max_wait: int = 60) -> None:
    deadline = time.time() + max_wait
    last_exc: Exception | None = None
    while time.time() < deadline:
        try:
            client = Redis.from_url(settings.redis_url, decode_responses=True)
            client.ping()
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(1)
    raise RuntimeError(f"redis not ready after {max_wait}s: {last_exc}")


if __name__ == "__main__":
    wait_for_db()
    wait_for_redis()
    print("dependencies ready")
    sys.exit(0)
