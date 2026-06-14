from __future__ import annotations

import argparse
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    index = max(0, min(len(sorted_values) - 1, round((pct / 100.0) * (len(sorted_values) - 1))))
    return sorted_values[index]


def timed_get(session: requests.Session, url: str, timeout: float) -> tuple[bool, float, int | None]:
    started = time.perf_counter()
    try:
        response = session.get(url, timeout=timeout)
        return response.ok, (time.perf_counter() - started) * 1000.0, response.status_code
    except requests.RequestException:
        return False, (time.perf_counter() - started) * 1000.0, None


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple latency probe for Access PoC")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--path", default="/healthz")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()

    url = args.base_url.rstrip("/") + args.path
    latencies: list[float] = []
    success = 0
    failures = 0
    status_codes: dict[str, int] = {}

    with requests.Session() as session:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = [pool.submit(timed_get, session, url, args.timeout) for _ in range(args.requests)]
            for future in as_completed(futures):
                ok, latency_ms, status = future.result()
                latencies.append(latency_ms)
                if ok:
                    success += 1
                else:
                    failures += 1
                status_key = str(status) if status is not None else "network_error"
                status_codes[status_key] = status_codes.get(status_key, 0) + 1

    latencies.sort()
    avg = statistics.mean(latencies) if latencies else 0.0
    print(f"url={url}")
    print(f"requests={args.requests} concurrency={args.concurrency} success={success} failures={failures}")
    print(f"avg_ms={avg:.2f} p50_ms={percentile(latencies, 50):.2f} p95_ms={percentile(latencies, 95):.2f} p99_ms={percentile(latencies, 99):.2f} max_ms={max(latencies) if latencies else 0.0:.2f}")
    print(f"status_codes={status_codes}")


if __name__ == "__main__":
    main()
