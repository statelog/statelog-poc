from __future__ import annotations

import argparse
import json
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

ADMIN_API_KEY_HEADER = "X-Admin-Api-Key"
CLIENT_ID_HEADER = "X-Client-Id"
API_KEY_HEADER = "X-API-Key"
TENANT_ID_HEADER = "X-Tenant-Id"


_thread_local = threading.local()


def percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    index = max(0, min(len(sorted_values) - 1, round((pct / 100.0) * (len(sorted_values) - 1))))
    return sorted_values[index]


def get_session() -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = requests.Session()
        _thread_local.session = session
    return session


def post_json(session: requests.Session, url: str, *, headers: dict[str, str], json: dict, timeout: float) -> requests.Response:
    return session.post(url, headers=headers, json=json, timeout=timeout)


def ensure_resource(response: requests.Response, allowed: tuple[int, ...] = (200, 409)) -> None:
    if response.status_code not in allowed:
        raise RuntimeError(f"bootstrap_failed status={response.status_code} body={response.text}")


def bootstrap(args: argparse.Namespace) -> list[dict[str, str]]:
    base_url = args.base_url.rstrip("/")
    admin_headers = {ADMIN_API_KEY_HEADER: args.admin_api_key}
    session = requests.Session()

    ensure_resource(
        post_json(
            session,
            f"{base_url}/admin/tenants",
            headers=admin_headers,
            json={"tenant_id": args.tenant_id, "name": args.tenant_name, "monthly_quota": max(args.requests * 3, 5000)},
            timeout=args.timeout,
        )
    )

    client_headers_list: list[dict[str, str]] = []
    for idx in range(args.client_shards):
        client_id = f"{args.client_prefix}-{idx}"
        api_key = f"{args.api_key_prefix}-{idx}"
        ensure_resource(
            post_json(
                session,
                f"{base_url}/admin/clients",
                headers=admin_headers,
                json={"tenant_id": args.tenant_id, "client_id": client_id, "api_key": api_key},
                timeout=args.timeout,
            )
        )
        client_headers = {
            TENANT_ID_HEADER: args.tenant_id,
            CLIENT_ID_HEADER: client_id,
            API_KEY_HEADER: api_key,
        }
        client_headers_list.append(client_headers)

    primary_headers = client_headers_list[0]
    ensure_resource(
        post_json(
            session,
            f"{base_url}/admin/devices",
            headers=primary_headers,
            json={"tenant_id": args.tenant_id, "device_id": args.device_id, "description": "load-test-gate"},
            timeout=args.timeout,
        )
    )
    ensure_resource(
        post_json(
            session,
            f"{base_url}/rights/create",
            headers=primary_headers,
            json={"tenant_id": args.tenant_id, "right_id": args.right_id, "owner_id": args.user_id, "valid": True},
            timeout=args.timeout,
        )
    )
    return client_headers_list


def run_iteration(idx: int, args: argparse.Namespace, client_headers_list: list[dict[str, str]]) -> dict:
    base_url = args.base_url.rstrip("/")
    session = get_session()
    headers = client_headers_list[idx % len(client_headers_list)]
    ip_address = f"10.{(idx // 65536) % 255}.{(idx // 256) % 255}.{idx % 255}"

    total_started = time.perf_counter()
    issue_started = time.perf_counter()
    issue_response = post_json(
        session,
        f"{base_url}/token/issue",
        headers=headers,
        json={
            "tenant_id": args.tenant_id,
            "right_id": args.right_id,
            "user_id": args.user_id,
            "device_id": args.device_id,
            "scope": "access",
        },
        timeout=args.timeout,
    )
    issue_ms = (time.perf_counter() - issue_started) * 1000.0
    if issue_response.status_code != 200:
        return {
            "ok": False,
            "issue_status": issue_response.status_code,
            "access_status": None,
            "issue_ms": issue_ms,
            "access_ms": 0.0,
            "total_ms": (time.perf_counter() - total_started) * 1000.0,
        }

    token = issue_response.json()["token"]

    access_started = time.perf_counter()
    access_response = post_json(
        session,
        f"{base_url}/request/access",
        headers=headers,
        json={
            "token": token,
            "request_type": "access",
            "device_id": args.device_id,
            "ip_address": ip_address,
            "country_code": args.country_code,
        },
        timeout=args.timeout,
    )
    access_ms = (time.perf_counter() - access_started) * 1000.0
    total_ms = (time.perf_counter() - total_started) * 1000.0
    return {
        "ok": issue_response.ok and access_response.ok,
        "issue_status": issue_response.status_code,
        "access_status": access_response.status_code,
        "issue_ms": issue_ms,
        "access_ms": access_ms,
        "total_ms": total_ms,
    }


def summarize_metrics(values: list[float]) -> dict[str, float]:
    values = sorted(values)
    avg = statistics.mean(values) if values else 0.0
    return {
        'avg_ms': round(avg, 2),
        'p50_ms': round(percentile(values, 50), 2),
        'p95_ms': round(percentile(values, 95), 2),
        'p99_ms': round(percentile(values, 99), 2),
        'max_ms': round(max(values) if values else 0.0, 2),
    }


def summarize(name: str, values: list[float]) -> str:
    metrics = summarize_metrics(values)
    return (
        f"{name}: avg_ms={metrics['avg_ms']:.2f} p50_ms={metrics['p50_ms']:.2f} "
        f"p95_ms={metrics['p95_ms']:.2f} p99_ms={metrics['p99_ms']:.2f} max_ms={metrics['max_ms']:.2f}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure end-to-end /request/access flow latency")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--tenant-id", default="tenant-load")
    parser.add_argument("--tenant-name", default="Load Test Tenant")
    parser.add_argument("--device-id", default="gate-load-1")
    parser.add_argument("--right-id", default="right-load-1")
    parser.add_argument("--user-id", default="user-load-1")
    parser.add_argument("--country-code", default="EE")
    parser.add_argument("--client-shards", type=int, default=16)
    parser.add_argument("--client-prefix", default="load-client")
    parser.add_argument("--api-key-prefix", default="load-api-key")
    parser.add_argument("--admin-api-key", default="admin-dev-key")
    parser.add_argument("--json-output", default="")
    args = parser.parse_args()

    client_headers_list = bootstrap(args)
    issue_latencies: list[float] = []
    access_latencies: list[float] = []
    total_latencies: list[float] = []
    issue_statuses: dict[str, int] = {}
    access_statuses: dict[str, int] = {}
    success = 0
    failures = 0

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(run_iteration, idx, args, client_headers_list) for idx in range(args.requests)]
        for future in as_completed(futures):
            result = future.result()
            issue_latencies.append(result["issue_ms"])
            access_latencies.append(result["access_ms"])
            total_latencies.append(result["total_ms"])
            issue_key = str(result["issue_status"]) if result["issue_status"] is not None else "network_error"
            access_key = str(result["access_status"]) if result["access_status"] is not None else "network_error"
            issue_statuses[issue_key] = issue_statuses.get(issue_key, 0) + 1
            access_statuses[access_key] = access_statuses.get(access_key, 0) + 1
            if result["ok"]:
                success += 1
            else:
                failures += 1

    token_metrics = summarize_metrics(issue_latencies)
    access_metrics = summarize_metrics(access_latencies)
    total_metrics = summarize_metrics(total_latencies)

    print(f"requests={args.requests} concurrency={args.concurrency} client_shards={args.client_shards} success={success} failures={failures}")
    print(summarize("token_issue", issue_latencies))
    print(summarize("request_access", access_latencies))
    print(summarize("end_to_end", total_latencies))
    print(f"token_issue_status_codes={issue_statuses}")
    print(f"request_access_status_codes={access_statuses}")

    if args.json_output is not None:
        payload = {
            'requests': args.requests,
            'concurrency': args.concurrency,
            'client_shards': args.client_shards,
            'success': success,
            'failures': failures,
            'token_issue': token_metrics,
            'request_access': access_metrics,
            'end_to_end': total_metrics,
            'token_issue_status_codes': issue_statuses,
            'request_access_status_codes': access_statuses,
        }
        serialized = json.dumps(payload)
        if args.json_output in ('', '-'):
            print(serialized)
        else:
            from pathlib import Path
            out = Path(args.json_output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(serialized + '\n', encoding='utf-8')


if __name__ == "__main__":
    main()
