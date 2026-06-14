from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path


def run_probe(args: argparse.Namespace, requests_per_round: int) -> dict:
    cmd = [
        sys.executable,
        'load/access_flow_probe.py',
        '--base-url', args.base_url,
        '--requests', str(requests_per_round),
        '--concurrency', str(args.concurrency),
        '--client-shards', str(args.client_shards),
        '--admin-api-key', args.admin_api_key,
        '--tenant-id', args.tenant_id,
        '--tenant-name', args.tenant_name,
        '--device-id', args.device_id,
        '--right-id', args.right_id,
        '--user-id', args.user_id,
        '--country-code', args.country_code,
        '--json-output', '-',
    ]
    completed = subprocess.run(cmd, check=True, capture_output=True, text=True)
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(description='Run repeated access flow probes and write JSON/CSV reports')
    parser.add_argument('--base-url', default='http://127.0.0.1:8000')
    parser.add_argument('--duration-seconds', type=int, default=300)
    parser.add_argument('--round-requests', type=int, default=250)
    parser.add_argument('--concurrency', type=int, default=25)
    parser.add_argument('--client-shards', type=int, default=32)
    parser.add_argument('--admin-api-key', default='admin-dev-key')
    parser.add_argument('--tenant-id', default='tenant-soak')
    parser.add_argument('--tenant-name', default='Soak Tenant')
    parser.add_argument('--device-id', default='gate-soak-1')
    parser.add_argument('--right-id', default='right-soak-1')
    parser.add_argument('--user-id', default='user-soak-1')
    parser.add_argument('--country-code', default='EE')
    parser.add_argument('--json-report', default='load/reports/soak_report.json')
    parser.add_argument('--csv-report', default='load/reports/soak_report.csv')
    args = parser.parse_args()

    start = time.time()
    rounds = []
    round_number = 0
    while time.time() - start < args.duration_seconds:
        round_number += 1
        payload = run_probe(args, args.round_requests)
        payload['round'] = round_number
        payload['elapsed_seconds'] = round(time.time() - start, 2)
        rounds.append(payload)

    json_path = Path(args.json_report)
    csv_path = Path(args.csv_report)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    summary = {
        'duration_seconds': args.duration_seconds,
        'round_requests': args.round_requests,
        'concurrency': args.concurrency,
        'client_shards': args.client_shards,
        'rounds_completed': len(rounds),
        'rounds': rounds,
    }
    json_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')

    with csv_path.open('w', newline='', encoding='utf-8') as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                'round', 'elapsed_seconds', 'requests', 'concurrency', 'client_shards', 'success', 'failures',
                'token_issue_avg_ms', 'token_issue_p95_ms', 'token_issue_p99_ms',
                'request_access_avg_ms', 'request_access_p95_ms', 'request_access_p99_ms',
                'end_to_end_avg_ms', 'end_to_end_p95_ms', 'end_to_end_p99_ms',
            ],
        )
        writer.writeheader()
        for item in rounds:
            writer.writerow({
                'round': item['round'],
                'elapsed_seconds': item['elapsed_seconds'],
                'requests': item['requests'],
                'concurrency': item['concurrency'],
                'client_shards': item['client_shards'],
                'success': item['success'],
                'failures': item['failures'],
                'token_issue_avg_ms': item['token_issue']['avg_ms'],
                'token_issue_p95_ms': item['token_issue']['p95_ms'],
                'token_issue_p99_ms': item['token_issue']['p99_ms'],
                'request_access_avg_ms': item['request_access']['avg_ms'],
                'request_access_p95_ms': item['request_access']['p95_ms'],
                'request_access_p99_ms': item['request_access']['p99_ms'],
                'end_to_end_avg_ms': item['end_to_end']['avg_ms'],
                'end_to_end_p95_ms': item['end_to_end']['p95_ms'],
                'end_to_end_p99_ms': item['end_to_end']['p99_ms'],
            })

    print(f'JSON report: {json_path}')
    print(f'CSV report: {csv_path}')


if __name__ == '__main__':
    main()
