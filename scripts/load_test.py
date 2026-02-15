#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed


def make_url(base_url: str, ip: str) -> str:
    return f"{base_url.rstrip('/')}/v1/asn/lookup?ip={ip}"


def one_request(url: str, timeout_sec: float) -> tuple[int, float]:
    started = time.perf_counter()
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            status = resp.status
            _ = resp.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        _ = exc.read()
    except urllib.error.URLError:
        status = 0
    elapsed_ms = (time.perf_counter() - started) * 1000
    return status, elapsed_ms


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simple load test for ASN Lookup API")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--ip", default="8.8.8.8")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout-sec", type=float, default=4.0)
    parser.add_argument("--json", action="store_true", help="Output summary as JSON")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    total = max(1, args.requests)
    concurrency = max(1, min(args.concurrency, total))
    url = make_url(args.base_url, args.ip)

    lock = threading.Lock()
    status_counts: Counter[int] = Counter()
    latencies_ms: list[float] = []

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one_request, url, args.timeout_sec) for _ in range(total)]
        for future in as_completed(futures):
            status, latency_ms = future.result()
            with lock:
                status_counts[status] += 1
                latencies_ms.append(latency_ms)
    total_elapsed = time.perf_counter() - started

    success = status_counts.get(200, 0)
    rate_limited = status_counts.get(429, 0)
    failures = total - success - rate_limited
    avg_latency = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0

    summary = {
        "base_url": args.base_url,
        "endpoint": "/v1/asn/lookup",
        "ip": args.ip,
        "requests": total,
        "concurrency": concurrency,
        "duration_sec": round(total_elapsed, 3),
        "rps": round(total / total_elapsed, 2) if total_elapsed > 0 else 0.0,
        "avg_latency_ms": round(avg_latency, 2),
        "status_counts": dict(sorted(status_counts.items())),
        "success_200": success,
        "rate_limited_429": rate_limited,
        "other_failures": failures,
    }

    if args.json:
        print(json.dumps(summary, ensure_ascii=True))
        return

    print("Load test summary")
    print(f"- URL: {url}")
    print(f"- Requests: {total}")
    print(f"- Concurrency: {concurrency}")
    print(f"- Duration: {summary['duration_sec']}s")
    print(f"- Throughput: {summary['rps']} req/s")
    print(f"- Avg latency: {summary['avg_latency_ms']} ms")
    print(f"- Status counts: {summary['status_counts']}")
    print(f"- 200 OK: {success}")
    print(f"- 429 Rate Limited: {rate_limited}")
    print(f"- Other failures: {failures}")


if __name__ == "__main__":
    main()
