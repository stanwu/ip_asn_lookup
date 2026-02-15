from __future__ import annotations

import json
import os
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from app.asn_lookup import InvalidIPError, UpstreamLookupError, lookup_asn


class RateLimiter:
    def __init__(self, max_requests: int, window_sec: int) -> None:
        self.max_requests = max_requests
        self.window_sec = window_sec
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, now: float | None = None) -> tuple[bool, int]:
        if self.max_requests <= 0 or self.window_sec <= 0:
            return True, -1

        current = now if now is not None else time.time()
        window_start = current - self.window_sec

        with self._lock:
            bucket = self._hits[key]
            while bucket and bucket[0] <= window_start:
                bucket.popleft()

            if len(bucket) >= self.max_requests:
                retry_after = max(1, int(bucket[0] + self.window_sec - current))
                return False, retry_after

            bucket.append(current)
            return True, -1


def _single_lookup(ip: str) -> tuple[int, dict]:
    try:
        result = lookup_asn(ip)
        return 200, result.__dict__
    except InvalidIPError as exc:
        return 400, {"error": str(exc)}
    except UpstreamLookupError as exc:
        return 502, {"error": str(exc)}


def _batch_lookup(ips: list[str]) -> tuple[int, dict]:
    if not ips or len(ips) > 100:
        return 400, {"error": "ips must contain between 1 and 100 entries"}

    items: list[dict] = []
    for ip in ips:
        status, payload = _single_lookup(ip)
        if status == 200:
            items.append({"ip": ip, "result": payload, "error": None})
        else:
            items.append({"ip": ip, "result": None, "error": payload["error"]})
    return 200, {"items": items}


class ASNLookupHandler(BaseHTTPRequestHandler):
    server_version = "ASNLookupHTTP/1.0"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _client_key(self) -> str:
        forwarded_for = self.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return self.client_address[0]

    def _enforce_rate_limit(self) -> bool:
        key = self._client_key()
        allowed, retry_after = self.server.rate_limiter.check(key)
        if allowed:
            return True

        payload = json.dumps({"error": "rate limit exceeded"}).encode("utf-8")
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Retry-After", str(retry_after))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        return False

    def do_GET(self) -> None:  # noqa: N802
        if not self._enforce_rate_limit():
            return
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok"})
            return

        if parsed.path == "/v1/asn/lookup":
            query = parse_qs(parsed.query)
            ip = query.get("ip", [None])[0]
            if not ip:
                self._send_json(400, {"error": "query parameter 'ip' is required"})
                return
            status, payload = _single_lookup(ip)
            self._send_json(status, payload)
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self._enforce_rate_limit():
            return
        parsed = urlparse(self.path)
        if parsed.path != "/v1/asn/lookup-batch":
            self._send_json(404, {"error": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length > 0 else b""

        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON body"})
            return

        ips = payload.get("ips")
        if not isinstance(ips, list) or not all(isinstance(item, str) for item in ips):
            self._send_json(400, {"error": "'ips' must be a list of strings"})
            return

        status, body = _batch_lookup(ips)
        self._send_json(status, body)


def run() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    rate_limit_requests = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))
    rate_limit_window_sec = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
    server = HTTPServer((host, port), ASNLookupHandler)
    server.rate_limiter = RateLimiter(
        max_requests=rate_limit_requests,
        window_sec=rate_limit_window_sec,
    )
    print(f"ASN Lookup API running at http://{host}:{port}")
    print(
        "Rate limit: "
        f"{rate_limit_requests} requests / {rate_limit_window_sec}s per IP "
        "(set RATE_LIMIT_REQUESTS=0 to disable)"
    )
    server.serve_forever()


if __name__ == "__main__":
    run()
