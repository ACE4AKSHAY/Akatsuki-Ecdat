"""Per-client token-bucket rate limiting, off unless configured.

`ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE` sets the sustained request rate per
client IP; `ECDAT_RATE_LIMIT_BURST` optionally overrides the bucket depth.
Setting the rate to 0 (the default) disables limiting entirely, which keeps
local single-operator use frictionless. Health probes are always exempt.
"""
from __future__ import annotations

import os
import threading
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.logging_config import get_request_id


class _Bucket:
    __slots__ = ("tokens", "last_refill")

    def __init__(self, tokens: float, now: float):
        self.tokens = tokens
        self.last_refill = now


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.rate_per_minute = _positive_env("ECDAT_RATE_LIMIT_REQUESTS_PER_MINUTE", 0)
        self.burst = _positive_env("ECDAT_RATE_LIMIT_BURST", max(self.rate_per_minute, 1))
        self.enabled = self.rate_per_minute > 0
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()
        self._last_sweep = time.monotonic()

    async def dispatch(self, request: Request, call_next):
        if not self.enabled or _is_exempt(request):
            return await call_next(request)

        client = (request.client.host if request.client else "unknown") or "unknown"
        allowed, retry_after = self._take_token(client)
        if not allowed:
            return JSONResponse(
                {
                    "detail": "Too many requests; slow down.",
                    "statusCode": 429,
                    "requestId": get_request_id(),
                },
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
        return await call_next(request)

    def _take_token(self, client: str) -> tuple[bool, int]:
        now = time.monotonic()
        refill_rate = self.rate_per_minute / 60.0
        with self._lock:
            self._sweep(now)
            bucket = self._buckets.get(client)
            if bucket is None:
                bucket = _Bucket(float(self.burst), now)
                self._buckets[client] = bucket
            else:
                elapsed = now - bucket.last_refill
                bucket.tokens = min(float(self.burst), bucket.tokens + elapsed * refill_rate)
                bucket.last_refill = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return True, 0
            deficit = 1.0 - bucket.tokens
            return False, max(1, round(deficit / refill_rate))

    def _sweep(self, now: float) -> None:
        # Drop idle buckets so a long-lived process does not grow without bound.
        if now - self._last_sweep < 300:
            return
        self._last_sweep = now
        for key in [k for k, b in self._buckets.items() if now - b.last_refill > 600]:
            del self._buckets[key]


def _is_exempt(request: Request) -> bool:
    return request.url.path.startswith("/health")


def _positive_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    if not raw.isascii() or not raw.isdecimal() or int(raw) < 0:
        raise ValueError(f"{name} must be a non-negative integer; received {raw!r}.")
    return int(raw)
