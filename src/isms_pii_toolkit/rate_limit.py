from __future__ import annotations

import time
from collections import defaultdict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


EXEMPT_PATHS = frozenset({"/", "/health", "/docs", "/openapi.json", "/redoc"})


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple fixed-window per-minute limiter (in-memory; use a shared store in production)."""

    def __init__(self, app, calls_per_minute: int = 120) -> None:
        super().__init__(app)
        self.calls_per_minute = max(1, calls_per_minute)
        self._counts: dict[tuple[str, int], int] = defaultdict(int)

    def _client_host(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def _prune(self, current_bucket: int) -> None:
        stale = [key for key in self._counts if key[1] < current_bucket - 1]
        for key in stale:
            del self._counts[key]

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.scope.get("path", "")
        if path in EXEMPT_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        bucket = int(time.time()) // 60
        self._prune(bucket)
        client = self._client_host(request)
        key = (client, bucket)
        self._counts[key] += 1
        if self._counts[key] > self.calls_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Try again later."},
            )
        return await call_next(request)
