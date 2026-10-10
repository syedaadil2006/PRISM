"""Operational metrics in the Prometheus text format (GET /api/metrics).

Counts every HTTP request by method, route and status code, with a latency
histogram, so PRISM can be watched by the same monitoring as other services
(Prometheus, Grafana, or anything that reads this format). Scrapers sign in
like any other client: ``Authorization: Bearer <access code>``.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

#: Upper bounds (seconds) of the latency histogram buckets.
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class RequestMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.requests: dict[tuple[str, str, str], int] = defaultdict(int)
        self.bucket_counts = [0] * len(BUCKETS)
        self.latency_sum = 0.0
        self.latency_count = 0
        self.started = time.time()

    def observe(self, method: str, route: str, status: int, seconds: float) -> None:
        with self._lock:
            self.requests[(method, route, str(status))] += 1
            self.latency_sum += seconds
            self.latency_count += 1
            for i, bound in enumerate(BUCKETS):
                if seconds <= bound:
                    self.bucket_counts[i] += 1

    def lines(self) -> list[str]:
        with self._lock:
            out = [
                "# HELP prism_http_requests_total HTTP requests by method, route and status.",
                "# TYPE prism_http_requests_total counter",
            ]
            for (method, route, status), count in sorted(self.requests.items()):
                out.append(f'prism_http_requests_total{{method="{method}",route="{route}",status="{status}"}} {count}')
            out += [
                "# HELP prism_http_request_seconds HTTP request latency.",
                "# TYPE prism_http_request_seconds histogram",
            ]
            for bound, count in zip(BUCKETS, self.bucket_counts):
                out.append(f'prism_http_request_seconds_bucket{{le="{bound}"}} {count}')
            out.append(f'prism_http_request_seconds_bucket{{le="+Inf"}} {self.latency_count}')
            out.append(f"prism_http_request_seconds_sum {self.latency_sum:.6f}")
            out.append(f"prism_http_request_seconds_count {self.latency_count}")
            out += [
                "# HELP prism_uptime_seconds Seconds since PRISM started.",
                "# TYPE prism_uptime_seconds gauge",
                f"prism_uptime_seconds {time.time() - self.started:.0f}",
            ]
        return out


def route_label(request: Request) -> str:
    """The route template (``/api/attacks/{chain_id}``), never the raw path, so labels stay few."""
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if path:
        return path
    return "/api/other" if request.url.path.startswith("/api/") else "static"


class MetricsMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, metrics: RequestMetrics) -> None:  # noqa: ANN001 - Starlette signature
        super().__init__(app)
        self.metrics = metrics

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001, ANN201
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            self.metrics.observe(request.method, route_label(request), status, time.perf_counter() - started)


def gauge(name: str, help_text: str, value: float, kind: str = "gauge") -> list[str]:
    return [f"# HELP {name} {help_text}", f"# TYPE {name} {kind}", f"{name} {value}"]
