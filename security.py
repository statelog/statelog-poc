from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response

REQUEST_COUNTER = Counter(
    "access_decision_requests_total",
    "Total access decision requests",
    ["tenant_id", "result", "request_type"],
)
RISK_SCORE_HISTOGRAM = Histogram(
    "access_risk_score",
    "Distribution of risk scores",
    buckets=(0, 10, 20, 30, 40, 50, 60, 70, 80, 100),
)
LATENCY_HISTOGRAM = Histogram(
    "access_request_latency_seconds",
    "Latency of access requests",
)
AUTH_FAILURE_COUNTER = Counter(
    "access_auth_failures_total",
    "Authentication failures",
    ["reason"],
)
RATE_LIMIT_COUNTER = Counter(
    "access_rate_limit_hits_total",
    "Rate limit hits",
    ["scope"],
)
CACHE_COUNTER = Counter(
    "access_decision_cache_total",
    "Decision cache hits and misses",
    ["result"],
)


def metrics_response() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
