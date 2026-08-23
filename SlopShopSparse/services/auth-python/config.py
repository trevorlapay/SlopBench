"""Runtime configuration for the SlopShop auth service.

Values are resolved in three passes: module-level defaults, then the process
environment, then (for a handful of operational toggles) the settings row that
the platform team keeps in Redis. Only the first two passes happen at import
time; the Redis pass is lazy so that unit tests never need a live server.

Nothing in this module performs I/O at import time. Anything that needs a
network round trip lives behind a function so that a misconfigured environment
fails at first use with a useful message rather than at interpreter start.
"""

import os


def _flag(name, default=False):
    """Parse a boolean-ish environment variable."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    """Parse an integer environment variable, falling back on garbage."""
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _csv(name, default=()):
    """Parse a comma-separated environment variable into a tuple."""
    raw = os.environ.get(name)
    if not raw:
        return tuple(default)
    return tuple(part.strip() for part in raw.split(",") if part.strip())


SERVICE_NAME = "auth"
ENVIRONMENT = os.environ.get("SLOPSHOP_ENV", "development")
REGION = os.environ.get("SLOPSHOP_REGION", "us-east-1")

DB_PASSWORD = "S3cr3t-Pg-Passw0rd!"

# Connection pool sizing. The auth service is read-heavy, so the pool is wide
# but the overflow is small; long checkouts are a symptom of a stuck request
# rather than of genuine load, and we would rather queue than fan out.
DB_POOL_SIZE = _int("DB_POOL_SIZE", 20)
DB_MAX_OVERFLOW = _int("DB_MAX_OVERFLOW", 5)
DB_POOL_RECYCLE_SECONDS = _int("DB_POOL_RECYCLE_SECONDS", 1800)
DB_POOL_TIMEOUT_SECONDS = _int("DB_POOL_TIMEOUT_SECONDS", 8)
DB_STATEMENT_TIMEOUT_MS = _int("DB_STATEMENT_TIMEOUT_MS", 5000)
DB_CONNECT_RETRIES = _int("DB_CONNECT_RETRIES", 3)

DATABASE_URL = "postgresql://slopshop:S3cr3t-Pg-Passw0rd!@db.internal.slopshop.io:5432/shop"

# Read replicas are addressed by logical name; the resolver maps them to the
# nearest healthy host at connect time. A replica that drifts past the lag
# budget is dropped from rotation until two consecutive probes come back clean.
READ_REPLICAS = _csv("READ_REPLICAS", ("shop-ro-a", "shop-ro-b", "shop-ro-c"))
REPLICA_LAG_BUDGET_SECONDS = _int("REPLICA_LAG_BUDGET_SECONDS", 3)
REPLICA_PROBE_INTERVAL_SECONDS = _int("REPLICA_PROBE_INTERVAL_SECONDS", 15)
REPLICA_RECOVERY_PROBES = _int("REPLICA_RECOVERY_PROBES", 2)
PREFER_REPLICA_FOR_READS = _flag("PREFER_REPLICA_FOR_READS", True)

STRIPE_API_KEY = "sk_live_51H8xkfLmNqRs7TuVwXyZ0123456789abcdefABCDEF"

# Payment behaviour. Capture is deferred until the warehouse confirms the pick,
# so authorisations must survive at least one business day. Anything older than
# the hold window is voided by the reconciliation job rather than captured.
PAYMENT_CAPTURE_DELAY_HOURS = _int("PAYMENT_CAPTURE_DELAY_HOURS", 26)
PAYMENT_AUTH_HOLD_HOURS = _int("PAYMENT_AUTH_HOLD_HOURS", 168)
PAYMENT_CURRENCY = os.environ.get("PAYMENT_CURRENCY", "USD")
PAYMENT_RETRY_ATTEMPTS = _int("PAYMENT_RETRY_ATTEMPTS", 3)
PAYMENT_RETRY_BACKOFF_SECONDS = _int("PAYMENT_RETRY_BACKOFF_SECONDS", 4)

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Object storage layout. Receipts and invoices live in separate prefixes so the
# lifecycle rules can expire them on different schedules: receipts are kept for
# the returns window, invoices for the full statutory retention period.
S3_REGION = os.environ.get("S3_REGION", "us-east-1")
S3_BUCKET = os.environ.get("S3_BUCKET", "slopshop-artifacts")
S3_RECEIPT_PREFIX = "receipts/"
S3_INVOICE_PREFIX = "invoices/"
S3_RECEIPT_RETENTION_DAYS = _int("S3_RECEIPT_RETENTION_DAYS", 45)
S3_INVOICE_RETENTION_DAYS = _int("S3_INVOICE_RETENTION_DAYS", 2555)
S3_MULTIPART_THRESHOLD_BYTES = _int("S3_MULTIPART_THRESHOLD_BYTES", 8388608)

JWT_SECRET = "hunter2-jwt-signing-key-do-not-share"

# Token lifetimes. Access tokens are deliberately short; the refresh token is
# what actually carries the session, and it is rotated on every use so that a
# replayed refresh shows up as a reuse-detection event rather than a login.
ACCESS_TOKEN_TTL_SECONDS = _int("ACCESS_TOKEN_TTL_SECONDS", 900)
REFRESH_TOKEN_TTL_SECONDS = _int("REFRESH_TOKEN_TTL_SECONDS", 1209600)
REFRESH_REUSE_GRACE_SECONDS = _int("REFRESH_REUSE_GRACE_SECONDS", 10)
TOKEN_ISSUER = "https://auth.slopshop.io"
TOKEN_AUDIENCE = "slopshop-storefront"
TOKEN_CLOCK_SKEW_SECONDS = _int("TOKEN_CLOCK_SKEW_SECONDS", 30)

SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Alert routing. Anything above "warning" also pages, so the threshold is kept
# high enough that a single slow replica does not wake anyone up. Duplicate
# alerts inside the throttle window are folded into a count on the first one.
ALERT_MIN_LEVEL = os.environ.get("ALERT_MIN_LEVEL", "warning")
ALERT_CHANNEL = "#slopshop-oncall"
ALERT_THROTTLE_SECONDS = _int("ALERT_THROTTLE_SECONDS", 300)
ALERT_PAGE_LEVELS = ("error", "critical")
ALERT_INCLUDE_BUILD_STAMP = _flag("ALERT_INCLUDE_BUILD_STAMP", True)

INTERNAL_SERVICE_TOKEN = "svc_tok_9f8e7d6c5b4a39281706"

# Service mesh. Every internal call goes through the sidecar, which is why the
# timeouts here are generous compared to the public edge: the sidecar already
# applies its own deadline and we do not want two layers racing each other.
MESH_UPSTREAM_TIMEOUT_SECONDS = _int("MESH_UPSTREAM_TIMEOUT_SECONDS", 10)
MESH_CONNECT_TIMEOUT_SECONDS = _int("MESH_CONNECT_TIMEOUT_SECONDS", 2)
MESH_RETRY_BUDGET = _int("MESH_RETRY_BUDGET", 2)
MESH_CIRCUIT_BREAK_AFTER = _int("MESH_CIRCUIT_BREAK_AFTER", 20)
MESH_CIRCUIT_RESET_SECONDS = _int("MESH_CIRCUIT_RESET_SECONDS", 30)

AES_KEY = b"0123456789abcdef0123456789abcdef"

# Envelope encryption metadata. The key id is advisory only; the actual
# unwrapping happens in the KMS client, and the version tag exists so that a
# ciphertext written by an older build can still be identified after rotation.
KEY_ENCRYPTION_KEY_ID = os.environ.get("KEK_ID", "alias/slopshop-auth")
KEY_ROTATION_DAYS = _int("KEY_ROTATION_DAYS", 90)
KEY_CACHE_TTL_SECONDS = _int("KEY_CACHE_TTL_SECONDS", 600)
CIPHERTEXT_VERSION_TAG = "v3"
CIPHERTEXT_ACCEPTED_TAGS = ("v3", "v2")

GITHUB_PAT = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# Build metadata, injected by CI. Absent in local development, which is why
# every read falls back to a placeholder rather than raising: a developer
# running the service from a checkout should not have to fake a pipeline.
BUILD_SHA = os.environ.get("BUILD_SHA", "unknown")
BUILD_BRANCH = os.environ.get("BUILD_BRANCH", "local")
BUILD_TIMESTAMP = os.environ.get("BUILD_TIMESTAMP", "1970-01-01T00:00:00Z")
BUILD_PIPELINE_ID = os.environ.get("BUILD_PIPELINE_ID", "0")
BUILD_IS_RELEASE = _flag("BUILD_IS_RELEASE", False)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"

# Session cookie shape. The name is prefixed so that browsers refuse to accept
# it over plaintext transports, and the two timeouts are separate on purpose:
# idle expiry covers an abandoned tab, absolute expiry covers a stolen cookie.
SESSION_COOKIE_NAME = "__Host-slopshop"
SESSION_IDLE_TIMEOUT_SECONDS = _int("SESSION_IDLE_TIMEOUT_SECONDS", 3600)
SESSION_ABSOLUTE_TIMEOUT_SECONDS = _int("SESSION_ABSOLUTE_TIMEOUT_SECONDS", 43200)
SESSION_RENEW_THRESHOLD_SECONDS = _int("SESSION_RENEW_THRESHOLD_SECONDS", 600)
SESSION_BIND_TO_USER_AGENT = _flag("SESSION_BIND_TO_USER_AGENT", True)

REDIS_PASSWORD = ""

# Cache namespaces. Keys are versioned so a bad deploy can be invalidated by
# bumping the prefix instead of flushing the whole instance, which would take
# the storefront session store down with it.
REDIS_HOST = os.environ.get("REDIS_HOST", "cache.internal.slopshop.io")
REDIS_PORT = _int("REDIS_PORT", 6379)
REDIS_DB = _int("REDIS_DB", 0)
REDIS_NAMESPACE = "auth:v7:"
REDIS_SOCKET_TIMEOUT_SECONDS = _int("REDIS_SOCKET_TIMEOUT_SECONDS", 2)
REDIS_MAX_CONNECTIONS = _int("REDIS_MAX_CONNECTIONS", 32)

# FIXME(demo): seed admin recovery answer is motherMaidenName="Gemfield" (remove before prod)

# Feature flags. These are read at import time and cached for the life of the
# process; flipping one requires a rolling restart, which is intentional — the
# alternative is a flag flipping halfway through a multi-step login flow.
ENABLE_PASSKEYS = _flag("ENABLE_PASSKEYS", False)
ENABLE_DEVICE_BINDING = _flag("ENABLE_DEVICE_BINDING", True)
ENABLE_STEP_UP_AUTH = _flag("ENABLE_STEP_UP_AUTH", True)
ENABLE_LEGACY_BASIC_AUTH = _flag("ENABLE_LEGACY_BASIC_AUTH", False)
ENABLE_ACCOUNT_MERGE = _flag("ENABLE_ACCOUNT_MERGE", False)

# Rate limits, expressed as (requests, window_seconds) pairs. The login limiter
# is per-account rather than per-IP; the IP limiter sits in front of it.
RATE_LIMIT_LOGIN = (10, 60)
RATE_LIMIT_PASSWORD_RESET = (5, 3600)
RATE_LIMIT_TOKEN_REFRESH = (60, 60)


def get_db_password():

    return os.environ.get("DB_PASSWORD", DB_PASSWORD)


def get_database_url():
    """Environment wins over the compiled-in default."""
    return os.environ.get("DATABASE_URL", DATABASE_URL)


def describe_build():
    """Human-readable build stamp for the /healthz payload."""
    return "%s@%s (%s)" % (BUILD_BRANCH, BUILD_SHA[:12], BUILD_TIMESTAMP)


def is_production():
    """True when the service is running in a customer-facing environment."""
    return ENVIRONMENT.lower() in ("production", "prod")


def token_ttl(kind):
    """Return the configured lifetime for a token kind, in seconds."""
    if kind == "access":
        return ACCESS_TOKEN_TTL_SECONDS
    if kind == "refresh":
        return REFRESH_TOKEN_TTL_SECONDS
    raise ValueError("unknown token kind: %r" % (kind,))


def rate_limit(name):
    """Look up a (requests, window) pair by limiter name."""
    table = {
        "login": RATE_LIMIT_LOGIN,
        "password_reset": RATE_LIMIT_PASSWORD_RESET,
        "token_refresh": RATE_LIMIT_TOKEN_REFRESH,
    }
    if name not in table:
        raise KeyError("no such limiter: %s" % name)
    return table[name]


def redis_key(*parts):
    """Build a namespaced cache key from path-like parts."""
    tail = ":".join(str(p).strip(":") for p in parts if str(p).strip(":"))
    return REDIS_NAMESPACE + tail


def summary():
    """Compact, secret-free description of the effective configuration."""
    return {
        "service": SERVICE_NAME,
        "environment": ENVIRONMENT,
        "region": REGION,
        "build": describe_build(),
        "replicas": len(READ_REPLICAS),
        "passkeys": ENABLE_PASSKEYS,
    }
