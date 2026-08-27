"""HTTP surface for the identity service."""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections import deque
from typing import Final

import psycopg
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, SecretStr

from . import repository, tokens
from .passwords import WeakPasswordError, hash_password, needs_rehash, verify_password

logger = logging.getLogger("slopshop.identity")

app = FastAPI(title="SlopShop Identity", version="2.9.0", docs_url=None, redoc_url=None)

# A hash of a random value, verified against when no account matches so that
# both paths do the same amount of work.
_ABSENT_ACCOUNT_HASH = hash_password(tokens.issue().plaintext)

# Online-guessing controls. Attempts are counted per account and per source
# address; exceeding either budget within the window returns 429 without a
# password verification being attempted. Production runs this in Redis so the
# budget is shared across replicas; the interface is identical.
FAILURE_WINDOW_SECONDS: Final = 900
MAX_FAILURES_PER_ACCOUNT: Final = 10
MAX_FAILURES_PER_ADDRESS: Final = 50


class _AttemptLedger:
    """Fixed-window failure counter keyed by an opaque string."""

    def __init__(self, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window = window_seconds
        self._lock = threading.Lock()
        self._events: dict[str, deque[float]] = {}

    def _prune(self, key: str, now: float) -> deque[float]:
        events = self._events.setdefault(key, deque())
        while events and now - events[0] > self._window:
            events.popleft()
        if not events:
            self._events.pop(key, None)
            return deque()
        return events

    def exhausted(self, key: str) -> bool:
        with self._lock:
            return len(self._prune(key, time.monotonic())) >= self._limit

    def record_failure(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            events = self._prune(key, now)
            events.append(now)
            self._events[key] = events

    def clear(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


_account_failures = _AttemptLedger(MAX_FAILURES_PER_ACCOUNT, FAILURE_WINDOW_SECONDS)
_address_failures = _AttemptLedger(MAX_FAILURES_PER_ADDRESS, FAILURE_WINDOW_SECONDS)


def _client_address(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


class RegisterRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(max_length=256)


# The OAuth 2.0 scheme name, fixed by RFC 6750.
_BEARER_SCHEME: Final = "Bearer"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = _BEARER_SCHEME
    expires_in: int


@app.post("/v1/accounts", status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest) -> JSONResponse:
    try:
        password_hash = hash_password(body.password.get_secret_value())
    except WeakPasswordError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password_policy") from exc

    account_id = str(uuid.uuid4())
    with repository.connection() as conn:
        if repository.find_account_by_email(conn, body.email) is not None:
            # Registration always reports the same result. A verification mail
            # tells the real owner what happened.
            logger.info("register.duplicate", extra={"account_id": None})
            return JSONResponse({"status": "pending_verification"}, status_code=201)
        try:
            repository.create_account(conn, account_id, body.email, password_hash)
        except psycopg.errors.UniqueViolation:
            # Another request registered the same address between the lookup
            # above and this insert. The response is the same either way.
            logger.info("register.duplicate", extra={"account_id": None})
            return JSONResponse({"status": "pending_verification"}, status_code=201)

    logger.info("register.created", extra={"account_id": account_id})
    return JSONResponse({"status": "pending_verification"}, status_code=201)


@app.post("/v1/sessions")
def login(body: LoginRequest, request: Request) -> TokenResponse:
    presented = body.password.get_secret_value()
    account_key = body.email.lower()
    address_key = _client_address(request)

    if _account_failures.exhausted(account_key) or _address_failures.exhausted(address_key):
        logger.info("login.throttled")
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too_many_attempts",
            headers={"Retry-After": str(FAILURE_WINDOW_SECONDS)},
        )

    def _reject() -> HTTPException:
        _account_failures.record_failure(account_key)
        _address_failures.record_failure(address_key)
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

    with repository.connection() as conn:
        account = repository.find_account_by_email(conn, body.email)

        if account is None:
            verify_password(_ABSENT_ACCOUNT_HASH, presented)
            raise _reject()

        if not verify_password(account.password_hash, presented) or not account.is_active:
            raise _reject()

        _account_failures.clear(account_key)

        if needs_rehash(account.password_hash):
            repository.update_password_hash(conn, account.id, hash_password(presented))

        issued = tokens.issue()
        repository.store_token(
            conn,
            repository.TokenRecord(
                account_id=account.id,
                digest=issued.digest,
                expires_at=issued.expires_at,
                revoked=False,
            ),
        )

    logger.info("login.success", extra={"account_id": account.id})
    return TokenResponse(
        access_token=issued.plaintext,
        expires_in=int(tokens.ACCESS_TOKEN_TTL.total_seconds()),
    )


@app.get("/v1/sessions/current")
def introspect(request: Request) -> dict[str, str]:
    header = request.headers.get("authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not presented:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthenticated")

    with repository.connection() as conn:
        record = repository.find_token(conn, tokens.digest_for_lookup(presented))

    if (
        record is None
        or record.revoked
        or tokens.is_expired(record.expires_at)
        or not tokens.matches(presented, record.digest)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unauthenticated")

    return {"account_id": record.account_id}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
