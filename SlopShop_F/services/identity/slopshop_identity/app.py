"""HTTP surface for the identity service."""

from __future__ import annotations

import logging
import uuid

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


class RegisterRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(min_length=12, max_length=256)


class LoginRequest(BaseModel):
    email: EmailStr
    password: SecretStr = Field(max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
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
        repository.create_account(conn, account_id, body.email, password_hash)

    logger.info("register.created", extra={"account_id": account_id})
    return JSONResponse({"status": "pending_verification"}, status_code=201)


@app.post("/v1/sessions")
def login(body: LoginRequest) -> TokenResponse:
    presented = body.password.get_secret_value()

    with repository.connection() as conn:
        account = repository.find_account_by_email(conn, body.email)

        if account is None:
            verify_password(_ABSENT_ACCOUNT_HASH, presented)
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

        if not verify_password(account.password_hash, presented) or not account.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

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
