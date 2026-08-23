"""Opaque bearer tokens.

Tokens are 256 bits of random output handed to the client in base64url form.
Only a SHA-256 digest of the token is persisted; lookups are by digest.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

TOKEN_BYTES = 32
ACCESS_TOKEN_TTL = timedelta(minutes=15)
REFRESH_TOKEN_TTL = timedelta(days=14)


@dataclass(frozen=True, slots=True)
class IssuedToken:
    """The plaintext token is returned to the caller exactly once."""

    plaintext: str
    digest: str
    expires_at: datetime


def _digest(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def issue(ttl: timedelta = ACCESS_TOKEN_TTL) -> IssuedToken:
    raw = secrets.token_bytes(TOKEN_BYTES)
    plaintext = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    return IssuedToken(
        plaintext=plaintext,
        digest=_digest(plaintext),
        expires_at=datetime.now(UTC) + ttl,
    )


def digest_for_lookup(presented: str) -> str:
    return _digest(presented)


def matches(presented: str, stored_digest: str) -> bool:
    return hmac.compare_digest(_digest(presented), stored_digest)


def is_expired(expires_at: datetime, *, now: datetime | None = None) -> bool:
    reference = now if now is not None else datetime.now(UTC)
    return expires_at <= reference
