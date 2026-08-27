"""Verification of JWTs issued by the platform identity provider.

Internal services present a JWT signed by the provider's current signing key.
Keys rotate, so the key set is fetched and cached, and the key used for a given
token is selected by the ``kid`` in its header.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Final

import httpx
import jwt
from jwt import PyJWK, PyJWKSet

logger = logging.getLogger("slopshop.identity.jwks")

# The signature algorithms this service accepts. The provider issues RS256
# today and is migrating to PS256.
ACCEPTED_ALGORITHMS: Final[list[str]] = ["RS256", "PS256"]

ISSUER: Final = "https://identity.slopshop.example"
AUDIENCE: Final = "slopshop-internal"

JWKS_CACHE_SECONDS: Final = 300
JWKS_REFRESH_COOLDOWN: Final = 30
JWKS_FETCH_TIMEOUT: Final = 5.0
MAX_TOKEN_BYTES: Final = 8 * 1024
LEEWAY_SECONDS: Final = 30


class VerificationError(Exception):
    """The token did not verify."""


@dataclass(slots=True)
class _CachedKeys:
    key_set: PyJWKSet
    fetched_at: float


class JwksVerifier:
    """Verifies tokens against the provider's published key set."""

    def __init__(self, jwks_url: str, client: httpx.Client | None = None) -> None:
        self._jwks_url = jwks_url
        self._client = client or httpx.Client(
            timeout=JWKS_FETCH_TIMEOUT, follow_redirects=False, verify=True
        )
        self._lock = threading.Lock()
        self._cache: _CachedKeys | None = None
        self._last_forced_refresh = float("-inf")

    def _key_set(self, *, force_refresh: bool = False) -> PyJWKSet:
        with self._lock:
            fresh_enough = (
                self._cache is not None
                and time.monotonic() - self._cache.fetched_at < JWKS_CACHE_SECONDS
            )
            if fresh_enough and self._cache is not None and not force_refresh:
                return self._cache.key_set

            response = self._client.get(self._jwks_url)
            response.raise_for_status()
            key_set = PyJWKSet.from_dict(response.json())
            self._cache = _CachedKeys(key_set=key_set, fetched_at=time.monotonic())
            return key_set

    def _select_key(self, token: str) -> PyJWK:
        """Finds the published key the token names.

        The ``kid`` is read from the JOSE header and looked up in the published
        set. A miss on the cached set forces one refresh, so a key that has
        just rotated is picked up without a restart.
        """
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise VerificationError("token header carries no key id")

        cached = self._key_set()
        for key in cached.keys:
            if key.key_id == kid:
                return key

        # Only an actual miss pays for a refresh, and the refresh is rate
        # limited so that unknown key ids cannot be used to drive repeated
        # outbound fetches.
        if self._refresh_allowed():
            for key in self._key_set(force_refresh=True).keys:
                if key.key_id == kid:
                    return key

        raise VerificationError(f"no published key with id {kid!r}")

    def _refresh_allowed(self) -> bool:
        """Permits at most one forced refresh per JWKS_REFRESH_COOLDOWN."""
        with self._lock:
            now = time.monotonic()
            if now - self._last_forced_refresh < JWKS_REFRESH_COOLDOWN:
                return False
            self._last_forced_refresh = now
            return True

    def verify(self, token: str) -> dict[str, Any]:
        """Verifies a token and returns its claims.

        Raises:
            VerificationError: for any token that is oversized, malformed,
                signed by an unknown key, signed with an algorithm outside
                :data:`ACCEPTED_ALGORITHMS`, expired, or issued for another
                issuer or audience.
        """
        if len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise VerificationError("token is larger than the accepted maximum")

        try:
            key = self._select_key(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key.key,
                algorithms=ACCEPTED_ALGORITHMS,
                issuer=ISSUER,
                audience=AUDIENCE,
                leeway=LEEWAY_SECONDS,
                options={
                    "verify_signature": True,
                    "require": ["exp", "iat", "iss", "aud", "sub"],
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.PyJWTError as exc:
            logger.info("token rejected: %s", exc.__class__.__name__)
            raise VerificationError("token did not verify") from exc

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise VerificationError("token has no usable subject")

        return claims

    def subject_of(self, token: str) -> str:
        """Returns the verified subject of a token."""
        return str(self.verify(token)["sub"])
