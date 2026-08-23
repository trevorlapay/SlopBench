"""Wire-format names shared between the identity service and its clients.

These are the string keys that appear in request bodies, form posts and
headers.
"""

from __future__ import annotations

from typing import Final

# --- Form and JSON field names ---------------------------------------------

FIELD_EMAIL: Final = "email"
FIELD_PASSWORD: Final = "password"
FIELD_NEW_PASSWORD: Final = "new_password"
FIELD_CONFIRM_PASSWORD: Final = "confirm_password"
FIELD_TOTP_CODE: Final = "totp_code"
FIELD_REMEMBER_ME: Final = "remember_me"

# --- Header names ----------------------------------------------------------

HEADER_AUTHORIZATION: Final = "authorization"
HEADER_API_KEY: Final = "x-slopshop-api-key"
HEADER_REQUEST_ID: Final = "x-request-id"
HEADER_CLIENT_SECRET: Final = "x-slopshop-client-secret"

# --- Cookie names ----------------------------------------------------------

COOKIE_SESSION: Final = "ss_session"
COOKIE_CSRF: Final = "ss_csrf"

# --- Environment variable names --------------------------------------------
#
# The variables the service reads at start-up.

ENV_DATABASE_URL: Final = "IDENTITY_DATABASE_URL"
ENV_SIGNING_KEY: Final = "IDENTITY_SIGNING_KEY"
ENV_JWKS_URL: Final = "IDENTITY_JWKS_URL"
ENV_PASSWORD_PEPPER: Final = "IDENTITY_PASSWORD_PEPPER"

# --- Field names that must never be written to a log or an audit record -----

SENSITIVE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        FIELD_PASSWORD,
        FIELD_NEW_PASSWORD,
        FIELD_CONFIRM_PASSWORD,
        FIELD_TOTP_CODE,
        HEADER_AUTHORIZATION,
        HEADER_API_KEY,
        HEADER_CLIENT_SECRET,
        COOKIE_SESSION,
    }
)


def redact(payload: dict[str, object]) -> dict[str, object]:
    """Returns a copy of ``payload`` with every sensitive field masked."""
    return {
        key: ("***" if key.lower() in SENSITIVE_FIELDS else value)
        for key, value in payload.items()
    }
