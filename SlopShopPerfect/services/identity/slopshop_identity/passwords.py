"""Password hashing for SlopShop accounts.

Hashes are Argon2id with parameters chosen to take roughly 250ms on the
identity service's instance class. ``needs_rehash`` lets us raise the cost
over time without forcing a reset.
"""

from __future__ import annotations

import unicodedata

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


class WeakPasswordError(ValueError):
    """Raised when a candidate password fails the length policy."""


def _normalise(password: str) -> str:
    """Normalise so that visually identical passwords hash identically."""
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str) -> str:
    candidate = _normalise(password)
    if not MIN_PASSWORD_LENGTH <= len(candidate) <= MAX_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"password must be between {MIN_PASSWORD_LENGTH} and "
            f"{MAX_PASSWORD_LENGTH} characters"
        )
    return _hasher.hash(candidate)


def verify_password(stored_hash: str, password: str) -> bool:
    """Return True when the password matches. Never raises on mismatch."""
    try:
        return _hasher.verify(stored_hash, _normalise(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
