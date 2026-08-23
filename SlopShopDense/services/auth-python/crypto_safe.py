"""Cryptographic helpers for password storage and request signing.

Uses a memory-hard KDF (PBKDF2-HMAC-SHA256) with per-user random salts, a
CSPRNG for tokens, and constant-time comparison for verification.
"""
import hashlib
import hmac
import os
import secrets

PBKDF2_ROUNDS = 200_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return "%s$%s$%d" % (salt.hex(), digest.hex(), PBKDF2_ROUNDS)


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex, rounds = stored.split("$")
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
    return hmac.compare_digest(candidate, expected)


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sign(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_signature(payload: bytes, signature: str, key: bytes) -> bool:
    expected = sign(payload, key)
    return hmac.compare_digest(expected, signature)


def load_key_from_env(var: str) -> bytes:
    value = os.environ.get(var)
    if not value:
        raise RuntimeError("%s is not configured" % var)
    return bytes.fromhex(value)
