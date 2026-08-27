"""Persistence for accounts and tokens.

Statements are prepared with bound parameters.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

import psycopg
from psycopg.rows import class_row


@dataclass(frozen=True, slots=True)
class Account:
    id: str
    email: str
    password_hash: str
    is_active: bool
    created_at: datetime


@dataclass(frozen=True, slots=True)
class TokenRecord:
    account_id: str
    digest: str
    expires_at: datetime
    revoked: bool


def _dsn() -> str:
    dsn = os.environ.get("IDENTITY_DATABASE_URL")
    if not dsn:
        raise RuntimeError("IDENTITY_DATABASE_URL is not configured")
    return dsn


@contextmanager
def connection() -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(_dsn(), sslmode="verify-full", autocommit=False)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def find_account_by_email(conn: psycopg.Connection, email: str) -> Account | None:
    with conn.cursor(row_factory=class_row(Account)) as cur:
        cur.execute(
            """
            SELECT id, email, password_hash, is_active, created_at
              FROM accounts
             WHERE lower(email) = lower(%s)
            """,
            (email,),
        )
        return cur.fetchone()


def create_account(
    conn: psycopg.Connection, account_id: str, email: str, password_hash: str
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO accounts (id, email, password_hash, is_active)
            VALUES (%s, %s, %s, FALSE)
            """,
            (account_id, email, password_hash),
        )


def activate_account(conn: psycopg.Connection, account_id: str) -> bool:
    """Marks a verified account usable. Returns False if it was already active."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE accounts SET is_active = TRUE WHERE id = %s AND is_active = FALSE",
            (account_id,),
        )
        return cur.rowcount == 1


def update_password_hash(conn: psycopg.Connection, account_id: str, password_hash: str) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE accounts SET password_hash = %s WHERE id = %s",
            (password_hash, account_id),
        )


def store_token(conn: psycopg.Connection, record: TokenRecord) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO access_tokens (account_id, digest, expires_at, revoked)
            VALUES (%s, %s, %s, %s)
            """,
            (record.account_id, record.digest, record.expires_at, record.revoked),
        )


def find_token(conn: psycopg.Connection, digest: str) -> TokenRecord | None:
    with conn.cursor(row_factory=class_row(TokenRecord)) as cur:
        cur.execute(
            """
            SELECT account_id, digest, expires_at, revoked
              FROM access_tokens
             WHERE digest = %s
            """,
            (digest,),
        )
        return cur.fetchone()


def revoke_tokens_for_account(conn: psycopg.Connection, account_id: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE access_tokens SET revoked = TRUE WHERE account_id = %s AND revoked = FALSE",
            (account_id,),
        )
        return cur.rowcount
