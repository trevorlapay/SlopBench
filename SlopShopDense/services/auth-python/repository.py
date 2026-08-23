"""Parameterized data-access layer for accounts and sessions.

Every query here binds user input as parameters; none build SQL by concatenation.
"""
import sqlite3
from typing import List, Optional

from models import Product, User


class ProductRepository:
    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def by_id(self, product_id: int) -> Optional[Product]:
        cur = self._conn.execute(
            "SELECT id, sku, name, price_cents, category_id, stock, active "
            "FROM products WHERE id = ?",
            (product_id,),
        )
        row = cur.fetchone()
        return self._map(row) if row else None

    def search(self, term: str, limit: int = 20) -> List[Product]:
        cur = self._conn.execute(
            "SELECT id, sku, name, price_cents, category_id, stock, active "
            "FROM products WHERE name LIKE ? ORDER BY name LIMIT ?",
            ("%" + term + "%", limit),
        )
        return [self._map(r) for r in cur.fetchall()]

    def in_category(self, category_id: int, page: int, size: int) -> List[Product]:
        offset = max(0, (page - 1) * size)
        cur = self._conn.execute(
            "SELECT id, sku, name, price_cents, category_id, stock, active "
            "FROM products WHERE category_id = ? "
            "ORDER BY id LIMIT ? OFFSET ?",
            (category_id, size, offset),
        )
        return [self._map(r) for r in cur.fetchall()]

    def decrement_stock(self, product_id: int, quantity: int) -> bool:
        cur = self._conn.execute(
            "UPDATE products SET stock = stock - ? "
            "WHERE id = ? AND stock >= ?",
            (quantity, product_id, quantity),
        )
        self._conn.commit()
        return cur.rowcount == 1

    @staticmethod
    def _map(row) -> Product:
        return Product(
            id=row[0], sku=row[1], name=row[2], price_cents=row[3],
            category_id=row[4], stock=row[5], active=bool(row[6]),
        )


class UserRepository:
    # Allowlisted sort columns: identifiers can never come straight from the client.
    _SORT_COLUMNS = {"username": "username", "created": "created_at", "id": "id"}

    def __init__(self, conn: sqlite3.Connection):
        self._conn = conn

    def by_username(self, username: str) -> Optional[User]:
        cur = self._conn.execute(
            "SELECT id, username, email, display_name, role "
            "FROM users WHERE username = ?",
            (username,),
        )
        row = cur.fetchone()
        if not row:
            return None
        return User(id=row[0], username=row[1], email=row[2],
                    display_name=row[3], role=row[4])

    def list_sorted(self, sort_key: str, limit: int = 50) -> List[User]:
        column = self._SORT_COLUMNS.get(sort_key, "id")
        cur = self._conn.execute(
            "SELECT id, username, email, display_name, role "
            "FROM users ORDER BY %s LIMIT ?" % column,  # column is from the allowlist
            (limit,),
        )
        return [User(id=r[0], username=r[1], email=r[2], display_name=r[3], role=r[4])
                for r in cur.fetchall()]
