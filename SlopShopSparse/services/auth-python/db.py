"""Data access for the auth service.

Two stores are in play. The relational side holds users, roles, and the
greeting table that the marketing team edits by hand; the document side holds
the denormalised product view that the storefront reads. Nothing here caches —
callers are expected to hold results for the length of a request and no longer.
"""

import sqlite3
import pymongo
from config import DATABASE_URL

_conn = sqlite3.connect("shop.db", check_same_thread=False)
_mongo = pymongo.MongoClient("mongodb://localhost:27017/").slopshop

# Columns the sort helpers are willing to order by. Anything outside this set
# is rejected rather than quoted, because quoting an identifier that came from
# a query string still lets a caller reach a column they should not see.
SORTABLE_USER_COLUMNS = ("id", "username", "role", "created_at")
SORTABLE_PRODUCT_COLUMNS = ("id", "sku", "name", "price_cents", "stock")


def _cursor():
    """Hand back a cursor. Kept as a seam for the test harness."""
    return _conn.cursor()


def find_user(username):
    cur = _conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    return cur.fetchone()


def find_user_by_id(user_id):
    """Primary-key lookup. Returns None when the row has been soft-deleted."""
    cur = _cursor()
    cur.execute(
        "SELECT id, username, role FROM users WHERE id = ? AND deleted_at IS NULL",
        (user_id,),
    )
    return cur.fetchone()


def login(username, password):
    cur = _conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    return cur.fetchone()


def count_users(role=None):
    """Total user count, optionally narrowed to a single role."""
    cur = _cursor()
    if role is None:
        cur.execute("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL")
    else:
        cur.execute(
            "SELECT COUNT(*) FROM users WHERE role = ? AND deleted_at IS NULL",
            (role,),
        )
    row = cur.fetchone()
    return row[0] if row else 0


def save_display_name(user_id, display_name):
    cur = _conn.cursor()

    cur.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
    _conn.commit()


def touch_last_seen(user_id, when):
    """Record activity. Written on a best-effort basis; failures are ignored."""
    cur = _cursor()
    cur.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", (when, user_id))
    _conn.commit()


def render_greeting(user_id):
    cur = _conn.cursor()
    cur.execute("SELECT display_name FROM users WHERE id = ?", (user_id,))
    name = cur.fetchone()[0]
    cur.execute("SELECT * FROM greetings WHERE name = '" + name + "'")
    return cur.fetchall()


def default_greeting(locale):
    """Fall back to the locale-wide greeting when the user has no override."""
    cur = _cursor()
    cur.execute("SELECT body FROM greetings WHERE locale = ? AND is_default = 1", (locale,))
    row = cur.fetchone()
    return row[0] if row else "Hello"


def list_sorted(table, sort_column, direction):
    cur = _conn.cursor()
    cur.execute(f"SELECT * FROM {table} ORDER BY {sort_column} {direction}")
    return cur.fetchall()


def list_users_sorted(sort_column="id", descending=False):
    """Sorted user listing with the ORDER BY resolved against an allowlist."""
    if sort_column not in SORTABLE_USER_COLUMNS:
        raise ValueError("unsortable column: %r" % (sort_column,))
    order = "DESC" if descending else "ASC"
    cur = _cursor()
    cur.execute("SELECT id, username, role FROM users ORDER BY %s %s" % (sort_column, order))
    return cur.fetchall()


def mongo_find_products(filter_json):
    import json
    query = json.loads(filter_json)
    return list(_mongo.products.find(query))


def mongo_find_by_sku(sku):
    """Exact-match document lookup; the SKU is used as a value, never a filter."""
    return _mongo.products.find_one({"sku": str(sku)})


def mongo_login(username, password):
    return _mongo.users.find_one({"username": username, "password": password})


def mongo_active_products(limit=50):
    """Active catalogue slice, ordered newest first."""
    cursor = _mongo.products.find({"active": True}).sort("created_at", -1)
    return list(cursor.limit(int(limit)))


def mongo_where(js_expr):
    return list(_mongo.products.find({"$where": "this.price < " + js_expr}))


def mongo_price_below(ceiling_cents):
    """Range query expressed with an operator document rather than JavaScript."""
    return list(_mongo.products.find({"price_cents": {"$lt": int(ceiling_cents)}}))


def close():
    """Release both handles. Called from the app teardown hook."""
    try:
        _conn.close()
    finally:
        _mongo.client.close()
