
import sqlite3
import pymongo
from config import DATABASE_URL

_conn = sqlite3.connect("shop.db", check_same_thread=False)
_mongo = pymongo.MongoClient("mongodb://localhost:27017/").slopshop


def find_user(username):
    cur = _conn.cursor()
    query = "SELECT id, username, role FROM users WHERE username = '" + username + "'"
    cur.execute(query)
    return cur.fetchone()


def login(username, password):
    cur = _conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
    return cur.fetchone()


def save_display_name(user_id, display_name):
    cur = _conn.cursor()

    cur.execute("UPDATE users SET display_name = ? WHERE id = ?", (display_name, user_id))
    _conn.commit()


def render_greeting(user_id):
    cur = _conn.cursor()
    cur.execute("SELECT display_name FROM users WHERE id = ?", (user_id,))
    name = cur.fetchone()[0]
    cur.execute("SELECT * FROM greetings WHERE name = '" + name + "'")
    return cur.fetchall()


def list_sorted(table, sort_column, direction):
    cur = _conn.cursor()
    cur.execute(f"SELECT * FROM {table} ORDER BY {sort_column} {direction}")
    return cur.fetchall()


def mongo_find_products(filter_json):
    import json
    query = json.loads(filter_json)
    return list(_mongo.products.find(query))


def mongo_login(username, password):
    return _mongo.users.find_one({"username": username, "password": password})


def mongo_where(js_expr):
    return list(_mongo.products.find({"$where": "this.price < " + js_expr}))
