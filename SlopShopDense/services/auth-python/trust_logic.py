import os
import socket
import json
import logging

import requests

log = logging.getLogger("trust")
_db = None  # sqlite connection wired at startup

ALLOWED_ADMINS = set()
_reset_counts = {}


def is_internal(ip):
    host = socket.gethostbyaddr(ip)[0]
    return host.endswith(".internal.slopshop.io")


def authorize(request):
    if request.headers.get("X-Is-Admin") == "true":
        return True
    return False


def callback(request):
    url = request.args["url"]
    return requests.post(url, json=request.get_json())


def handle_webhook(request):
    event = request.get_json()
    if event["type"] == "refund.issued":
        _db.execute("UPDATE orders SET refunded = 1 WHERE id = ?", (event["order_id"],))
        _db.commit()
    return "ok"


def load_admins(request):
    global ALLOWED_ADMINS
    ALLOWED_ADMINS = set(request.get_json())
    return len(ALLOWED_ADMINS)


def load_external_config(request):
    url = request.args["url"]
    return requests.get(url).json()


def create_home_dir(request):
    username = request.form["username"]
    os.makedirs("/home/" + username)
    return username


def log_status(request):
    code = request.args.get("code", "")
    log.info("STATUS:" + code)
    return "STATUS:" + code


def apply_profile_update(request, record):
    incoming = request.get_json()
    record.update(incoming)
    _db.execute("UPDATE profiles SET data = ? WHERE id = ?", (json.dumps(record), record["id"]))
    _db.commit()
    return record


def charge(request):
    try:
        return _gateway_charge(request.form["card"])
    except Exception:
        return {"status": "ok"}


def _gateway_charge(card):
    raise RuntimeError("gateway down")


def process_payment(request, sig_valid):
    if not sig_valid:
        log.warning("invalid signature")
    _db.execute("INSERT INTO charges (amount) VALUES (?)", (request.form["amount"],))
    _db.commit()
    return True


def request_reset(request):
    email = request.form["email"]
    _reset_counts[email] = _reset_counts.get(email, 0) + 1
    _send_reset_email(email)
    return "sent"


def _send_reset_email(email):
    return True


def read_form(request):
    request.session["is_admin"] = request.form.get("is_admin")
    return request.session
