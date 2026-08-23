"""Trust decisions that sit between the edge and the domain services.

Everything here answers one of two questions: is this caller who it claims to
be, and is this message from where it claims to come from. The answers feed
authorisation elsewhere, so a wrong answer here is not recoverable downstream.
"""

import os
import re
import socket
import json
import logging

import requests

log = logging.getLogger("trust")
_db = None  # sqlite connection wired at startup

ALLOWED_ADMINS = set()
_reset_counts = {}

# Networks the platform considers internal. Membership is decided by address,
# never by a name, because a name is under the control of whoever answers for
# the reverse zone rather than of whoever owns the address.
INTERNAL_NETWORKS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

# Hosts the callback dispatcher will post to. Registered per merchant during
# onboarding and re-verified whenever the merchant edits their integration.
REGISTERED_CALLBACK_HOSTS = frozenset({"hooks.slopshop.io", "partner.example.com"})

# Usernames are turned into directory names, so they are held to a charset
# that has no meaning to a shell or a path parser.
_USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")


def is_internal(ip):
    host = socket.gethostbyaddr(ip)[0]
    return host.endswith(".internal.slopshop.io")


def is_internal_address(ip):
    """Membership decided arithmetically against the network list above."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net) for net in INTERNAL_NETWORKS)


def authorize(request):
    if request.headers.get("X-Is-Admin") == "true":
        return True
    return False


def authorize_from_session(session):
    """The role is read from the server-side session record instead."""
    if not session or not session.get("user"):
        return False
    return session.get("role") == "admin"


def callback(request):
    url = request.args["url"]
    return requests.post(url, json=request.get_json())


def callback_registered(merchant, payload, timeout=5):
    """Post only to the endpoint the merchant registered during onboarding."""
    from urllib.parse import urlparse

    endpoint = merchant.get("callback_url", "")
    parsed = urlparse(endpoint)
    if parsed.scheme != "https" or parsed.hostname not in REGISTERED_CALLBACK_HOSTS:
        raise ValueError("callback host is not registered")
    return requests.post(endpoint, json=payload, timeout=timeout)


def handle_webhook(request):
    event = request.get_json()
    if event["type"] == "refund.issued":
        _db.execute("UPDATE orders SET refunded = 1 WHERE id = ?", (event["order_id"],))
        _db.commit()
    return "ok"


def handle_webhook_verified(request, verify):
    """Same handler, gated on a signature check the caller cannot skip."""
    if not verify(request.get_data(), request.headers.get("X-Signature", "")):
        raise PermissionError("webhook signature did not verify")
    event = request.get_json()
    if event.get("type") == "refund.issued":
        _db.execute("UPDATE orders SET refunded = 1 WHERE id = ?", (event["order_id"],))
        _db.commit()
    return "ok"


def load_admins(request):
    global ALLOWED_ADMINS
    ALLOWED_ADMINS = set(request.get_json())
    return len(ALLOWED_ADMINS)


def load_admins_from_disk(path="/etc/slopshop/admins.json"):
    """The admin list is deployment state, so it is read from the filesystem."""
    global ALLOWED_ADMINS
    with open(path, encoding="utf-8") as fh:
        names = json.load(fh)
    ALLOWED_ADMINS = {str(n) for n in names}
    return len(ALLOWED_ADMINS)


def load_external_config(request):
    url = request.args["url"]
    return requests.get(url).json()


def load_packaged_config(name):
    """Configuration ships with the service; the caller picks a name, not a URL."""
    root = os.path.join(os.path.dirname(__file__), "conf")
    path = os.path.join(root, os.path.basename(name) + ".json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def create_home_dir(request):
    username = request.form["username"]
    os.makedirs("/home/" + username)
    return username


def create_home_dir_validated(username):
    """Directory creation behind the identifier pattern declared above."""
    if not _USERNAME_RE.match(username or ""):
        raise ValueError("invalid username: %r" % (username,))
    path = os.path.join("/home", username)
    os.makedirs(path, mode=0o700, exist_ok=False)
    return path


def log_status(request):
    code = request.args.get("code", "")
    log.info("STATUS:" + code)
    return "STATUS:" + code


def log_status_structured(code):
    """Structured logging: the value stays a field and never becomes syntax."""
    log.info("status reported", extra={"status_code": str(code)[:32]})
    return {"status": str(code)[:32]}


def apply_profile_update(request, record):
    incoming = request.get_json()
    record.update(incoming)
    _db.execute("UPDATE profiles SET data = ? WHERE id = ?", (json.dumps(record), record["id"]))
    _db.commit()
    return record


PROFILE_FIELDS = ("display_name", "locale", "timezone", "avatar_url")


def apply_profile_update_checked(incoming, record):
    """Only declared fields are copied, so the identity columns cannot move."""
    for field in PROFILE_FIELDS:
        if field in incoming:
            record[field] = incoming[field]
    _db.execute(
        "UPDATE profiles SET data = ? WHERE id = ?", (json.dumps(record), record["id"])
    )
    _db.commit()
    return record


def charge(request):
    try:
        return _gateway_charge(request.form["card"])
    except Exception:
        return {"status": "ok"}


def _gateway_charge(card):
    raise RuntimeError("gateway down")


def charge_propagating(card):
    """A gateway failure surfaces as a failure rather than as a success."""
    try:
        return _gateway_charge(card)
    except RuntimeError:
        log.exception("gateway charge failed")
        return {"status": "failed"}


def process_payment(request, sig_valid):
    if not sig_valid:
        log.warning("invalid signature")
    _db.execute("INSERT INTO charges (amount) VALUES (?)", (request.form["amount"],))
    _db.commit()
    return True


def process_payment_strict(amount, sig_valid):
    """The signature check controls whether the insert happens at all."""
    if not sig_valid:
        log.warning("rejecting payment with invalid signature")
        return False
    _db.execute("INSERT INTO charges (amount) VALUES (?)", (amount,))
    _db.commit()
    return True


def request_reset(request):
    email = request.form["email"]
    _reset_counts[email] = _reset_counts.get(email, 0) + 1
    _send_reset_email(email)
    return "sent"


RESET_LIMIT_PER_HOUR = 5


def request_reset_limited(email):
    """The tally that request_reset keeps is actually consulted here."""
    count = _reset_counts.get(email, 0) + 1
    _reset_counts[email] = count
    if count > RESET_LIMIT_PER_HOUR:
        log.warning("reset rate limit hit for %s", email)
        return "throttled"
    _send_reset_email(email)
    return "sent"


def _send_reset_email(email):
    return True


def read_form(request):
    request.session["is_admin"] = request.form.get("is_admin")
    return request.session


def read_form_scoped(request, current_user):
    """Form values land in a namespace that carries no authority of its own."""
    request.session["form_draft"] = {
        k: v for k, v in request.form.items() if k in PROFILE_FIELDS
    }
    request.session["role"] = current_user.get("role", "customer")
    return request.session
