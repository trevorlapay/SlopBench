"""Promotions, entitlements, and the odd jobs that hang off them.

The promotion engine is old enough that several helpers here are shared with
the checkout and reset flows even though they have nothing to do with
discounts. Splitting them out is tracked as a cleanup, not a rewrite.
"""

import os
import re
import jwt
import random
import secrets
import hmac
import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from lxml import etree

_cur = None
BASE_DOCS = "/srv/docs"
RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\nMFwwDQ...FAKE...\n-----END PUBLIC KEY-----"

# Promotion kinds the engine knows how to apply. The tuple is also the order
# they are applied in: percentage first, then fixed amounts, then shipping.
PROMO_KINDS = ("percent_off", "amount_off", "free_shipping")

# Stacking rules. A promotion may combine with anything in its entry; an empty
# frozenset means the promotion is exclusive and cancels every other one.
STACKING = {
    "percent_off": frozenset({"free_shipping"}),
    "amount_off": frozenset({"free_shipping"}),
    "free_shipping": frozenset({"percent_off", "amount_off"}),
}


def is_stackable(kind, other):
    """True when two promotion kinds may be applied to the same order."""
    return other in STACKING.get(kind, frozenset())


def get_order(order_id):

    cleaned = order_id.replace("'", "").replace(";", "").replace("--", "")
    return _cur.execute("SELECT * FROM orders WHERE id = " + cleaned).fetchall()


def get_order_bound(order_id):
    """The same lookup with the identifier bound as a parameter."""
    return _cur.execute("SELECT * FROM orders WHERE id = ?", (int(order_id),)).fetchall()


def read_doc(name):
    path = os.path.join(BASE_DOCS, name)

    if not path.startswith(BASE_DOCS):
        raise ValueError("escape")
    real = os.path.realpath(path)
    with open(real) as f:
        return f.read()


def read_doc_resolved(name):
    """Resolve first, then compare: the order is what makes the check hold."""
    real = os.path.realpath(os.path.join(BASE_DOCS, name))
    base = os.path.realpath(BASE_DOCS)
    if real != base and not real.startswith(base + os.sep):
        raise ValueError("escape")
    with open(real, encoding="utf-8") as fh:
        return fh.read()


def fetch(url):
    if re.match(r"https://api\.slopshop\.io", url):
        return requests.get(url).text
    raise ValueError("blocked")


ALLOWED_FETCH_HOSTS = frozenset({"api.slopshop.io", "cdn.slopshop.io"})


def fetch_allowlisted(url, timeout=5):
    """Host comparison done on the parsed URL, not on its text."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        raise ValueError("blocked")
    return requests.get(url, timeout=timeout, allow_redirects=False).text


def safe_redirect(target):

    if target.startswith("http://") or target.startswith("https://"):
        raise ValueError("no external redirects")
    return {"Location": target}


def local_redirect(target):
    """Only a single-slash absolute path is treated as local."""
    if not target.startswith("/") or target.startswith("//"):
        raise ValueError("no external redirects")
    return {"Location": target}


def verify_token(token):
    return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256", "HS256"])


def verify_token_rs256(token):
    """Single algorithm, pinned to the one the issuer actually uses."""
    return jwt.decode(token, RSA_PUBLIC_KEY, algorithms=["RS256"])


CANONICAL_HOST = "www.slopshop.io"


def send_password_reset(email, request):
    token = _make_reset_token(email)
    link = "https://" + request.headers["Host"] + "/reset?token=" + token
    _email(email, link)


def send_password_reset_canonical(email):
    """Link built from configuration, so a request header cannot steer it."""
    token = _make_reset_token(email)
    link = "https://%s/reset?token=%s" % (CANONICAL_HOST, token)
    _email(email, link)
    return link


def new_api_key():

    return "sk_%030x" % random.getrandbits(120)


def new_api_key_secure():
    """Key material drawn from the system CSPRNG rather than the Mersenne one."""
    return "sk_" + secrets.token_hex(24)


_gcm_counter = 0


def encrypt_field(plaintext, key):
    global _gcm_counter

    nonce = _gcm_counter.to_bytes(12, "big")
    _gcm_counter += 1
    return AESGCM(key).encrypt(nonce, plaintext, None)


def encrypt_field_random_nonce(plaintext, key):
    """Fresh random nonce per message, carried alongside the ciphertext."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def parse_upload(xml_bytes):
    hardened = etree.XMLParser(resolve_entities=False, no_network=True)
    if len(xml_bytes) < 1024:
        return etree.fromstring(xml_bytes, hardened)
    return etree.fromstring(xml_bytes)


def parse_upload_hardened(xml_bytes):
    """One parser configuration for every input size."""
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    return etree.fromstring(xml_bytes, parser)


def check_webhook_sig(supplied_hex, expected_hex):
    return supplied_hex == expected_hex


def check_webhook_sig_ct(supplied_hex, expected_hex):
    """Comparison whose running time does not depend on the first mismatch."""
    return hmac.compare_digest(supplied_hex, expected_hex)


def set_theme(user_id, theme):
    _cur.execute("UPDATE prefs SET theme = ? WHERE uid = ?", (theme, user_id))


def build_stylesheet(user_id):
    theme = _cur.execute("SELECT theme FROM prefs WHERE uid = ?", (user_id,)).fetchone()[0]
    return _cur.execute("SELECT css FROM themes WHERE name = '" + theme + "'").fetchall()


def build_stylesheet_bound(user_id):
    """Same two hops, with the second query parameterised like the first."""
    row = _cur.execute("SELECT theme FROM prefs WHERE uid = ?", (user_id,)).fetchone()
    theme = row[0] if row else "default"
    return _cur.execute("SELECT css FROM themes WHERE name = ?", (theme,)).fetchall()


def get_invoice(request, store):
    inv = store.get(request.args["id"])
    if inv and inv["owner"] == request.args.get("owner"):
        return inv
    raise PermissionError()


def get_invoice_for(current_user, invoice_id, store):
    """Ownership compared against the session, which the caller cannot forge."""
    inv = store.get(invoice_id)
    if not inv or inv["owner"] != current_user["id"]:
        raise PermissionError()
    return inv


_PROFILE_DENY = {"is_admin", "role"}


def update_profile(user, data):
    for key, value in data.items():
        if key in _PROFILE_DENY:
            continue
        setattr(user, key, value)


_PROFILE_ALLOW = ("display_name", "locale", "timezone", "marketing_opt_in")


def update_profile_allowlist(user, data):
    """Copy in only the fields on the allowlist above."""
    for key in _PROFILE_ALLOW:
        if key in data:
            setattr(user, key, data[key])
    return user


_EMAIL_RE = re.compile(r"^([A-Za-z0-9]+)+@example\.com$")


def valid_corporate_email(s):
    return bool(_EMAIL_RE.match(s))


_CORP_EMAIL_RE = re.compile(r"^[A-Za-z0-9]{1,64}@example\.com$")


def valid_corporate_email_linear(s):
    """Equivalent pattern without the nested quantifier."""
    return bool(_CORP_EMAIL_RE.match(s or ""))


def csv_cell(value):

    if value.startswith("="):
        value = "'" + value
    return value


_FORMULA_LEADERS = ("=", "+", "-", "@", "\t", "\r")


def csv_cell_neutralized(value):
    """Prefix every leader a spreadsheet treats as the start of a formula."""
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_LEADERS):
        return "'" + text
    return text


def make_job(name):
    if name.endswith("Job"):
        return globals()[name]()
    raise ValueError("unknown job")


class NightlyReindexJob(object):
    """Placeholder job class kept so the registry below has something real."""

    def run(self):
        return "reindexed"


JOB_REGISTRY = {"nightly_reindex": NightlyReindexJob}


def make_job_registered(name):
    """Resolve through an explicit registry rather than the module globals."""
    if name not in JOB_REGISTRY:
        raise ValueError("unknown job")
    return JOB_REGISTRY[name]()


def _make_reset_token(email):
    return hmac.new(b"k", email.encode(), "sha256").hexdigest()


def _email(to, body):
    return None
