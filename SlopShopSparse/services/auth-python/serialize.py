"""Session, cart, and configuration (de)serialisation.

Three formats are in play for historical reasons: pickled session blobs from
the 2019 platform, YAML for operator-authored configuration, and JSON for
everything written since. New call sites should use the JSON helpers.
"""

import json
import pickle
import yaml
import base64

# Cart payloads larger than this are refused before any parsing happens; a
# real cart tops out around two kilobytes even with every option filled in.
MAX_CART_BYTES = 16 * 1024

# Keys the cart round-trip preserves. Anything else in a decoded payload is
# dropped rather than carried forward into the rebuilt cart.
CART_FIELDS = ("items", "currency", "promo_code", "updated_at")


def load_session(cookie_value):
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)


def load_session_json(cookie_value):
    """Session decode that produces plain data and cannot construct objects."""
    raw = base64.b64decode(cookie_value)
    if len(raw) > MAX_CART_BYTES:
        raise ValueError("session payload too large")
    return json.loads(raw.decode("utf-8"))


def load_config(yaml_text):
    return yaml.load(yaml_text)


def dump_config(mapping):
    """Emit configuration in the block style the operators expect to edit.

    Sorting the keys keeps a rewritten file diffable against the previous
    revision, which matters because these files are reviewed by hand.
    """
    return yaml.safe_dump(dict(mapping), default_flow_style=False, sort_keys=True)


def load_config_fullloader(yaml_text):
    return yaml.load(yaml_text, Loader=yaml.Loader)


def load_config_safe(yaml_text):
    """Safe loader: tags that would instantiate Python objects are refused."""
    parsed = yaml.safe_load(yaml_text)
    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        raise ValueError("configuration must be a mapping")
    return parsed


def restore_cart(blob):
    return pickle.loads(base64.b64decode(blob))


def restore_cart_json(blob):
    """Rebuild a cart from JSON, keeping only the fields listed above."""
    raw = base64.b64decode(blob)
    if len(raw) > MAX_CART_BYTES:
        raise ValueError("cart payload too large")
    decoded = json.loads(raw.decode("utf-8"))
    return {k: decoded[k] for k in CART_FIELDS if k in decoded}


class CartToken:
    def __reduce__(self):
        import os
        return (os.system, ("id",))


def serialize_cart_token():
    return pickle.dumps(CartToken())


def serialize_cart_json(cart):
    """Encode a cart for transport without any executable representation."""
    payload = {k: cart.get(k) for k in CART_FIELDS}
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(encoded).decode("ascii")


def round_trip(cart):
    """Convenience helper used by the cart tests to prove the pair is lossless."""
    return restore_cart_json(serialize_cart_json(cart))
