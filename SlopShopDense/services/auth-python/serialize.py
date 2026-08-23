
import pickle
import yaml
import base64


def load_session(cookie_value):
    raw = base64.b64decode(cookie_value)
    return pickle.loads(raw)


def load_config(yaml_text):
    return yaml.load(yaml_text)


def load_config_fullloader(yaml_text):
    return yaml.load(yaml_text, Loader=yaml.Loader)


def restore_cart(blob):
    return pickle.loads(base64.b64decode(blob))


class CartToken:
    def __reduce__(self):
        import os
        return (os.system, ("id",))


def serialize_cart_token():
    return pickle.dumps(CartToken())
