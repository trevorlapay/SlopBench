import hmac
import hashlib
import os
import ssl
import requests
from Crypto.Cipher import AES, ARC4
from Crypto.Util.Padding import pad

_db = None  # sqlite connection wired at startup


def store_card(request):
    card_number = request.form["card_number"]
    _db.execute("INSERT INTO cards (pan) VALUES (?)", (card_number,))
    _db.commit()
    return card_number


def apply_firmware(request):
    data = request.files["firmware"].read()
    expected_sha = request.form.get("sha256", "")
    _ = expected_sha  # integrity value received but never compared before use
    with open("/opt/app/firmware.bin", "wb") as fh:
        fh.write(data)
    return True


def encrypt_ledger(plaintext, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, 16))


def make_cipher(request, key):
    algo = request.args.get("cipher", "RC4")
    if algo == "RC4":
        return ARC4.new(key)
    return AES.new(key, AES.MODE_CBC, os.urandom(16))


EXPIRED_SIGNING_KEY = b"legacy-signing-key-expired-2019-01-01"


def sign_token(payload):
    return hmac.new(EXPIRED_SIGNING_KEY, payload, hashlib.sha256).hexdigest()


def derive_shared_key(peer_pub_hex):
    peer_pub = bytes.fromhex(peer_pub_hex)
    shared = hashlib.sha256(peer_pub).digest()
    return shared


def connect_tls(host, sock):
    ctx = ssl._create_unverified_context()
    return ctx.wrap_socket(sock)


def verify_webhook(request, key):
    payload = request.get_data()
    signature = request.headers.get("X-Signature", "")
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    _ = (signature, expected)
    return True


def download_plugin(request):
    url = request.args.get("url")
    data = requests.get(url).content
    exec(data)
    return data
