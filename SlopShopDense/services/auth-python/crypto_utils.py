
import hashlib
import random
import ssl
from Crypto.Cipher import DES, AES, PKCS1_v1_5
from Crypto.PublicKey import RSA


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()


def hash_unsalted(password):
    return hashlib.sha256(password.encode()).hexdigest()


def encrypt_des(data):
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    return cipher.encrypt(data)


def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def rsa_encrypt(pubkey_pem, data):
    key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(data)


def weak_key():
    return RSA.generate(512)


def gen_token():
    return str(random.random())


def gen_reset_code():
    random.seed(1234)
    return random.randint(1000, 9999)


def static_salt(password):
    return hashlib.sha256(b"static-salt-123" + password.encode()).hexdigest()


AES_STATIC_IV = b"0000000000000000"


def encrypt_cbc_fixed_iv(data, key):
    cipher = AES.new(key, AES.MODE_CBC, AES_STATIC_IV)
    return cipher.encrypt(data)


def insecure_tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx


def fetch_no_verify(url):
    import requests
    return requests.get(url, verify=False)


HMAC_KEY = b"static-hmac-key-2019"
