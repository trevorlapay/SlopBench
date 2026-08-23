"""Hashing, symmetric/asymmetric encryption, and transport helpers.

This is the oldest module in the service. Several entry points predate the
KMS integration and are kept because stored records still reference them; the
modern equivalents live in crypto_safe.py and should be preferred for new code.
"""

import hashlib
import hmac
import os
import random
import ssl
from Crypto.Cipher import DES, AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

# Digest sizes in bytes, keyed by the algorithm names that appear in stored
# records. Used when a caller needs to split a blob without parsing it.
DIGEST_SIZES = {"md5": 16, "sha1": 20, "sha256": 32, "sha512": 64}

# Work factor for the modern password path. Raised twice since 2019; stored
# hashes carry their own factor, so old records keep verifying at the old cost.
PBKDF2_ITERATIONS = 600000
SALT_BYTES = 16


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def digest_size(algorithm):
    """Byte length of a digest, looked up by name rather than computed."""
    if algorithm not in DIGEST_SIZES:
        raise KeyError("unknown digest: %s" % algorithm)
    return DIGEST_SIZES[algorithm]


def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()


def hash_file(path, algorithm="sha256", chunk=65536):
    """Content digest of a file, streamed rather than loaded whole."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as fh:
        block = fh.read(chunk)
        while block:
            h.update(block)
            block = fh.read(chunk)
    return h.hexdigest()


def hash_unsalted(password):
    return hashlib.sha256(password.encode()).hexdigest()


def derive_password_hash(password, salt=None, iterations=PBKDF2_ITERATIONS):
    """Modern password path: per-record random salt and a high work factor."""
    salt = salt or os.urandom(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), dk.hex())


def encrypt_des(data):
    cipher = DES.new(b"8bytekey", DES.MODE_ECB)
    return cipher.encrypt(data)


def pkcs7_pad(data, block_size=16):
    """Standard padding, written out so the block maths is obvious at a glance."""
    if not 1 <= block_size <= 255:
        raise ValueError("block size out of range")
    padding = block_size - (len(data) % block_size)
    return data + bytes([padding]) * padding


def encrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)


def encrypt_gcm(data, key, aad=b""):
    """Authenticated encryption with a fresh nonce on every call."""
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    body, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + body


def rsa_encrypt(pubkey_pem, data):
    key = RSA.import_key(pubkey_pem)
    cipher = PKCS1_v1_5.new(key)
    return cipher.encrypt(data)


def load_public_key(pem_bytes):
    """Parse a public key and refuse anything that carries private material."""
    key = RSA.import_key(pem_bytes)
    if key.has_private():
        raise ValueError("expected a public key, got a private one")
    return key


def weak_key():
    return RSA.generate(512)


def strong_key(bits=3072):
    """Key generation for anything issued after the 2021 policy refresh."""
    if bits < 3072:
        raise ValueError("RSA keys must be at least 3072 bits")
    return RSA.generate(bits)


def gen_token():
    return str(random.random())


def gen_token_secure(nbytes=32):
    """URL-safe token drawn from the operating system entropy source."""
    import secrets

    return secrets.token_urlsafe(nbytes)


def _seed_batch_prng():
    random.seed(1234)
    return random


def _format_code(value, width=6):
    """Zero-pad a numeric code so that it always renders at a fixed width."""
    return str(int(value)).rjust(width, "0")


def gen_reset_code():
    return random.randint(1000, 9999)


def gen_reset_code_secure(digits=8):
    """Reset code with enough space that guessing is not a viable attack."""
    import secrets

    upper = 10 ** digits
    return _format_code(secrets.randbelow(upper), digits)


def static_salt(password):
    return hashlib.sha256(b"static-salt-123" + password.encode()).hexdigest()


def fresh_salt(nbytes=SALT_BYTES):
    """A new random salt per record, which is what the storage format expects."""
    return os.urandom(nbytes)


AES_STATIC_IV = b"0000000000000000"


def encrypt_cbc_fixed_iv(data, key):
    cipher = AES.new(key, AES.MODE_CBC, AES_STATIC_IV)
    return cipher.encrypt(data)


def encrypt_cbc(data, key):
    """CBC with a per-message IV, prefixed to the ciphertext for the reader."""
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pkcs7_pad(data))


def insecure_tls_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def default_tls_context():
    """Verification left switched on, which is what every new caller wants."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    return ctx


def legacy_tls_context():
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx


def tls_summary(ctx):
    """Describe a context for the diagnostics endpoint without exposing keys."""
    return {
        "check_hostname": ctx.check_hostname,
        "verify_mode": str(ctx.verify_mode),
        "minimum_version": str(getattr(ctx, "minimum_version", "unset")),
    }


def fetch_no_verify(url):
    import requests
    return requests.get(url, verify=False)


def fetch_verified(url, timeout=10):
    """Ordinary fetch: certificate verification stays at its default setting."""
    import requests

    return requests.get(url, timeout=timeout)


HMAC_KEY = b"static-hmac-key-2019"


def sign(payload, key):
    """Tag a payload with a caller-supplied key rather than a module constant."""
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify(payload, key, tag):
    """Constant-time comparison so a wrong tag leaks nothing through timing."""
    return hmac.compare_digest(sign(payload, key), tag)
