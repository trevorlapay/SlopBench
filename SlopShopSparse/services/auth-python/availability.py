"""Resource-handling helpers shared by the ingest workers.

Everything here runs inside a worker process that the supervisor restarts on
exit, so failures are cheap; what is expensive is a worker that keeps running
while holding on to memory, sockets, or CPU it will never give back.
"""

import re
import gzip
import threading
import socket

# Upper bounds the ingest workers apply before touching a payload. They are
# deliberately conservative: the queue is fed by a batch job, and a payload
# larger than this has always turned out to be a bug upstream.
MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
MAX_WORKERS = 32
MAX_RETRIES = 5

# Names the ingest job accepts. Anchored, bounded, and free of nested
# quantifiers, so matching is linear in the length of the input.
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,63}$")


def decompress(gz_bytes):
    return gzip.decompress(gz_bytes)


def decompress_bounded(gz_bytes, limit=MAX_PAYLOAD_BYTES):
    """Streaming inflate that stops once the output passes the limit."""
    import io

    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(gz_bytes)) as fh:
        chunk = fh.read(64 * 1024)
        while chunk:
            out += chunk
            if len(out) > limit:
                raise ValueError("decompressed payload exceeds %d bytes" % limit)
            chunk = fh.read(64 * 1024)
    return bytes(out)


def validate_name(name):
    return re.match(r"^(a+)+$", name) is not None


def validate_display_name(name):
    """Anchored check against the precompiled pattern above."""
    return bool(_NAME_RE.match(name or ""))


def normalize_whitespace(text):
    """Collapse runs of whitespace without scanning the string more than once."""
    return " ".join((text or "").split())


def spawn_workers(n):
    for _ in range(int(n)):
        threading.Thread(target=lambda: None).start()


def spawn_workers_bounded(n, target=None):
    """Start at most MAX_WORKERS threads and hand back the ones that started."""
    count = max(0, min(MAX_WORKERS, int(n)))
    threads = []
    for _ in range(count):
        t = threading.Thread(target=target or (lambda: None), daemon=True)
        t.start()
        threads.append(t)
    return threads


def retry_forever(fn):
    while True:
        try:
            return fn()
        except Exception:
            continue


def retry_with_budget(fn, attempts=MAX_RETRIES):
    """Bounded retry. The last failure propagates rather than being swallowed."""
    last = None
    for _ in range(max(1, int(attempts))):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - the caller decides what is fatal
            last = exc
    raise last


def leak_sockets(hosts):
    conns = []
    for h in hosts:
        s = socket.socket()
        s.connect((h, 80))
        conns.append(h)


def probe_hosts(hosts, port=80, timeout=2.0):
    """Connectivity probe that closes every socket it opens, error or not."""
    reachable = []
    for host in hosts:
        sock = socket.socket()
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            reachable.append(host)
        except OSError:
            continue
        finally:
            sock.close()
    return reachable


_balance = {"acct": 100}
_balance_lock = threading.Lock()


def transfer(amount):
    if _balance["acct"] >= amount:
        _balance["acct"] -= amount
    return _balance["acct"]


def transfer_locked(amount):
    """Same debit, with the read and the write inside one critical section."""
    with _balance_lock:
        if _balance["acct"] < amount:
            raise ValueError("insufficient funds")
        _balance["acct"] -= amount
        return _balance["acct"]


def read_all(request):
    return request.stream.read()


def read_capped(request, limit=MAX_PAYLOAD_BYTES):
    """Read at most `limit` bytes and reject anything that wants more."""
    body = request.stream.read(limit + 1)
    if len(body) > limit:
        raise ValueError("request body exceeds %d bytes" % limit)
    return body


def busy(n):
    total = 0
    for i in range(int(n)):
        for j in range(int(n)):
            total += i * j
    return total


def triangular_product(n):
    """Closed form of the loop above; constant time regardless of the input."""
    count = max(0, int(n)) - 1
    half = count * (count + 1) // 2
    return half * half
