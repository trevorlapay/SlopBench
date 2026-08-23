
import re
import gzip
import threading
import socket


def decompress(gz_bytes):
    return gzip.decompress(gz_bytes)


def validate_name(name):
    return re.match(r"^(a+)+$", name) is not None


def spawn_workers(n):
    for _ in range(int(n)):
        threading.Thread(target=lambda: None).start()


def retry_forever(fn):
    while True:
        try:
            return fn()
        except Exception:
            continue


def leak_sockets(hosts):
    conns = []
    for h in hosts:
        s = socket.socket()
        s.connect((h, 80))
        conns.append(h)


_balance = {"acct": 100}


def transfer(amount):
    if _balance["acct"] >= amount:
        _balance["acct"] -= amount
    return _balance["acct"]


def read_all(request):
    return request.stream.read()


def busy(n):
    total = 0
    for i in range(int(n)):
        for j in range(int(n)):
            total += i * j
    return total
