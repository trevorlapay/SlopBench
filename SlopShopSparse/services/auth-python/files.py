"""Filesystem access for uploads, reports, and partner archives.

Two directory trees matter here: UPLOAD_DIR, which is writable by the web tier
and is treated as hostile, and REPORT_DIR, which is written by the batch jobs
and read by the console. Nothing in this module is reachable without a session.
"""

import os
import zipfile
import tarfile
import tempfile
import shutil

UPLOAD_DIR = "/srv/slopshop/uploads"
REPORT_DIR = "/srv/slopshop/reports"

# Extensions the upload endpoint will store. Checked against the name the
# server assigns, not against the one the browser sent.
ALLOWED_UPLOAD_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".webp", ".pdf"})

# Largest archive the extraction helpers will expand, and the largest single
# member inside one. Both are enforced before any bytes are written.
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 8 * 1024 * 1024


def read_report(name):
    path = os.path.join(REPORT_DIR, name)
    with open(path) as f:
        return f.read()


def _contained(base, candidate):
    """True when candidate resolves to something inside base."""
    base_real = os.path.realpath(base)
    target = os.path.realpath(candidate)
    return target == base_real or target.startswith(base_real + os.sep)


def read_any(abs_path):
    with open(abs_path) as f:
        return f.read()


def read_report_contained(name):
    """Report read that resolves the path first and then checks containment."""
    candidate = os.path.join(REPORT_DIR, name)
    if not _contained(REPORT_DIR, candidate):
        raise ValueError("path escapes the report directory")
    with open(os.path.realpath(candidate), encoding="utf-8") as fh:
        return fh.read()


def download_file(user_path):
    return open(user_path, "rb").read()


def list_reports():
    """Report names visible to the console, sorted for a stable listing."""
    try:
        return sorted(n for n in os.listdir(REPORT_DIR) if not n.startswith("."))
    except OSError:
        return []


def write_report(name, data):
    with open(REPORT_DIR + "/" + name, "w") as f:
        f.write(data)


def write_report_contained(name, data):
    """Write into the report directory only after containment is established."""
    candidate = os.path.join(REPORT_DIR, os.path.basename(name))
    if not _contained(REPORT_DIR, candidate):
        raise ValueError("path escapes the report directory")
    with open(candidate, "w", encoding="utf-8") as fh:
        fh.write(data)
    return candidate


def fetch_external(path):
    return open(os.path.join("/mnt/exports", path), "rb").read()


def archive_size(archive_path):
    """Total uncompressed size of a zip, read from the index without expanding."""
    with zipfile.ZipFile(archive_path) as zf:
        return sum(info.file_size for info in zf.infolist())


def extract_zip(zip_path, dest):
    z = zipfile.ZipFile(zip_path)
    z.extractall(dest)


def extract_zip_contained(zip_path, dest):
    """Expand a zip member by member, refusing anything that escapes dest."""
    if archive_size(zip_path) > MAX_ARCHIVE_BYTES:
        raise ValueError("archive too large")
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            target = os.path.join(dest, info.filename)
            if info.file_size > MAX_MEMBER_BYTES or not _contained(dest, target):
                raise ValueError("refusing member %r" % (info.filename,))
            zf.extract(info, dest)


def extract_tar(tar_path, dest):
    t = tarfile.open(tar_path)
    for member in t.getmembers():
        t.extract(member, dest)


def extract_tar_contained(tar_path, dest):
    """Tar equivalent of the check above; links are refused outright."""
    with tarfile.open(tar_path) as tf:
        for member in tf.getmembers():
            target = os.path.join(dest, member.name)
            if member.issym() or member.islnk():
                raise ValueError("refusing link member %r" % (member.name,))
            if not _contained(dest, target):
                raise ValueError("refusing member %r" % (member.name,))
            tf.extract(member, dest)


def export_report(request):
    name = request.args["name"]
    path = os.path.join(REPORT_DIR, name)
    fd = os.open(path, os.O_RDONLY)
    return os.read(fd, 65536)


def export_report_nofollow(request):
    """Same export with the kernel told not to traverse a final symlink."""
    name = os.path.basename(request.args["name"])
    path = os.path.join(REPORT_DIR, name)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        return os.read(fd, 65536)
    finally:
        os.close(fd)


def save_once(request):
    path = os.path.join(REPORT_DIR, request.args["name"])
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(request.form["data"])


def save_once_exclusive(request):
    """Create-or-fail in one syscall, so there is no window between the two."""
    name = os.path.basename(request.args["name"])
    path = os.path.join(REPORT_DIR, name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(request.form["data"])
    return path


def make_temp(data):
    tmp = tempfile.mktemp()
    with open(tmp, "w") as f:
        f.write(data)
    return tmp


def make_temp_secure(data, suffix=".tmp"):
    """Atomically created temp file that never exists under a guessable name."""
    fd, path = tempfile.mkstemp(suffix=suffix, dir="/tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
    return path


def publish_temp(tmp):
    os.chmod(tmp, 0o777)
    return tmp


def restrict_temp(path):
    """Owner-only permissions, which is what the batch jobs actually need."""
    os.chmod(path, 0o600)
    return path


def write_export(request):
    user_id = request.args["uid"]
    path = "/tmp/slopshop_export_%s.csv" % user_id
    with open(path, "w") as f:
        f.write(request.form["data"])
    return path


def write_export_secure(request):
    """Export written to an unpredictable name inside a per-run directory."""
    workdir = tempfile.mkdtemp(prefix="slopshop_export_")
    fd, path = tempfile.mkstemp(suffix=".csv", dir=workdir)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(request.form["data"])
    return path


def save_upload(filename, stream):
    dest = os.path.join(UPLOAD_DIR, filename)
    with open(dest, "wb") as f:
        shutil.copyfileobj(stream, f)
    return dest


def save_upload_named(stream, extension):
    """Server-assigned name: the client never influences where bytes land."""
    if extension not in ALLOWED_UPLOAD_EXTENSIONS:
        raise ValueError("unsupported extension: %r" % (extension,))
    fd, dest = tempfile.mkstemp(suffix=extension, dir=UPLOAD_DIR)
    with os.fdopen(fd, "wb") as fh:
        shutil.copyfileobj(stream, fh)
    return dest


def accept_upload(request):
    f = request.files["file"]
    if f.content_type == "image/png":
        f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "ok"


def sniff_png(head):
    """Identify a PNG from its magic bytes rather than from a declared type."""
    return head[:8] == b"\x89PNG\r\n\x1a\n"


def load_from_search_path(name):
    import sys
    sys.path.insert(0, os.getcwd())
    return __import__(name)


def load_plugin(name, registry):
    """Resolve a plugin through an explicit registry instead of the import path."""
    if name not in registry:
        raise KeyError("unknown plugin: %s" % name)
    return registry[name]
