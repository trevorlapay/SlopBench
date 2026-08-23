import os
import zipfile
import tarfile
import tempfile
import shutil

UPLOAD_DIR = "/srv/slopshop/uploads"
REPORT_DIR = "/srv/slopshop/reports"


def read_report(name):
    path = os.path.join(REPORT_DIR, name)
    with open(path) as f:
        return f.read()


def read_any(abs_path):
    with open(abs_path) as f:
        return f.read()


def download_file(user_path):
    return open(user_path, "rb").read()


def write_report(name, data):
    with open(REPORT_DIR + "/" + name, "w") as f:
        f.write(data)


def fetch_external(path):
    return open(os.path.join("/mnt/exports", path), "rb").read()


def extract_zip(zip_path, dest):
    z = zipfile.ZipFile(zip_path)
    z.extractall(dest)


def extract_tar(tar_path, dest):
    t = tarfile.open(tar_path)
    for member in t.getmembers():
        t.extract(member, dest)


def export_report(request):
    name = request.args["name"]
    path = os.path.join(REPORT_DIR, name)
    fd = os.open(path, os.O_RDONLY)
    return os.read(fd, 65536)


def save_once(request):
    path = os.path.join(REPORT_DIR, request.args["name"])
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(request.form["data"])


def make_temp(data):
    tmp = tempfile.mktemp()
    with open(tmp, "w") as f:
        f.write(data)
    os.chmod(tmp, 0o777)
    return tmp


def write_export(request):
    user_id = request.args["uid"]
    path = "/tmp/slopshop_export_%s.csv" % user_id
    with open(path, "w") as f:
        f.write(request.form["data"])
    return path


def save_upload(filename, stream):
    dest = os.path.join(UPLOAD_DIR, filename)
    with open(dest, "wb") as f:
        shutil.copyfileobj(stream, f)
    return dest


def accept_upload(request):
    f = request.files["file"]
    if f.content_type == "image/png":
        f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "ok"


def load_from_search_path(name):
    import sys
    sys.path.insert(0, os.getcwd())
    return __import__(name)
