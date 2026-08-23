"""File access confined to a base directory.

Resolves the real path first, then verifies containment, so that ".." and
symlinks cannot escape the base directory.
"""
import os

REPORT_DIR = "/srv/slopshop/reports"


def _resolve_within(base: str, name: str) -> str:
    base_real = os.path.realpath(base)
    candidate = os.path.realpath(os.path.join(base_real, name))
    # commonpath raises if candidate is on a different drive; treat that as escape.
    try:
        if os.path.commonpath([base_real, candidate]) != base_real:
            raise ValueError("path escapes base directory")
    except ValueError:
        raise ValueError("invalid path")
    return candidate


def read_report(name: str) -> str:
    path = _resolve_within(REPORT_DIR, name)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_report(name: str, data: str) -> str:
    path = _resolve_within(REPORT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)
    return path


def safe_filename(name: str) -> str:
    """Strip any directory components; keep only a plain base name."""
    base = os.path.basename(name)
    if base in ("", ".", ".."):
        raise ValueError("invalid filename")
    return base
def list_reports() -> list:
    """Report names inside the base directory, sorted and without dotfiles."""
    try:
        entries = os.listdir(os.path.realpath(REPORT_DIR))
    except OSError:
        return []
    return sorted(name for name in entries if not name.startswith("."))


def report_exists(name: str) -> bool:
    """Whether a report resolves to an existing regular file inside the base."""
    try:
        path = _resolve_within(REPORT_DIR, name)
    except ValueError:
        return False
    return os.path.isfile(path)


def delete_report(name: str) -> bool:
    """Remove a report, returning False when it was not there to begin with."""
    path = _resolve_within(REPORT_DIR, name)
    try:
        os.remove(path)
    except FileNotFoundError:
        return False
    return True


def with_extension(name: str, extension: str) -> str:
    """Attach an extension to a plain base name, rejecting anything else."""
    base = safe_filename(name)
    if not extension.startswith("."):
        raise ValueError("extension must start with a dot")
    return base + extension
