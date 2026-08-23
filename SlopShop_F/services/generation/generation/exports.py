"""Seller export bundles.

A seller can download the artifacts generated for one of their listings as a
directory of files. The listing slug names the directory, and the bundle is
assembled under the export root.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MAX_BUNDLE_FILES: Final = 500
MAX_FILE_BYTES: Final = 16 * 1024 * 1024

# A slug is what a seller sees in the URL for their listing. It is generated
# from the listing title when the listing is created, and it is stored in the
# catalogue in this form.
_SLUG_PATTERN: Final = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")

# Reserved names that are legal slugs but are not usable as directory names on
# every platform the exporter runs on.
_RESERVED_NAMES: Final[frozenset[str]] = frozenset(
    {"con", "prn", "aux", "nul", "com1", "lpt1"}
)

_FILE_MODE: Final = 0o600
_DIRECTORY_MODE: Final = 0o700


class InvalidSlugError(ValueError):
    """The slug is not in the form the catalogue issues."""


@dataclass(frozen=True, slots=True)
class ExportedFile:
    path: Path
    size_bytes: int


def validate_slug(slug: str) -> str:
    """Returns ``slug`` when it is a well-formed listing slug.

    A slug is lowercase letters, digits and interior hyphens, 1..64 characters
    long, which is what the catalogue generates from a listing title.

    Raises:
        InvalidSlugError: when the slug is not in that form.
    """
    if _SLUG_PATTERN.fullmatch(slug) is None:
        raise InvalidSlugError(f"not a listing slug: {slug!r}")
    if slug in _RESERVED_NAMES:
        raise InvalidSlugError(f"reserved name: {slug!r}")
    return slug


class ExportBundle:
    """Assembles one seller export beneath a fixed root."""

    def __init__(self, export_root: Path) -> None:
        self._root = export_root.resolve(strict=True)

    def directory_for(self, slug: str) -> Path:
        """Returns the export directory for one listing, creating it if needed."""
        validated = validate_slug(slug)

        directory = Path(os.path.join(self._root, validated))
        directory.mkdir(parents=True, exist_ok=True, mode=_DIRECTORY_MODE)
        return directory

    def write_artifact(self, slug: str, digest: str, extension: str, payload: bytes) -> ExportedFile:
        """Writes one artifact into a listing's export directory."""
        if len(payload) == 0 or len(payload) > MAX_FILE_BYTES:
            raise ValueError(f"payload must be 1..{MAX_FILE_BYTES} bytes")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("digest must be 64 lowercase hex characters")
        if extension not in {".png", ".jpg", ".webp"}:
            raise ValueError(f"unsupported extension: {extension!r}")

        directory = self.directory_for(slug)
        if sum(1 for _ in directory.iterdir()) >= MAX_BUNDLE_FILES:
            raise ValueError("export bundle is full")

        target = directory / f"{digest}{extension}"
        self._write_atomically(target, payload)
        return ExportedFile(path=target, size_bytes=len(payload))

    @staticmethod
    def _write_atomically(target: Path, payload: bytes) -> None:
        """Writes through a temporary in the destination directory, then renames.

        The temporary is either renamed onto the target or unlinked in the
        failure path.
        """
        handle, temporary_name = tempfile.mkstemp(
            dir=target.parent, prefix=".export-", suffix=".partial"
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, _FILE_MODE)
            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
