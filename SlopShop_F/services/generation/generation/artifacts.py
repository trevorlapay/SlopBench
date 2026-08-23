"""Content-addressed storage for rendered artifacts.

An artifact is stored under the hex SHA-256 of its bytes, in a two-level
directory fan-out.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MAX_ARTIFACT_BYTES: Final = 16 * 1024 * 1024

_EXTENSIONS: Final[dict[str, str]] = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/webp": ".webp",
}

# Owner read/write only; the directories the service creates are owner-only too.
_FILE_MODE: Final = 0o600
_DIRECTORY_MODE: Final = 0o700


class ArtifactTooLargeError(ValueError):
    """The payload exceeds MAX_ARTIFACT_BYTES."""


class UnsupportedMediaTypeError(ValueError):
    """The media type has no configured extension."""


class StorageEscapeError(RuntimeError):
    """A resolved path fell outside the storage root."""


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    digest: str
    media_type: str
    size_bytes: int
    path: Path


class ArtifactStore:
    """Writes artifacts beneath a fixed root directory."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve(strict=True)

    @property
    def root(self) -> Path:
        return self._root

    def _shard_for(self, digest: str) -> Path:
        """Two levels of fan-out keep any one directory small."""
        return self._root / digest[:2] / digest[2:4]

    def _resolve_within_root(self, candidate: Path) -> Path:
        resolved = candidate.resolve()
        if not resolved.is_relative_to(self._root):
            raise StorageEscapeError(f"path escapes storage root: {resolved}")
        return resolved

    def put(self, payload: bytes, media_type: str) -> StoredArtifact:
        """Stores ``payload`` and returns its record.

        Writing the same bytes twice is a no-op that returns the same record.
        """
        if len(payload) == 0 or len(payload) > MAX_ARTIFACT_BYTES:
            raise ArtifactTooLargeError(
                f"payload must be 1..{MAX_ARTIFACT_BYTES} bytes, got {len(payload)}"
            )

        extension = _EXTENSIONS.get(media_type)
        if extension is None:
            raise UnsupportedMediaTypeError(media_type)

        digest = hashlib.sha256(payload).hexdigest()
        directory = self._shard_for(digest)
        directory.mkdir(parents=True, exist_ok=True, mode=_DIRECTORY_MODE)

        target = self._resolve_within_root(directory / f"{digest}{extension}")

        if not target.exists():
            self._write_atomically(target, payload)

        return StoredArtifact(
            digest=digest,
            media_type=media_type,
            size_bytes=len(payload),
            path=target,
        )

    @staticmethod
    def _write_atomically(target: Path, payload: bytes) -> None:
        """Writes through a temporary in the same directory, then renames.

        ``mkstemp`` creates the temporary with owner-only permissions in the
        destination directory, and the rename is atomic on one filesystem.
        """
        handle, temporary_name = tempfile.mkstemp(dir=target.parent, suffix=".partial")
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

    def get(self, digest: str, media_type: str) -> bytes:
        """Reads back a stored artifact by digest.

        Raises:
            ValueError: when ``digest`` is not 64 lowercase hex characters.
            FileNotFoundError: when no such artifact exists.
        """
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("digest must be 64 lowercase hex characters")

        extension = _EXTENSIONS.get(media_type)
        if extension is None:
            raise UnsupportedMediaTypeError(media_type)

        target = self._resolve_within_root(self._shard_for(digest) / f"{digest}{extension}")
        return target.read_bytes()
