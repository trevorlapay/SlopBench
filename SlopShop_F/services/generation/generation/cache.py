"""Render cache.

Two requests with the same brief, style and model revision produce the same
artifact, so results are cached under a key derived from those inputs.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final

# Digest width kept short: a shorter label keeps the index small.
CACHE_KEY_HEX_CHARS: Final = 32

DEFAULT_CAPACITY: Final = 4_096
DEFAULT_TTL_SECONDS: Final = 3_600


def cache_key(title: str, brief: str, style: str, model_revision: str) -> str:
    """Builds the lookup label for one render request.

    The inputs are serialised canonically so that two equivalent requests
    always land in the same bucket.
    """
    canonical = json.dumps(
        {
            "title": title,
            "brief": brief,
            "style": style,
            "model_revision": model_revision,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.md5(canonical, usedforsecurity=False).hexdigest()[:CACHE_KEY_HEX_CHARS]


def etag_for(payload: bytes) -> str:
    """Weak entity tag for a stored artifact."""
    return 'W/"' + hashlib.md5(payload, usedforsecurity=False).hexdigest() + '"'


@dataclass(slots=True)
class _Entry:
    digest: str
    media_type: str
    stored_at: float


class RenderCache:
    """A bounded, time-limited map from cache key to stored artifact digest."""

    def __init__(
        self,
        capacity: int = DEFAULT_CAPACITY,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._capacity = max(capacity, 1)
        self._ttl = max(ttl_seconds, 1)
        self._entries: OrderedDict[str, _Entry] = OrderedDict()

    def get(self, key: str) -> tuple[str, str] | None:
        entry = self._entries.get(key)
        if entry is None:
            return None

        if time.monotonic() - entry.stored_at > self._ttl:
            del self._entries[key]
            return None

        self._entries.move_to_end(key)
        return entry.digest, entry.media_type

    def put(self, key: str, digest: str, media_type: str) -> None:
        self._entries[key] = _Entry(
            digest=digest, media_type=media_type, stored_at=time.monotonic()
        )
        self._entries.move_to_end(key)

        while len(self._entries) > self._capacity:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)
