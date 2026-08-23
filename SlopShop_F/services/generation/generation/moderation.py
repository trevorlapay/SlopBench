"""Content checks applied before a brief is rendered and after an artifact
returns.

Patterns are compiled once at import and applied to a length-bounded slice of
the input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

# Longest text this module will examine. Callers bound their input before
# calling, and this is the backstop.
MAX_SCANNED_CHARS: Final = 8_000


class Decision(StrEnum):
    ALLOW = "allow"
    REVIEW = "review"
    REFUSE = "refuse"


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision
    reasons: tuple[str, ...]

    @property
    def blocked(self) -> bool:
        return self.decision is Decision.REFUSE


# Categories that are refused outright. Each entry is a plain alternation of
# literals, compiled once at import.
_REFUSE_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "counterfeit": re.compile(
        r"\b(counterfeit|replica trademark|forged certificate)\b", re.IGNORECASE
    ),
    "credentials": re.compile(
        r"\b(passport scan|driver licence template|national insurance number)\b",
        re.IGNORECASE,
    ),
    "weapons": re.compile(
        r"\b(ghost gun|auto sear|suppressor blueprint)\b", re.IGNORECASE
    ),
}

# Categories that are allowed but queued for a human look.
_REVIEW_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "likeness": re.compile(
        r"\b(portrait of|likeness of|in the style of)\b", re.IGNORECASE
    ),
    "medical_claim": re.compile(
        r"\b(cures|clinically proven|fda approved)\b", re.IGNORECASE
    ),
}

# Artifact MIME types the pipeline is able to handle.
_ALLOWED_ARTIFACT_TYPES: Final[frozenset[str]] = frozenset(
    {"image/png", "image/jpeg", "image/webp"}
)

# Magic bytes for each accepted type. The declared type must agree with the
# bytes actually present.
_MAGIC: Final[dict[str, tuple[bytes, ...]]] = {
    "image/png": (b"\x89PNG\r\n\x1a\n",),
    "image/jpeg": (b"\xff\xd8\xff",),
    "image/webp": (b"RIFF",),
}


def screen_text(text: str) -> Verdict:
    """Classifies a seller brief."""
    scanned = text[:MAX_SCANNED_CHARS]

    refusals = tuple(
        name for name, pattern in _REFUSE_PATTERNS.items() if pattern.search(scanned)
    )
    if refusals:
        return Verdict(Decision.REFUSE, refusals)

    reviews = tuple(
        name for name, pattern in _REVIEW_PATTERNS.items() if pattern.search(scanned)
    )
    if reviews:
        return Verdict(Decision.REVIEW, reviews)

    return Verdict(Decision.ALLOW, ())


def screen_artifact(declared_type: str, payload: bytes, max_bytes: int) -> Verdict:
    """Checks a returned artifact against the declared type and a size cap."""
    reasons: list[str] = []

    if declared_type not in _ALLOWED_ARTIFACT_TYPES:
        reasons.append("unsupported_media_type")
    elif not any(payload.startswith(prefix) for prefix in _MAGIC[declared_type]):
        reasons.append("magic_bytes_mismatch")

    if len(payload) == 0:
        reasons.append("empty_artifact")
    elif len(payload) > max_bytes:
        reasons.append("artifact_too_large")

    if reasons:
        return Verdict(Decision.REFUSE, tuple(reasons))
    return Verdict(Decision.ALLOW, ())
