"""Path and data normalization utilities."""

from __future__ import annotations

import posixpath
import re


def safe_div(numerator: float, denominator: float) -> float:
    """Safely divide two numbers, returning 0.0 when denominator is zero."""
    return numerator / denominator if denominator else 0.0


def normalize_path(path: str) -> str:
    """Normalize a file path for cross-platform comparison.

    - Converts backslashes to forward slashes
    - Removes leading ./ or /
    - Collapses repeated separators
    - Lowercases on Windows-style paths
    """
    p = path.replace("\\", "/")
    p = re.sub(r"/+", "/", p)
    # Remove leading ./ prefix (NOT character-by-character)
    while p.startswith("./"):
        p = p[2:]
    p = p.lstrip("/")
    p = posixpath.normpath(p)
    if p == ".":
        return ""
    return p


def paths_match(a: str, b: str) -> bool:
    """Check if two file paths refer to the same file (cross-platform tolerant)."""
    return normalize_path(a) == normalize_path(b)


def normalize_severity(raw: str | None) -> str | None:
    """Map various severity representations to standard values."""
    if raw is None:
        return None
    low = raw.strip().lower()
    mapping = {
        # SARIF levels
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "low",
        # Standard
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        # Aliases
        "informational": "low",
        "info": "low",
        # Numeric-ish
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }
    return mapping.get(low)


def severity_weight(severity: str | None) -> float:
    """Return a numeric weight for severity-weighted metrics."""
    weights = {
        "critical": 4.0,
        "high": 3.0,
        "medium": 2.0,
        "low": 1.0,
    }
    if severity is None:
        return 1.0
    return weights.get(severity.lower(), 1.0)
