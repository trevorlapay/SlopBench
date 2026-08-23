"""Benchmark download and cache management."""

from __future__ import annotations

import os
import platform
from pathlib import Path


def get_default_cache_dir() -> Path:
    """Get platform-appropriate default cache directory."""
    env_override = os.environ.get("SASTBENCH_CACHE_DIR")
    if env_override:
        return Path(env_override)

    system = platform.system()
    if system == "Windows":
        base = os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")
        return Path(base) / "sastbench" / "cache"
    elif system == "Darwin":
        return Path.home() / "Library" / "Caches" / "sastbench"
    else:
        xdg = os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")
        return Path(xdg) / "sastbench"


def ensure_cache_dir(cache_dir: Path | None = None) -> Path:
    """Ensure cache directory exists and return its path."""
    d = cache_dir or get_default_cache_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_benchmark_cache_path(benchmark_name: str, cache_dir: Path | None = None) -> Path:
    """Get the cache path for a specific benchmark."""
    d = ensure_cache_dir(cache_dir)
    result = (d / benchmark_name).resolve()
    if not str(result).startswith(str(d.resolve())):
        raise ValueError(f"Invalid benchmark name: {benchmark_name!r}")
    return result
