"""Tests for cache utility functions."""

import os
from pathlib import Path

import pytest

from sastbench.utils.cache import get_default_cache_dir, get_benchmark_cache_path


class TestGetDefaultCacheDir:
    def test_env_override(self, monkeypatch, tmp_path):
        """SASTBENCH_CACHE_DIR env var overrides platform default."""
        custom = str(tmp_path / "my_cache")
        monkeypatch.setenv("SASTBENCH_CACHE_DIR", custom)
        assert get_default_cache_dir() == Path(custom)

    def test_returns_path_object(self, monkeypatch):
        """Always returns a Path, regardless of platform."""
        monkeypatch.delenv("SASTBENCH_CACHE_DIR", raising=False)
        result = get_default_cache_dir()
        assert isinstance(result, Path)

    def test_contains_SASTBench(self, monkeypatch):
        """Default path includes 'sastbench' somewhere in the name."""
        monkeypatch.delenv("SASTBENCH_CACHE_DIR", raising=False)
        result = get_default_cache_dir()
        assert "sastbench" in str(result).lower()


class TestGetBenchmarkCachePath:
    def test_returns_subdir(self, tmp_path):
        """Benchmark cache path is a subdirectory of the cache dir."""
        result = get_benchmark_cache_path("juliet", cache_dir=tmp_path)
        assert result == tmp_path / "juliet"
        assert result.parent.exists()

    def test_creates_parent(self, tmp_path):
        """ensure_cache_dir creates the parent directory."""
        cache = tmp_path / "new_cache"
        result = get_benchmark_cache_path("bigvul", cache_dir=cache)
        assert result == cache / "bigvul"
        assert cache.exists()

    def test_different_benchmarks(self, tmp_path):
        """Different benchmark names yield different paths."""
        p1 = get_benchmark_cache_path("juliet", cache_dir=tmp_path)
        p2 = get_benchmark_cache_path("primevul", cache_dir=tmp_path)
        assert p1 != p2
