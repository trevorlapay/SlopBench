"""Abstract base class for benchmark ground truth adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sastbench.models import GroundTruth, TestCase
from sastbench.utils.cache import ensure_cache_dir, get_benchmark_cache_path


class BenchmarkAdapter(ABC):
    """Base class for all benchmark dataset adapters.

    Each adapter knows how to:
    1. Download its benchmark dataset (if not cached)
    2. Extract TestCases (code) and GroundTruths (labels) from the raw data
    """

    name: str = ""
    description: str = ""
    url: str = ""
    languages: tuple[str, ...] = ()

    @abstractmethod
    def download(self, cache_dir: Path) -> Path:
        """Download benchmark data to cache_dir. Returns path to downloaded data."""

    @abstractmethod
    def extract(
        self,
        benchmark_path: Path,
        *,
        cwe_filter: list[str] | None = None,
        language_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        """Extract test cases and ground truth from local benchmark data.

        Args:
            benchmark_path: Path to the raw benchmark data.
            cwe_filter: If set, only include these CWE IDs.
            language_filter: If set, only include these languages.
            max_cases: If set, limit the number of test cases.

        Returns:
            Tuple of (test_cases, ground_truths).
        """

    def ensure_available(
        self,
        cache_dir: Path | None = None,
        local_override: Path | None = None,
    ) -> Path:
        """Return local path to benchmark data, downloading if needed."""
        if local_override and local_override.exists():
            return local_override
        cd = ensure_cache_dir(cache_dir)
        cached = get_benchmark_cache_path(self.name, cd)
        if cached.exists() and self._cache_is_valid(cached):
            return cached
        return self.download(cd)

    @staticmethod
    def _cache_is_valid(path: Path) -> bool:
        """Check that a cached directory is non-empty (not a partial download)."""
        if not path.is_dir():
            return False
        # Require at least one file that isn't the zip itself
        for child in path.iterdir():
            if child.suffix != ".zip":
                return True
        return False

    def info(self) -> dict[str, str | list[str]]:
        """Return metadata about this benchmark."""
        return {
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "languages": self.languages,
        }
