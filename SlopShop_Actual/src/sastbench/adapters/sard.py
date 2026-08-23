"""SARD (Software Assurance Reference Dataset) adapter.

SARD from NIST contains test cases for various CWEs in C/C++/Java.
The dataset structure varies; this adapter supports the common directory layout
and XML manifest format.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase

logger = logging.getLogger(__name__)


class SardAdapter(BenchmarkAdapter):
    name = "sard"
    description = "NIST SARD — Software Assurance Reference Dataset"
    url = "https://samate.nist.gov/SARD/"
    languages = ("c", "cpp", "java")

    def download(self, cache_dir: Path) -> Path:
        dest = cache_dir / self.name
        dest.mkdir(parents=True, exist_ok=True)
        logger.info(
            "SARD requires manual download from %s. "
            "Place the test suite in %s",
            self.url,
            dest,
        )
        return dest

    def extract(
        self,
        benchmark_path: Path,
        *,
        cwe_filter: list[str] | None = None,
        language_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        # SARD shares structure with Juliet in many cases.
        # Delegate to Juliet adapter logic for compatible layouts.
        from sastbench.adapters.juliet import JulietAdapter

        juliet = JulietAdapter()
        cases, gts = juliet.extract(
            benchmark_path,
            cwe_filter=cwe_filter,
            language_filter=language_filter,
            max_cases=max_cases,
        )
        gts = [gt.model_copy(update={"benchmark_name": "sard"}) for gt in gts]
        return cases, gts
