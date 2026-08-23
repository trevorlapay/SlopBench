"""CASTLE adapter.

CASTLE is a newer CWE-focused benchmark for evaluating static analyzers and LLMs.
"""

from __future__ import annotations

import logging
from pathlib import Path

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase
from sastbench.utils.cwe import normalize_cwe

logger = logging.getLogger(__name__)


class CastleAdapter(BenchmarkAdapter):
    name = "castle"
    description = "CASTLE — CWE-focused benchmark for static analyzers and LLMs"
    url = "https://github.com/CASTLE-Benchmark/CASTLE-Benchmark"
    languages = ("c", "cpp", "java")

    def download(self, cache_dir: Path) -> Path:
        import zipfile
        import httpx

        dest = cache_dir / self.name
        dest.mkdir(parents=True, exist_ok=True)

        zip_url = "https://github.com/CASTLE-Benchmark/CASTLE-Benchmark/archive/refs/heads/main.zip"
        zip_path = dest / "castle.zip"
        if not zip_path.exists():
            logger.info("Downloading CASTLE dataset...")
            tmp_path = zip_path.with_suffix('.tmp')
            with httpx.stream("GET", zip_url, follow_redirects=True) as resp:
                resp.raise_for_status()
                with open(tmp_path, "wb") as f:
                    for chunk in resp.iter_bytes(8192):
                        f.write(chunk)
            tmp_path.rename(zip_path)
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(dest)
        return dest

    def extract(
        self,
        benchmark_path: Path,
        *,
        cwe_filter: list[str] | None = None,
        language_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        """Extract test cases from CASTLE dataset.

        Note: CASTLE is predominantly C-only.  When *language_filter* is
        provided and ``"c"`` is not in the list, no cases will be returned.
        """
        import json as _json

        # CASTLE is C-only; if the caller filters to other languages, short-circuit.
        if language_filter and "c" not in language_filter:
            logger.info("CASTLE is C-only; language_filter %s excludes all cases", language_filter)
            return [], []

        test_cases: list[TestCase] = []
        ground_truths: list[GroundTruth] = []

        # Look for CASTLE JSON dataset files
        json_files = list(benchmark_path.rglob("CASTLE-*.json"))
        # Prefer full (not .min) version
        json_files = [f for f in json_files if ".min." not in f.name]

        count = 0
        for json_file in json_files:
            try:
                data = _json.loads(json_file.read_text(encoding="utf-8"))
            except (_json.JSONDecodeError, UnicodeDecodeError):
                continue

            tests = data.get("tests", [])
            if not tests:
                continue

            logger.info("Reading %s: %d tests", json_file.name, len(tests))

            for test in tests:
                if max_cases is not None and count >= max_cases:
                    return test_cases, ground_truths

                code = test.get("code", "")
                if not code.strip():
                    continue

                cwe_raw = str(test.get("cwe", ""))
                cwe = normalize_cwe(cwe_raw)
                if cwe_filter and (cwe is None or cwe not in cwe_filter):
                    continue

                is_vulnerable = test.get("vulnerable", False)
                test_id = test.get("id", test.get("name", f"castle_{count}"))
                vuln_lines = test.get("lines", [])

                file_path = f"castle_{count}.c"
                test_cases.append(
                    TestCase(
                        original_id=str(test_id),
                        original_path=file_path,
                        code=code,
                        language="c",
                        metadata={
                            "cwe": cwe or "",
                            "description": test.get("description", ""),
                            "vulnerable": is_vulnerable,
                        },
                    )
                )

                if vuln_lines and is_vulnerable and cwe:
                    for line_no in vuln_lines:
                        ground_truths.append(
                            GroundTruth(
                                file_path=file_path,
                                start_line=line_no,
                                cwe_id=cwe,
                                is_vulnerable=True,
                                benchmark_name="castle",
                                metadata={"original_id": str(test_id)},
                            )
                        )
                elif cwe:
                    ground_truths.append(
                        GroundTruth(
                            file_path=file_path,
                            cwe_id=cwe,
                            is_vulnerable=is_vulnerable,
                            benchmark_name="castle",
                            metadata={"original_id": str(test_id)},
                        )
                    )

                count += 1

        return test_cases, ground_truths
