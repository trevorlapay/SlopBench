"""Custom ground truth adapter — user-provided JSON or CSV files."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase
from sastbench.utils.cwe import normalize_cwe
from sastbench.utils.normalize import normalize_path


class CustomAdapter(BenchmarkAdapter):
    """Adapter for user-provided custom ground truth data.

    Supports JSON and CSV formats. No download needed.

    JSON format:
    {
        "ground_truths": [
            {"file_path": "...", "cwe_id": "CWE-79", "start_line": 10, ...}
        ],
        "test_cases": [  // optional
            {"original_id": "...", "original_path": "...", "code": "...", "language": "c"}
        ]
    }

    CSV format (ground_truths.csv):
    file_path,cwe_id,start_line,end_line,is_vulnerable
    code/a.c,CWE-79,10,,true
    """

    name = "custom"
    description = "User-provided custom ground truth (JSON or CSV)"
    url = ""
    languages = ()

    def download(self, cache_dir: Path) -> Path:
        raise NotImplementedError("Custom adapter does not support download")

    def extract(
        self,
        benchmark_path: Path,
        *,
        cwe_filter: list[str] | None = None,
        language_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        if benchmark_path.suffix == ".json":
            return self._extract_json(benchmark_path, cwe_filter=cwe_filter, max_cases=max_cases)
        elif benchmark_path.suffix == ".csv":
            return self._extract_csv(benchmark_path, cwe_filter=cwe_filter, max_cases=max_cases)
        else:
            # Try to find files in the directory
            json_path = benchmark_path / "ground_truths.json"
            csv_path = benchmark_path / "ground_truths.csv"
            if json_path.exists():
                return self._extract_json(json_path, cwe_filter=cwe_filter, max_cases=max_cases)
            elif csv_path.exists():
                return self._extract_csv(csv_path, cwe_filter=cwe_filter, max_cases=max_cases)
            raise FileNotFoundError(
                f"No ground truth file found at {benchmark_path}. "
                "Expected .json, .csv, or directory with ground_truths.json/csv"
            )

    def _extract_json(
        self,
        path: Path,
        *,
        cwe_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        data = json.loads(path.read_text(encoding="utf-8"))
        ground_truths: list[GroundTruth] = []
        test_cases: list[TestCase] = []

        for gt_data in data.get("ground_truths", []):
            cwe = normalize_cwe(gt_data.get("cwe_id", ""))
            if cwe is None:
                continue
            if cwe_filter and cwe not in cwe_filter:
                continue
            ground_truths.append(
                GroundTruth(
                    file_path=normalize_path(gt_data["file_path"]),
                    start_line=gt_data.get("start_line"),
                    end_line=gt_data.get("end_line"),
                    function_name=gt_data.get("function_name"),
                    cwe_id=cwe,
                    is_vulnerable=gt_data.get("is_vulnerable", True),
                    benchmark_name="custom",
                    metadata=gt_data.get("metadata", {}),
                )
            )

        for tc_data in data.get("test_cases", []):
            test_cases.append(
                TestCase(
                    original_id=tc_data["original_id"],
                    original_path=tc_data.get("original_path", ""),
                    code=tc_data["code"],
                    language=tc_data.get("language", "unknown"),
                    metadata=tc_data.get("metadata", {}),
                )
            )

        if max_cases is not None and len(test_cases) > max_cases:
            test_cases = test_cases[:max_cases]
            kept_paths = {tc.original_path for tc in test_cases}
            ground_truths = [gt for gt in ground_truths if gt.file_path in kept_paths]

        return test_cases, ground_truths

    def _extract_csv(
        self,
        path: Path,
        *,
        cwe_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        ground_truths: list[GroundTruth] = []

        with open(path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                cwe = normalize_cwe(row.get("cwe_id", ""))
                if cwe is None:
                    continue
                if cwe_filter and cwe not in cwe_filter:
                    continue

                start_line = row.get("start_line")
                end_line = row.get("end_line")
                is_vuln_str = row.get("is_vulnerable", "true").strip().lower()

                ground_truths.append(
                    GroundTruth(
                        file_path=normalize_path(row["file_path"]),
                        start_line=int(start_line) if start_line else None,
                        end_line=int(end_line) if end_line else None,
                        function_name=row.get("function_name") or None,
                        cwe_id=cwe,
                        is_vulnerable=is_vuln_str in ("true", "1", "yes"),
                        benchmark_name="custom",
                    )
                )

        return [], ground_truths
