"""HumanEval adapter — safe code corpus.

Downloads the OpenAI HumanEval dataset (164 Python functions).
These are algorithmic solutions with no security-relevant APIs,
making them a reliable "known safe" corpus for vulnerability
detection benchmarking.

Source: https://github.com/openai/human-eval
"""

from __future__ import annotations

import gzip
import json
import logging
from pathlib import Path

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase

logger = logging.getLogger(__name__)

HUMANEVAL_URL = (
    "https://raw.githubusercontent.com/openai/human-eval/master/data/HumanEval.jsonl.gz"
)


class HumanEvalAdapter(BenchmarkAdapter):
    name = "humaneval"
    description = "HumanEval — 164 Python algorithmic functions (known safe corpus)"
    url = "https://github.com/openai/human-eval"
    languages = ("python",)

    def download(self, cache_dir: Path) -> Path:
        import httpx

        dest = cache_dir / self.name
        dest.mkdir(parents=True, exist_ok=True)

        jsonl_path = dest / "HumanEval.jsonl"
        if not jsonl_path.exists():
            logger.info("Downloading HumanEval dataset (~45KB)...")
            resp = httpx.get(HUMANEVAL_URL, follow_redirects=True, timeout=60)
            resp.raise_for_status()
            data = gzip.decompress(resp.content).decode("utf-8")
            jsonl_path.write_text(data, encoding="utf-8")
            logger.info("HumanEval downloaded to %s", jsonl_path)

        return dest

    @staticmethod
    def _cache_is_valid(path: Path) -> bool:
        return (path / "HumanEval.jsonl").exists()

    def extract(
        self,
        benchmark_path: Path,
        *,
        cwe_filter: list[str] | None = None,
        language_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        jsonl_path = benchmark_path / "HumanEval.jsonl"
        if not jsonl_path.exists():
            logger.warning("HumanEval.jsonl not found in %s", benchmark_path)
            return [], []

        # Language filter — HumanEval is Python only
        if language_filter and "python" not in language_filter:
            logger.info("HumanEval skipped — language filter excludes Python")
            return [], []

        lines = jsonl_path.read_text(encoding="utf-8").strip().split("\n")
        logger.info("Loaded %d HumanEval problems", len(lines))

        test_cases: list[TestCase] = []
        ground_truths: list[GroundTruth] = []

        for i, line in enumerate(lines):
            if max_cases is not None and i >= max_cases:
                break

            record = json.loads(line)
            task_id = record["task_id"]  # e.g. "HumanEval/0"
            prompt = record["prompt"]
            solution = record["canonical_solution"]
            entry_point = record.get("entry_point", "")

            # Build complete Python file: prompt (signature+docstring) + solution body
            code = prompt + solution

            file_path = f"humaneval_{i:04d}.py"

            test_cases.append(
                TestCase(
                    original_id=task_id,
                    original_path=file_path,
                    code=code,
                    language="python",
                    metadata={
                        "task_id": task_id,
                        "entry_point": entry_point,
                        "is_vulnerable": False,
                    },
                )
            )

            ground_truths.append(
                GroundTruth(
                    file_path=file_path,
                    cwe_id="CWE-000",
                    is_vulnerable=False,
                    benchmark_name="humaneval",
                    metadata={"task_id": task_id},
                )
            )

        logger.info("Extracted %d safe HumanEval functions", len(test_cases))
        return test_cases, ground_truths
