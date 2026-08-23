"""BigVul adapter.

Downloads the BigVul dataset from HuggingFace (bstee615/bigvul) as parquet.
The test split contains ~33k real C/C++ functions (vulnerable and safe) from
open-source projects, linked to CVEs.

Key columns: func_before (source code), vul (0/1), CWE ID, lang, project, commit_id.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase
from sastbench.utils.cwe import normalize_cwe

logger = logging.getLogger(__name__)

PARQUET_INDEX_URL = (
    "https://huggingface.co/api/datasets/bstee615/bigvul/parquet/default/test"
)


class BigVulAdapter(BenchmarkAdapter):
    name = "bigvul"
    description = "BigVul — real-world C/C++ vulnerability dataset from HuggingFace (33k functions)"
    url = "https://huggingface.co/datasets/bstee615/bigvul"
    languages = ("c", "cpp")

    def download(self, cache_dir: Path) -> Path:
        import httpx

        dest = cache_dir / self.name
        dest.mkdir(parents=True, exist_ok=True)

        parquet_path = dest / "bigvul_functions.parquet"
        if not parquet_path.exists():
            logger.info("Fetching parquet URL list from HuggingFace...")
            resp = httpx.get(PARQUET_INDEX_URL, follow_redirects=True, timeout=60)
            resp.raise_for_status()
            urls = resp.json()
            if not urls:
                raise RuntimeError("HuggingFace returned no parquet URLs for bstee615/bigvul")
            parquet_url = urls[0]

            logger.info("Downloading BigVul parquet (~50MB)...")
            tmp_path = parquet_path.with_suffix(".tmp")
            with httpx.stream("GET", parquet_url, follow_redirects=True, timeout=300) as dl:
                dl.raise_for_status()
                with open(tmp_path, "wb") as f:
                    for chunk in dl.iter_bytes(8192):
                        f.write(chunk)
            tmp_path.rename(parquet_path)
            logger.info("BigVul downloaded to %s", parquet_path)

        return dest

    @staticmethod
    def _cache_is_valid(path: Path) -> bool:
        """Cache is valid only if the parquet file exists."""
        return (path / "bigvul_functions.parquet").exists()

    def extract(
        self,
        benchmark_path: Path,
        *,
        cwe_filter: list[str] | None = None,
        language_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        parquet_path = benchmark_path / "bigvul_functions.parquet"
        if not parquet_path.exists():
            # Fall back to any parquet file in the directory
            parquet_files = list(benchmark_path.rglob("*.parquet"))
            if not parquet_files:
                logger.warning("No parquet files found in %s", benchmark_path)
                return [], []
            parquet_path = parquet_files[0]

        df = pd.read_parquet(parquet_path)
        logger.info("Loaded %d rows from %s", len(df), parquet_path.name)

        test_cases: list[TestCase] = []
        ground_truths: list[GroundTruth] = []
        count = 0

        for _, row in df.iterrows():
            if max_cases is not None and count >= max_cases:
                break

            code = row.get("func_before")
            if not isinstance(code, str) or not code.strip():
                continue

            # Vulnerability flag
            is_vulnerable = bool(int(row.get("vul", 1)))

            # CWE — use CWE-000 when missing/null
            cwe_raw = row.get("CWE ID")
            if pd.isna(cwe_raw) or not str(cwe_raw).strip():
                cwe = None
            else:
                cwe = normalize_cwe(str(cwe_raw))
            if cwe_filter and (cwe is None or cwe not in cwe_filter):
                continue

            # Language
            raw_lang = str(row.get("lang", "C")).strip()
            if raw_lang.lower() in ("c++", "cpp"):
                lang = "cpp"
            else:
                lang = "c"
            if language_filter and lang not in language_filter:
                continue

            ext = "cpp" if lang == "cpp" else "c"
            file_path = f"bigvul_{count}.{ext}"

            func_id = str(row.get("commit_id", f"bigvul_{count}"))

            test_cases.append(
                TestCase(
                    original_id=func_id,
                    original_path=file_path,
                    code=code,
                    language=lang,
                    metadata={
                        "project": str(row.get("project", "")),
                        "commit_id": func_id,
                        "is_vulnerable": is_vulnerable,
                    },
                )
            )

            gt_cwe = cwe or "CWE-000"
            ground_truths.append(
                GroundTruth(
                    file_path=file_path,
                    cwe_id=gt_cwe,
                    is_vulnerable=is_vulnerable,
                    benchmark_name="bigvul",
                    metadata={"original_id": func_id},
                )
            )

            count += 1

        logger.info(
            "Extracted %d cases (%d vulnerable, %d safe)",
            count,
            sum(1 for g in ground_truths if g.is_vulnerable),
            sum(1 for g in ground_truths if not g.is_vulnerable),
        )
        return test_cases, ground_truths
