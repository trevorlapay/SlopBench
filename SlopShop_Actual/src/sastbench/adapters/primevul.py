"""PrimeVul adapter.

PrimeVul is a high-quality dataset of real-world C/C++ vulnerable and benign functions
from the DLVulDet/PrimeVul GitHub repository. Data is typically in CSV/JSON format
with columns: func_before, target (1=vulnerable, 0=benign), cwe_id, etc.
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase
from sastbench.utils.cwe import normalize_cwe

logger = logging.getLogger(__name__)

# Patterns that indicate C++ rather than plain C
_CPP_INDICATORS = re.compile(
    r'\b(?:class\s+\w+|namespace\s+\w+|template\s*<|std::|cout|cin|cerr'
    r'|nullptr|dynamic_cast|static_cast|reinterpret_cast|const_cast'
    r'|using\s+namespace|public:|private:|protected:|virtual\s)'
)

PRIMEVUL_REPO = "https://github.com/DLVulDet/PrimeVul"
PRIMEVUL_HF = "https://huggingface.co/datasets/ASSERT-KTH/PrimeVul"
PRIMEVUL_PARQUET = "https://huggingface.co/api/datasets/ASSERT-KTH/PrimeVul/parquet/default/test_paired"


class PrimeVulAdapter(BenchmarkAdapter):
    name = "primevul"
    description = "PrimeVul — high-quality real-world C/C++ vulnerability dataset"
    url = PRIMEVUL_REPO
    languages = ("c", "cpp")

    def download(self, cache_dir: Path) -> Path:
        import httpx

        dest = cache_dir / self.name
        dest.mkdir(parents=True, exist_ok=True)

        parquet_path = dest / "test_paired.parquet"
        if not parquet_path.exists():
            logger.info("Downloading PrimeVul test set from HuggingFace...")
            # Get parquet URL from HF API
            api_url = "https://huggingface.co/api/datasets/ASSERT-KTH/PrimeVul/parquet/default/test_paired"
            resp = httpx.get(api_url, follow_redirects=True, timeout=30)
            resp.raise_for_status()
            parquet_urls = resp.json()
            if parquet_urls:
                dl_url = parquet_urls[0]  # First parquet shard
                logger.info("Downloading %s...", dl_url)
                tmp_path = parquet_path.with_suffix('.tmp')
                with httpx.stream("GET", dl_url, follow_redirects=True, timeout=300) as r:
                    r.raise_for_status()
                    with open(tmp_path, "wb") as f:
                        for chunk in r.iter_bytes(65536):
                            f.write(chunk)
                tmp_path.rename(parquet_path)

        # Also download train set for more data
        train_path = dest / "train_paired.parquet"
        if not train_path.exists():
            api_url2 = "https://huggingface.co/api/datasets/ASSERT-KTH/PrimeVul/parquet/default/train_paired"
            resp2 = httpx.get(api_url2, follow_redirects=True, timeout=30)
            if resp2.status_code == 200:
                urls2 = resp2.json()
                if urls2:
                    tmp_path = train_path.with_suffix('.tmp')
                    with httpx.stream("GET", urls2[0], follow_redirects=True, timeout=300) as r2:
                        r2.raise_for_status()
                        with open(tmp_path, "wb") as f:
                            for chunk in r2.iter_bytes(65536):
                                f.write(chunk)
                    tmp_path.rename(train_path)

        return dest

    def extract(
        self,
        benchmark_path: Path,
        *,
        cwe_filter: list[str] | None = None,
        language_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        test_cases: list[TestCase] = []
        ground_truths: list[GroundTruth] = []

        # Try parquet files first (HuggingFace format)
        parquet_files = list(benchmark_path.rglob("*.parquet"))
        if parquet_files:
            return self._extract_parquet(parquet_files, cwe_filter=cwe_filter, max_cases=max_cases)

        # Fall back to CSV
        csv_files = list(benchmark_path.rglob("*.csv"))
        if not csv_files:
            logger.warning("No parquet or CSV files found in %s", benchmark_path)
            return test_cases, ground_truths

        return self._extract_csv(csv_files, cwe_filter=cwe_filter, max_cases=max_cases)

    def _extract_parquet(
        self,
        parquet_files: list[Path],
        *,
        cwe_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        import pandas as pd

        test_cases: list[TestCase] = []
        ground_truths: list[GroundTruth] = []
        count = 0

        for pf in sorted(parquet_files):
            df = pd.read_parquet(pf)
            logger.info("Reading %s: %d rows, columns: %s", pf.name, len(df), list(df.columns))

            for _, row in df.iterrows():
                if max_cases is not None and count >= max_cases:
                    return test_cases, ground_truths

                # Extract code, guarding against pandas NA/NaN values
                raw_code = row.get("func")
                if raw_code is None or (pd.notna(raw_code) is False):
                    raw_code = row.get("func_before")
                if raw_code is None or (pd.notna(raw_code) is False):
                    raw_code = row.get("code", "")
                if raw_code is None or (pd.notna(raw_code) is False):
                    raw_code = ""
                code = str(raw_code)
                if not code.strip():
                    continue

                # CWE in PrimeVul can be an array like ['CWE-119'] or ['Other']
                cwe_raw = row.get("cwe") or row.get("cwe_id", "")
                if hasattr(cwe_raw, "__iter__") and not isinstance(cwe_raw, str):
                    # It's an array — take first CWE-like entry
                    cwe = None
                    for c in cwe_raw:
                        normalized = normalize_cwe(str(c))
                        if normalized:
                            cwe = normalized
                            break
                else:
                    cwe = normalize_cwe(str(cwe_raw)) if cwe_raw else None

                if cwe_filter and (cwe is None or cwe not in cwe_filter):
                    continue

                # is_vulnerable is a bool in PrimeVul HF format
                is_vuln_raw = row.get("is_vulnerable", row.get("target", row.get("label", False)))
                if isinstance(is_vuln_raw, bool):
                    is_vulnerable = is_vuln_raw
                elif pd.notna(is_vuln_raw):
                    is_vulnerable = int(is_vuln_raw) == 1
                else:
                    is_vulnerable = False

                func_id = str(row.get("idx") or row.get("id") or row.get("commit_id", f"primevul_{count}"))

                # Detect language: C++ if code contains C++ indicators, else C
                lang = "cpp" if _CPP_INDICATORS.search(code) else "c"
                ext = "cpp" if lang == "cpp" else "c"
                file_path = f"primevul_{count}.{ext}"

                test_cases.append(
                    TestCase(
                        original_id=str(func_id)[:200],
                        original_path=file_path,
                        code=code,
                        language=lang,
                        metadata={"cwe": cwe or "unknown", "is_vulnerable": is_vulnerable},
                    )
                )

                # Use CWE-000 as placeholder when CWE is unknown (e.g., "Other")
                gt_cwe = cwe or "CWE-000"
                ground_truths.append(
                    GroundTruth(
                        file_path=file_path,
                        cwe_id=gt_cwe,
                        is_vulnerable=is_vulnerable,
                        benchmark_name="primevul",
                        metadata={"original_id": str(func_id)[:200]},
                    )
                )

                count += 1

        return test_cases, ground_truths

    def _extract_csv(
        self,
        csv_files: list[Path],
        *,
        cwe_filter: list[str] | None = None,
        max_cases: int | None = None,
    ) -> tuple[list[TestCase], list[GroundTruth]]:
        """Fallback extraction from PrimeVul CSV files."""
        test_cases: list[TestCase] = []
        ground_truths: list[GroundTruth] = []
        count = 0

        for csv_file in sorted(csv_files):
            with open(csv_file, encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if max_cases is not None and count >= max_cases:
                        return test_cases, ground_truths

                    code = row.get("func") or row.get("func_before") or row.get("code", "")
                    if not code.strip():
                        continue

                    cwe_raw = row.get("cwe") or row.get("cwe_id", "")
                    cwe = normalize_cwe(cwe_raw) if cwe_raw else None
                    if cwe_filter and (cwe is None or cwe not in cwe_filter):
                        continue

                    target = row.get("target", row.get("is_vulnerable", row.get("label", "")))
                    is_vulnerable = str(target).strip() in ("1", "true", "True")

                    func_id = row.get("idx") or row.get("id") or row.get("commit_id", f"primevul_{count}")

                    lang = "cpp" if _CPP_INDICATORS.search(code) else "c"
                    ext = "cpp" if lang == "cpp" else "c"
                    file_path = f"primevul_{count}.{ext}"

                    test_cases.append(
                        TestCase(
                            original_id=str(func_id)[:200],
                            original_path=file_path,
                            code=code,
                            language=lang,
                            metadata={"cwe": cwe or "unknown", "is_vulnerable": is_vulnerable},
                        )
                    )

                    gt_cwe = cwe or "CWE-000"
                    ground_truths.append(
                        GroundTruth(
                            file_path=file_path,
                            cwe_id=gt_cwe,
                            is_vulnerable=is_vulnerable,
                            benchmark_name="primevul",
                            metadata={"original_id": str(func_id)[:200]},
                        )
                    )
                    count += 1

        return test_cases, ground_truths