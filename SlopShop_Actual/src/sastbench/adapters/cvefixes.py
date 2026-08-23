"""CVEFixes adapter.

CVEFixes dataset contains real vulnerable code snippets and their patches,
linked to CVE entries. Typically in CSV/JSON format with columns:
code_before, code_after, cwe_id, cve_id, etc.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase
from sastbench.utils.cwe import normalize_cwe

logger = logging.getLogger(__name__)


class CVEFixesAdapter(BenchmarkAdapter):
    name = "cvefixes"
    description = "CVEFixes — real vulnerable code and patches linked to CVEs"
    url = "https://zenodo.org/records/7029359"
    languages = ("c", "cpp", "java", "python")

    def download(self, cache_dir: Path) -> Path:
        import zipfile
        import httpx

        dest = cache_dir / self.name
        dest.mkdir(parents=True, exist_ok=True)

        # Get download URL from Zenodo API
        zip_path = dest / "cvefixes.zip"
        if not zip_path.exists():
            logger.info("Fetching CVEFixes download URL from Zenodo...")
            api_resp = httpx.get("https://zenodo.org/api/records/7029359", timeout=30)
            api_resp.raise_for_status()
            files = api_resp.json().get("files", [])
            zip_file = next((f for f in files if f["key"].endswith(".zip")), None)
            if not zip_file:
                raise RuntimeError("No zip file found in CVEFixes Zenodo record")

            download_url = zip_file["links"]["self"]
            logger.info("Downloading CVEFixes (~3.7GB) from Zenodo...")
            tmp_path = zip_path.with_suffix('.tmp')
            with httpx.stream("GET", download_url, follow_redirects=True, timeout=1800) as resp:
                resp.raise_for_status()
                with open(tmp_path, "wb") as f:
                    for chunk in resp.iter_bytes(65536):
                        f.write(chunk)
            tmp_path.rename(zip_path)

            logger.info("Extracting CVEFixes...")
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
        test_cases: list[TestCase] = []
        ground_truths: list[GroundTruth] = []

        csv_files = list(benchmark_path.rglob("*.csv"))
        if not csv_files:
            logger.warning("No CSV files found in %s", benchmark_path)
            return test_cases, ground_truths

        count = 0
        for csv_file in csv_files:
            with open(csv_file, encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if max_cases is not None and count >= max_cases:
                        return test_cases, ground_truths

                    code = row.get("code_before") or row.get("code") or row.get("func_before", "")
                    if not code.strip():
                        continue

                    cwe_raw = row.get("cwe_id") or row.get("cwe", "")
                    cwe = normalize_cwe(cwe_raw) if cwe_raw else None
                    if cwe_filter and (cwe is None or cwe not in cwe_filter):
                        continue

                    lang = row.get("language", row.get("lang", "c")).lower()
                    if language_filter and lang not in language_filter:
                        continue

                    ext = {"python": ".py", "java": ".java", "cpp": ".cpp"}.get(lang, ".c")
                    func_id = row.get("cve_id") or row.get("id", f"cvefixes_{count}")
                    file_path = f"cvefixes_{count}{ext}"

                    test_cases.append(
                        TestCase(
                            original_id=str(func_id),
                            original_path=file_path,
                            code=code,
                            language=lang,
                            metadata={k: v for k, v in row.items() if k not in ("code_before", "code", "func_before")},
                        )
                    )

                    if cwe:
                        ground_truths.append(
                            GroundTruth(
                                file_path=file_path,
                                cwe_id=cwe,
                                is_vulnerable=True,
                                benchmark_name="cvefixes",
                                metadata={"original_id": str(func_id)},
                            )
                        )

                    count += 1

        return test_cases, ground_truths
