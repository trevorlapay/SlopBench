"""Juliet Test Suite adapter.

The Juliet Test Suite is a collection of synthetic test cases from NIST/SARD.
Each test case typically has a "bad" function (vulnerable) and "good" functions (safe).
Organized by CWE in directories like: testcases/CWE79_XSS/s01/CWE79_XSS__*.c
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from sastbench.adapters.base import BenchmarkAdapter
from sastbench.models import GroundTruth, TestCase
from sastbench.utils.cwe import normalize_cwe

logger = logging.getLogger(__name__)

# Pattern to extract CWE number from Juliet directory/file names
_CWE_DIR_PATTERN = re.compile(r"CWE(\d+)")
# Pattern to identify bad (vulnerable) vs good (safe) functions in file names
_BAD_FUNC_PATTERN = re.compile(r"\bbad\b", re.IGNORECASE)
_GOOD_FUNC_PATTERN = re.compile(r"\bgood\b", re.IGNORECASE)

JULIET_DOWNLOAD_URL = (
    "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
)

SUPPORTED_EXTENSIONS = {".c", ".cpp", ".java"}


class JulietAdapter(BenchmarkAdapter):
    name = "juliet"
    description = "NIST Juliet Test Suite — synthetic C/C++/Java vulnerability test cases"
    url = "https://samate.nist.gov/SARD/test-suites"
    languages = ("c", "cpp")

    def download(self, cache_dir: Path) -> Path:
        """Download Juliet Test Suite from NIST."""
        import zipfile

        import httpx

        dest = cache_dir / self.name
        dest.mkdir(parents=True, exist_ok=True)

        zip_path = dest / "juliet-c-cpp.zip"
        if not zip_path.exists():
            logger.info("Downloading Juliet C/C++ test suite...")
            tmp_path = zip_path.with_suffix('.tmp')
            with httpx.stream("GET", JULIET_DOWNLOAD_URL, follow_redirects=True) as resp:
                resp.raise_for_status()
                with open(tmp_path, "wb") as f:
                    for chunk in resp.iter_bytes(8192):
                        f.write(chunk)
            tmp_path.rename(zip_path)

            logger.info("Extracting Juliet C/C++...")
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

        # Find testcases directory
        testcases_dir = self._find_testcases_dir(benchmark_path)
        if testcases_dir is None:
            logger.warning("No testcases directory found in %s", benchmark_path)
            return test_cases, ground_truths

        # Collect source files grouped by CWE
        cwe_files: dict[str, list[tuple[str, Path]]] = {}  # cwe_id → [(cwe_id, path)]
        for cwe_dir in sorted(testcases_dir.iterdir()):
            if not cwe_dir.is_dir():
                continue
            m = _CWE_DIR_PATTERN.search(cwe_dir.name)
            if not m:
                continue
            cwe_id = normalize_cwe(m.group(1))
            if cwe_id is None:
                continue
            if cwe_filter and cwe_id not in cwe_filter:
                continue

            files = []
            for source_file in self._iter_source_files(cwe_dir):
                ext = source_file.suffix.lower()
                lang = self._ext_to_language(ext)
                if language_filter and lang not in language_filter:
                    continue
                files.append((cwe_id, source_file))
            if files:
                cwe_files[cwe_id] = files

        if not cwe_files:
            return test_cases, ground_truths

        # Round-robin sample across CWEs to ensure diversity
        selected: list[tuple[str, Path]] = []
        if max_cases:
            per_cwe = max(1, max_cases // len(cwe_files))
            for cwe_id, files in sorted(cwe_files.items()):
                selected.extend(files[:per_cwe])
            # Fill remainder if we're short
            if len(selected) < max_cases:
                for cwe_id, files in sorted(cwe_files.items()):
                    for f in files[per_cwe:]:
                        if len(selected) >= max_cases:
                            break
                        selected.append(f)
            selected = selected[:max_cases]
        else:
            for files in cwe_files.values():
                selected.extend(files)

        # Process selected files
        for cwe_id, source_file in selected:
            ext = source_file.suffix.lower()
            lang = self._ext_to_language(ext)
            if language_filter and lang not in language_filter:
                continue

            try:
                code = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                logger.warning("Could not read %s", source_file)
                continue

            rel_path = str(source_file.relative_to(benchmark_path))
            original_id = source_file.stem

            test_cases.append(
                TestCase(
                    original_id=original_id,
                    original_path=rel_path,
                    code=code,
                    language=lang,
                    metadata={"cwe_id": cwe_id},
                )
            )

            # Juliet files typically contain BOTH bad and good code.
            # Ground truth comes from POTENTIAL FLAW comments and
            # OMITBAD/OMITGOOD guards in the source.
            has_bad = "OMITBAD" in code or "_bad" in source_file.stem
            flaw_lines = self._find_flaw_lines(code)

            if has_bad or flaw_lines:
                if flaw_lines:
                    for line_no in flaw_lines:
                        ground_truths.append(
                            GroundTruth(
                                file_path=rel_path,
                                start_line=line_no,
                                cwe_id=cwe_id,
                                is_vulnerable=True,
                                benchmark_name="juliet",
                                metadata={"original_id": original_id},
                            )
                        )
                else:
                    ground_truths.append(
                        GroundTruth(
                            file_path=rel_path,
                            cwe_id=cwe_id,
                            is_vulnerable=True,
                            benchmark_name="juliet",
                            metadata={"original_id": original_id},
                        )
                    )
            elif "_good" in source_file.name.lower() and "OMITBAD" not in code:
                ground_truths.append(
                    GroundTruth(
                        file_path=rel_path,
                        cwe_id=cwe_id,
                        is_vulnerable=False,
                        benchmark_name="juliet",
                        metadata={"original_id": original_id},
                    )
                )

        return test_cases, ground_truths

    @staticmethod
    def _find_testcases_dir(base: Path) -> Path | None:
        """Find the 'testcases' directory within the benchmark path."""
        if (base / "testcases").is_dir():
            return base / "testcases"
        # Search one level deep
        for child in base.iterdir():
            if child.is_dir() and (child / "testcases").is_dir():
                return child / "testcases"
        return None

    @staticmethod
    def _iter_source_files(directory: Path):
        """Yield source files recursively from a directory."""
        for f in sorted(directory.rglob("*")):
            if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS:
                yield f

    @staticmethod
    def _ext_to_language(ext: str) -> str:
        return {".c": "c", ".cpp": "cpp", ".h": "c", ".java": "java"}.get(ext, "unknown")

    @staticmethod
    def _find_flaw_lines(code: str) -> list[int]:
        """Find lines marked with FLAW comments (Juliet convention)."""
        lines: list[int] = []
        for i, line in enumerate(code.splitlines(), 1):
            if "POTENTIAL FLAW" in line or "FLAW:" in line:
                lines.append(i)
        return lines
