"""CSV parser with configurable column mapping."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from sastbench.models import Finding, Severity
from sastbench.parsers.base import BaseParser
from sastbench.utils.cwe import normalize_cwe
from sastbench.utils.normalize import normalize_path, normalize_severity

logger = logging.getLogger(__name__)

DEFAULT_COLUMN_MAPPING: dict[str, str] = {
    "file_path": "file_path",
    "start_line": "start_line",
    "end_line": "end_line",
    "function_name": "function_name",
    "cwe_id": "cwe_id",
    "severity": "severity",
    "confidence": "confidence",
    "message": "message",
    "rule_id": "rule_id",
    "tool_name": "tool_name",
}


class CsvParser(BaseParser):
    """Parse CSV findings files with configurable column mapping."""

    def __init__(self, column_mapping: dict[str, str] | None = None) -> None:
        self.column_mapping = column_mapping or DEFAULT_COLUMN_MAPPING

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == ".csv"

    def parse(self, path: Path) -> list[Finding]:
        with open(path, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            findings: list[Finding] = []
            for row in reader:
                try:
                    finding = self._parse_row(row)
                    if finding is not None:
                        findings.append(finding)
                except Exception:
                    logger.warning("Skipping malformed CSV row", exc_info=True)
        return findings

    def _parse_row(self, row: dict[str, str]) -> Finding | None:
        def get(field: str) -> str | None:
            col = self.column_mapping.get(field)
            if col is None or col not in row:
                return None
            val = row[col].strip()
            return val if val else None

        file_path = get("file_path")
        if not file_path:
            logger.warning("CSV row missing file_path, skipping")
            return None

        raw_cwe = get("cwe_id")
        cwe_id = normalize_cwe(raw_cwe) if raw_cwe else None

        raw_severity = get("severity")
        severity: Severity | None = None
        if raw_severity:
            mapped = normalize_severity(raw_severity)
            if mapped:
                try:
                    severity = Severity(mapped)
                except ValueError:
                    severity = None

        raw_start = get("start_line")
        raw_end = get("end_line")
        raw_conf = get("confidence")

        try:
            start_line = int(raw_start) if raw_start else None
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid value for 'start_line': {raw_start!r}") from exc
        try:
            end_line = int(raw_end) if raw_end else None
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid value for 'end_line': {raw_end!r}") from exc
        try:
            confidence = float(raw_conf) if raw_conf else None
        except (ValueError, TypeError) as exc:
            raise ValueError(f"Invalid value for 'confidence': {raw_conf!r}") from exc

        return Finding(
            file_path=normalize_path(file_path),
            start_line=start_line,
            end_line=end_line,
            function_name=get("function_name"),
            cwe_id=cwe_id,
            severity=severity,
            confidence=confidence,
            message=get("message"),
            rule_id=get("rule_id"),
            tool_name=get("tool_name"),
        )
