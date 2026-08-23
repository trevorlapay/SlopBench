"""Generic JSON parser with configurable field mapping."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sastbench.models import Finding, Severity
from sastbench.parsers.base import BaseParser
from sastbench.utils.cwe import normalize_cwe
from sastbench.utils.normalize import normalize_path, normalize_severity

logger = logging.getLogger(__name__)

_CONFIDENCE_MAP = {
    "critical": 1.0, "very high": 0.95, "high": 0.8,
    "medium": 0.5, "moderate": 0.5,
    "low": 0.2, "very low": 0.1, "none": 0.0,
}


def _parse_confidence(value: Any) -> float | None:
    """Parse confidence from float, int, or string like 'high'."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip().lower()
    if s in _CONFIDENCE_MAP:
        return _CONFIDENCE_MAP[s]
    try:
        return float(s)
    except (ValueError, TypeError):
        return None

DEFAULT_FIELD_MAPPING: dict[str, str] = {
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

DEFAULT_ROOT_KEY = "findings"


def _resolve_dotpath(obj: Any, dotpath: str) -> Any:
    """Resolve a dot-notation path like 'location.file' against a dict."""
    parts = dotpath.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
        if current is None:
            return None
    return current


class JsonParser(BaseParser):
    """Parse generic JSON findings files with configurable field mapping."""

    _SENTINEL = object()

    def __init__(
        self,
        field_mapping: dict[str, str] | None = None,
        root_key: str | object = _SENTINEL,
    ) -> None:
        self.field_mapping = field_mapping or DEFAULT_FIELD_MAPPING
        self.root_key: str | None = DEFAULT_ROOT_KEY if root_key is self._SENTINEL else root_key  # type: ignore[assignment]

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == ".json"

    def parse(self, path: Path) -> list[Finding]:
        with open(path, encoding="utf-8-sig") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in {path.name}: {exc}") from exc

        # Navigate to the root list
        if self.root_key:
            items = _resolve_dotpath(data, self.root_key)
        else:
            items = data

        if not isinstance(items, list):
            logger.warning("Expected a list at root key %r, got %s", self.root_key, type(items))
            return []

        findings: list[Finding] = []
        for item in items:
            try:
                finding = self._parse_item(item)
                if finding is not None:
                    findings.append(finding)
            except Exception:
                logger.warning("Skipping malformed JSON item", exc_info=True)
        return findings

    def _parse_item(self, item: dict) -> Finding | None:
        def get(field: str) -> Any:
            json_path = self.field_mapping.get(field)
            if json_path is None:
                return None
            return _resolve_dotpath(item, json_path)

        file_path = get("file_path")
        if not file_path:
            logger.warning("JSON item missing file_path, skipping")
            return None

        # Normalize values
        raw_cwe = get("cwe_id")
        cwe_id = normalize_cwe(str(raw_cwe)) if raw_cwe else None

        raw_severity = get("severity")
        severity: Severity | None = None
        if raw_severity:
            mapped = normalize_severity(str(raw_severity))
            if mapped:
                try:
                    severity = Severity(mapped)
                except ValueError:
                    severity = None

        start_line = get("start_line")
        end_line = get("end_line")
        confidence = get("confidence")

        return Finding(
            file_path=normalize_path(str(file_path)),
            start_line=int(start_line) if start_line is not None else None,
            end_line=int(end_line) if end_line is not None else None,
            function_name=get("function_name"),
            cwe_id=cwe_id,
            severity=severity,
            confidence=_parse_confidence(confidence),
            message=get("message"),
            rule_id=get("rule_id"),
            tool_name=get("tool_name"),
        )
