"""Parser for SARIF 2.1.0 agent output files."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from sastbench.models import Finding, Severity
from sastbench.parsers.base import BaseParser
from sastbench.utils.cwe import normalize_cwe
from sastbench.utils.normalize import normalize_path, normalize_severity

logger = logging.getLogger(__name__)


class SarifParser(BaseParser):
    """Parse SARIF 2.1.0 JSON files into Finding objects."""

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() == ".sarif" or path.name.lower().endswith(".sarif.json")

    def parse(self, path: Path) -> list[Finding]:
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in SARIF file {path.name}: {exc}") from exc

        findings: list[Finding] = []
        for run in data.get("runs", []):
            tool_name = self._extract_tool_name(run)
            rules_map = self._build_rules_map(run)

            for result in run.get("results", []):
                try:
                    finding = self._parse_result(result, tool_name, rules_map)
                    if finding is not None:
                        findings.append(finding)
                except Exception:
                    logger.warning("Skipping malformed SARIF result", exc_info=True)
        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tool_name(run: dict) -> str | None:
        try:
            return run["tool"]["driver"]["name"]
        except (KeyError, TypeError):
            return None

    @staticmethod
    def _build_rules_map(run: dict) -> dict[str, dict]:
        """Build a lookup from ruleId → rule descriptor."""
        rules: dict[str, dict] = {}
        try:
            for rule in run["tool"]["driver"].get("rules", []):
                rid = rule.get("id")
                if rid:
                    rules[rid] = rule
        except (KeyError, TypeError):
            pass
        return rules

    def _parse_result(
        self, result: dict, tool_name: str | None, rules_map: dict[str, dict]
    ) -> Finding | None:
        rule_id = result.get("ruleId")
        message = self._extract_message(result)
        file_path, start_line, end_line = self._extract_location(result)

        if file_path is None:
            logger.warning("SARIF result missing file path, skipping")
            return None

        cwe_id = self._extract_cwe(result, rule_id, rules_map)
        severity = self._extract_severity(result)

        return Finding(
            file_path=normalize_path(file_path),
            start_line=start_line,
            end_line=end_line,
            cwe_id=cwe_id,
            severity=severity,
            message=message,
            rule_id=rule_id,
            tool_name=tool_name,
        )

    @staticmethod
    def _extract_message(result: dict) -> str | None:
        msg = result.get("message")
        if isinstance(msg, dict):
            return msg.get("text")
        return None

    @staticmethod
    def _extract_location(result: dict) -> tuple[str | None, int | None, int | None]:
        """Extract file path and line range from the first location.

        Only the first ``locations[]`` entry is used, which aligns with the
        SARIF spec's convention that the primary location is listed first.
        Additional locations (e.g. related code-flow steps) are ignored.
        """
        locations = result.get("locations", [])
        if not locations:
            return None, None, None
        phys = locations[0].get("physicalLocation", {})
        artifact = phys.get("artifactLocation", {})
        file_path = artifact.get("uri")
        region = phys.get("region", {})
        start_line = region.get("startLine")
        end_line = region.get("endLine")
        return file_path, start_line, end_line

    @staticmethod
    def _extract_cwe(
        result: dict, rule_id: str | None, rules_map: dict[str, dict]
    ) -> str | None:
        # 1. result.properties.cwe
        props = result.get("properties", {})
        if props:
            cwe_raw = props.get("cwe")
            if cwe_raw:
                val = cwe_raw if isinstance(cwe_raw, str) else str(cwe_raw[0]) if cwe_raw else None
                if val:
                    normalized = normalize_cwe(val)
                    if normalized:
                        return normalized

        # 2. rule.properties.cwe (from rules descriptor)
        if rule_id and rule_id in rules_map:
            rule_props = rules_map[rule_id].get("properties", {})
            cwe_raw = rule_props.get("cwe")
            if cwe_raw:
                val = cwe_raw if isinstance(cwe_raw, str) else str(cwe_raw[0]) if cwe_raw else None
                if val:
                    normalized = normalize_cwe(val)
                    if normalized:
                        return normalized

        # 3. ruleId itself if it looks like a CWE identifier
        if rule_id:
            if re.search(r"(?i)\bCWE[-_]?\d+\b", rule_id):
                normalized = normalize_cwe(rule_id)
                if normalized:
                    return normalized

        return None

    @staticmethod
    def _extract_severity(result: dict) -> Severity | None:
        level = result.get("level")
        if level is None:
            return None
        mapped = normalize_severity(level)
        if mapped is None:
            return None
        try:
            return Severity(mapped)
        except ValueError:
            logger.warning("Unknown severity level: %s", level)
            return None
