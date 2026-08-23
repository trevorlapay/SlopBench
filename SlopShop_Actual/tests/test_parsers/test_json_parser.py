"""Tests for the generic JSON parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastbench.models import Severity
from sastbench.parsers.json_parser import JsonParser

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"


class TestJsonParserCanParse:
    def test_json_extension(self, tmp_path: Path):
        p = tmp_path / "data.json"
        p.touch()
        assert JsonParser().can_parse(p)

    def test_csv_rejected(self, tmp_path: Path):
        p = tmp_path / "data.csv"
        p.touch()
        assert not JsonParser().can_parse(p)


class TestJsonParserDefaultMapping:
    def test_agent_b_fixture(self):
        findings = JsonParser().parse(FIXTURES / "agent_output" / "agent_b.json")
        assert len(findings) == 3
        f0 = findings[0]
        assert f0.file_path == "src/api/endpoint.py"
        assert f0.cwe_id == "CWE-89"
        assert f0.severity == Severity.HIGH
        assert f0.confidence == 0.92
        assert f0.tool_name == "AgentBeta"

    def test_critical_severity(self):
        findings = JsonParser().parse(FIXTURES / "agent_output" / "agent_b.json")
        assert findings[1].severity == Severity.CRITICAL


class TestJsonParserCustomMapping:
    def test_nested_field_mapping(self, tmp_path: Path):
        data = {
            "results": [
                {
                    "location": {"file": "src/app.py", "line": 10},
                    "vuln": {"cwe": "79", "sev": "warning"},
                    "desc": "XSS found",
                }
            ]
        }
        p = tmp_path / "custom.json"
        p.write_text(json.dumps(data))

        parser = JsonParser(
            field_mapping={
                "file_path": "location.file",
                "start_line": "location.line",
                "cwe_id": "vuln.cwe",
                "severity": "vuln.sev",
                "message": "desc",
            },
            root_key="results",
        )
        findings = parser.parse(p)
        assert len(findings) == 1
        assert findings[0].file_path == "src/app.py"
        assert findings[0].cwe_id == "CWE-79"
        assert findings[0].severity == Severity.MEDIUM  # "warning" → medium

    def test_root_key_none_uses_top_level_list(self, tmp_path: Path):
        data = [{"file_path": "a.py", "start_line": 1}]
        p = tmp_path / "flat.json"
        p.write_text(json.dumps(data))
        findings = JsonParser(root_key=None).parse(p)
        assert len(findings) == 1

    def test_missing_root_key_returns_empty(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text(json.dumps({"other": []}))
        assert JsonParser().parse(p) == []

    def test_missing_file_path_skipped(self, tmp_path: Path):
        data = {"findings": [{"cwe_id": "CWE-79", "severity": "high"}]}
        p = tmp_path / "nopath.json"
        p.write_text(json.dumps(data))
        assert JsonParser().parse(p) == []


class TestJsonParserNormalization:
    def test_path_normalization(self, tmp_path: Path):
        data = {"findings": [{"file_path": "./src\\app.py", "start_line": 1}]}
        p = tmp_path / "paths.json"
        p.write_text(json.dumps(data))
        findings = JsonParser().parse(p)
        assert findings[0].file_path == "src/app.py"

    def test_cwe_normalization(self, tmp_path: Path):
        data = {"findings": [{"file_path": "a.py", "cwe_id": "cwe_79"}]}
        p = tmp_path / "cwe.json"
        p.write_text(json.dumps(data))
        findings = JsonParser().parse(p)
        assert findings[0].cwe_id == "CWE-79"
