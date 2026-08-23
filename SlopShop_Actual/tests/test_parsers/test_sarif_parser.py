"""Tests for the SARIF parser."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from sastbench.models import Severity
from sastbench.parsers.sarif_parser import SarifParser

FIXTURES = Path(__file__).resolve().parent.parent.parent / "fixtures"


class TestSarifParserCanParse:
    def test_sarif_extension(self, tmp_path: Path):
        p = tmp_path / "results.sarif"
        p.touch()
        assert SarifParser().can_parse(p)

    def test_json_extension_rejected(self, tmp_path: Path):
        p = tmp_path / "results.json"
        p.touch()
        assert not SarifParser().can_parse(p)


class TestSarifParserSampleFixture:
    @pytest.fixture()
    def findings(self):
        return SarifParser().parse(FIXTURES / "sarif" / "sample.sarif")

    def test_count(self, findings):
        assert len(findings) == 4

    def test_sql_injection(self, findings):
        f = findings[0]
        assert f.rule_id == "SQL001"
        assert f.cwe_id == "CWE-89"
        assert f.file_path == "src/db/queries.py"
        assert f.start_line == 42
        assert f.end_line == 45
        assert f.severity == Severity.HIGH
        assert f.tool_name == "SampleScanner"

    def test_xss(self, findings):
        f = findings[1]
        assert f.cwe_id == "CWE-79"
        assert f.severity == Severity.MEDIUM
        assert f.end_line is None

    def test_path_traversal_cwe_from_result_properties(self, findings):
        f = findings[2]
        assert f.cwe_id == "CWE-22"
        assert f.file_path == "src/utils/file_handler.py"  # normalized

    def test_cwe_from_rule_id(self, findings):
        f = findings[3]
        assert f.cwe_id == "CWE-78"
        assert f.severity == Severity.HIGH


class TestSarifParserAgentA:
    def test_agent_a_parse(self):
        findings = SarifParser().parse(FIXTURES / "agent_output" / "agent_a.sarif")
        assert len(findings) == 2
        assert findings[0].cwe_id == "CWE-89"
        assert findings[0].tool_name == "AgentAlpha"
        assert findings[1].cwe_id == "CWE-798"


class TestSarifParserEdgeCases:
    def test_empty_results(self, tmp_path: Path):
        data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "X"}}, "results": []}]}
        p = tmp_path / "empty.sarif"
        p.write_text(json.dumps(data))
        assert SarifParser().parse(p) == []

    def test_missing_location_skips_result(self, tmp_path: Path):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "X"}},
                    "results": [
                        {"ruleId": "R1", "level": "error", "message": {"text": "no location"}},
                    ],
                }
            ],
        }
        p = tmp_path / "noloc.sarif"
        p.write_text(json.dumps(data))
        assert SarifParser().parse(p) == []

    def test_no_runs_key(self, tmp_path: Path):
        p = tmp_path / "noruns.sarif"
        p.write_text(json.dumps({"version": "2.1.0"}))
        assert SarifParser().parse(p) == []

    def test_missing_optional_fields(self, tmp_path: Path):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "T"}},
                    "results": [
                        {
                            "ruleId": "R1",
                            "message": {"text": "msg"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        p = tmp_path / "minimal.sarif"
        p.write_text(json.dumps(data))
        findings = SarifParser().parse(p)
        assert len(findings) == 1
        assert findings[0].severity is None
        assert findings[0].cwe_id is None
