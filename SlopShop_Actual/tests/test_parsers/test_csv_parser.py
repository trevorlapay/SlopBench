"""Tests for the CSV parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastbench.models import Severity
from sastbench.parsers.csv_parser import CsvParser


class TestCsvParserCanParse:
    def test_csv_extension(self, tmp_path: Path):
        p = tmp_path / "data.csv"
        p.touch()
        assert CsvParser().can_parse(p)

    def test_json_rejected(self, tmp_path: Path):
        p = tmp_path / "data.json"
        p.touch()
        assert not CsvParser().can_parse(p)


class TestCsvParserDefaultMapping:
    def test_basic_csv(self, tmp_path: Path):
        csv_content = (
            "file_path,start_line,end_line,cwe_id,severity,message,rule_id,tool_name\n"
            "src/app.py,10,15,CWE-89,high,SQL injection,SQL001,Scanner\n"
            "src/web.py,20,,CWE-79,medium,XSS found,XSS001,Scanner\n"
        )
        p = tmp_path / "findings.csv"
        p.write_text(csv_content)
        findings = CsvParser().parse(p)
        assert len(findings) == 2

        f0 = findings[0]
        assert f0.file_path == "src/app.py"
        assert f0.start_line == 10
        assert f0.end_line == 15
        assert f0.cwe_id == "CWE-89"
        assert f0.severity == Severity.HIGH
        assert f0.tool_name == "Scanner"

        f1 = findings[1]
        assert f1.end_line is None
        assert f1.severity == Severity.MEDIUM


class TestCsvParserCustomMapping:
    def test_custom_columns(self, tmp_path: Path):
        csv_content = (
            "path,line,weakness,level\n"
            "lib/io.py,5,CWE-22,error\n"
        )
        p = tmp_path / "custom.csv"
        p.write_text(csv_content)
        parser = CsvParser(column_mapping={
            "file_path": "path",
            "start_line": "line",
            "cwe_id": "weakness",
            "severity": "level",
        })
        findings = parser.parse(p)
        assert len(findings) == 1
        assert findings[0].file_path == "lib/io.py"
        assert findings[0].cwe_id == "CWE-22"
        assert findings[0].severity == Severity.HIGH  # "error" → high


class TestCsvParserEdgeCases:
    def test_missing_file_path_skipped(self, tmp_path: Path):
        csv_content = "file_path,cwe_id\n,CWE-79\n"
        p = tmp_path / "nofp.csv"
        p.write_text(csv_content)
        assert CsvParser().parse(p) == []

    def test_empty_csv(self, tmp_path: Path):
        p = tmp_path / "empty.csv"
        p.write_text("file_path,cwe_id\n")
        assert CsvParser().parse(p) == []

    def test_cwe_normalization(self, tmp_path: Path):
        csv_content = "file_path,cwe_id\na.py,79\n"
        p = tmp_path / "cwe.csv"
        p.write_text(csv_content)
        findings = CsvParser().parse(p)
        assert findings[0].cwe_id == "CWE-79"

    def test_path_normalization(self, tmp_path: Path):
        csv_content = "file_path,start_line\n./src\\app.py,1\n"
        p = tmp_path / "paths.csv"
        p.write_text(csv_content)
        findings = CsvParser().parse(p)
        assert findings[0].file_path == "src/app.py"

    def test_confidence_parsing(self, tmp_path: Path):
        csv_content = "file_path,confidence\napp.py,0.95\n"
        p = tmp_path / "conf.csv"
        p.write_text(csv_content)
        findings = CsvParser().parse(p)
        assert findings[0].confidence == 0.95
