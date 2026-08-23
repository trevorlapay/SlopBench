"""Tests for custom ground truth adapter."""

import json
import csv
from pathlib import Path

import pytest

from sastbench.adapters.custom import CustomAdapter


@pytest.fixture
def json_ground_truth(tmp_path) -> Path:
    data = {
        "ground_truths": [
            {"file_path": "code/a.c", "cwe_id": "CWE-79", "start_line": 10, "is_vulnerable": True},
            {"file_path": "code/b.c", "cwe_id": "CWE-89", "start_line": 20, "is_vulnerable": True},
            {"file_path": "code/c.c", "cwe_id": "CWE-79", "start_line": 5, "is_vulnerable": False},
        ],
        "test_cases": [
            {"original_id": "tc1", "code": "void bad() {}", "language": "c"},
            {"original_id": "tc2", "code": "String q = input;", "language": "java"},
        ],
    }
    path = tmp_path / "custom.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def csv_ground_truth(tmp_path) -> Path:
    path = tmp_path / "custom.csv"
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file_path", "cwe_id", "start_line", "is_vulnerable"])
        writer.writerow(["code/a.c", "CWE-79", "10", "true"])
        writer.writerow(["code/b.c", "CWE-89", "20", "true"])
        writer.writerow(["code/c.c", "CWE-120", "5", "false"])
    return path


class TestCustomAdapter:
    def test_json_extraction(self, json_ground_truth):
        adapter = CustomAdapter()
        test_cases, gts = adapter.extract(json_ground_truth)
        assert len(test_cases) == 2
        assert len(gts) == 3
        assert gts[0].cwe_id == "CWE-79"
        assert gts[1].cwe_id == "CWE-89"

    def test_csv_extraction(self, csv_ground_truth):
        adapter = CustomAdapter()
        test_cases, gts = adapter.extract(csv_ground_truth)
        assert len(test_cases) == 0  # CSV only has ground truths
        assert len(gts) == 3
        assert gts[2].is_vulnerable is False

    def test_cwe_filter(self, json_ground_truth):
        adapter = CustomAdapter()
        _, gts = adapter.extract(json_ground_truth, cwe_filter=["CWE-79"])
        assert len(gts) == 2  # Only CWE-79 entries

    def test_directory_with_json(self, tmp_path):
        data = {
            "ground_truths": [
                {"file_path": "code/a.c", "cwe_id": "CWE-79", "start_line": 10},
            ]
        }
        (tmp_path / "ground_truths.json").write_text(json.dumps(data))
        adapter = CustomAdapter()
        _, gts = adapter.extract(tmp_path)
        assert len(gts) == 1

    def test_missing_file(self, tmp_path):
        adapter = CustomAdapter()
        with pytest.raises(FileNotFoundError):
            adapter.extract(tmp_path / "nonexistent")

    def test_info(self):
        adapter = CustomAdapter()
        info = adapter.info()
        assert info["name"] == "custom"


class TestAdapterRegistry:
    def test_get_adapter(self):
        from sastbench.adapters import get_adapter
        adapter = get_adapter("custom")
        assert adapter.name == "custom"

    def test_get_adapter_unknown(self):
        from sastbench.adapters import get_adapter
        with pytest.raises(ValueError, match="Unknown benchmark"):
            get_adapter("nonexistent")

    def test_list_benchmarks(self):
        from sastbench.adapters import list_benchmarks
        benchmarks = list_benchmarks()
        assert len(benchmarks) >= 7
        names = [b["name"] for b in benchmarks]
        assert "juliet" in names
        assert "custom" in names
