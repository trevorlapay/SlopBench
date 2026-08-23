"""Tests for the gt-quality CLI command."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from sastbench.cli import cli


def _build_workspace(tmp_path, *, gt_entries, code_files, agent_outputs=None):
    """Helper: create a minimal workspace + evaluator_data structure.

    Args:
        gt_entries: list of dicts with file_path, is_vulnerable (and optional cwe_id)
        code_files: dict mapping filename -> content (placed under code/)
        agent_outputs: dict mapping agent_name -> list of file_paths they flagged
    """
    ws = tmp_path / "workspace"
    ws.mkdir()
    code_dir = ws / "code"
    code_dir.mkdir()
    for name, content in code_files.items():
        (code_dir / name).write_text(content, encoding="utf-8")

    # Evaluator data (outside workspace)
    ev = tmp_path / "evaluator_data" / "workspace"
    ev.mkdir(parents=True)
    (ev / "ground_truth.json").write_text(
        json.dumps(gt_entries), encoding="utf-8"
    )
    (ev / "config.json").write_text(
        json.dumps({"benchmark": "test", "total_test_cases": len(code_files)}),
        encoding="utf-8",
    )
    (ev / "file_mapping.json").write_text("{}", encoding="utf-8")

    # Agent outputs
    if agent_outputs:
        for agent_name, flagged_paths in agent_outputs.items():
            out_dir = ws / f"output_agent_{agent_name}"
            out_dir.mkdir()
            findings = [
                {"file_path": fp, "message": "vuln found"}
                for fp in flagged_paths
            ]
            (out_dir / "findings.json").write_text(
                json.dumps({"agent_name": agent_name, "findings": findings}),
                encoding="utf-8",
            )

    return ws


class TestGtQualityCommand:
    """Test suite for SASTBench gt-quality."""

    def test_no_evaluator_data(self, tmp_path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert "No evaluator data found" in result.output

    def test_no_agent_outputs(self, tmp_path):
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": False},
            ],
            code_files={
                "sample_0001.c": "void bad() { char buf[10]; gets(buf); }\n",
                "sample_0002.c": "void good() { return 0; }\n",
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "No agent outputs found" in result.output
        assert "Skipped" in result.output

    def test_suspect_safe_labels(self, tmp_path):
        """When 2+ agents flag a 'safe' file, it should be suspect."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": False},
            ],
            code_files={
                "sample_0001.c": "void bad() { char buf[10]; gets(buf); }\nvoid x() {}\nvoid y() {}\n",
                "sample_0002.c": "void mislabeled() { system(input); }\nvoid a() {}\nvoid b() {}\n",
            },
            agent_outputs={
                "alpha": ["code/sample_0001.c", "code/sample_0002.c"],
                "beta": ["code/sample_0001.c", "code/sample_0002.c"],
                "gamma": ["code/sample_0001.c"],
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "sample_0002.c" in result.output
        assert "1 suspect files out of 1 safe files" in result.output

    def test_no_suspect_safe_labels(self, tmp_path):
        """When only 1 agent flags a safe file, it's NOT suspect."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": False},
            ],
            code_files={
                "sample_0001.c": "void bad() { char buf[10]; gets(buf); }\nvoid x() {}\nvoid y() {}\n",
                "sample_0002.c": "void good() { return 0; }\nvoid a() {}\nvoid b() {}\n",
            },
            agent_outputs={
                "alpha": ["code/sample_0001.c", "code/sample_0002.c"],
                "beta": ["code/sample_0001.c"],
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "No suspect safe labels found" in result.output

    def test_suspect_vulnerable_labels(self, tmp_path):
        """When zero agents flag a 'vulnerable' file, it should be suspect."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": True},
            ],
            code_files={
                "sample_0001.c": "void bad() { char buf[10]; gets(buf); }\nvoid x() {}\nvoid y() {}\n",
                "sample_0002.c": "// just a refactoring patch\nvoid clean() { return 0; }\nvoid a() {}\n",
            },
            agent_outputs={
                "alpha": ["code/sample_0001.c"],
                "beta": ["code/sample_0001.c"],
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "sample_0002.c" in result.output
        assert "0/2 agents flagged it" in result.output
        assert "1 suspect files out of 2 vulnerable files" in result.output

    def test_no_suspect_vulnerable_labels(self, tmp_path):
        """When at least one agent flags each vuln file, no suspects."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
            ],
            code_files={
                "sample_0001.c": "void bad() { char buf[10]; gets(buf); }\nvoid x() {}\nvoid y() {}\n",
            },
            agent_outputs={
                "alpha": ["code/sample_0001.c"],
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "No suspect vulnerable labels found" in result.output

    def test_trivial_files(self, tmp_path):
        """Files with < 3 lines should be flagged as trivial."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": False},
            ],
            code_files={
                "sample_0001.c": "x",  # 1 line, < 50 chars
                "sample_0002.c": "void good() { return 0; }\nint main() { good(); }\nint helper() { return 1; }\n",
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "sample_0001.c" in result.output
        assert "1 line" in result.output
        assert "1 trivial files" in result.output

    def test_no_trivial_files(self, tmp_path):
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
            ],
            code_files={
                "sample_0001.c": "void bad() { char buf[10]; gets(buf); }\nint main() { bad(); }\nint x() { return 0; }\n",
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "No trivial files found" in result.output

    def test_near_duplicates(self, tmp_path):
        """Files with identical first-500-char hash should be flagged."""
        same_content = "void func() { int x = 0; return x; }\nint main() { func(); }\nint y() { return 1; }\n"
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": False},
                {"file_path": "code/sample_0003.c", "is_vulnerable": True},
            ],
            code_files={
                "sample_0001.c": same_content,
                "sample_0002.c": same_content,
                "sample_0003.c": "void unique() { different(); }\nint a() {}\nint b() {}\n",
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "sample_0001.c" in result.output
        assert "sample_0002.c" in result.output
        assert "1 duplicate groups" in result.output

    def test_no_near_duplicates(self, tmp_path):
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": False},
            ],
            code_files={
                "sample_0001.c": "void bad() { gets(buf); }\nint main() {}\nint x() {}\n",
                "sample_0002.c": "void good() { return 0; }\nint main() {}\nint x() {}\n",
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "No near-duplicates found" in result.output

    def test_adjusted_scores(self, tmp_path):
        """Check 5 should show raw vs adjusted metrics in a table."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
                {"file_path": "code/sample_0002.c", "is_vulnerable": False},
                {"file_path": "code/sample_0003.c", "is_vulnerable": True},
            ],
            code_files={
                "sample_0001.c": "void bad1() { gets(buf); }\nint a() {}\nint b() {}\n",
                "sample_0002.c": "void mislabeled() { system(input); }\nint a() {}\nint b() {}\n",
                "sample_0003.c": "// just cleanup\nvoid clean() { return; }\nint a() {}\n",
            },
            agent_outputs={
                "alpha": ["code/sample_0001.c", "code/sample_0002.c"],
                "beta": ["code/sample_0001.c", "code/sample_0002.c"],
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        # Check 5 table should contain agent names and metric columns
        assert "Raw vs Adjusted" in result.output
        assert "alpha" in result.output
        assert "beta" in result.output
        assert "Adj P" in result.output

    def test_no_adjustments_needed(self, tmp_path):
        """When no suspect labels, adjusted scores section says so."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
            ],
            code_files={
                "sample_0001.c": "void bad() { gets(buf); }\nint a() {}\nint b() {}\n",
            },
            agent_outputs={
                "alpha": ["code/sample_0001.c"],
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "raw and adjusted scores are identical" in result.output

    def test_all_five_checks_present(self, tmp_path):
        """All 5 check headers should appear in output."""
        ws = _build_workspace(
            tmp_path,
            gt_entries=[
                {"file_path": "code/sample_0001.c", "is_vulnerable": True},
            ],
            code_files={
                "sample_0001.c": "void bad() { gets(buf); }\nint a() {}\nint b() {}\n",
            },
            agent_outputs={
                "alpha": ["code/sample_0001.c"],
            },
        )
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", str(ws)])
        assert result.exit_code == 0
        assert "Check 1" in result.output
        assert "Check 2" in result.output
        assert "Check 3" in result.output
        assert "Check 4" in result.output
        assert "Check 5" in result.output

    def test_nonexistent_workspace(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["gt-quality", "/nonexistent/path"])
        assert result.exit_code != 0
