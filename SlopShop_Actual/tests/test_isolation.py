"""Tests for workspace isolation utilities."""

import json
from pathlib import Path

import pytest

from sastbench.models import GroundTruth, TestCase
from sastbench.utils.isolation import (
    cleanup_isolated_workspace,
    copy_results_back,
    create_isolated_workspace,
)
from sastbench.workspace import WorkspacePreparer


@pytest.fixture
def prepared_workspace(tmp_path) -> Path:
    """Create a prepared workspace for testing isolation."""
    test_cases = [
        TestCase(
            original_id=f"tc_{i}",
            original_path=f"test/tc_{i}.c",
            code=f"void func_{i}() {{ return; }}",
            language="c",
        )
        for i in range(5)
    ]
    gts = [
        GroundTruth(
            file_path=tc.original_path,
            start_line=1,
            cwe_id="CWE-120",
            is_vulnerable=True,
            benchmark_name="test",
        )
        for tc in test_cases
    ]
    preparer = WorkspacePreparer()
    return preparer.build(test_cases, gts, tmp_path / "bigvul_workspace", "bigvul")


class TestCreateIsolatedWorkspace:
    def test_creates_isolated_copy(self, prepared_workspace, tmp_path):
        isolated = create_isolated_workspace(
            prepared_workspace, base_dir=tmp_path / "isolated"
        )
        try:
            assert isolated.exists()
            assert (isolated / "AGENTS.md").exists()
            assert (isolated / "code").is_dir()
            assert (isolated / "manifest.json").exists()
            assert (isolated / "output").is_dir()
        finally:
            cleanup_isolated_workspace(isolated)

    def test_no_gt_in_isolated(self, prepared_workspace, tmp_path):
        isolated = create_isolated_workspace(
            prepared_workspace, base_dir=tmp_path / "isolated"
        )
        try:
            assert not (isolated / ".sastbench").exists()
            for f in isolated.rglob("ground_truth*"):
                pytest.fail(f"Ground truth found in isolated workspace: {f}")
            for f in isolated.rglob("file_mapping*"):
                pytest.fail(f"File mapping found in isolated workspace: {f}")
        finally:
            cleanup_isolated_workspace(isolated)

    def test_neutral_directory_name(self, prepared_workspace, tmp_path):
        isolated = create_isolated_workspace(
            prepared_workspace, base_dir=tmp_path / "isolated"
        )
        try:
            # Name should not contain benchmark hints
            assert "bigvul" not in isolated.name.lower()
            assert "primevul" not in isolated.name.lower()
            assert isolated.name.startswith("workspace_")
        finally:
            cleanup_isolated_workspace(isolated)

    def test_parent_traversal_safe(self, prepared_workspace, tmp_path):
        isolated = create_isolated_workspace(
            prepared_workspace, base_dir=tmp_path / "isolated"
        )
        try:
            # Parent directory should not contain evaluator_data
            parent = isolated.parent
            assert not (parent / "evaluator_data").exists()
        finally:
            cleanup_isolated_workspace(isolated)

    def test_code_files_preserved(self, prepared_workspace, tmp_path):
        isolated = create_isolated_workspace(
            prepared_workspace, base_dir=tmp_path / "isolated"
        )
        try:
            orig_files = sorted(f.name for f in (prepared_workspace / "code").iterdir())
            iso_files = sorted(f.name for f in (isolated / "code").iterdir())
            assert orig_files == iso_files
        finally:
            cleanup_isolated_workspace(isolated)


class TestCopyResultsBack:
    def test_copies_findings(self, prepared_workspace, tmp_path):
        isolated = create_isolated_workspace(
            prepared_workspace, base_dir=tmp_path / "isolated"
        )
        try:
            # Simulate agent writing findings
            findings = {"findings": [{"file_path": "code/sample_0001.c", "start_line": 1, "cwe_id": "CWE-120"}]}
            (isolated / "output" / "findings.json").write_text(
                json.dumps(findings), encoding="utf-8"
            )

            copy_results_back(isolated, prepared_workspace)

            result = prepared_workspace / "output" / "findings.json"
            assert result.exists()
            loaded = json.loads(result.read_text())
            assert len(loaded["findings"]) == 1
        finally:
            cleanup_isolated_workspace(isolated)


class TestCleanup:
    def test_cleanup_removes_directory(self, prepared_workspace, tmp_path):
        isolated = create_isolated_workspace(
            prepared_workspace, base_dir=tmp_path / "isolated"
        )
        assert isolated.exists()
        cleanup_isolated_workspace(isolated)
        assert not isolated.exists()

    def test_cleanup_nonexistent_no_error(self, tmp_path):
        cleanup_isolated_workspace(tmp_path / "nonexistent")
