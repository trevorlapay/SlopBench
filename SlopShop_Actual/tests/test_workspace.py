"""Tests for workspace preparer."""

import json
from pathlib import Path

import pytest

from sastbench.models import GroundTruth, TestCase
from sastbench.workspace import (
    WorkspacePreparer,
    build_run_prompt,
    load_workspace_config,
    load_workspace_ground_truth,
)


@pytest.fixture
def sample_test_cases() -> list[TestCase]:
    return [
        TestCase(
            original_id="CWE79_XSS_01",
            original_path="testcases/CWE79/CWE79_XSS_01.c",
            code='void bad() { printf("%s", user_input); }',
            language="c",
        ),
        TestCase(
            original_id="CWE89_SQL_01",
            original_path="testcases/CWE89/CWE89_SQL_01.java",
            code='String q = "SELECT * FROM users WHERE id=" + input;',
            language="java",
        ),
        TestCase(
            original_id="CWE120_BUF_01",
            original_path="testcases/CWE120/CWE120_BUF_01.c",
            code="void bad() { char buf[10]; strcpy(buf, input); }",
            language="c",
        ),
    ]


@pytest.fixture
def sample_gts() -> list[GroundTruth]:
    return [
        GroundTruth(
            file_path="testcases/CWE79/CWE79_XSS_01.c",
            start_line=1,
            cwe_id="CWE-79",
            is_vulnerable=True,
            benchmark_name="juliet",
        ),
        GroundTruth(
            file_path="testcases/CWE89/CWE89_SQL_01.java",
            start_line=1,
            cwe_id="CWE-89",
            is_vulnerable=True,
            benchmark_name="juliet",
        ),
        GroundTruth(
            file_path="testcases/CWE120/CWE120_BUF_01.c",
            start_line=1,
            cwe_id="CWE-120",
            is_vulnerable=True,
            benchmark_name="juliet",
        ),
    ]


class TestWorkspacePreparer:
    def test_build_creates_workspace(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        assert ws.exists()
        assert (ws / "AGENTS.md").exists()
        assert (ws / "manifest.json").exists()
        assert (ws / "output_schema.json").exists()
        assert (ws / "code").is_dir()
        assert (ws / "output").is_dir()
        # GT should NOT be in workspace — it's in evaluator_data/
        assert not (ws / ".sastbench").exists()
        evaluator_dir = tmp_path / "evaluator_data" / "workspace"
        assert evaluator_dir.is_dir()
        assert (evaluator_dir / "ground_truth.json").exists()

    def test_neutral_file_naming(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        code_files = sorted((ws / "code").iterdir())
        assert len(code_files) == 3
        names = [f.name for f in code_files]
        # Files should be named sample_NNNN.ext with no CWE hints
        assert all(n.startswith("sample_") for n in names)
        # Should have 2 .c and 1 .java (order may vary due to shuffling)
        exts = sorted(f.suffix for f in code_files)
        assert exts == [".c", ".c", ".java"]

        # No CWE in filenames
        for name in names:
            assert "CWE" not in name
            assert "cwe" not in name

    def test_manifest_has_no_cwe_info(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        manifest = json.loads((ws / "manifest.json").read_text())
        assert manifest["total_files"] == 3
        for f in manifest["files"]:
            assert "cwe" not in f["path"].lower()
            assert "language" in f
            assert "cwe" not in json.dumps(f).lower()

    def test_ground_truth_uses_neutral_paths(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        gts = load_workspace_ground_truth(ws)
        assert len(gts) == 3
        for gt in gts:
            assert gt.file_path.startswith("code/sample_")
            assert "CWE" not in gt.file_path

    def test_file_mapping_preserved(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        evaluator_dir = tmp_path / "evaluator_data" / "workspace"
        mapping = json.loads((evaluator_dir / "file_mapping.json").read_text())
        assert len(mapping) == 3
        first_key = list(mapping.keys())[0]
        assert mapping[first_key]["benchmark"] == "juliet"
        assert "original_id" in mapping[first_key]
        assert "opaque_id" in mapping[first_key]
        # original_path should NOT be in mapping (prevents index-based gaming)
        assert "original_path" not in mapping[first_key]

    def test_config_saved(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        config = load_workspace_config(ws)
        assert config["benchmark"] == "juliet"
        assert config["total_test_cases"] == 3
        assert config["total_ground_truths"] == 3

    def test_no_gt_in_workspace(self, tmp_path, sample_test_cases, sample_gts):
        """Ground truth must NOT be inside the workspace (agents could read it)."""
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        # No .SASTBench, no ground_truth.json anywhere in workspace
        assert not (ws / ".sastbench").exists()
        for f in ws.rglob("ground_truth*"):
            assert False, f"Ground truth file found in workspace: {f}"
        for f in ws.rglob("file_mapping*"):
            assert False, f"File mapping found in workspace: {f}"

    def test_copilot_instructions(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        assert (ws / ".github" / "copilot-instructions.md").exists()
        content = (ws / ".github" / "copilot-instructions.md").read_text()
        assert "AGENTS.md" in content

    def test_agents_md_content(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        agents_md = (ws / "AGENTS.md").read_text()
        assert "Reading Input" in agents_md
        assert "Writing Output" in agents_md
        assert "output/findings.json" in agents_md
        # Should NOT contain any vulnerability hints
        assert "vulnerability" not in agents_md.lower().split("cwe")[0][:50]

    def test_empty_test_cases(self, tmp_path):
        preparer = WorkspacePreparer()
        ws = preparer.build([], [], tmp_path / "workspace", "empty")

        assert ws.exists()
        assert len(list((ws / "code").iterdir())) == 0


class TestLoadWorkspaceGroundTruth:
    def test_missing_workspace(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_workspace_ground_truth(tmp_path / "nonexistent")

    def test_roundtrip(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(sample_test_cases, sample_gts, tmp_path / "workspace", "juliet")

        loaded = load_workspace_ground_truth(ws)
        assert len(loaded) == len(sample_gts)
        # CWE IDs should be preserved
        cwe_ids = {gt.cwe_id for gt in loaded}
        assert "CWE-79" in cwe_ids
        assert "CWE-89" in cwe_ids


class TestPromptTemplateSaving:
    """Tests for prompt template persistence in evaluator data."""

    def test_prompt_saved_to_evaluator_data(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
            prompt_template="selective",
        )
        evaluator_dir = tmp_path / "evaluator_data" / "workspace"
        prompt_path = evaluator_dir / "prompt.txt"
        assert prompt_path.exists()
        content = prompt_path.read_text(encoding="utf-8")
        assert len(content) > 0
        assert "security" in content.lower() or "vulnerab" in content.lower()

    def test_config_includes_prompt_template(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
            prompt_template="thorough",
        )
        config = load_workspace_config(ws)
        assert config["prompt_template"] == "thorough"

    def test_default_prompt_template(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
        )
        config = load_workspace_config(ws)
        assert config["prompt_template"] == "selective"


class TestBuildRunPrompt:
    """Tests for the build_run_prompt helper."""

    def test_basic_prompt_generation(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
        )
        prompt = build_run_prompt(ws, agent_name="TestAgent")
        # Should contain analysis instructions
        assert "vulnerab" in prompt.lower() or "security" in prompt.lower()
        # Should contain workspace instructions
        assert "AGENTS.md" in prompt
        assert "TestAgent" in prompt
        # Should contain a findings.json path
        assert "findings.json" in prompt

    def test_custom_output_dir(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
        )
        prompt = build_run_prompt(ws, agent_name="Test", output_dir="output_custom")
        assert "output_custom/findings.json" in prompt

    def test_default_output_dir_slug(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
        )
        prompt = build_run_prompt(ws, agent_name="Sonnet 4.6")
        assert "output_sonnet_46/findings.json" in prompt

    def test_override_prompt_template(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
            prompt_template="minimal",
        )
        prompt = build_run_prompt(ws, agent_name="Test", prompt_template="thorough")
        # Should use the override, not saved template
        from sastbench.prompt_templates import get_prompt_template
        thorough_text = get_prompt_template("thorough")
        assert thorough_text.strip().splitlines()[0] in prompt

    def test_uses_saved_template_by_default(self, tmp_path, sample_test_cases, sample_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            sample_test_cases, sample_gts, tmp_path / "workspace", "juliet",
            prompt_template="minimal",
        )
        prompt = build_run_prompt(ws, agent_name="Test")
        from sastbench.prompt_templates import get_prompt_template
        minimal_text = get_prompt_template("minimal")
        assert minimal_text.strip().splitlines()[0] in prompt

    def test_missing_workspace_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            build_run_prompt(tmp_path / "nonexistent", agent_name="Test")
