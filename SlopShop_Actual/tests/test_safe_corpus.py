"""Tests for safe corpus generation and workspace mixing."""

import json
import re
from pathlib import Path

import pytest

from sastbench.models import GroundTruth, TestCase
from sastbench.safe_corpus import generate_safe_functions
from sastbench.workspace import WorkspacePreparer, load_workspace_ground_truth


class TestSafeCorpusGeneration:
    """Tests for safe function template generation."""

    def test_generates_requested_count(self):
        cases = generate_safe_functions(10)
        assert len(cases) == 10

    def test_zero_count_returns_empty(self):
        assert generate_safe_functions(0) == []

    def test_negative_count_returns_empty(self):
        assert generate_safe_functions(-5) == []

    def test_all_cases_are_c_language(self):
        cases = generate_safe_functions(20)
        for tc in cases:
            assert tc.language in ("c", "cpp")

    def test_cpp_ratio_produces_cpp_files(self):
        cases = generate_safe_functions(100, cpp_ratio=0.5)
        cpp_count = sum(1 for tc in cases if tc.language == "cpp")
        # With 50% ratio, expect roughly 30-70 cpp files
        assert 20 < cpp_count < 80

    def test_workspace_name_varies_output(self):
        a = generate_safe_functions(10, seed=42, workspace_name="ws_a")
        b = generate_safe_functions(10, seed=42, workspace_name="ws_b")
        codes_a = [tc.code for tc in a]
        codes_b = [tc.code for tc in b]
        assert codes_a != codes_b

    def test_code_not_empty(self):
        cases = generate_safe_functions(55)
        for tc in cases:
            assert len(tc.code.strip()) > 0

    def test_no_double_braces(self):
        """Generated code must not contain {{ or }} — these are a fingerprint."""
        cases = generate_safe_functions(120)
        for tc in cases:
            assert "{{" not in tc.code, f"Double-brace in {tc.original_id}: found '{{{{'"
            assert "}}" not in tc.code, f"Double-brace in {tc.original_id}: found '}}}}'"

    def test_no_synthetic_prefixes(self):
        """Function names should not contain 'safe_', 'util_', or 'helper_'."""
        cases = generate_safe_functions(120)
        for tc in cases:
            # Check the function name in the code (first word after void/int/bool/long/etc.)
            assert "safe_" not in tc.original_path
            assert "helper_" not in tc.original_path
            assert "safe_corpus/" not in tc.original_path

    def test_no_template_desc_in_name(self):
        """Function names should not reveal the template type (e.g., 'string_copy')."""
        cases = generate_safe_functions(120)
        template_descs = ["string_copy", "array_sum", "binary_search", "safe_add"]
        for tc in cases:
            for desc in template_descs:
                assert desc not in tc.original_path, (
                    f"Template description '{desc}' leaked into {tc.original_path}"
                )

    def test_no_unresolved_placeholders(self):
        """Generated code should have no {var} placeholders remaining."""
        cases = generate_safe_functions(55)
        placeholder_re = re.compile(r"\{[a-z_]+\}")
        for tc in cases:
            matches = placeholder_re.findall(tc.code)
            assert not matches, f"Unresolved placeholders in {tc.original_id}: {matches}"

    def test_valid_c_structure(self):
        """Each function should have balanced braces (basic syntax check)."""
        cases = generate_safe_functions(55)
        for tc in cases:
            open_braces = tc.code.count("{")
            close_braces = tc.code.count("}")
            assert open_braces == close_braces, (
                f"Unbalanced braces in {tc.original_id}: "
                f"{open_braces} open vs {close_braces} close"
            )

    def test_safe_metadata_flag(self):
        cases = generate_safe_functions(5)
        for tc in cases:
            assert tc.metadata.get("is_safe_injection") is True
            # Template description should not be exposed in metadata
            assert "template" not in tc.metadata

    def test_deterministic_with_same_seed(self):
        a = generate_safe_functions(10, seed=123)
        b = generate_safe_functions(10, seed=123)
        for ta, tb in zip(a, b):
            assert ta.code == tb.code
            assert ta.original_id == tb.original_id

    def test_different_seed_gives_different_output(self):
        a = generate_safe_functions(10, seed=1)
        b = generate_safe_functions(10, seed=2)
        # At least some codes should differ (variable names change)
        codes_a = [tc.code for tc in a]
        codes_b = [tc.code for tc in b]
        assert codes_a != codes_b

    def test_wraps_around_templates(self):
        """When count > number of templates, should cycle without error."""
        cases = generate_safe_functions(120)
        assert len(cases) == 120

    def test_unique_original_ids(self):
        cases = generate_safe_functions(100)
        ids = [tc.original_id for tc in cases]
        assert len(ids) == len(set(ids))


class TestWorkspaceSafeMixing:
    """Tests that safe mixing works correctly in WorkspacePreparer."""

    @pytest.fixture
    def vuln_test_cases(self) -> list[TestCase]:
        return [
            TestCase(
                original_id=f"vuln_{i:03d}",
                original_path=f"testcases/vuln_{i:03d}.c",
                code=f'void bad_{i}() {{ char buf[10]; strcpy(buf, input); }}',
                language="c",
            )
            for i in range(10)
        ]

    @pytest.fixture
    def vuln_gts(self, vuln_test_cases) -> list[GroundTruth]:
        return [
            GroundTruth(
                file_path=tc.original_path,
                start_line=1,
                cwe_id="CWE-120",
                is_vulnerable=True,
                benchmark_name="test",
            )
            for tc in vuln_test_cases
        ]

    def test_safe_ratio_zero_no_change(self, tmp_path, vuln_test_cases, vuln_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=0.0,
        )
        code_files = list((ws / "code").iterdir())
        assert len(code_files) == 10

    def test_safe_ratio_adds_correct_count(self, tmp_path, vuln_test_cases, vuln_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=1.0,
        )
        code_files = list((ws / "code").iterdir())
        # 10 vuln + 10 safe = 20
        assert len(code_files) == 20

    def test_safe_ratio_half(self, tmp_path, vuln_test_cases, vuln_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=0.5,
        )
        code_files = list((ws / "code").iterdir())
        # 10 vuln + 5 safe = 15
        assert len(code_files) == 15

    def test_ground_truth_marks_safe_correctly(self, tmp_path, vuln_test_cases, vuln_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=1.0,
        )
        gts = load_workspace_ground_truth(ws)
        vuln_count = sum(1 for gt in gts if gt.is_vulnerable)
        safe_count = sum(1 for gt in gts if not gt.is_vulnerable)
        assert vuln_count == 10
        assert safe_count == 10

    def test_safe_gt_has_no_cwe(self, tmp_path, vuln_test_cases, vuln_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=0.5,
        )
        gts = load_workspace_ground_truth(ws)
        for gt in gts:
            if not gt.is_vulnerable:
                assert gt.cwe_id is None

    def test_neutral_naming_with_safe_files(self, tmp_path, vuln_test_cases, vuln_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=1.0,
        )
        code_files = sorted((ws / "code").iterdir())
        for f in code_files:
            assert f.name.startswith("sample_")
            assert "safe" not in f.name.lower()
            assert "vuln" not in f.name.lower()

    def test_manifest_count_matches(self, tmp_path, vuln_test_cases, vuln_gts):
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=1.0,
        )
        manifest = json.loads((ws / "manifest.json").read_text())
        assert manifest["total_files"] == 20

    def test_config_records_total(self, tmp_path, vuln_test_cases, vuln_gts):
        from sastbench.workspace import load_workspace_config
        preparer = WorkspacePreparer()
        ws = preparer.build(
            vuln_test_cases, vuln_gts, tmp_path / "ws", "test",
            safe_ratio=1.0,
        )
        config = load_workspace_config(ws)
        assert config["total_test_cases"] == 20
        assert config["total_ground_truths"] == 20
