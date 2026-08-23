"""Tests for function-level matching."""

import pytest

from sastbench.models import Finding, GroundTruth, MatchingConfig, MatchGranularity
from sastbench.matching.function_matcher import function_matches


def _finding(
    path: str = "src/app.py",
    cwe: str | None = "CWE-79",
    func: str | None = "handle_input",
) -> Finding:
    return Finding(file_path=path, cwe_id=cwe, function_name=func)


def _gt(
    path: str = "src/app.py",
    cwe: str = "CWE-79",
    func: str | None = "handle_input",
) -> GroundTruth:
    return GroundTruth(file_path=path, cwe_id=cwe, function_name=func)


def _config(require_cwe: bool = True) -> MatchingConfig:
    return MatchingConfig(granularity=MatchGranularity.FUNCTION, require_cwe_match=require_cwe)


class TestFunctionMatches:
    def test_same_file_same_function(self):
        assert function_matches(_finding(), _gt(), _config())

    def test_same_file_different_function(self):
        assert not function_matches(_finding(func="other"), _gt(), _config())

    def test_different_file_same_function(self):
        assert not function_matches(_finding(path="other.py"), _gt(), _config())

    def test_finding_no_function_falls_back_to_file(self):
        """When finding has no function name, fall back to file-level."""
        assert function_matches(_finding(func=None), _gt(), _config())

    def test_gt_no_function_falls_back_to_file(self):
        """When GT has no function name, fall back to file-level."""
        assert function_matches(_finding(), _gt(func=None), _config())

    def test_both_no_function_falls_back_to_file(self):
        assert function_matches(_finding(func=None), _gt(func=None), _config())

    def test_cwe_mismatch_blocks(self):
        assert not function_matches(_finding(cwe="CWE-89"), _gt(), _config())

    def test_cwe_not_required(self):
        cfg = _config(require_cwe=False)
        assert function_matches(_finding(cwe="CWE-89"), _gt(), cfg)
