"""Tests for line-level matching."""

import pytest

from sastbench.models import Finding, GroundTruth, MatchingConfig, MatchGranularity
from sastbench.matching.line_matcher import line_matches


def _finding(
    path: str = "src/app.py",
    cwe: str | None = "CWE-79",
    line: int | None = 10,
) -> Finding:
    return Finding(file_path=path, cwe_id=cwe, start_line=line)


def _gt(
    path: str = "src/app.py",
    cwe: str = "CWE-79",
    line: int | None = 10,
) -> GroundTruth:
    return GroundTruth(file_path=path, cwe_id=cwe, start_line=line)


def _config(tolerance: int = 3, require_cwe: bool = True) -> MatchingConfig:
    return MatchingConfig(
        granularity=MatchGranularity.LINE,
        line_tolerance=tolerance,
        require_cwe_match=require_cwe,
    )


class TestLineMatches:
    def test_exact_same_line(self):
        assert line_matches(_finding(), _gt(), _config())

    def test_within_tolerance(self):
        assert line_matches(_finding(line=12), _gt(line=10), _config(tolerance=3))

    def test_at_boundary(self):
        """Exactly at tolerance boundary should match."""
        assert line_matches(_finding(line=13), _gt(line=10), _config(tolerance=3))

    def test_just_outside_boundary(self):
        """One line past tolerance boundary should not match."""
        assert not line_matches(_finding(line=14), _gt(line=10), _config(tolerance=3))

    def test_negative_direction(self):
        assert line_matches(_finding(line=7), _gt(line=10), _config(tolerance=3))

    def test_negative_at_boundary(self):
        assert line_matches(_finding(line=7), _gt(line=10), _config(tolerance=3))

    def test_negative_just_outside(self):
        assert not line_matches(_finding(line=6), _gt(line=10), _config(tolerance=3))

    def test_zero_tolerance_exact(self):
        assert line_matches(_finding(line=10), _gt(line=10), _config(tolerance=0))

    def test_zero_tolerance_off_by_one(self):
        assert not line_matches(_finding(line=11), _gt(line=10), _config(tolerance=0))

    def test_finding_no_line_falls_back_to_file(self):
        assert line_matches(_finding(line=None), _gt(line=10), _config())

    def test_gt_no_line_falls_back_to_file(self):
        assert line_matches(_finding(line=10), _gt(line=None), _config())

    def test_both_no_line_falls_back_to_file(self):
        assert line_matches(_finding(line=None), _gt(line=None), _config())

    def test_different_file(self):
        assert not line_matches(_finding(path="other.py"), _gt(), _config())

    def test_cwe_mismatch(self):
        assert not line_matches(_finding(cwe="CWE-89"), _gt(), _config())

    def test_cwe_not_required(self):
        cfg = _config(require_cwe=False)
        assert line_matches(_finding(cwe="CWE-89"), _gt(), cfg)
