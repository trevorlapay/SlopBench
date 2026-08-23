"""Tests for file-level matching."""

import pytest

from sastbench.models import Finding, GroundTruth, MatchingConfig, MatchGranularity
from sastbench.matching.file_matcher import file_matches


def _finding(path: str = "src/app.py", cwe: str | None = "CWE-79") -> Finding:
    return Finding(file_path=path, cwe_id=cwe)


def _gt(path: str = "src/app.py", cwe: str = "CWE-79", vuln: bool = True) -> GroundTruth:
    return GroundTruth(file_path=path, cwe_id=cwe, is_vulnerable=vuln)


def _config(require_cwe: bool = True) -> MatchingConfig:
    return MatchingConfig(granularity=MatchGranularity.FILE, require_cwe_match=require_cwe)


class TestFileMatches:
    def test_same_file_same_cwe(self):
        assert file_matches(_finding(), _gt(), _config())

    def test_different_file(self):
        assert not file_matches(_finding("other.py"), _gt(), _config())

    def test_same_file_different_cwe(self):
        assert not file_matches(_finding(cwe="CWE-89"), _gt(), _config())

    def test_cwe_match_not_required(self):
        cfg = _config(require_cwe=False)
        assert file_matches(_finding(cwe="CWE-89"), _gt(), cfg)

    def test_finding_no_cwe_require_match(self):
        assert not file_matches(_finding(cwe=None), _gt(), _config())

    def test_finding_no_cwe_no_require(self):
        assert file_matches(_finding(cwe=None), _gt(), _config(require_cwe=False))

    def test_path_normalization_backslash(self):
        f = _finding("src\\app.py")
        assert file_matches(f, _gt("src/app.py"), _config())

    def test_path_normalization_leading_dot_slash(self):
        f = _finding("./src/app.py")
        assert file_matches(f, _gt("src/app.py"), _config())
