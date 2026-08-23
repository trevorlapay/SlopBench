"""Tests for normalization utilities."""

from sastbench.utils.normalize import (
    normalize_path,
    normalize_severity,
    paths_match,
    severity_weight,
)


class TestNormalizePath:
    def test_forward_slashes(self):
        assert normalize_path("code/sample_001.c") == "code/sample_001.c"

    def test_backslashes(self):
        assert normalize_path("code\\sample_001.c") == "code/sample_001.c"

    def test_leading_dot_slash(self):
        assert normalize_path("./code/sample_001.c") == "code/sample_001.c"

    def test_leading_slash(self):
        assert normalize_path("/code/sample_001.c") == "code/sample_001.c"

    def test_double_slashes(self):
        assert normalize_path("code//sample_001.c") == "code/sample_001.c"

    def test_dot_dot(self):
        assert normalize_path("code/subdir/../sample_001.c") == "code/sample_001.c"

    def test_empty_result(self):
        assert normalize_path("./") == ""

    def test_dotfile_preserved(self):
        assert normalize_path(".gitignore") == ".gitignore"

    def test_dot_dot_hidden(self):
        assert normalize_path("..hidden") == "..hidden"

    def test_github_workflows(self):
        assert normalize_path(".github/workflows") == ".github/workflows"

    def test_dot_slash_dotfile(self):
        assert normalize_path("./.gitignore") == ".gitignore"


class TestPathsMatch:
    def test_same(self):
        assert paths_match("code/a.c", "code/a.c") is True

    def test_slash_diff(self):
        assert paths_match("code/a.c", "code\\a.c") is True

    def test_leading_dot(self):
        assert paths_match("./code/a.c", "code/a.c") is True

    def test_different(self):
        assert paths_match("code/a.c", "code/b.c") is False


class TestNormalizeSeverity:
    def test_sarif_error(self):
        assert normalize_severity("error") == "high"

    def test_sarif_warning(self):
        assert normalize_severity("warning") == "medium"

    def test_sarif_note(self):
        assert normalize_severity("note") == "low"

    def test_standard(self):
        assert normalize_severity("critical") == "critical"

    def test_none(self):
        assert normalize_severity(None) is None

    def test_unknown(self):
        assert normalize_severity("unknown") is None

    def test_informational(self):
        assert normalize_severity("informational") == "low"

    def test_info(self):
        assert normalize_severity("info") == "low"


class TestSeverityWeight:
    def test_critical(self):
        assert severity_weight("critical") == 4.0

    def test_low(self):
        assert severity_weight("low") == 1.0

    def test_none(self):
        assert severity_weight(None) == 1.0
