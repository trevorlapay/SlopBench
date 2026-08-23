"""Tests for CWE utilities."""

from sastbench.utils.cwe import (
    cwe_matches,
    get_cwe_family,
    get_cwe_parent,
    normalize_cwe,
)


class TestNormalizeCwe:
    def test_standard_format(self):
        assert normalize_cwe("CWE-79") == "CWE-79"

    def test_no_dash(self):
        assert normalize_cwe("CWE79") == "CWE-79"

    def test_underscore(self):
        assert normalize_cwe("cwe_79") == "CWE-79"

    def test_number_only(self):
        assert normalize_cwe("79") == "CWE-79"

    def test_leading_zeros(self):
        assert normalize_cwe("CWE-0079") == "CWE-79"

    def test_empty(self):
        assert normalize_cwe("") is None

    def test_garbage(self):
        assert normalize_cwe("not-a-cwe") is None

    def test_case_insensitive(self):
        assert normalize_cwe("cwe-89") == "CWE-89"

    def test_cwe_zero(self):
        assert normalize_cwe("CWE-0") is None

    def test_cwe_zero_padded(self):
        assert normalize_cwe("CWE-000") is None


class TestCweMatches:
    def test_exact_match(self):
        assert cwe_matches("CWE-79", "CWE-79") is True

    def test_normalized_match(self):
        assert cwe_matches("cwe79", "CWE-79") is True

    def test_no_match(self):
        assert cwe_matches("CWE-79", "CWE-89") is False

    def test_parent_match_disabled(self):
        assert cwe_matches("CWE-74", "CWE-79", allow_parent=False) is False

    def test_parent_match_enabled(self):
        # CWE-79 is child of CWE-74
        assert cwe_matches("CWE-74", "CWE-79", allow_parent=True) is True

    def test_child_match_enabled(self):
        # Agent reports child, ground truth is parent
        assert cwe_matches("CWE-79", "CWE-74", allow_parent=True) is True

    def test_none_inputs(self):
        assert cwe_matches("", "CWE-79") is False
        assert cwe_matches("CWE-79", "") is False


class TestGetCweParent:
    def test_known_parent(self):
        assert get_cwe_parent("CWE-79") == "CWE-74"

    def test_no_parent(self):
        assert get_cwe_parent("CWE-74") is None

    def test_invalid(self):
        assert get_cwe_parent("invalid") is None


class TestGetCweFamily:
    def test_direct_child(self):
        assert get_cwe_family("CWE-79") == "CWE-74"

    def test_grandchild(self):
        # CWE-23 → CWE-22 → CWE-20
        assert get_cwe_family("CWE-23") == "CWE-20"

    def test_root(self):
        assert get_cwe_family("CWE-74") == "CWE-74"
