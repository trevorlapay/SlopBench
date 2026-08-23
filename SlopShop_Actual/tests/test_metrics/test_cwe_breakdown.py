"""Tests for per-CWE breakdown and averages."""

import pytest

from sastbench.models import (
    Finding,
    GroundTruth,
    MatchedPair,
    MatchResult,
    Severity,
    StandardMetrics,
)
from sastbench.metrics.cwe_breakdown import (
    compute_cwe_breakdown,
    compute_macro_average,
    compute_micro_average,
)


def _finding(cwe: str = "CWE-79", path: str = "a.py", line: int = 1) -> Finding:
    return Finding(file_path=path, start_line=line, cwe_id=cwe, severity=Severity.HIGH)


def _gt(cwe: str = "CWE-79", path: str = "a.py", line: int = 1) -> GroundTruth:
    return GroundTruth(file_path=path, start_line=line, cwe_id=cwe)


def _pair(cwe: str = "CWE-79", path: str = "a.py", line: int = 1) -> MatchedPair:
    return MatchedPair(finding=_finding(cwe, path, line), ground_truth=_gt(cwe, path, line))


class TestCweBreakdown:
    def test_single_cwe(self):
        mr = MatchResult(
            true_positives=[_pair("CWE-79")],
            false_positives=[_finding("CWE-79")],
            false_negatives=[],
        )
        breakdown = compute_cwe_breakdown(mr)
        assert "CWE-79" in breakdown
        assert breakdown["CWE-79"].true_positives == 1
        assert breakdown["CWE-79"].false_positives == 1

    def test_multiple_cwes(self):
        mr = MatchResult(
            true_positives=[_pair("CWE-79"), _pair("CWE-89")],
            false_positives=[_finding("CWE-89")],
            false_negatives=[_gt("CWE-22")],
        )
        breakdown = compute_cwe_breakdown(mr)
        assert set(breakdown.keys()) == {"CWE-22", "CWE-79", "CWE-89"}
        assert breakdown["CWE-79"].true_positives == 1
        assert breakdown["CWE-79"].false_positives == 0
        assert breakdown["CWE-89"].true_positives == 1
        assert breakdown["CWE-89"].false_positives == 1
        assert breakdown["CWE-22"].false_negatives == 1

    def test_unknown_cwe_for_fp(self):
        fp_no_cwe = Finding(file_path="a.py", start_line=1)
        mr = MatchResult(false_positives=[fp_no_cwe])
        breakdown = compute_cwe_breakdown(mr)
        assert "UNKNOWN" in breakdown
        assert breakdown["UNKNOWN"].false_positives == 1

    def test_empty_result(self):
        mr = MatchResult()
        breakdown = compute_cwe_breakdown(mr)
        assert breakdown == {}


class TestMacroAverage:
    def test_macro_average(self):
        per_cwe = {
            "CWE-79": StandardMetrics(precision=1.0, recall=0.5, f1=2 / 3),
            "CWE-89": StandardMetrics(precision=0.5, recall=1.0, f1=2 / 3),
        }
        avg = compute_macro_average(per_cwe)
        assert avg.precision == pytest.approx(0.75)
        assert avg.recall == pytest.approx(0.75)

    def test_empty(self):
        avg = compute_macro_average({})
        assert avg.precision == 0.0


class TestMicroAverage:
    def test_micro_equals_standard(self):
        mr = MatchResult(
            true_positives=[_pair("CWE-79"), _pair("CWE-89")],
            false_positives=[_finding("CWE-79")],
            false_negatives=[_gt("CWE-89")],
            true_negatives=1,
        )
        micro = compute_micro_average(mr)
        assert micro.true_positives == 2
        assert micro.false_positives == 1
        assert micro.precision == pytest.approx(2 / 3)
