"""Tests for standard metrics computation."""

import pytest

from sastbench.models import (
    Finding,
    GroundTruth,
    MatchedPair,
    MatchResult,
    Severity,
)
from sastbench.metrics.standard import compute_standard_metrics


def _finding(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> Finding:
    return Finding(file_path=path, start_line=line, cwe_id=cwe, severity=Severity.HIGH)


def _gt(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> GroundTruth:
    return GroundTruth(file_path=path, start_line=line, cwe_id=cwe)


def _pair(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> MatchedPair:
    return MatchedPair(finding=_finding(path, line, cwe), ground_truth=_gt(path, line, cwe))


class TestStandardMetrics:
    def test_perfect_scores(self):
        mr = MatchResult(
            true_positives=[_pair()],
            false_positives=[],
            false_negatives=[],
            true_negatives=1,
        )
        m = compute_standard_metrics(mr)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0
        assert m.accuracy == 1.0
        assert m.false_positive_rate == 0.0
        assert m.false_negative_rate == 0.0

    def test_all_zeros(self):
        mr = MatchResult()
        m = compute_standard_metrics(mr)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0
        assert m.accuracy == 0.0
        assert m.false_positive_rate == 0.0
        assert m.false_negative_rate == 0.0

    def test_all_false_positives(self):
        mr = MatchResult(false_positives=[_finding(), _finding(line=2)])
        m = compute_standard_metrics(mr)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0
        assert m.true_positives == 0
        assert m.false_positives == 2

    def test_all_false_negatives(self):
        mr = MatchResult(false_negatives=[_gt(), _gt(line=2)])
        m = compute_standard_metrics(mr)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0
        assert m.false_negatives == 2

    def test_mixed(self):
        mr = MatchResult(
            true_positives=[_pair("a.py", 1), _pair("a.py", 2)],
            false_positives=[_finding("b.py", 1)],
            false_negatives=[_gt("c.py", 1)],
            true_negatives=2,
        )
        m = compute_standard_metrics(mr)
        assert m.true_positives == 2
        assert m.false_positives == 1
        assert m.false_negatives == 1
        assert m.true_negatives == 2
        assert m.precision == pytest.approx(2 / 3)
        assert m.recall == pytest.approx(2 / 3)
        assert m.f1 == pytest.approx(2 / 3)
        assert m.accuracy == pytest.approx(4 / 6)
        assert m.false_positive_rate == pytest.approx(1 / 3)
        assert m.false_negative_rate == pytest.approx(1 / 3)

    def test_no_true_negatives(self):
        mr = MatchResult(
            true_positives=[_pair()],
            false_positives=[_finding("b.py")],
            false_negatives=[],
            true_negatives=0,
        )
        m = compute_standard_metrics(mr)
        assert m.precision == pytest.approx(0.5)
        assert m.recall == 1.0
        assert m.false_positive_rate == 1.0
