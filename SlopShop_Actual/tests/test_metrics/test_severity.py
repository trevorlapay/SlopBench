"""Tests for severity-weighted metrics."""

import pytest

from sastbench.models import (
    Finding,
    GroundTruth,
    MatchedPair,
    MatchResult,
    Severity,
)
from sastbench.metrics.severity import compute_severity_weighted_metrics


def _finding(sev: Severity, path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> Finding:
    return Finding(file_path=path, start_line=line, cwe_id=cwe, severity=sev)


def _gt(path: str = "a.py", line: int = 1, cwe: str = "CWE-79", sev: str | None = None) -> GroundTruth:
    meta = {"severity": sev} if sev else {}
    return GroundTruth(file_path=path, start_line=line, cwe_id=cwe, metadata=meta)


def _pair(sev: Severity, path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> MatchedPair:
    return MatchedPair(
        finding=_finding(sev, path, line, cwe),
        ground_truth=_gt(path, line, cwe),
    )


class TestSeverityWeighted:
    def test_critical_weighted_more(self):
        mr_critical = MatchResult(
            true_positives=[_pair(Severity.CRITICAL)],
            false_positives=[_finding(Severity.LOW, "b.py")],
        )
        mr_low = MatchResult(
            true_positives=[_pair(Severity.LOW)],
            false_positives=[_finding(Severity.LOW, "b.py")],
        )
        m_crit = compute_severity_weighted_metrics(mr_critical)
        m_low = compute_severity_weighted_metrics(mr_low)
        # Critical TP should produce higher weighted precision than low TP
        # (both have same low-weight FP)
        assert m_crit.precision > m_low.precision

    def test_mixed_severity(self):
        mr = MatchResult(
            true_positives=[_pair(Severity.CRITICAL), _pair(Severity.LOW, line=2)],
            false_positives=[_finding(Severity.LOW, "b.py")],
            false_negatives=[_gt("c.py", sev="high")],
        )
        m = compute_severity_weighted_metrics(mr)
        # weighted_tp = 4.0 + 1.0 = 5.0
        # weighted_fp = 1.0
        # weighted_fn = 3.0 (high)
        assert m.precision == pytest.approx(5.0 / 6.0)
        assert m.recall == pytest.approx(5.0 / 8.0)

    def test_empty(self):
        mr = MatchResult()
        m = compute_severity_weighted_metrics(mr)
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0

    def test_fn_without_severity_metadata(self):
        mr = MatchResult(false_negatives=[_gt("a.py", sev=None)])
        m = compute_severity_weighted_metrics(mr)
        assert m.false_negatives == 1
        assert m.recall == 0.0
