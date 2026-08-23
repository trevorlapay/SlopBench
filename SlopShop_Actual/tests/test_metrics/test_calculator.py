"""Tests for the main calculate_metrics integration point."""

import pytest

from sastbench.models import (
    Finding,
    GroundTruth,
    MatchedPair,
    MatchGranularity,
    MatchResult,
    MatchingConfig,
    Severity,
)
from sastbench.metrics.calculator import calculate_metrics


def _finding(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> Finding:
    return Finding(file_path=path, start_line=line, cwe_id=cwe, severity=Severity.HIGH)


def _gt(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> GroundTruth:
    return GroundTruth(file_path=path, start_line=line, cwe_id=cwe)


def _pair(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> MatchedPair:
    return MatchedPair(finding=_finding(path, line, cwe), ground_truth=_gt(path, line, cwe))


class TestCalculateMetrics:
    def test_basic_report_fields(self):
        """calculate_metrics returns a coherent MetricsReport."""
        mr = MatchResult(
            true_positives=[_pair("a.py", 1), _pair("b.py", 2, cwe="CWE-89")],
            false_positives=[_finding("c.py", 3)],
            false_negatives=[_gt("d.py", 4)],
            true_negatives=5,
        )
        report = calculate_metrics(mr, agent_name="test-agent", benchmark_name="juliet")
        assert report.agent_name == "test-agent"
        assert report.benchmark_name == "juliet"
        assert report.matching_granularity == MatchGranularity.FILE
        assert report.total_findings == 3  # 2 TP + 1 FP
        assert report.total_ground_truths == 3  # 2 TP + 1 FN
        assert report.overall.true_positives == 2
        assert report.overall.false_positives == 1
        assert report.overall.precision == pytest.approx(2 / 3)
        assert report.per_cwe  # should have per-CWE breakdown
        assert report.severity_weighted is not None
        assert report.match_result is mr

    def test_empty_match_result(self):
        """calculate_metrics handles an empty MatchResult (no findings)."""
        mr = MatchResult()
        report = calculate_metrics(mr, agent_name="empty", benchmark_name="none")
        assert report.total_findings == 0
        assert report.total_ground_truths == 0
        assert report.overall.precision == 0.0
        assert report.overall.recall == 0.0
        assert report.overall.f1 == 0.0
        assert report.per_cwe == {}
