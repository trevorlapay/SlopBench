"""Tests for multi-agent comparison."""

import pytest

from sastbench.models import (
    Finding,
    GroundTruth,
    MatchedPair,
    MatchGranularity,
    MatchResult,
    MetricsReport,
    Severity,
    StandardMetrics,
)
from sastbench.metrics.comparison import compare_agents


def _finding(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> Finding:
    return Finding(file_path=path, start_line=line, cwe_id=cwe, severity=Severity.HIGH)


def _gt(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> GroundTruth:
    return GroundTruth(file_path=path, start_line=line, cwe_id=cwe)


def _pair(path: str = "a.py", line: int = 1, cwe: str = "CWE-79") -> MatchedPair:
    return MatchedPair(finding=_finding(path, line, cwe), ground_truth=_gt(path, line, cwe))


def _report(name: str, tp_lines: list[int], fp_lines: list[int] | None = None) -> MetricsReport:
    tps = [_pair(line=l) for l in tp_lines]
    fps = [_finding(line=l) for l in (fp_lines or [])]
    mr = MatchResult(true_positives=tps, false_positives=fps)
    n_tp = len(tps)
    n_fp = len(fps)
    precision = n_tp / (n_tp + n_fp) if (n_tp + n_fp) else 0.0
    recall = 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return MetricsReport(
        agent_name=name,
        benchmark_name="test-bench",
        matching_granularity=MatchGranularity.LINE,
        overall=StandardMetrics(precision=precision, recall=recall, f1=f1),
        match_result=mr,
    )


class TestCompareAgents:
    def test_empty(self):
        report = compare_agents([])
        assert report.agents == []

    def test_single_agent(self):
        r = _report("agent-a", [1, 2, 3])
        report = compare_agents([r])
        assert report.agents == ["agent-a"]
        assert "f1" in report.rankings

    def test_two_agents_ranking(self):
        r1 = _report("alpha", [1, 2, 3])
        r2 = _report("beta", [1, 2], fp_lines=[10, 11])
        report = compare_agents([r1, r2])
        prec_rankings = report.rankings["precision"]
        assert prec_rankings[0].agent_name == "alpha"
        assert prec_rankings[0].rank == 1

    def test_overlap_matrix(self):
        r1 = _report("a", [1, 2, 3])
        r2 = _report("b", [2, 3, 4])
        report = compare_agents([r1, r2])
        assert report.overlap_matrix["a"]["b"] == pytest.approx(2 / 3)
        assert report.overlap_matrix["a"]["a"] == pytest.approx(1.0)

    def test_unique_finds(self):
        r1 = _report("a", [1, 2, 3])
        r2 = _report("b", [2, 3, 4])
        report = compare_agents([r1, r2])
        unique_a = [f.start_line for f in report.unique_finds["a"]]
        unique_b = [f.start_line for f in report.unique_finds["b"]]
        assert 1 in unique_a
        assert 4 in unique_b
