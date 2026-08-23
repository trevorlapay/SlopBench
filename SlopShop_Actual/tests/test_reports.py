"""Tests for report generators."""

import json
from pathlib import Path
from io import StringIO

import pytest
from rich.console import Console

from sastbench.models import (
    AgentRanking,
    ComparisonReport,
    DiffReport,
    Finding,
    MatchGranularity,
    MetricsReport,
    Severity,
    StandardMetrics,
    AgentDiffStats,
)
from sastbench.reports.console import print_metrics_report, print_diff_report, print_comparison_report
from sastbench.reports.json_report import generate_json_report, generate_diff_json, generate_comparison_json
from sastbench.reports.html_report import generate_html_report


@pytest.fixture
def sample_report() -> MetricsReport:
    return MetricsReport(
        agent_name="test-agent",
        benchmark_name="juliet",
        matching_granularity=MatchGranularity.LINE,
        overall=StandardMetrics(
            precision=0.85,
            recall=0.70,
            f1=0.77,
            accuracy=0.80,
            false_positive_rate=0.15,
            false_negative_rate=0.30,
            true_positives=14,
            false_positives=3,
            false_negatives=6,
            true_negatives=17,
        ),
        per_cwe={
            "CWE-79": StandardMetrics(precision=0.90, recall=0.80, f1=0.85, true_positives=9, false_positives=1, false_negatives=2),
            "CWE-89": StandardMetrics(precision=0.75, recall=0.60, f1=0.67, true_positives=5, false_positives=2, false_negatives=4),
        },
        total_findings=17,
        total_ground_truths=20,
    )


class TestConsoleReport:
    def test_print_metrics_report(self, sample_report):
        console = Console(file=StringIO(), force_terminal=True)
        print_metrics_report(sample_report, console=console)
        output = console.file.getvalue()
        assert "test-agent" in output
        assert "juliet" in output
        assert "Precision" in output

    def test_print_diff_report(self):
        report = DiffReport(
            agents=["agent_a", "agent_b"],
            agreement_rate=0.75,
            jaccard_index=0.60,
            cohens_kappa=0.55,
            per_agent={
                "agent_a": AgentDiffStats(total_findings=10, files_flagged=5),
                "agent_b": AgentDiffStats(total_findings=8, files_flagged=4),
            },
        )
        console = Console(file=StringIO(), force_terminal=True)
        print_diff_report(report, console=console)
        output = console.file.getvalue()
        assert "agent_a" in output
        assert "Agreement" in output


class TestJsonReport:
    def test_generate_json_report(self, tmp_path, sample_report):
        path = generate_json_report(sample_report, tmp_path / "report.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["agent_name"] == "test-agent"
        assert data["overall"]["precision"] == 0.85

    def test_generate_diff_json(self, tmp_path):
        report = DiffReport(agents=["a", "b"], agreement_rate=0.5)
        path = generate_diff_json(report, tmp_path / "diff.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["agreement_rate"] == 0.5


class TestHtmlReport:
    def test_generate_html_report(self, tmp_path, sample_report):
        path = generate_html_report(sample_report, tmp_path / "report.html")
        assert path.exists()
        html = path.read_text(encoding="utf-8")
        assert "test-agent" in html
        assert "juliet" in html
        assert "plotly" in html.lower()
        assert "CWE-79" in html

    def test_html_report_no_cwe(self, tmp_path):
        report = MetricsReport(
            agent_name="minimal",
            benchmark_name="test",
            matching_granularity=MatchGranularity.FILE,
            overall=StandardMetrics(precision=1.0, recall=1.0, f1=1.0),
        )
        path = generate_html_report(report, tmp_path / "minimal.html")
        assert path.exists()


class TestComparisonReport:
    def test_print_comparison_report(self):
        report = ComparisonReport(
            agents=["agent_x", "agent_y"],
            benchmark_name="juliet",
            rankings={
                "f1": [
                    AgentRanking(agent_name="agent_x", value=0.9, rank=1),
                    AgentRanking(agent_name="agent_y", value=0.7, rank=2),
                ],
            },
        )
        console = Console(file=StringIO(), force_terminal=True)
        print_comparison_report(report, console=console)
        output = console.file.getvalue()
        assert "agent_x" in output
        assert "agent_y" in output
        assert "juliet" in output

    def test_generate_comparison_json(self, tmp_path):
        report = ComparisonReport(
            agents=["a", "b"],
            benchmark_name="test-bench",
            rankings={
                "precision": [
                    AgentRanking(agent_name="a", value=0.8, rank=1),
                    AgentRanking(agent_name="b", value=0.6, rank=2),
                ],
            },
            unique_finds={
                "a": [Finding(file_path="x.py", start_line=1, cwe_id="CWE-79", severity=Severity.HIGH)],
                "b": [],
            },
        )
        path = generate_comparison_json(report, tmp_path / "comparison.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["benchmark_name"] == "test-bench"
        assert len(data["agents"]) == 2
        assert "precision" in data["rankings"]
