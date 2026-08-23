"""Tests for agent-vs-agent diff."""

import pytest

from sastbench.models import Finding, Severity
from sastbench.metrics.diff import diff_agents


def _finding(
    path: str = "a.py", line: int = 1, cwe: str = "CWE-79", sev: Severity = Severity.HIGH,
) -> Finding:
    return Finding(file_path=path, start_line=line, cwe_id=cwe, severity=sev)


class TestDiffAgents:
    def test_empty(self):
        report = diff_agents({})
        assert report.agents == []
        assert report.agreement_rate == 0.0

    def test_identical_findings(self):
        findings = [_finding(line=1), _finding(line=10, cwe="CWE-89")]
        report = diff_agents({"a": findings, "b": findings}, match_tolerance=3)
        assert report.agreement_rate == 1.0
        assert report.jaccard_index == 1.0
        assert len(report.agreed_findings) == 2
        assert len(report.unique_findings["a"]) == 0
        assert len(report.unique_findings["b"]) == 0

    def test_no_overlap(self):
        report = diff_agents(
            {
                "a": [_finding(path="x.py", line=1, cwe="CWE-79")],
                "b": [_finding(path="y.py", line=1, cwe="CWE-89")],
            },
            match_tolerance=3,
        )
        assert report.agreement_rate == 0.0
        assert report.jaccard_index == 0.0
        assert len(report.agreed_findings) == 0
        assert len(report.unique_findings["a"]) == 1
        assert len(report.unique_findings["b"]) == 1

    def test_line_tolerance(self):
        report = diff_agents(
            {
                "a": [_finding(line=10)],
                "b": [_finding(line=12)],
            },
            match_tolerance=3,
        )
        assert report.agreement_rate == 1.0
        assert len(report.agreed_findings) == 1

    def test_line_tolerance_exceeded(self):
        report = diff_agents(
            {
                "a": [_finding(line=10)],
                "b": [_finding(line=20)],
            },
            match_tolerance=3,
        )
        assert report.agreement_rate == 0.0
        assert len(report.unique_findings["a"]) == 1

    def test_per_agent_stats(self):
        report = diff_agents({
            "a": [_finding(line=1, cwe="CWE-79"), _finding(line=2, cwe="CWE-89")],
            "b": [_finding(line=1, cwe="CWE-79")],
        })
        assert report.per_agent["a"].total_findings == 2
        assert report.per_agent["b"].total_findings == 1
        assert report.per_agent["a"].files_flagged == 1

    def test_cwe_distribution(self):
        report = diff_agents({
            "a": [_finding(cwe="CWE-79"), _finding(line=2, cwe="CWE-89")],
        })
        assert report.cwe_distribution["a"]["CWE-79"] == 1
        assert report.cwe_distribution["a"]["CWE-89"] == 1

    def test_cohens_kappa_perfect(self):
        findings = [_finding(line=1)]
        report = diff_agents({"a": findings, "b": findings}, match_tolerance=3)
        assert report.cohens_kappa == pytest.approx(1.0)

    def test_three_agents_consensus(self):
        shared = _finding(line=1, cwe="CWE-79")
        report = diff_agents(
            {
                "a": [shared, _finding(line=100, cwe="CWE-89")],
                "b": [shared],
                "c": [shared, _finding(path="z.py", line=5, cwe="CWE-22")],
            },
            match_tolerance=3,
        )
        assert len(report.consensus_findings) >= 1
        agents_in_consensus = report.consensus_findings[0].finding.agents
        assert "a" in agents_in_consensus
        assert "b" in agents_in_consensus
        assert "c" in agents_in_consensus

    def test_single_agent(self):
        report = diff_agents({"a": [_finding(line=1)]})
        assert report.jaccard_index == 1.0
        assert report.agreement_rate == 0.0
