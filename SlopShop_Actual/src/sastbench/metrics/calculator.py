"""Main metrics calculator tying all modules together."""

from __future__ import annotations

from sastbench.models import MatchResult, MetricsReport
from sastbench.metrics.standard import compute_standard_metrics
from sastbench.metrics.cwe_breakdown import compute_cwe_breakdown
from sastbench.metrics.severity import compute_severity_weighted_metrics


def calculate_metrics(
    match_result: MatchResult,
    agent_name: str,
    benchmark_name: str,
) -> MetricsReport:
    """Calculate full metrics report from a match result."""
    overall = compute_standard_metrics(match_result)
    per_cwe = compute_cwe_breakdown(match_result)
    severity_weighted = compute_severity_weighted_metrics(match_result)

    total_findings = (
        len(match_result.true_positives) + len(match_result.false_positives)
    )
    total_ground_truths = (
        len(match_result.true_positives) + len(match_result.false_negatives)
    )

    return MetricsReport(
        agent_name=agent_name,
        benchmark_name=benchmark_name,
        matching_granularity=match_result.config.granularity,
        overall=overall,
        per_cwe=per_cwe,
        severity_weighted=severity_weighted,
        total_findings=total_findings,
        total_ground_truths=total_ground_truths,
        match_result=match_result,
    )
