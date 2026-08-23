"""Multi-agent comparison with ground truth."""

from __future__ import annotations

from sastbench.models import (
    AgentRanking,
    ComparisonReport,
    Finding,
    MetricsReport,
)
from sastbench.utils.normalize import normalize_path


def _rank_by(reports: list[MetricsReport], metric: str) -> list[AgentRanking]:
    """Rank agents by a given metric (descending) using standard competition ranking.

    Agents with the same metric value receive the same rank.  The next rank
    after a tie is offset by the number of tied entries (e.g. 1, 1, 3).
    """
    values = [(r.agent_name, getattr(r.overall, metric)) for r in reports]
    values.sort(key=lambda x: x[1], reverse=True)
    rankings: list[AgentRanking] = []
    for i, (name, val) in enumerate(values):
        if i == 0 or val != values[i - 1][1]:
            current_rank = i + 1
        rankings.append(AgentRanking(agent_name=name, value=val, rank=current_rank))
    return rankings


def _finding_key(f: Finding) -> tuple[str, int | None, str | None]:
    return (normalize_path(f.file_path), f.start_line, f.cwe_id)


def _tp_keys(report: MetricsReport) -> set[tuple[str, int | None, str | None]]:
    if not report.match_result:
        return set()
    return {_finding_key(p.finding) for p in report.match_result.true_positives}


def compare_agents(reports: list[MetricsReport]) -> ComparisonReport:
    """Compare multiple agents' MetricsReports."""
    if not reports:
        return ComparisonReport(agents=[], benchmark_name="")

    agents = [r.agent_name for r in reports]
    benchmark_name = reports[0].benchmark_name

    # Rankings by key metrics
    rankings: dict[str, list[AgentRanking]] = {}
    for metric in ("precision", "recall", "f1"):
        rankings[metric] = _rank_by(reports, metric)

    # TP key sets per agent
    agent_tp: dict[str, set[tuple]] = {}
    for r in reports:
        agent_tp[r.agent_name] = _tp_keys(r)

    # Overlap matrix: percentage of agent_a's TPs also found by agent_b
    overlap_matrix: dict[str, dict[str, float]] = {}
    for a in agents:
        overlap_matrix[a] = {}
        for b in agents:
            if not agent_tp[a]:
                overlap_matrix[a][b] = 0.0
            else:
                overlap_matrix[a][b] = len(agent_tp[a] & agent_tp[b]) / len(agent_tp[a])

    # Unique finds: TPs found by this agent but no other
    all_other_keys: dict[str, set[tuple]] = {}
    for a in agents:
        all_other_keys[a] = set()
        for b in agents:
            if b != a:
                all_other_keys[a] |= agent_tp[b]

    unique_finds: dict[str, list[Finding]] = {}
    for r in reports:
        name = r.agent_name
        unique_keys = agent_tp[name] - all_other_keys[name]
        if r.match_result:
            unique_finds[name] = [
                p.finding
                for p in r.match_result.true_positives
                if _finding_key(p.finding) in unique_keys
            ]
        else:
            unique_finds[name] = []

    return ComparisonReport(
        agents=agents,
        benchmark_name=benchmark_name,
        rankings=rankings,
        overlap_matrix=overlap_matrix,
        unique_finds=unique_finds,
    )
