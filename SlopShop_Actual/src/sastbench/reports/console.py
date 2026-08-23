"""Console (rich) rendering of SASTBench reports."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

_DEFAULT = Console()


def _pct(x: float) -> str:
    try:
        return f"{x:.1%}"
    except Exception:
        return str(x)


def print_metrics_report(report, console: Console | None = None) -> None:
    """Render a single agent's MetricsReport."""
    console = console or _DEFAULT
    m = report.overall

    table = Table(title=f"{report.agent_name} — {report.benchmark_name} "
                        f"({report.matching_granularity.value if hasattr(report.matching_granularity, 'value') else report.matching_granularity})",
                  header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Precision", _pct(m.precision))
    table.add_row("Recall", _pct(m.recall))
    table.add_row("F1", _pct(m.f1))
    table.add_row("Accuracy", _pct(m.accuracy))
    table.add_row("FPR", _pct(m.false_positive_rate))
    table.add_section()
    table.add_row("True positives", str(m.true_positives))
    table.add_row("False positives", str(m.false_positives))
    table.add_row("False negatives", str(m.false_negatives))
    table.add_row("True negatives", str(m.true_negatives))
    table.add_section()
    table.add_row("Total findings", str(report.total_findings))
    table.add_row("Total ground truths", str(report.total_ground_truths))
    console.print(table)

    if report.per_cwe:
        cwe_table = Table(title="Per-CWE", header_style="bold magenta")
        for col in ("CWE", "P", "R", "F1", "TP", "FP", "FN"):
            cwe_table.add_column(col, justify="right" if col != "CWE" else "left")
        for cwe, cm in sorted(report.per_cwe.items()):
            cwe_table.add_row(cwe, _pct(cm.precision), _pct(cm.recall), _pct(cm.f1),
                              str(cm.true_positives), str(cm.false_positives), str(cm.false_negatives))
        console.print(cwe_table)


def print_comparison_report(comparison, console: Console | None = None) -> None:
    """Render a ComparisonReport (multiple agents vs ground truth)."""
    console = console or _DEFAULT
    table = Table(title=f"Comparison — {comparison.benchmark_name}", header_style="bold cyan")
    table.add_column("Metric", style="bold")
    for agent in comparison.agents:
        table.add_column(agent, justify="right")

    # rankings is dict[metric -> list[AgentRanking]]
    for metric, rankings in comparison.rankings.items():
        by_agent = {r.agent_name: r.value for r in rankings}
        row = [metric]
        for agent in comparison.agents:
            v = by_agent.get(agent)
            row.append(_pct(v) if isinstance(v, float) and 0 <= v <= 1 else (str(v) if v is not None else "-"))
        table.add_row(*row)
    console.print(table)

    for agent, finds in comparison.unique_finds.items():
        if finds:
            console.print(f"[dim]{agent}: {len(finds)} unique finding(s)[/dim]")


def print_diff_report(diff_report, console: Console | None = None) -> None:
    """Render a DiffReport (agent-vs-agent, no ground truth)."""
    console = console or _DEFAULT
    table = Table(title=f"Agent diff (tolerance={diff_report.match_tolerance})", header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")
    table.add_row("Agents", ", ".join(diff_report.agents))
    table.add_row("Agreement rate", _pct(diff_report.agreement_rate))
    table.add_row("Jaccard index", f"{diff_report.jaccard_index:.3f}")
    table.add_row("Cohen's kappa", f"{diff_report.cohens_kappa:.3f}")
    table.add_row("Agreed findings", str(len(diff_report.agreed_findings)))
    console.print(table)

    per = Table(title="Per agent", header_style="bold magenta")
    per.add_column("Agent")
    per.add_column("Findings", justify="right")
    per.add_column("Files", justify="right")
    per.add_column("Unique", justify="right")
    for agent in diff_report.agents:
        stats = diff_report.per_agent.get(agent)
        uniq = len(diff_report.unique_findings.get(agent, []))
        per.add_row(agent, str(stats.total_findings if stats else 0),
                    str(stats.files_flagged if stats else 0), str(uniq))
    console.print(per)
