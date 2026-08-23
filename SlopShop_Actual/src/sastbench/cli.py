"""SASTBench CLI — entry point for all commands."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click
from rich.console import Console

from sastbench import __version__

console = Console()
logger = logging.getLogger("sastbench")


@click.group()
@click.version_option(version=__version__, prog_name="sastbench")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging")
def cli(verbose: bool = False) -> None:
    """SASTBench — Benchmark framework for vulnerability-hunting AI agents."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")


@cli.command()
@click.option("--benchmark", "-b", required=True, help="Benchmark name (juliet, primevul, bigvul, etc.)")
@click.option("--benchmark-path", type=click.Path(exists=True), help="Local path to benchmark data (skips download)")
@click.option("--output-dir", "-o", required=True, type=click.Path(), help="Output workspace directory")
@click.option("--cwe-filter", multiple=True, help="Only include specific CWEs (e.g., CWE-79)")
@click.option("--max-cases", type=int, help="Limit number of test cases")
@click.option("--language", multiple=True, help="Filter by language (e.g., c, java)")
@click.option("--shuffle/--no-shuffle", default=True, help="Randomize file order to prevent systematic bias (default: shuffle)")
@click.option("--seed", type=int, default=42, help="Random seed for reproducible shuffling")
@click.option("--mix-safe", type=float, default=0.0, help="Ratio of safe files to inject (e.g. 1.0 = equal count of safe C functions)")
@click.option("--prompt-template", default="selective", help="Prompt template to save with workspace (default: selective)")
def prepare(
    benchmark: str,
    benchmark_path: str | None,
    output_dir: str,
    cwe_filter: tuple[str, ...],
    max_cases: int | None,
    language: tuple[str, ...],
    shuffle: bool,
    seed: int,
    mix_safe: float,
    prompt_template: str,
) -> None:
    """Prepare a workspace from a benchmark dataset."""
    from sastbench.adapters import get_adapter
    from sastbench.workspace import WorkspacePreparer

    adapter = get_adapter(benchmark)
    console.print(f"[bold]Using benchmark:[/bold] {adapter.name} — {adapter.description}")

    local_path = Path(benchmark_path) if benchmark_path else None
    data_path = adapter.ensure_available(local_override=local_path)
    console.print(f"[bold]Data path:[/bold] {data_path}")

    cwe_list = list(cwe_filter) if cwe_filter else None
    lang_list = list(language) if language else None
    test_cases, ground_truths = adapter.extract(
        data_path,
        cwe_filter=cwe_list,
        language_filter=lang_list,
        max_cases=max_cases,
    )
    console.print(f"  Extracted {len(test_cases)} test cases, {len(ground_truths)} ground truths")
    if mix_safe > 0:
        safe_count = int(len(test_cases) * mix_safe)
        console.print(f"  Mixing in {safe_count} safe functions (ratio={mix_safe})")
    if shuffle:
        console.print(f"  Shuffling with seed={seed} to prevent ordering bias")

    preparer = WorkspacePreparer()
    ws = preparer.build(
        test_cases, ground_truths, Path(output_dir), benchmark,
        shuffle=shuffle, seed=seed, safe_ratio=mix_safe,
        prompt_template=prompt_template,
    )
    console.print(f"[bold green]✓ Workspace created:[/bold green] {ws}")
    console.print(f"  Prompt template: {prompt_template}")
    console.print("  Generate agent prompt: [bold]SASTBench show-run-prompt {ws} --agent-name <name>[/bold]")


@cli.command()
@click.option("--workspace", "-w", required=True, type=click.Path(exists=True), help="Path to prepared workspace")
@click.option("--agent-output", type=click.Path(exists=True), help="Path to agent output file (auto-detected from workspace/output/ if omitted)")
@click.option("--format", "fmt", type=click.Choice(["sarif", "json", "csv", "auto"]), default="auto", help="Agent output format")
@click.option("--agent-name", default="unknown", help="Name for the agent being evaluated")
@click.option("--granularity", type=click.Choice(["file", "function", "line"]), default="file")
@click.option("--line-tolerance", type=int, default=3, help="Line tolerance for line-level matching")
@click.option("--no-cwe-match", is_flag=True, help="Don't require CWE match (useful when GT uses different CWE taxonomy)")
@click.option("--allow-parent-cwe", is_flag=True, help="Accept parent/child CWE matches (e.g. CWE-787 matches GT CWE-119)")
@click.option("--require-line", is_flag=True, help="Require findings to include a start_line within tolerance of GT (no credit without location)")
@click.option("--binary", is_flag=True, help="Binary classification mode: just check if agent flagged vulnerable files vs safe files (ignores CWE labels entirely)")
@click.option("--report", multiple=True, default=("console",), help="Report formats: console, json, html")
@click.option("--output-dir", type=click.Path(), default="./reports", help="Directory for report files")
def evaluate(
    workspace: str,
    agent_output: str | None,
    fmt: str,
    agent_name: str,
    granularity: str,
    line_tolerance: int,
    no_cwe_match: bool,
    allow_parent_cwe: bool,
    require_line: bool,
    binary: bool,
    report: tuple[str, ...],
    output_dir: str,
) -> None:
    """Evaluate agent output against benchmark ground truth."""
    from sastbench.matching.engine import MatchingEngine
    from sastbench.metrics.calculator import calculate_metrics
    from sastbench.models import MatchGranularity, MatchingConfig
    from sastbench.workspace import load_workspace_config, load_workspace_ground_truth

    ws_path = Path(workspace)
    ground_truths = load_workspace_ground_truth(ws_path)
    config = load_workspace_config(ws_path)
    console.print(f"[bold]Workspace:[/bold] {ws_path} ({config['benchmark']})")
    console.print(f"  Ground truths: {len(ground_truths)}")

    findings = _load_agent_output(ws_path, agent_output, fmt)
    console.print(f"  Agent findings: {len(findings)}")

    if binary:
        result = _binary_evaluate(ground_truths, findings, agent_name)
        from rich.table import Table
        table = Table(title=f"Binary Classification: {agent_name}", header_style="bold cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        for k in ["precision", "recall", "f1", "accuracy"]:
            table.add_row(k.title(), f"{result[k]:.1%}")
        table.add_row("", "")
        for k in ["tp", "fp", "fn", "tn"]:
            table.add_row(k.upper(), str(result[k]))
        console.print(table)
        # Show baseline context
        console.print(
            f"\n  [dim]Dataset balance: {result['vuln_count']} vulnerable, {result['safe_count']} safe[/dim]"
        )
        console.print(
            f"  [dim]\"Flag everything\" baseline: P={result['baseline_precision']:.1%} R=100% F1={result['baseline_f1']:.1%}[/dim]"
        )
        if result['precision'] <= result['baseline_precision'] + 0.01:
            console.print(
                f"  [yellow]⚠ Agent precision ({result['precision']:.1%}) is at or below the flag-everything "
                f"baseline ({result['baseline_precision']:.1%}). The agent may not be discriminating "
                f"between vulnerable and safe code.[/yellow]"
            )
        # Save JSON
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        import re as _re
        safe = _re.sub(r'[^a-z0-9_-]', '', agent_name.lower().replace(' ', '_'))
        p = out / f"{safe}_binary.json"
        p.write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[green]JSON: {p}[/green]")
        return

    match_config = MatchingConfig(
        granularity=MatchGranularity(granularity),
        line_tolerance=line_tolerance,
        require_cwe_match=not no_cwe_match,
        allow_parent_cwe=allow_parent_cwe,
        require_line_number=require_line,
    )
    engine = MatchingEngine(match_config)
    match_result = engine.match(findings, ground_truths)
    metrics_report = calculate_metrics(match_result, agent_name, config["benchmark"])
    _output_reports(metrics_report, report, output_dir, agent_name)


@cli.command()
@click.option("--agent", "-a", multiple=True, required=True, help="Agent output: name:path:format")
@click.option("--match-tolerance", type=int, default=3, help="Line tolerance for matching findings between agents")
@click.option("--report", multiple=True, default=("console",), help="Report formats")
@click.option("--output-dir", type=click.Path(), default="./reports")
def diff(
    agent: tuple[str, ...],
    match_tolerance: int,
    report: tuple[str, ...],
    output_dir: str,
) -> None:
    """Compare findings from multiple agents without ground truth."""
    from sastbench.metrics.diff import diff_agents
    from sastbench.models import Finding
    from sastbench.reports.console import print_diff_report
    from sastbench.reports.json_report import generate_diff_json

    agent_findings: dict[str, list[Finding]] = {}
    for spec in agent:
        parts = spec.split(":")
        if len(parts) < 2:
            raise click.BadParameter(f"Agent spec must be name:path[:format], got '{spec}'")
        name = parts[0]
        # Handle Windows drive letters (e.g. name:C:\path:fmt)
        if len(parts) >= 3 and len(parts[1]) == 1 and parts[1].isalpha():
            # parts[1] is a drive letter
            if len(parts) >= 4:
                path = parts[1] + ":" + parts[2]
                fmt = parts[3] if len(parts) > 3 else "auto"
            else:
                path = parts[1] + ":" + parts[2]
                fmt = "auto"
        else:
            path = parts[1]
            fmt = parts[2] if len(parts) > 2 else "auto"
        findings = _parse_file(Path(path), fmt)
        agent_findings[name] = findings

    diff_report = diff_agents(agent_findings, match_tolerance=match_tolerance)

    if "console" in report:
        print_diff_report(diff_report, console=console)
    if "json" in report:
        out = Path(output_dir)
        generate_diff_json(diff_report, out / "diff_report.json")
        console.print(f"[green]JSON report: {out / 'diff_report.json'}[/green]")


@cli.command()
@click.option("--workspace", "-w", required=True, type=click.Path(exists=True), help="Path to prepared workspace")
@click.option("--agent", "-a", multiple=True, required=True, help="Agent: name:path (e.g. 'Sonnet:output_agent_a/findings.json')")
@click.option("--granularity", type=click.Choice(["file", "function", "line"]), default="file")
@click.option("--line-tolerance", type=int, default=5, help="Line tolerance for matching")
@click.option("--no-cwe-match", is_flag=True, help="Don't require CWE match")
@click.option("--allow-parent-cwe", is_flag=True, help="Accept parent/child CWE matches (e.g. CWE-787 matches GT CWE-119)")
@click.option("--require-line", is_flag=True, help="Require findings to include a start_line within tolerance of GT")
@click.option("--binary", is_flag=True, help="Binary classification mode (vuln vs safe, ignores CWE)")
@click.option("--report", multiple=True, default=("console",), help="Report formats: console, json, html")
@click.option("--output-dir", type=click.Path(), default="./reports", help="Directory for report files")
def compare(
    workspace: str,
    agent: tuple[str, ...],
    granularity: str,
    line_tolerance: int,
    no_cwe_match: bool,
    allow_parent_cwe: bool,
    require_line: bool,
    binary: bool,
    report: tuple[str, ...],
    output_dir: str,
) -> None:
    """Compare multiple agents against the same benchmark ground truth.

    Example:
        SASTBench compare -w workspace/juliet
          -a "Sonnet:workspace/juliet/output_agent_a/findings.json"
          -a "Opus:workspace/juliet/output_agent_c/findings.json"
    """
    from sastbench.matching.engine import MatchingEngine
    from sastbench.metrics.calculator import calculate_metrics
    from sastbench.metrics.comparison import compare_agents
    from sastbench.models import MatchGranularity, MatchingConfig
    from sastbench.reports.console import print_comparison_report
    from sastbench.reports.json_report import generate_json_report, generate_comparison_json
    from sastbench.reports.html_report import generate_html_report
    from sastbench.workspace import load_workspace_config, load_workspace_ground_truth

    ws_path = Path(workspace)
    ground_truths = load_workspace_ground_truth(ws_path)
    config = load_workspace_config(ws_path)

    code_dir = ws_path / "code"
    if code_dir.exists():
        total_lines = sum(
            len(f.read_text(encoding="utf-8", errors="replace").splitlines())
            for f in code_dir.iterdir() if f.is_file()
        )
    else:
        total_lines = 0

    console.print(f"[bold]{config['benchmark'].upper()}:[/bold] "
                  f"{config['total_test_cases']} files, {total_lines/1000:.1f} KLOC, "
                  f"{len(ground_truths)} ground truths")

    if binary:
        from rich.table import Table
        table = Table(title=f"Binary Classification: {config['benchmark']}", header_style="bold cyan")
        table.add_column("Agent", style="bold")
        table.add_column("Findings", justify="right")
        table.add_column("Precision", justify="right")
        table.add_column("Recall", justify="right")
        table.add_column("F1", justify="right")
        table.add_column("Accuracy", justify="right")
        table.add_column("TP", justify="right")
        table.add_column("FP", justify="right")
        table.add_column("FN", justify="right")
        table.add_column("TN", justify="right")

        for spec in agent:
            parts = spec.split(":")
            if len(parts) < 2:
                raise click.BadParameter(f"Agent spec must be name:path[:format], got '{spec}'")
            name = parts[0]
            path = ":".join(parts[1:-1]) if len(parts) > 2 else parts[1]
            findings = _parse_file(Path(path), "auto")
            r = _binary_evaluate(ground_truths, findings, name)
            table.add_row(name, str(r["findings"]),
                          f"{r['precision']:.1%}", f"{r['recall']:.1%}",
                          f"{r['f1']:.1%}", f"{r['accuracy']:.1%}",
                          str(r["tp"]), str(r["fp"]), str(r["fn"]), str(r["tn"]))
        console.print(table)
        # Show baseline
        vuln_count = sum(1 for g in ground_truths if g.is_vulnerable)
        safe_count = sum(1 for g in ground_truths if not g.is_vulnerable)
        total = vuln_count + safe_count
        bl_prec = vuln_count / total if total > 0 else 0
        bl_f1 = 2 * bl_prec / (bl_prec + 1) if total > 0 else 0
        console.print(
            f"\n  [dim]Dataset: {vuln_count} vulnerable, {safe_count} safe. "
            f"\"Flag everything\" baseline: P={bl_prec:.1%} R=100% F1={bl_f1:.1%}[/dim]"
        )
        console.print(
            f"  [dim]Precision at or below {bl_prec:.1%} indicates no discrimination between vulnerable and safe code.[/dim]"
        )
        return

    match_config = MatchingConfig(
        granularity=MatchGranularity(granularity),
        line_tolerance=line_tolerance,
        require_cwe_match=not no_cwe_match,
        allow_parent_cwe=allow_parent_cwe,
        require_line_number=require_line,
    )

    reports = []
    out = Path(output_dir)
    for spec in agent:
        parts = spec.split(":", 1)
        if len(parts) < 2:
            raise click.BadParameter(f"Agent spec must be name:path, got '{spec}'")
        name, path = parts[0], parts[1]

        findings = _parse_file(Path(path), "auto")
        engine = MatchingEngine(match_config)
        result = engine.match(findings, ground_truths)
        agent_report = calculate_metrics(result, name, config["benchmark"])
        reports.append(agent_report)

        m = agent_report.overall
        console.print(
            f"  {name:<16} {len(findings):>5} findings | "
            f"P={m.precision:.1%} R={m.recall:.1%} F1={m.f1:.1%} | "
            f"TP={m.true_positives} FP={m.false_positives} FN={m.false_negatives}"
        )

        if "json" in report or "html" in report:
            import re as _re
            safe = _re.sub(r'[^a-z0-9_-]', '', name.lower().replace(' ', '_'))
            if "json" in report:
                generate_json_report(agent_report, out / f"{safe}.json")
            if "html" in report:
                generate_html_report(agent_report, out / f"{safe}.html")

    if len(reports) >= 2:
        comparison = compare_agents(reports)
        if "console" in report:
            print_comparison_report(comparison, console=console)
        if "json" in report:
            p = generate_comparison_json(comparison, out / "comparison.json")
            console.print(f"[green]Comparison JSON: {p}[/green]")


@cli.command("head2head")
@click.option("--workspace", "-w", required=True, type=click.Path(exists=True), help="Path to prepared workspace")
@click.option("--agent", "-a", multiple=True, required=True, help="Agent: name:path")
@click.option("--granularity", type=click.Choice(["file", "function", "line"]), default="file")
@click.option("--line-tolerance", type=int, default=5, help="Line tolerance for matching")
@click.option("--no-cwe-match", is_flag=True, help="Don't require CWE match")
@click.option("--allow-parent-cwe", is_flag=True, help="Accept parent/child CWE matches")
@click.option("--require-line", is_flag=True, help="Require findings to include a start_line within tolerance of GT")
@click.option("--match-tolerance", type=int, default=5, help="Tolerance for agent-to-agent diff matching")
@click.option("--output-dir", type=click.Path(), default="./reports")
def head2head(
    workspace: str,
    agent: tuple[str, ...],
    granularity: str,
    line_tolerance: int,
    no_cwe_match: bool,
    allow_parent_cwe: bool,
    require_line: bool,
    match_tolerance: int,
    output_dir: str,
) -> None:
    """Full head-to-head: evaluate each agent against ground truth AND compare agents to each other.

    Combines three analyses in one report:
    1. Each agent's metrics against ground truth (precision, recall, F1)
    2. Rankings — which agent performed best on each metric
    3. Agent-vs-agent diff — what each agent finds that others miss

    Example:
        SASTBench head2head -w workspaces/bigvul
          -a "Sonnet:workspaces/bigvul/output_agent_a/findings.json"
          -a "Opus:workspaces/bigvul/output_agent_c/findings.json"
          -a "GPT-5.4:workspaces/bigvul/output_agent_d/findings.json"
    """
    from sastbench.matching.engine import MatchingEngine
    from sastbench.metrics.calculator import calculate_metrics
    from sastbench.metrics.comparison import compare_agents
    from sastbench.metrics.diff import diff_agents
    from sastbench.models import MatchGranularity, MatchingConfig
    from sastbench.reports.console import print_comparison_report, print_diff_report
    from sastbench.reports.json_report import generate_json_report, generate_comparison_json, generate_diff_json
    from sastbench.workspace import load_workspace_config, load_workspace_ground_truth
    from rich.table import Table

    ws_path = Path(workspace)
    ground_truths = load_workspace_ground_truth(ws_path)
    config = load_workspace_config(ws_path)
    vuln_count = sum(1 for g in ground_truths if g.is_vulnerable)
    safe_count = sum(1 for g in ground_truths if not g.is_vulnerable)

    code_dir = ws_path / "code"
    total_lines = sum(
        len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        for f in code_dir.iterdir() if f.is_file()
    ) if code_dir.exists() else 0

    console.rule(f"[bold blue]Head-to-Head: {config['benchmark'].upper()}")
    console.print(
        f"  {config['total_test_cases']} files, {total_lines/1000:.1f} KLOC, "
        f"{len(ground_truths)} GTs ({vuln_count} vuln, {safe_count} safe)\n"
    )

    # --- Part 1: Evaluate each agent against ground truth ---
    console.rule("[bold cyan]Part 1: Agent vs Ground Truth")

    match_config = MatchingConfig(
        granularity=MatchGranularity(granularity),
        line_tolerance=line_tolerance,
        require_cwe_match=not no_cwe_match,
        allow_parent_cwe=allow_parent_cwe,
        require_line_number=require_line,
    )

    reports = []
    all_findings = {}
    out = Path(output_dir)

    # Also do binary if dataset has safe files
    has_safe = safe_count > 0
    binary_results = []

    summary_table = Table(title="Agent vs Ground Truth", header_style="bold cyan")
    summary_table.add_column("Agent", style="bold")
    summary_table.add_column("Findings", justify="right")
    summary_table.add_column("Precision", justify="right")
    summary_table.add_column("Recall", justify="right")
    summary_table.add_column("F1", justify="right")
    summary_table.add_column("TP", justify="right")
    summary_table.add_column("FP", justify="right")
    summary_table.add_column("FN", justify="right")
    if has_safe:
        summary_table.add_column("Bin.Prec", justify="right")
        summary_table.add_column("Bin.F1", justify="right")

    for spec in agent:
        parts = spec.split(":")
        if len(parts) < 2:
            raise click.BadParameter(f"Agent spec must be name:path, got '{spec}'")
        name = parts[0]
        path = ":".join(parts[1:])  # Handle Windows drive letters

        findings = _parse_file(Path(path), "auto")
        all_findings[name] = findings

        engine = MatchingEngine(match_config)
        result = engine.match(findings, ground_truths)
        report = calculate_metrics(result, name, config["benchmark"])
        reports.append(report)
        m = report.overall

        row = [
            name, str(len(findings)),
            f"{m.precision:.1%}", f"{m.recall:.1%}", f"{m.f1:.1%}",
            str(m.true_positives), str(m.false_positives), str(m.false_negatives),
        ]

        if has_safe:
            br = _binary_evaluate(ground_truths, findings, name)
            binary_results.append(br)
            row.extend([f"{br['precision']:.1%}", f"{br['f1']:.1%}"])

        summary_table.add_row(*row)

    console.print(summary_table)

    if has_safe:
        total = vuln_count + safe_count
        bl_prec = vuln_count / total if total > 0 else 0
        bl_f1 = 2 * bl_prec / (bl_prec + 1) if total > 0 else 0
        console.print(
            f"\n  [dim]Binary baseline (\"flag everything\"): P={bl_prec:.1%} R=100% F1={bl_f1:.1%} — "
            f"precision at or below {bl_prec:.1%} indicates no discrimination.[/dim]"
        )

    # --- Part 2: Rankings ---
    if len(reports) >= 2:
        console.print()
        console.rule("[bold cyan]Part 2: Rankings")
        comparison = compare_agents(reports)
        print_comparison_report(comparison, console=console)
        generate_comparison_json(comparison, out / "head2head_comparison.json")

    # --- Part 3: Agent-vs-agent diff ---
    if len(all_findings) >= 2:
        console.print()
        console.rule("[bold cyan]Part 3: Agent vs Agent (what each uniquely finds)")
        diff_report = diff_agents(all_findings, match_tolerance=match_tolerance)
        print_diff_report(diff_report, console=console)
        generate_diff_json(diff_report, out / "head2head_diff.json")

        # Show which agent's unique findings are real (matched GT) vs noise (FP)
        if len(reports) >= 2:
            console.print()
            unique_table = Table(title="Unique Finding Quality (vs Ground Truth)", header_style="bold cyan")
            unique_table.add_column("Agent", style="bold")
            unique_table.add_column("Unique Finds", justify="right")
            unique_table.add_column("Unique TPs", justify="right")
            unique_table.add_column("Unique FPs", justify="right")
            unique_table.add_column("Quality", justify="right")

            # For each agent, check how many of their unique findings are real
            for i, (name, _) in enumerate([(parts.split(":")[0], None) for parts in agent]):
                if name not in diff_report.unique_findings:
                    unique_table.add_row(name, "0", "0", "0", "—")
                    continue
                unique = diff_report.unique_findings[name]
                if not unique:
                    unique_table.add_row(name, "0", "0", "0", "—")
                    continue

                # Check each unique finding against GT
                from sastbench.utils.normalize import normalize_path
                gt_vuln_paths = {normalize_path(g.file_path) for g in ground_truths if g.is_vulnerable}
                unique_tp = sum(1 for f in unique if normalize_path(f.file_path) in gt_vuln_paths)
                unique_fp = len(unique) - unique_tp
                quality = unique_tp / len(unique) if unique else 0

                unique_table.add_row(
                    name, str(len(unique)), str(unique_tp), str(unique_fp),
                    f"{quality:.0%}"
                )

            console.print(unique_table)
            console.print(
                "\n  [dim]\"Quality\" = fraction of agent's unique findings that match a real vulnerability. "
                "Higher means the agent is finding real bugs others miss, not just hallucinating.[/dim]"
            )

    console.print(f"\n[green]Reports saved to {out}/[/green]")


@cli.command("evaluate-all")
@click.argument("workspaces", nargs=-1, type=click.Path(exists=True))
@click.option("--granularity", type=click.Choice(["file", "function", "line"]), default="file")
@click.option("--line-tolerance", type=int, default=5)
@click.option("--no-cwe-match", is_flag=True, help="Don't require CWE match")
@click.option("--allow-parent-cwe", is_flag=True, help="Accept parent/child CWE matches")
@click.option("--require-line", is_flag=True, help="Require findings to include a start_line within tolerance of GT")
@click.option("--binary", is_flag=True, help="Binary classification mode")
@click.option("--output-dir", type=click.Path(), default="./reports")
def evaluate_all(
    workspaces: tuple[str, ...],
    granularity: str,
    line_tolerance: int,
    no_cwe_match: bool,
    allow_parent_cwe: bool,
    require_line: bool,
    binary: bool,
    output_dir: str,
) -> None:
    """Evaluate all agents across multiple workspaces in one command.

    Auto-detects agent outputs in each workspace's output_agent_*/ directories.

    Example:
        SASTBench evaluate-all workspaces/bigvul workspaces/primevul workspaces/castle
        SASTBench evaluate-all workspaces/* --binary
        SASTBench evaluate-all workspaces/* --no-cwe-match --granularity file
    """
    from sastbench.matching.engine import MatchingEngine
    from sastbench.metrics.calculator import calculate_metrics
    from sastbench.models import MatchGranularity, MatchingConfig
    from sastbench.workspace import load_workspace_config, load_workspace_ground_truth
    from rich.table import Table

    all_results = []

    for ws_str in workspaces:
        ws_path = Path(ws_str)
        try:
            ground_truths = load_workspace_ground_truth(ws_path)
            config = load_workspace_config(ws_path)
        except FileNotFoundError:
            console.print(f"[yellow]Skipping {ws_path.name} — not a SASTBench workspace[/yellow]")
            continue

        code_dir = ws_path / "code"
        if code_dir.exists():
            total_lines = sum(
                len(f.read_text(encoding="utf-8", errors="replace").splitlines())
                for f in code_dir.iterdir() if f.is_file()
            )
        else:
            total_lines = 0
        vuln_gt = sum(1 for g in ground_truths if g.is_vulnerable)
        bench = config["benchmark"]

        console.print(f"\n[bold]{bench.upper()}:[/bold] {config['total_test_cases']} files, "
                      f"{total_lines/1000:.1f} KLOC, {len(ground_truths)} GTs ({vuln_gt} vuln)")

        agents = _detect_agents(ws_path)
        if not agents:
            console.print("  [yellow]No agent outputs found[/yellow]")
            continue

        for agent_name, findings_path in agents:
            findings = _parse_file(findings_path, "auto")

            if binary:
                r = _binary_evaluate(ground_truths, findings, agent_name)
                console.print(
                    f"  {agent_name:<16} {r['findings']:>5} finds | "
                    f"P={r['precision']:.1%} R={r['recall']:.1%} F1={r['f1']:.1%} Acc={r['accuracy']:.1%} | "
                    f"TP={r['tp']} FP={r['fp']} FN={r['fn']} TN={r['tn']}"
                )
                all_results.append({"benchmark": bench, "kloc": round(total_lines/1000, 1),
                                     "gts": len(ground_truths), "mode": "binary", **r})
            else:
                mcfg = MatchingConfig(
                    granularity=MatchGranularity(granularity),
                    line_tolerance=line_tolerance,
                    require_cwe_match=not no_cwe_match,
                    allow_parent_cwe=allow_parent_cwe,
                    require_line_number=require_line,
                )
                result = MatchingEngine(mcfg).match(findings, ground_truths)
                report = calculate_metrics(result, agent_name, bench)
                m = report.overall
                console.print(
                    f"  {agent_name:<16} {len(findings):>5} finds | "
                    f"P={m.precision:.1%} R={m.recall:.1%} F1={m.f1:.1%} | "
                    f"TP={m.true_positives} FP={m.false_positives} FN={m.false_negatives}"
                )
                all_results.append({
                    "benchmark": bench, "kloc": round(total_lines/1000, 1),
                    "gts": len(ground_truths), "agent": agent_name, "mode": "matching",
                    "findings": len(findings), "precision": round(m.precision, 3),
                    "recall": round(m.recall, 3), "f1": round(m.f1, 3),
                    "tp": m.true_positives, "fp": m.false_positives, "fn": m.false_negatives,
                })

    # Save summary
    if all_results:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        p = out / "evaluate_all_summary.json"
        p.write_text(json.dumps(all_results, indent=2, default=str), encoding="utf-8")
        console.print(f"\n[green]Summary saved: {p}[/green]")


@cli.command()
@click.argument("report_dirs", nargs=-1, type=click.Path(exists=True))
def summary(report_dirs: tuple[str, ...]) -> None:
    """Generate a summary table from existing evaluation report JSONs.

    Pass one or more report directories containing evaluation JSON files.

    Example:
        SASTBench summary reports/juliet reports/bigvul
    """
    from rich.table import Table

    all_reports = []
    for report_dir in report_dirs:
        rd = Path(report_dir)
        for json_file in sorted(rd.glob("*.json")):
            if json_file.name in ("comparison.json", "comparison_4way.json",
                                   "diff_report.json", "diff.json",
                                   "full_summary.json", "full_summary_4way.json"):
                continue
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                if "agent_name" in data and "overall" in data:
                    all_reports.append(data)
            except (json.JSONDecodeError, KeyError):
                continue

    if not all_reports:
        console.print("[yellow]No evaluation reports found.[/yellow]")
        return

    table = Table(title="SASTBench Summary", show_header=True, header_style="bold cyan")
    table.add_column("Benchmark", style="bold")
    table.add_column("Agent", style="bold")
    table.add_column("Findings", justify="right")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")
    table.add_column("TP", justify="right")
    table.add_column("FP", justify="right")
    table.add_column("FN", justify="right")

    for r in all_reports:
        m = r["overall"]
        table.add_row(
            r.get("benchmark_name", "?"),
            r.get("agent_name", "?"),
            str(r.get("total_findings", "?")),
            f"{m['precision']:.1%}",
            f"{m['recall']:.1%}",
            f"{m['f1']:.1%}",
            str(m.get("true_positives", "?")),
            str(m.get("false_positives", "?")),
            str(m.get("false_negatives", "?")),
        )

    console.print(table)


@cli.command()
@click.argument("workspace", type=click.Path(exists=True))
def status(workspace: str) -> None:
    """Show which agents have written output and basic stats for a workspace.

    Example:
        SASTBench status workspaces/bigvul_full
    """
    from collections import Counter

    from rich.table import Table

    from sastbench.workspace import _find_evaluator_dir

    ws_path = Path(workspace)

    # Load evaluator config & GT
    try:
        evaluator_dir = _find_evaluator_dir(ws_path)
        config = json.loads((evaluator_dir / "config.json").read_text(encoding="utf-8"))
        gt = json.loads((evaluator_dir / "ground_truth.json").read_text(encoding="utf-8"))
        benchmark = config.get("benchmark", ws_path.name)
        total_gts = len(gt)
    except FileNotFoundError:
        benchmark = ws_path.name
        config = {}
        total_gts = 0

    # Count code files and KLOC
    code_dir = ws_path / "code"
    code_files = list(code_dir.iterdir()) if code_dir.exists() else []
    num_files = len(code_files)
    total_lines = sum(
        len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        for f in code_files if f.is_file()
    )
    kloc = total_lines / 1000

    console.print(
        f"[bold]{benchmark.upper()}:[/bold] {num_files} files, {kloc:.1f} KLOC, {total_gts} GTs"
    )

    # Scan for output_*/ directories
    output_dirs = sorted(
        d for d in ws_path.iterdir()
        if d.is_dir() and d.name.startswith("output_")
    )
    if not output_dirs:
        # Also check the default output/ directory
        out = ws_path / "output"
        if out.is_dir():
            output_dirs = [out]

    if not output_dirs:
        console.print("  [yellow]No output directories found[/yellow]")
        return

    for d in output_dirs:
        # Look for findings files
        findings_file = None
        for fname in ["findings.json", "findings.sarif", "findings.csv"]:
            p = d / fname
            if p.exists() and p.stat().st_size > 10:
                findings_file = p
                break

        if findings_file is None:
            console.print(f"  [red]✗[/red] {d.name}:   pending")
            continue

        # Count findings and extract agent name
        try:
            findings = _parse_file(findings_file, "auto")
            agent_name = d.name
            try:
                data = json.loads(findings_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    agent_name = data.get("agent_name", d.name)
            except Exception:
                pass
            console.print(
                f"  [green]✓[/green] {d.name}:  {len(findings)} findings ({agent_name})"
            )
        except Exception as e:
            console.print(f"  [red]✗[/red] {d.name}:   error: {e}")


@cli.command()
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--workspace", "-w", type=click.Path(exists=True), help="Workspace path for file coverage stats")
def analyze(findings_file: str, workspace: str | None) -> None:
    """Detailed analysis of a single agent's findings file.

    Example:
        SASTBench analyze workspaces/bigvul_full/output_sonnet46/findings.json
        SASTBench analyze findings.json --workspace workspaces/bigvul_full
    """
    from collections import Counter

    from rich.table import Table

    findings_path = Path(findings_file)
    findings = _parse_file(findings_path, "auto")

    if not findings:
        console.print("[yellow]No findings in file.[/yellow]")
        return

    # Basic stats
    total = len(findings)
    unique_files = len({f.file_path for f in findings})
    fpf = total / unique_files if unique_files > 0 else 0

    console.print(f"[bold]Findings:[/bold] {total}")
    console.print(f"[bold]Unique files flagged:[/bold] {unique_files}")
    console.print(f"[bold]Findings per file:[/bold] {fpf:.2f}")

    # CWE distribution (top 15)
    cwe_counts = Counter(f.cwe_id for f in findings if f.cwe_id)
    if cwe_counts:
        table = Table(title="CWE Distribution (top 15)", header_style="bold cyan")
        table.add_column("CWE", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Pct", justify="right")
        for cwe, count in cwe_counts.most_common(15):
            table.add_row(cwe, str(count), f"{count / total:.1%}")
        console.print(table)

    # Severity distribution
    sev_counts = Counter(f.severity.value if f.severity else "unknown" for f in findings)
    if sev_counts:
        table = Table(title="Severity Distribution", header_style="bold cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Pct", justify="right")
        for sev in ["critical", "high", "medium", "low", "info", "unknown"]:
            if sev in sev_counts:
                table.add_row(sev, str(sev_counts[sev]), f"{sev_counts[sev] / total:.1%}")
        console.print(table)

    # Confidence stats
    confidences = [f.confidence for f in findings if f.confidence is not None]
    if confidences:
        avg_c = sum(confidences) / len(confidences)
        min_c = min(confidences)
        max_c = max(confidences)
        console.print(f"\n[bold]Confidence:[/bold] avg={avg_c:.3f}, min={min_c:.3f}, max={max_c:.3f} (n={len(confidences)})")

        # Histogram buckets
        buckets = {"0.0–0.2": 0, "0.2–0.4": 0, "0.4–0.6": 0, "0.6–0.8": 0, "0.8–1.0": 0}
        for c in confidences:
            if c < 0.2:
                buckets["0.0–0.2"] += 1
            elif c < 0.4:
                buckets["0.2–0.4"] += 1
            elif c < 0.6:
                buckets["0.4–0.6"] += 1
            elif c < 0.8:
                buckets["0.6–0.8"] += 1
            else:
                buckets["0.8–1.0"] += 1
        table = Table(title="Confidence Histogram", header_style="bold cyan")
        table.add_column("Bucket")
        table.add_column("Count", justify="right")
        for bucket, count in buckets.items():
            table.add_row(bucket, str(count))
        console.print(table)

    # File coverage (if workspace provided)
    if workspace:
        ws_path = Path(workspace)
        code_dir = ws_path / "code"
        if code_dir.exists():
            from sastbench.utils.normalize import normalize_path

            all_code_files = {normalize_path(f"code/{f.name}") for f in code_dir.iterdir() if f.is_file()}
            flagged_files = {normalize_path(f.file_path) for f in findings}
            covered = len(flagged_files & all_code_files)
            total_code = len(all_code_files)
            console.print(
                f"\n[bold]File coverage:[/bold] {covered}/{total_code} "
                f"({covered / total_code:.1%})" if total_code > 0 else
                "\n[bold]File coverage:[/bold] no code files found"
            )


@cli.command()
@click.argument("workspace", type=click.Path(exists=True))
def audit(workspace: str) -> None:
    """Check for GT leakage — does any agent's CWE distribution suspiciously match the ground truth?

    Example:
        SASTBench audit workspaces/bigvul_full
    """
    from collections import Counter

    from rich.table import Table

    from sastbench.workspace import _find_evaluator_dir

    ws_path = Path(workspace)

    # Load GT
    try:
        evaluator_dir = _find_evaluator_dir(ws_path)
        gt_data = json.loads((evaluator_dir / "ground_truth.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        console.print("[red]No evaluator data found for this workspace.[/red]")
        return

    gt_cwe_counts = Counter(g.get("cwe_id", "unknown") for g in gt_data if g.get("is_vulnerable", True))
    gt_total = sum(gt_cwe_counts.values())
    gt_file_count = len({g.get("file_path") for g in gt_data if g.get("is_vulnerable", True)})

    console.print(f"[bold]Ground Truth:[/bold] {gt_total} vulnerable GTs, {len(gt_cwe_counts)} CWEs, {gt_file_count} files")

    # Scan output directories
    output_dirs = sorted(
        d for d in ws_path.iterdir()
        if d.is_dir() and d.name.startswith("output_")
    )
    if not output_dirs:
        out = ws_path / "output"
        if out.is_dir():
            output_dirs = [out]

    if not output_dirs:
        console.print("  [yellow]No agent outputs to audit[/yellow]")
        return

    table = Table(title="GT Leakage Audit", header_style="bold cyan")
    table.add_column("Agent", style="bold")
    table.add_column("Findings", justify="right")
    table.add_column("CWE Corr", justify="right")
    table.add_column("Count Match", justify="center")
    table.add_column("Conf Uniform", justify="center")
    table.add_column("Flags", style="bold")

    for d in output_dirs:
        findings_file = None
        for fname in ["findings.json", "findings.sarif", "findings.csv"]:
            p = d / fname
            if p.exists() and p.stat().st_size > 10:
                findings_file = p
                break
        if findings_file is None:
            continue

        try:
            findings = _parse_file(findings_file, "auto")
        except Exception:
            continue

        flags = []

        # CWE distribution correlation
        agent_cwe_counts = Counter(f.cwe_id for f in findings if f.cwe_id)
        all_cwes = sorted(set(gt_cwe_counts.keys()) | set(agent_cwe_counts.keys()))
        if len(all_cwes) >= 2:
            gt_vec = [gt_cwe_counts.get(c, 0) for c in all_cwes]
            agent_vec = [agent_cwe_counts.get(c, 0) for c in all_cwes]
            # Pearson correlation
            n = len(all_cwes)
            mean_gt = sum(gt_vec) / n
            mean_ag = sum(agent_vec) / n
            cov = sum((g - mean_gt) * (a - mean_ag) for g, a in zip(gt_vec, agent_vec))
            std_gt = (sum((g - mean_gt) ** 2 for g in gt_vec)) ** 0.5
            std_ag = (sum((a - mean_ag) ** 2 for a in agent_vec)) ** 0.5
            corr = cov / (std_gt * std_ag) if std_gt > 0 and std_ag > 0 else 0.0
        else:
            corr = 0.0

        if corr > 0.95:
            flags.append("HIGH CWE CORR")
        corr_str = f"{corr:.3f}"

        # Exact count match
        count_match = len(findings) == gt_total
        if count_match:
            flags.append("EXACT COUNT")
        count_str = "⚠ YES" if count_match else "no"

        # Confidence uniformity
        confidences = [f.confidence for f in findings if f.confidence is not None]
        if confidences and len(set(confidences)) == 1:
            flags.append("UNIFORM CONF")
            conf_str = f"⚠ all {confidences[0]:.2f}"
        elif confidences:
            conf_str = "varied"
        else:
            conf_str = "n/a"

        flag_str = ", ".join(flags) if flags else "[green]clean[/green]"
        if flags:
            flag_str = f"[red]{flag_str}[/red]"

        table.add_row(d.name, str(len(findings)), corr_str, count_str, conf_str, flag_str)

    console.print(table)


@cli.command()
@click.argument("workspace", type=click.Path(exists=True))
def verify(workspace: str) -> None:
    """Verify workspace integrity after preparation.

    Checks file counts, GT path validity, ordering bias, and essential files.

    Example:
        SASTBench verify workspaces/bigvul_full
    """
    from collections import Counter

    from sastbench.workspace import _find_evaluator_dir

    ws_path = Path(workspace)
    name = ws_path.name
    issues: list[str] = []

    # Check essential files
    for required in ["AGENTS.md", "manifest.json", "output_schema.json"]:
        if not (ws_path / required).exists():
            issues.append(f"Missing {required}")

    for required_dir in ["code", "output"]:
        if not (ws_path / required_dir).is_dir():
            issues.append(f"Missing directory {required_dir}/")

    # Check evaluator data
    try:
        evaluator_dir = _find_evaluator_dir(ws_path)
    except FileNotFoundError:
        issues.append("No evaluator data found (run 'SASTBench prepare' first)")
        for issue in issues:
            console.print(f"  [red]⚠[/red] [{name}] {issue}")
        console.print(f"\n[red]❌ FAIL[/red] {name}: {len(issues)} issue(s)")
        raise SystemExit(1)

    config_path = evaluator_dir / "config.json"
    gt_path = evaluator_dir / "ground_truth.json"
    mapping_path = evaluator_dir / "file_mapping.json"

    for p, label in [(config_path, "config.json"), (gt_path, "ground_truth.json"), (mapping_path, "file_mapping.json")]:
        if not p.exists():
            issues.append(f"Missing evaluator data: {label}")

    if not config_path.exists() or not gt_path.exists() or not mapping_path.exists():
        for issue in issues:
            console.print(f"  [red]⚠[/red] [{name}] {issue}")
        console.print(f"\n[red]❌ FAIL[/red] {name}: {len(issues)} issue(s)")
        raise SystemExit(1)

    config = json.loads(config_path.read_text(encoding="utf-8"))
    gt = json.loads(gt_path.read_text(encoding="utf-8"))
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))

    # Check file counts
    code_dir = ws_path / "code"
    code_files = list(code_dir.iterdir()) if code_dir.exists() else []
    expected = config["total_test_cases"]
    if len(code_files) != expected:
        issues.append(f"Code files: {len(code_files)} (expected {expected})")

    if len(mapping) != expected:
        issues.append(f"Mapping entries: {len(mapping)} (expected {expected})")

    # Check GT paths reference actual code files
    code_paths = {f"code/{f.name}" for f in code_files}
    gt_paths = {g["file_path"] for g in gt}
    unmapped = gt_paths - code_paths
    if unmapped:
        issues.append(f"{len(unmapped)} GT paths not in code/: {list(unmapped)[:3]}")

    # Check ordering bias (for paired datasets)
    vuln_gts = [g for g in gt if g.get("is_vulnerable", True)]
    safe_gts = [g for g in gt if not g.get("is_vulnerable", True)]

    if vuln_gts and safe_gts:
        vuln_nums = []
        safe_nums = []
        for g in gt:
            try:
                num = int(g["file_path"].split("_")[1].split(".")[0])
                if g.get("is_vulnerable", True):
                    vuln_nums.append(num)
                else:
                    safe_nums.append(num)
            except (IndexError, ValueError):
                continue

        if vuln_nums and safe_nums:
            vuln_odd = sum(1 for n in vuln_nums if n % 2 == 1)
            vuln_even = sum(1 for n in vuln_nums if n % 2 == 0)
            ratio = vuln_odd / max(vuln_even, 1)
            if ratio > 3.0 or ratio < 0.33:
                issues.append(f"Ordering bias: vuln odd/even = {vuln_odd}/{vuln_even} (ratio {ratio:.1f})")

    # CWE and summary stats
    cwes = Counter(g.get("cwe_id", "unknown") for g in gt)
    total_lines = sum(
        len(f.read_text(encoding="utf-8", errors="replace").splitlines())
        for f in code_files if f.is_file()
    )

    if issues:
        for issue in issues:
            console.print(f"  [red]⚠[/red] [{name}] {issue}")
        console.print(
            f"\n[red]❌ FAIL[/red] {name}: {len(code_files)} files, {total_lines / 1000:.1f} KLOC, "
            f"{len(gt)} GTs ({len(vuln_gts)} vuln, {len(safe_gts)} safe), {len(cwes)} CWEs — "
            f"{len(issues)} issue(s)"
        )
        raise SystemExit(1)
    else:
        console.print(
            f"[green]✅ PASS[/green] {name}: {len(code_files)} files, {total_lines / 1000:.1f} KLOC, "
            f"{len(gt)} GTs ({len(vuln_gts)} vuln, {len(safe_gts)} safe), {len(cwes)} CWEs"
        )


@cli.command("gt-quality")
@click.argument("workspace", type=click.Path(exists=True))
def gt_quality(workspace: str) -> None:
    """Analyze ground truth data quality to explain unexpected model scores.

    Runs 5 checks: suspect safe labels, suspect vulnerable labels,
    trivial files, near-duplicates, and adjusted scores.

    Example:
        SASTBench gt-quality workspaces/bigvul_mixed
    """
    import hashlib
    from collections import defaultdict

    from rich.table import Table

    from sastbench.parsers import detect_and_parse
    from sastbench.utils.normalize import normalize_path
    from sastbench.workspace import _find_evaluator_dir

    ws_path = Path(workspace)

    # --- Load ground truth ---
    try:
        evaluator_dir = _find_evaluator_dir(ws_path)
        gt_data = json.loads(
            (evaluator_dir / "ground_truth.json").read_text(encoding="utf-8")
        )
    except FileNotFoundError:
        console.print("[red]No evaluator data found for this workspace.[/red]")
        return

    gt_vuln_paths: set[str] = set()
    gt_safe_paths: set[str] = set()
    for g in gt_data:
        p = normalize_path(g["file_path"])
        if g.get("is_vulnerable", True):
            gt_vuln_paths.add(p)
        else:
            gt_safe_paths.add(p)

    # --- Load all agent outputs ---
    agents = _detect_agents(ws_path)
    if not agents:
        console.print("[yellow]No agent outputs found — checks 1, 2, and 5 require agent data.[/yellow]")

    # Build per-file flagging info: path -> list of agent names
    file_flagged_by: dict[str, list[str]] = defaultdict(list)
    agent_findings_map: dict[str, set[str]] = {}

    for agent_name, findings_path in agents:
        try:
            findings = detect_and_parse(findings_path)
        except Exception:
            continue
        flagged: set[str] = set()
        for f in findings:
            np = normalize_path(f.file_path)
            flagged.add(np)
            file_flagged_by[np].append(agent_name)
        agent_findings_map[agent_name] = flagged

    total_agents = len(agent_findings_map)

    # ================================================================
    # Check 1: Suspect Safe Labels (multi-model consensus)
    # ================================================================
    console.print("\n[bold cyan]Check 1: Suspect Safe Labels[/bold cyan]")
    console.print("[dim](agents agree file is vulnerable, GT says safe)[/dim]\n")

    suspect_safe: list[tuple[str, list[str]]] = []
    for path in sorted(gt_safe_paths):
        flaggers = file_flagged_by.get(path, [])
        if len(flaggers) >= 2:
            suspect_safe.append((path, flaggers))

    if suspect_safe and total_agents > 0:
        for path, flaggers in suspect_safe:
            names = ", ".join(sorted(set(flaggers)))
            console.print(
                f"  {path} — flagged by {len(set(flaggers))}/{total_agents} agents ({names})"
            )
        pct = len(suspect_safe) / max(len(gt_safe_paths), 1) * 100
        console.print(
            f"\n  [bold]Total: {len(suspect_safe)} suspect files out of "
            f"{len(gt_safe_paths)} safe files ({pct:.1f}%)[/bold]"
        )
    elif not agents:
        console.print("  [yellow]Skipped — no agent outputs[/yellow]")
    else:
        console.print("  [green]No suspect safe labels found.[/green]")

    # ================================================================
    # Check 2: Suspect Vulnerable Labels (no model finds anything)
    # ================================================================
    console.print("\n[bold cyan]Check 2: Suspect Vulnerable Labels[/bold cyan]")
    console.print("[dim](no agent found anything, GT says vulnerable)[/dim]\n")

    suspect_vuln: list[str] = []
    if agents:
        for path in sorted(gt_vuln_paths):
            flaggers = file_flagged_by.get(path, [])
            if len(flaggers) == 0:
                suspect_vuln.append(path)

        if suspect_vuln:
            for path in suspect_vuln:
                console.print(f"  {path} — 0/{total_agents} agents flagged it")
            pct = len(suspect_vuln) / max(len(gt_vuln_paths), 1) * 100
            console.print(
                f"\n  [bold]Total: {len(suspect_vuln)} suspect files out of "
                f"{len(gt_vuln_paths)} vulnerable files ({pct:.1f}%)[/bold]"
            )
        else:
            console.print("  [green]No suspect vulnerable labels found.[/green]")
    else:
        console.print("  [yellow]Skipped — no agent outputs[/yellow]")

    # ================================================================
    # Check 3: Trivial / Empty Files
    # ================================================================
    console.print("\n[bold cyan]Check 3: Trivial / Empty Files[/bold cyan]")
    console.print("[dim](< 3 lines or < 50 characters)[/dim]\n")

    code_dir = ws_path / "code"
    trivial_files: list[tuple[str, int, str]] = []
    total_code_files = 0

    if code_dir.is_dir():
        for f in sorted(code_dir.iterdir()):
            if not f.is_file():
                continue
            total_code_files += 1
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            lines = len(content.splitlines())
            chars = len(content)
            if lines < 3 or chars < 50:
                np = normalize_path(f"code/{f.name}")
                label = "vulnerable" if np in gt_vuln_paths else "safe"
                trivial_files.append((f.name, lines, label))

    if trivial_files:
        for name, lines, label in trivial_files:
            console.print(f"  code/{name} — {lines} line(s) (GT: {label})")
        pct = len(trivial_files) / max(total_code_files, 1) * 100
        console.print(
            f"\n  [bold]Total: {len(trivial_files)} trivial files ({pct:.1f}%)[/bold]"
        )
    else:
        console.print("  [green]No trivial files found.[/green]")

    # ================================================================
    # Check 4: Near-Duplicate Detection
    # ================================================================
    console.print("\n[bold cyan]Check 4: Near-Duplicate Detection[/bold cyan]")
    console.print("[dim](identical first-500-char content hash)[/dim]\n")

    hash_groups: dict[str, list[str]] = defaultdict(list)
    if code_dir.is_dir():
        for f in sorted(code_dir.iterdir()):
            if not f.is_file():
                continue
            try:
                content = f.read_text(encoding="utf-8", errors="replace")[:500]
            except Exception:
                continue
            h = hashlib.sha256(content.encode("utf-8")).hexdigest()
            hash_groups[h].append(f.name)

    dup_groups = {h: names for h, names in hash_groups.items() if len(names) > 1}
    if dup_groups:
        dup_file_count = 0
        for i, (_, names) in enumerate(sorted(dup_groups.items()), 1):
            labels = set()
            for name in names:
                np = normalize_path(f"code/{name}")
                labels.add("vuln" if np in gt_vuln_paths else "safe")
            label_str = "/".join(sorted(labels))
            console.print(f"  Group {i}: {', '.join(names)} ({label_str})")
            dup_file_count += len(names)
        console.print(
            f"\n  [bold]Total: {len(dup_groups)} duplicate groups "
            f"affecting {dup_file_count} files[/bold]"
        )
    else:
        console.print("  [green]No near-duplicates found.[/green]")

    # ================================================================
    # Check 5: Adjusted Scores
    # ================================================================
    console.print("\n[bold cyan]Check 5: Adjusted Scores[/bold cyan]")
    console.print("[dim](what if suspect labels were corrected?)[/dim]\n")

    suspect_safe_set = {s[0] for s in suspect_safe}
    suspect_vuln_set = set(suspect_vuln)

    if not agents:
        console.print("  [yellow]Skipped — no agent outputs[/yellow]")
    elif not suspect_safe_set and not suspect_vuln_set:
        console.print("  [green]No suspect labels — raw and adjusted scores are identical.[/green]")
    else:
        # Adjusted GT: suspect safe->vuln, suspect vuln->safe
        adj_vuln = (gt_vuln_paths - suspect_vuln_set) | suspect_safe_set
        adj_safe = (gt_safe_paths - suspect_safe_set) | suspect_vuln_set

        table = Table(
            title="Raw vs Adjusted Metrics",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Agent", style="bold")
        table.add_column("Raw P", justify="right")
        table.add_column("Raw R", justify="right")
        table.add_column("Raw F1", justify="right")
        table.add_column("Adj P", justify="right")
        table.add_column("Adj R", justify="right")
        table.add_column("Adj F1", justify="right")

        for agent_name, flagged in sorted(agent_findings_map.items()):
            # Raw metrics
            raw_tp = len(flagged & gt_vuln_paths)
            raw_fp = len(flagged & gt_safe_paths)
            raw_fn = len(gt_vuln_paths - flagged)
            raw_p = raw_tp / (raw_tp + raw_fp) if (raw_tp + raw_fp) else 0.0
            raw_r = raw_tp / (raw_tp + raw_fn) if (raw_tp + raw_fn) else 0.0
            raw_f1 = 2 * raw_p * raw_r / (raw_p + raw_r) if (raw_p + raw_r) else 0.0

            # Adjusted metrics
            adj_tp = len(flagged & adj_vuln)
            adj_fp = len(flagged & adj_safe)
            adj_fn = len(adj_vuln - flagged)
            adj_p = adj_tp / (adj_tp + adj_fp) if (adj_tp + adj_fp) else 0.0
            adj_r = adj_tp / (adj_tp + adj_fn) if (adj_tp + adj_fn) else 0.0
            adj_f1 = 2 * adj_p * adj_r / (adj_p + adj_r) if (adj_p + adj_r) else 0.0

            table.add_row(
                agent_name,
                f"{raw_p:.1%}", f"{raw_r:.1%}", f"{raw_f1:.1%}",
                f"{adj_p:.1%}", f"{adj_r:.1%}", f"{adj_f1:.1%}",
            )

        console.print(table)
        console.print(
            f"\n  [dim]Adjustments: {len(suspect_safe_set)} safe->vuln, "
            f"{len(suspect_vuln_set)} vuln->safe[/dim]"
        )


@cli.command("list-benchmarks")
def list_benchmarks_cmd() -> None:
    """List available benchmark datasets."""
    from sastbench.adapters import list_benchmarks

    benchmarks = list_benchmarks()
    from rich.table import Table

    table = Table(title="Available Benchmarks", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Languages")
    table.add_column("URL")

    for b in benchmarks:
        table.add_row(
            b["name"],
            b["description"],
            ", ".join(b["languages"]) if b["languages"] else "—",
            b["url"] or "—",
        )

    console.print(table)


@cli.command("list-prompts")
def list_prompts_cmd() -> None:
    """List available prompt templates for vulnerability analysis."""
    from sastbench.prompt_templates import list_prompt_templates
    from rich.table import Table

    templates = list_prompt_templates()
    table = Table(title="Prompt Templates", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="bold")
    table.add_column("Description")
    table.add_column("Size")

    for t in templates:
        table.add_row(t["name"], t["description"], f"{t['length']} chars")

    console.print(table)
    console.print("\n  [dim]Use with: SASTBench run --prompt-template <name>[/dim]")
    console.print("  [dim]Or provide a custom file path: --prompt-template /path/to/prompt.txt[/dim]")


@cli.command("show-prompt")
@click.argument("name", default="default")
def show_prompt_cmd(name: str) -> None:
    """Show the contents of a prompt template."""
    from sastbench.prompt_templates import get_prompt_template

    try:
        content = get_prompt_template(name)
        console.print(f"[bold]Prompt template: {name}[/bold]\n")
        console.print(content)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)


@cli.command("show-run-prompt")
@click.argument("workspace", type=click.Path(exists=True))
@click.option("--agent-name", default="Agent", help="Name for the agent (used in output path and JSON)")
@click.option("--output-dir", default=None, help="Output subdirectory name (e.g. output_sonnet46)")
@click.option("--prompt-template", default=None, help="Override the saved prompt template (e.g. default, thorough)")
def show_run_prompt_cmd(
    workspace: str,
    agent_name: str,
    output_dir: str | None,
    prompt_template: str | None,
) -> None:
    """Generate the exact prompt to send to an agent for a workspace.

    Combines the analysis prompt template, workspace instructions, and output
    path into a single copy-pasteable block.  No more ad-hoc prompt writing.

    Example:

        SASTBench show-run-prompt workspaces/bigvul_real --agent-name "Sonnet 4.6" --output-dir output_sonnet46
    """
    from sastbench.workspace import build_run_prompt

    try:
        prompt = build_run_prompt(
            Path(workspace),
            agent_name=agent_name,
            output_dir=output_dir,
            prompt_template=prompt_template,
        )
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]{e}[/red]")
        raise SystemExit(1)

    # Print raw text so it can be piped / copied directly
    click.echo(prompt)


@cli.group()
def cache() -> None:
    """Manage benchmark data cache."""


@cache.command("list")
def cache_list() -> None:
    """Show cached benchmark datasets."""
    from sastbench.utils.cache import get_default_cache_dir

    cache_dir = get_default_cache_dir()
    if not cache_dir.exists():
        console.print("No cache directory found.")
        return

    from rich.table import Table

    table = Table(title=f"Cache: {cache_dir}", show_header=True)
    table.add_column("Benchmark")
    table.add_column("Size")

    total = 0
    for child in sorted(cache_dir.iterdir()):
        if child.is_dir():
            size = sum(f.stat().st_size for f in child.rglob("*") if f.is_file())
            total += size
            table.add_row(child.name, f"{size / 1024 / 1024:.1f} MB")

    console.print(table)
    console.print(f"Total: {total / 1024 / 1024:.1f} MB")


@cache.command("clear")
@click.option("--benchmark", help="Clear specific benchmark only")
@click.confirmation_option(prompt="Are you sure you want to clear the cache?")
def cache_clear(benchmark: str | None) -> None:
    """Clear cached benchmark data."""
    import shutil

    from sastbench.utils.cache import get_default_cache_dir

    cache_dir = get_default_cache_dir()
    if benchmark:
        target = (cache_dir / benchmark).resolve()
        if not str(target).startswith(str(cache_dir.resolve())):
            raise click.BadParameter("Invalid benchmark name")
        if target.exists():
            shutil.rmtree(target)
            console.print(f"Cleared cache for {benchmark}")
        else:
            console.print(f"No cache found for {benchmark}")
    else:
        if cache_dir.exists():
            shutil.rmtree(cache_dir)
            console.print("Cache cleared")


# ---- Helpers ----

def _load_agent_output(
    ws_path: Path, agent_output: str | None, fmt: str
) -> list:
    """Load agent findings from workspace output dir or explicit path."""
    from sastbench.models import Finding

    if agent_output:
        return _parse_file(Path(agent_output), fmt)

    # Auto-detect from workspace/output/
    output_dir = ws_path / "output"
    for name in ["findings.json", "findings.sarif", "findings.csv"]:
        p = output_dir / name
        if p.exists():
            detected_fmt = name.rsplit(".", 1)[-1]
            if detected_fmt == "sarif":
                detected_fmt = "sarif"
            return _parse_file(p, detected_fmt)

    console.print("[red]No agent output found in workspace/output/[/red]")
    raise click.UsageError("No agent output found in workspace/output/")
    return []  # unreachable, kept for type checker


def _parse_file(path: Path, fmt: str) -> list:
    """Parse a findings file."""
    from sastbench.parsers import detect_and_parse

    if fmt and fmt != "auto":
        from sastbench.parsers.csv_parser import CsvParser
        from sastbench.parsers.json_parser import JsonParser
        from sastbench.parsers.sarif_parser import SarifParser

        parser_map = {
            "sarif": SarifParser(),
            "json": JsonParser(),
            "csv": CsvParser(),
        }
        parser = parser_map.get(fmt)
        if parser:
            return parser.parse(path)

    return detect_and_parse(path)


def _binary_evaluate(ground_truths, findings, agent_name: str, *, workspace_path: Path | None = None) -> dict:
    """Binary classification: did agent flag vulnerable files and skip safe ones?

    Returns dict with TP, FP, FN, TN, precision, recall, F1, accuracy,
    plus baseline metrics for a "flag everything" strategy.
    Used when ground truth has unknown CWEs (e.g., PrimeVul with CWE-000).

    Findings on paths outside the ground-truth universe are counted as
    additional false positives.  When *workspace_path* is given, a warning
    is emitted for any GT file that doesn't exist in the workspace code dir.
    """
    from sastbench.utils.normalize import normalize_path

    gt_vuln = {normalize_path(g.file_path) for g in ground_truths if g.is_vulnerable}
    gt_safe = {normalize_path(g.file_path) for g in ground_truths if not g.is_vulnerable}
    gt_universe = gt_vuln | gt_safe
    flagged = {normalize_path(f.file_path) for f in findings}

    # Validate GT files exist in workspace when path is provided
    if workspace_path is not None:
        code_dir = workspace_path / "code"
        if code_dir.is_dir():
            existing = {normalize_path(str(p.relative_to(code_dir))) for p in code_dir.rglob("*") if p.is_file()}
            missing = gt_universe - existing
            if missing:
                logger.warning(
                    "%d ground-truth files not found in workspace code dir: %s",
                    len(missing),
                    list(missing)[:10],
                )

    # Findings on unknown paths count as false positives
    out_of_universe = flagged - gt_universe

    tp = len(flagged & gt_vuln)
    fp = len(flagged & gt_safe) + len(out_of_universe)
    fn = len(gt_vuln - flagged)
    tn = len(gt_safe - flagged)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0.0

    # Compute baseline: what would "flag everything" achieve?
    total = len(gt_vuln) + len(gt_safe)
    baseline_precision = len(gt_vuln) / total if total > 0 else 0.0
    baseline_f1 = 2 * baseline_precision / (baseline_precision + 1) if total > 0 else 0.0

    return {
        "agent": agent_name, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy,
        "findings": len(findings), "flagged_files": len(flagged),
        "out_of_universe_fps": len(out_of_universe),
        "vuln_count": len(gt_vuln), "safe_count": len(gt_safe),
        "baseline_precision": baseline_precision, "baseline_f1": baseline_f1,
    }


def _detect_agents(ws_path: Path) -> list[tuple[str, Path]]:
    """Auto-detect agent output directories in a workspace."""
    agents = []
    for d in sorted(ws_path.iterdir()):
        # Match output_*/ directories (output_agent_a, output_sonnet46, etc.)
        # but not the bare output/ directory
        if d.is_dir() and d.name.startswith("output_") and d.name != "output":
            findings_file = d / "findings.json"
            if not findings_file.exists():
                findings_file = d / "findings.sarif"
            if not findings_file.exists():
                findings_file = d / "findings.csv"
            if findings_file.exists() and findings_file.stat().st_size > 10:
                # Try to extract agent name from the JSON
                name = d.name.replace("output_agent_", "agent_").replace("output_", "")
                try:
                    data = json.loads(findings_file.read_text(encoding="utf-8-sig"))
                    name = data.get("agent_name", name)
                except Exception:
                    pass
                agents.append((name, findings_file))
    # Also check output/ directory
    for fname in ["findings.json", "findings.sarif", "findings.csv"]:
        p = ws_path / "output" / fname
        if p.exists() and p.stat().st_size > 10:
            name = "default"
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                name = data.get("agent_name", name)
            except Exception:
                pass
            agents.append((name, p))
            break
    return agents


def _output_reports(
    metrics_report,
    report_formats: tuple[str, ...],
    output_dir: str,
    agent_name: str = "evaluation",
) -> None:
    """Generate requested reports."""
    from sastbench.reports.console import print_metrics_report
    from sastbench.reports.html_report import generate_html_report
    from sastbench.reports.json_report import generate_json_report

    if "console" in report_formats:
        print_metrics_report(metrics_report, console=console)

    out = Path(output_dir)
    import re as _re
    safe = _re.sub(r'[^a-z0-9_-]', '', agent_name.lower().replace(' ', '_'))
    if "json" in report_formats:
        p = generate_json_report(metrics_report, out / f"{safe}_report.json")
        console.print(f"[green]JSON report: {p}[/green]")

    if "html" in report_formats:
        p = generate_html_report(metrics_report, out / f"{safe}_report.html")
        console.print(f"[green]HTML report: {p}[/green]")


if __name__ == "__main__":
    cli()
