"""Agent-vs-agent diff without ground truth."""

from __future__ import annotations

from collections import defaultdict

from sastbench.models import (
    AgentDiffStats,
    ConsensusFinding,
    DiffReport,
    Finding,
    MatchedFinding,
)
from sastbench.utils.normalize import normalize_path


def _findings_match(a: Finding, b: Finding, tolerance: int) -> bool:
    """Check if two findings match: same file, CWE, and line within tolerance."""
    if normalize_path(a.file_path) != normalize_path(b.file_path):
        return False
    if a.cwe_id != b.cwe_id:
        return False
    line_a = a.start_line or 0
    line_b = b.start_line or 0
    return abs(line_a - line_b) <= tolerance


def _build_agent_stats(findings: list[Finding]) -> AgentDiffStats:
    cwe_dist: dict[str, int] = defaultdict(int)
    sev_dist: dict[str, int] = defaultdict(int)
    files: set[str] = set()
    for f in findings:
        cwe_dist[f.cwe_id or "UNKNOWN"] += 1
        sev_dist[f.severity.value if f.severity else "unknown"] += 1
        files.add(f.file_path)
    return AgentDiffStats(
        total_findings=len(findings),
        cwe_distribution=dict(cwe_dist),
        severity_distribution=dict(sev_dist),
        files_flagged=len(files),
    )


def diff_agents(
    agent_findings: dict[str, list[Finding]],
    match_tolerance: int = 3,
) -> DiffReport:
    """Compare findings from multiple agents without ground truth."""
    agents = sorted(agent_findings.keys())
    if not agents:
        return DiffReport(agents=[], match_tolerance=match_tolerance)

    # Per-agent stats
    per_agent = {name: _build_agent_stats(findings) for name, findings in agent_findings.items()}

    # Match findings across agents using pairwise comparison
    # For each finding, track which agents reported it
    # Use first agent's findings as anchors, then match others
    matched_groups: list[dict[str, Finding]] = []  # each is {agent: finding}

    all_findings: list[tuple[str, Finding]] = []
    for agent in agents:
        for f in agent_findings[agent]:
            all_findings.append((agent, f))

    # Track which findings have been assigned to a group
    assigned: set[int] = set()

    for i, (agent_i, finding_i) in enumerate(all_findings):
        if i in assigned:
            continue
        group: dict[str, Finding] = {agent_i: finding_i}
        assigned.add(i)
        for j, (agent_j, finding_j) in enumerate(all_findings):
            if j in assigned:
                continue
            if agent_j in group:
                continue
            if _findings_match(finding_i, finding_j, match_tolerance):
                group[agent_j] = finding_j
                assigned.add(j)
        matched_groups.append(group)

    # Agreed findings: found by 2+ agents
    agreed_findings: list[MatchedFinding] = []
    unique_findings: dict[str, list[Finding]] = {a: [] for a in agents}

    for group in matched_groups:
        if len(group) >= 2:
            representative = next(iter(group.values()))
            agreed_findings.append(MatchedFinding(
                file_path=representative.file_path,
                start_line=representative.start_line,
                cwe_id=representative.cwe_id,
                agents=sorted(group.keys()),
            ))
        elif len(group) == 1:
            agent, finding = next(iter(group.items()))
            unique_findings[agent].append(finding)

    total_unique = len(matched_groups)
    matched_count = sum(1 for g in matched_groups if len(g) >= 2)

    agreement_rate = matched_count / total_unique if total_unique else 0.0

    # Jaccard index: |intersection| / |union|
    # intersection = findings found by ALL agents
    # union = all unique finding groups
    if len(agents) >= 2:
        intersection_count = sum(1 for g in matched_groups if len(g) == len(agents))
        jaccard_index = intersection_count / total_unique if total_unique else 0.0
    else:
        jaccard_index = 1.0 if total_unique > 0 else 0.0

    # Cohen's kappa for exactly 2 agents
    cohens_kappa = 0.0
    if len(agents) == 2:
        cohens_kappa = _compute_cohens_kappa(
            agent_findings[agents[0]],
            agent_findings[agents[1]],
            match_tolerance,
        )

    # CWE and severity distributions per agent
    cwe_distribution = {name: stats.cwe_distribution for name, stats in per_agent.items()}
    severity_distribution = {name: stats.severity_distribution for name, stats in per_agent.items()}

    # Consensus findings (for 3+ agents): found by majority
    consensus_findings: list[ConsensusFinding] = []
    if len(agents) >= 3:
        majority = len(agents) // 2 + 1
        for group in matched_groups:
            if len(group) >= majority:
                representative = next(iter(group.values()))
                consensus_findings.append(ConsensusFinding(
                    finding=MatchedFinding(
                        file_path=representative.file_path,
                        start_line=representative.start_line,
                        cwe_id=representative.cwe_id,
                        agents=sorted(group.keys()),
                    ),
                    agent_count=len(group),
                    total_agents=len(agents),
                ))

    return DiffReport(
        agents=agents,
        match_tolerance=match_tolerance,
        agreement_rate=agreement_rate,
        jaccard_index=jaccard_index,
        cohens_kappa=cohens_kappa,
        per_agent=per_agent,
        agreed_findings=agreed_findings,
        unique_findings=unique_findings,
        cwe_distribution=cwe_distribution,
        severity_distribution=severity_distribution,
        consensus_findings=consensus_findings,
    )


def _compute_cohens_kappa(
    findings_a: list[Finding],
    findings_b: list[Finding],
    tolerance: int,
) -> float:
    """Compute Cohen's kappa for two agents.

    We treat each unique finding location as a "case" and each agent as a
    binary rater (flagged / not flagged).  Matching between agents uses
    ``_findings_match`` (abs-tolerance) so the result is consistent with the
    rest of the diff pipeline.

    **Approximation note:** Without a defined universe of all possible
    locations we cannot observe true negatives (both agents agree "not
    flagged").  ``a_no_b_no`` is therefore set to 0, making this an
    optimistic lower-bound of the real kappa.  The result is clamped to
    [0, 1].
    """
    # Deduplicate by building groups via _findings_match (same logic as
    # the main diff_agents grouping).
    all_entries: list[tuple[str, Finding]] = []
    for f in findings_a:
        all_entries.append(("a", f))
    for f in findings_b:
        all_entries.append(("b", f))

    groups: list[set[str]] = []
    assigned: set[int] = set()
    for i, (agent_i, fi) in enumerate(all_entries):
        if i in assigned:
            continue
        group_agents: set[str] = {agent_i}
        assigned.add(i)
        for j, (agent_j, fj) in enumerate(all_entries):
            if j in assigned:
                continue
            if agent_j in group_agents:
                continue
            if _findings_match(fi, fj, tolerance):
                group_agents.add(agent_j)
                assigned.add(j)
        groups.append(group_agents)

    if not groups:
        return 0.0

    a_yes_b_yes = sum(1 for g in groups if "a" in g and "b" in g)
    a_yes_b_no = sum(1 for g in groups if "a" in g and "b" not in g)
    a_no_b_yes = sum(1 for g in groups if "a" not in g and "b" in g)
    # True negatives are unobservable without a defined universe.
    a_no_b_no = 0

    total = a_yes_b_yes + a_yes_b_no + a_no_b_yes + a_no_b_no
    if total == 0:
        return 0.0

    po = (a_yes_b_yes + a_no_b_no) / total  # observed agreement
    # Expected agreement by chance
    p_a_yes = (a_yes_b_yes + a_yes_b_no) / total
    p_b_yes = (a_yes_b_yes + a_no_b_yes) / total
    pe = p_a_yes * p_b_yes + (1 - p_a_yes) * (1 - p_b_yes)

    if pe == 1.0:
        return 1.0 if po == 1.0 else 0.0

    kappa = (po - pe) / (1 - pe)
    return max(0.0, min(1.0, kappa))
