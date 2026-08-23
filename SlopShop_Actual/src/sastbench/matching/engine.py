"""Main matching engine that pairs Findings against GroundTruths.

Uses maximum bipartite matching (via scipy when available, otherwise a
Hopcroft-Karp–style augmenting-paths fallback) to find the optimal 1:1
assignment between findings and ground truths.
"""

from __future__ import annotations

from typing import Callable

from sastbench.models import (
    Finding,
    GroundTruth,
    MatchedPair,
    MatchGranularity,
    MatchingConfig,
    MatchResult,
)
from sastbench.matching.file_matcher import file_matches
from sastbench.matching.function_matcher import function_matches
from sastbench.matching.line_matcher import line_matches

MatchFn = Callable[[Finding, GroundTruth, MatchingConfig], bool]

_MATCHERS: dict[MatchGranularity, MatchFn] = {
    MatchGranularity.FILE: file_matches,
    MatchGranularity.FUNCTION: function_matches,
    MatchGranularity.LINE: line_matches,
}


def _max_bipartite_matching(
    n_findings: int,
    n_gts: int,
    adj: dict[int, list[int]],
) -> list[tuple[int, int]]:
    """Return a maximum cardinality matching as (finding_idx, gt_idx) pairs.

    Uses scipy's ``linear_sum_assignment`` when available, falling back to an
    augmenting-paths algorithm.
    """
    if not adj:
        return []

    try:
        import numpy as np
        from scipy.optimize import linear_sum_assignment

        cost = np.ones((n_findings, n_gts), dtype=int)
        for f_idx, gt_indices in adj.items():
            for g_idx in gt_indices:
                cost[f_idx, g_idx] = 0
        row_ind, col_ind = linear_sum_assignment(cost)
        return [
            (int(r), int(c))
            for r, c in zip(row_ind, col_ind)
            if cost[r, c] == 0
        ]
    except ImportError:
        pass

    # Augmenting-paths fallback (Hopcroft-Karp style, one path at a time)
    match_f: dict[int, int] = {}  # finding_idx -> gt_idx
    match_g: dict[int, int] = {}  # gt_idx -> finding_idx

    def _augment(f: int, visited: set[int]) -> bool:
        for g in adj.get(f, []):
            if g in visited:
                continue
            visited.add(g)
            if g not in match_g or _augment(match_g[g], visited):
                match_f[f] = g
                match_g[g] = f
                return True
        return False

    for f_idx in range(n_findings):
        if f_idx in adj:
            _augment(f_idx, set())

    return list(match_f.items())


class MatchingEngine:
    """Match agent findings against ground truths using a configured strategy."""

    def __init__(self, config: MatchingConfig | None = None) -> None:
        self.config = config or MatchingConfig()

    def match(
        self,
        findings: list[Finding],
        ground_truths: list[GroundTruth],
    ) -> MatchResult:
        """Match findings against ground truths and return a MatchResult."""
        matcher = _MATCHERS[self.config.granularity]

        vulnerable_gts = [gt for gt in ground_truths if gt.is_vulnerable]
        non_vulnerable_gts = [gt for gt in ground_truths if not gt.is_vulnerable]

        # Build adjacency: finding_idx -> list of compatible gt_indices
        adj: dict[int, list[int]] = {}
        for f_idx, finding in enumerate(findings):
            compatible: list[int] = []
            for g_idx, gt in enumerate(vulnerable_gts):
                if matcher(finding, gt, self.config):
                    compatible.append(g_idx)
            if compatible:
                adj[f_idx] = compatible

        # Optimal 1:1 matching via maximum bipartite matching
        pairs = _max_bipartite_matching(len(findings), len(vulnerable_gts), adj)

        matched_finding_indices: set[int] = set()
        matched_gt_indices: set[int] = set()
        true_positives: list[MatchedPair] = []

        for f_idx, g_idx in pairs:
            true_positives.append(
                MatchedPair(finding=findings[f_idx], ground_truth=vulnerable_gts[g_idx])
            )
            matched_finding_indices.add(f_idx)
            matched_gt_indices.add(g_idx)

        # False positives: findings that didn't match any vulnerable GT
        false_positives = [f for i, f in enumerate(findings) if i not in matched_finding_indices]

        # False negatives: vulnerable GTs that weren't matched
        false_negatives = [
            gt for i, gt in enumerate(vulnerable_gts) if i not in matched_gt_indices
        ]

        # True negatives: non-vulnerable GTs that were NOT flagged by any finding
        true_negatives = 0
        for gt in non_vulnerable_gts:
            flagged = any(matcher(f, gt, self.config) for f in findings)
            if not flagged:
                true_negatives += 1

        return MatchResult(
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            true_negatives=true_negatives,
            config=self.config,
        )
