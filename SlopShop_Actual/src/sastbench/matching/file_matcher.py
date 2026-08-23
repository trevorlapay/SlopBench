"""File-level matching: finding matches ground truth if same file (and optionally CWE)."""

from __future__ import annotations

from sastbench.models import Finding, GroundTruth, MatchingConfig
from sastbench.utils.cwe import cwe_matches
from sastbench.utils.normalize import paths_match


def file_matches(
    finding: Finding,
    gt: GroundTruth,
    config: MatchingConfig,
) -> bool:
    """Return True if a finding matches a ground truth at file granularity.

    When config.require_line_number is True, additionally enforces that:
    - The finding provides a start_line (otherwise rejected as FP)
    - If the GT has line info, the finding's line must be within tolerance
    """
    if not paths_match(finding.file_path, gt.file_path):
        return False
    if config.require_cwe_match:
        if finding.cwe_id is None or not cwe_matches(
            finding.cwe_id, gt.cwe_id, allow_parent=config.allow_parent_cwe,
        ):
            return False
    if config.require_line_number:
        # Agent MUST provide a line number
        if finding.start_line is None:
            return False
        # If GT has line info, agent must be within tolerance
        ranges = (gt.metadata or {}).get("vuln_line_ranges")
        if ranges:
            from sastbench.matching.line_matcher import _line_in_range
            if not _line_in_range(finding.start_line, gt, config.line_tolerance):
                return False
        elif gt.start_line is not None:
            if abs(finding.start_line - gt.start_line) > config.line_tolerance:
                return False
        # GT has no line info — line check passes (can't penalize agent for GT gap)
    return True
