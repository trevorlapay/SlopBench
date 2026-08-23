"""Function-level matching: same file AND same function_name.

Falls back to file-level matching when either side has no function_name.
"""

from __future__ import annotations

from sastbench.models import Finding, GroundTruth, MatchingConfig
from sastbench.matching.file_matcher import file_matches


def function_matches(
    finding: Finding,
    gt: GroundTruth,
    config: MatchingConfig,
) -> bool:
    """Return True if a finding matches a ground truth at function granularity.

    The check first requires a file-level match (same normalized path and,
    when configured, the same CWE).  If both sides provide a
    ``function_name`` they must be equal.

    **Fallback behaviour:** When either the finding or the ground truth is
    missing ``function_name`` (i.e. it is ``None``), the matcher falls back
    to file-level matching and returns ``True`` (assuming the file-level
    check passed).  This is intentional graceful degradation — not all agent
    outputs or benchmarks include function-level information.
    """
    # Must pass file-level check first (path + optional CWE)
    if not file_matches(finding, gt, config):
        return False
    # If either side lacks a function name, fall back to file-level match
    if finding.function_name is None or gt.function_name is None:
        return True
    return finding.function_name == gt.function_name
