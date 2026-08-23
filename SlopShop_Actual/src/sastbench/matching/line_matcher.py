"""Line-level matching: same file AND start_line within ±line_tolerance.

Supports multi-hunk ground truths via metadata.vuln_line_ranges.
Falls back to file-level matching when either side has no line numbers.
"""

from __future__ import annotations

from sastbench.models import Finding, GroundTruth, MatchingConfig
from sastbench.matching.file_matcher import file_matches


def _line_in_range(
    finding_line: int,
    gt: GroundTruth,
    tolerance: int,
) -> bool:
    """Check if finding line is within tolerance of any GT hunk range."""
    # Check multi-hunk ranges from metadata first
    ranges = (gt.metadata or {}).get("vuln_line_ranges")
    if ranges:
        for r in ranges:
            start = r.get("start_line", 0)
            end = r.get("end_line", start)
            # Finding is near this hunk if within tolerance of the range
            if start - tolerance <= finding_line <= end + tolerance:
                return True
        return False

    # Single-line fallback: use gt.start_line
    if gt.start_line is not None:
        return abs(finding_line - gt.start_line) <= tolerance

    return True  # GT has no line info — can't check


def line_matches(
    finding: Finding,
    gt: GroundTruth,
    config: MatchingConfig,
) -> bool:
    """Return True if a finding matches a ground truth at line granularity.

    The check first requires a file-level match (same normalized path and,
    when configured, the same CWE).  If both sides provide a ``start_line``
    the lines must be within ``config.line_tolerance`` of any GT hunk range.

    **Fallback behaviour:** When either the finding or the ground truth is
    missing ``start_line`` (i.e. it is ``None``), the matcher falls back to
    file-level matching and returns ``True`` (assuming the file-level check
    passed).  This is intentional graceful degradation — many agent outputs
    and some benchmarks omit line numbers.
    """
    # Must pass file-level check first (path + optional CWE)
    if not file_matches(finding, gt, config):
        return False
    # If finding has no line number, fall back to file-level match
    if finding.start_line is None:
        return True
    # If GT has no line info at all, fall back to file-level match
    has_ranges = bool((gt.metadata or {}).get("vuln_line_ranges"))
    if gt.start_line is None and not has_ranges:
        return True
    return _line_in_range(finding.start_line, gt, config.line_tolerance)
