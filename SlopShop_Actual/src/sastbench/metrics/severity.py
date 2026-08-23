"""Severity-weighted metrics computation.

Only precision, recall, and F1 are computed as severity-weighted values.
Accuracy and FPR are omitted (set to 0.0) because true negatives cannot
be meaningfully severity-weighted.
"""

from __future__ import annotations

from sastbench.models import MatchResult, StandardMetrics
from sastbench.utils.normalize import safe_div as _safe_div, severity_weight


def compute_severity_weighted_metrics(match_result: MatchResult) -> StandardMetrics:
    """Compute metrics weighted by severity (critical misses penalized more).

    Only precision, recall, F1, and FNR are severity-weighted.
    Accuracy and FPR are set to 0.0 because true negatives cannot be
    meaningfully severity-weighted.
    """
    weighted_tp = 0.0
    weighted_fp = 0.0
    weighted_fn = 0.0

    for pair in match_result.true_positives:
        sev = pair.finding.severity
        weight = severity_weight(sev.value if sev else None)
        weighted_tp += weight

    for finding in match_result.false_positives:
        weight = severity_weight(finding.severity.value if finding.severity else None)
        weighted_fp += weight

    for gt in match_result.false_negatives:
        # Ground truths don't have severity directly; use metadata or default
        sev = gt.metadata.get("severity") if gt.metadata else None
        weight = severity_weight(sev)
        weighted_fn += weight

    precision = _safe_div(weighted_tp, weighted_tp + weighted_fp)
    recall = _safe_div(weighted_tp, weighted_tp + weighted_fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fnr = _safe_div(weighted_fn, weighted_fn + weighted_tp)

    return StandardMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=0.0,
        false_positive_rate=0.0,
        false_negative_rate=fnr,
        true_positives=len(match_result.true_positives),
        false_positives=len(match_result.false_positives),
        false_negatives=len(match_result.false_negatives),
        true_negatives=match_result.true_negatives,
    )
