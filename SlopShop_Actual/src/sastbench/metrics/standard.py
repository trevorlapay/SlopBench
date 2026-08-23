"""Standard metrics computation from match results."""

from __future__ import annotations

from sastbench.models import MatchResult, StandardMetrics
from sastbench.utils.normalize import safe_div as _safe_div


def compute_standard_metrics(match_result: MatchResult) -> StandardMetrics:
    """Compute precision, recall, F1, accuracy, FPR, FNR from a MatchResult."""
    tp = len(match_result.true_positives)
    fp = len(match_result.false_positives)
    fn = len(match_result.false_negatives)
    tn = match_result.true_negatives

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)

    return StandardMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
    )


def compute_standard_metrics_from_counts(
    tp: int, fp: int, fn: int, tn: int = 0,
) -> StandardMetrics:
    """Compute standard metrics from raw counts."""
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, tp + tn + fp + fn)
    fpr = _safe_div(fp, fp + tn)
    fnr = _safe_div(fn, fn + tp)

    return StandardMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
    )
