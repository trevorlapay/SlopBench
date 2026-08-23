"""Per-CWE metrics breakdown and averaging."""

from __future__ import annotations

from collections import defaultdict

from sastbench.models import MatchResult, StandardMetrics
from sastbench.metrics.standard import compute_standard_metrics_from_counts


_UNKNOWN = "UNKNOWN"


def compute_cwe_breakdown(match_result: MatchResult) -> dict[str, StandardMetrics]:
    """Break down metrics per CWE category."""
    tp_by_cwe: dict[str, int] = defaultdict(int)
    fp_by_cwe: dict[str, int] = defaultdict(int)
    fn_by_cwe: dict[str, int] = defaultdict(int)

    for pair in match_result.true_positives:
        cwe = pair.ground_truth.cwe_id or _UNKNOWN
        tp_by_cwe[cwe] += 1

    for finding in match_result.false_positives:
        cwe = finding.cwe_id or _UNKNOWN
        fp_by_cwe[cwe] += 1

    for gt in match_result.false_negatives:
        cwe = gt.cwe_id or _UNKNOWN
        fn_by_cwe[cwe] += 1

    all_cwes = set(tp_by_cwe) | set(fp_by_cwe) | set(fn_by_cwe)
    result: dict[str, StandardMetrics] = {}
    for cwe in sorted(all_cwes):
        result[cwe] = compute_standard_metrics_from_counts(
            tp=tp_by_cwe[cwe],
            fp=fp_by_cwe[cwe],
            fn=fn_by_cwe[cwe],
        )
    return result


def compute_macro_average(per_cwe: dict[str, StandardMetrics]) -> StandardMetrics:
    """Macro-average across all CWEs."""
    if not per_cwe:
        return StandardMetrics()

    n = len(per_cwe)
    total_precision = sum(m.precision for m in per_cwe.values())
    total_recall = sum(m.recall for m in per_cwe.values())
    total_f1 = sum(m.f1 for m in per_cwe.values())
    total_accuracy = sum(m.accuracy for m in per_cwe.values())
    total_fpr = sum(m.false_positive_rate for m in per_cwe.values())
    total_fnr = sum(m.false_negative_rate for m in per_cwe.values())
    return StandardMetrics(
        precision=total_precision / n,
        recall=total_recall / n,
        f1=total_f1 / n,
        accuracy=total_accuracy / n,
        false_positive_rate=total_fpr / n,
        false_negative_rate=total_fnr / n,
        true_positives=0,
        false_positives=0,
        false_negatives=0,
        true_negatives=0,
    )


def compute_micro_average(match_result: MatchResult) -> StandardMetrics:
    """Micro-average (same as overall standard metrics)."""
    from sastbench.metrics.standard import compute_standard_metrics

    return compute_standard_metrics(match_result)
