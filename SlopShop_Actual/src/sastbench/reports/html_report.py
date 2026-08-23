"""Self-contained HTML report generation for SASTBench (no external JS deps)."""

from __future__ import annotations

import html
from pathlib import Path


def _pct(x: float) -> str:
    try:
        return f"{x:.1%}"
    except Exception:
        return str(x)


def _metric_cards(m) -> str:
    cards = [
        ("Precision", _pct(m.precision)),
        ("Recall", _pct(m.recall)),
        ("F1", _pct(m.f1)),
        ("Accuracy", _pct(m.accuracy)),
        ("FPR", _pct(m.false_positive_rate)),
        ("TP", str(m.true_positives)),
        ("FP", str(m.false_positives)),
        ("FN", str(m.false_negatives)),
    ]
    return "".join(
        f'<div class="card"><div class="v">{html.escape(v)}</div>'
        f'<div class="k">{html.escape(k)}</div></div>'
        for k, v in cards
    )


def _per_cwe_rows(per_cwe) -> str:
    rows = []
    for cwe, cm in sorted(per_cwe.items()):
        rows.append(
            f"<tr><td>{html.escape(cwe)}</td><td>{_pct(cm.precision)}</td>"
            f"<td>{_pct(cm.recall)}</td><td>{_pct(cm.f1)}</td>"
            f"<td>{cm.true_positives}</td><td>{cm.false_positives}</td><td>{cm.false_negatives}</td></tr>"
        )
    return "".join(rows)


def generate_html_report(report, path: Path | str) -> Path:
    """Render a MetricsReport to a standalone HTML file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    m = report.overall
    gran = getattr(report.matching_granularity, "value", report.matching_granularity)

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>SASTBench — {html.escape(report.agent_name)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #1f2328; }}
  h1 {{ font-size: 1.4rem; }} .sub {{ color: #656d76; margin-bottom: 1.5rem; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 2rem; }}
  .card {{ background: #f6f8fa; border: 1px solid #d0d7de; border-radius: 8px; padding: 1rem 1.25rem; min-width: 90px; text-align: center; }}
  .card .v {{ font-size: 1.4rem; font-weight: 700; }} .card .k {{ color: #656d76; font-size: .8rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #d0d7de; padding: .4rem .6rem; text-align: right; }}
  th:first-child, td:first-child {{ text-align: left; }} th {{ background: #f6f8fa; }}
</style></head><body>
<h1>{html.escape(report.agent_name)} — {html.escape(report.benchmark_name)}</h1>
<div class="sub">granularity: {html.escape(str(gran))} ·
  {report.total_findings} findings · {report.total_ground_truths} ground truths ·
  {html.escape(str(report.timestamp))}</div>
<div class="cards">{_metric_cards(m)}</div>
"""
    if report.per_cwe:
        doc += ("<h2>Per-CWE</h2><table><thead><tr><th>CWE</th><th>P</th><th>R</th><th>F1</th>"
                "<th>TP</th><th>FP</th><th>FN</th></tr></thead><tbody>"
                f"{_per_cwe_rows(report.per_cwe)}</tbody></table>")
    doc += "</body></html>"

    path.write_text(doc, encoding="utf-8")
    return path
