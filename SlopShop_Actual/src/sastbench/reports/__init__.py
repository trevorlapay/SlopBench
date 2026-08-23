"""Report rendering for SASTBench: console (rich), JSON, and HTML."""

from sastbench.reports.console import (
    print_comparison_report,
    print_diff_report,
    print_metrics_report,
)
from sastbench.reports.html_report import generate_html_report
from sastbench.reports.json_report import (
    generate_comparison_json,
    generate_diff_json,
    generate_json_report,
)

__all__ = [
    "print_metrics_report",
    "print_comparison_report",
    "print_diff_report",
    "generate_json_report",
    "generate_comparison_json",
    "generate_diff_json",
    "generate_html_report",
]
