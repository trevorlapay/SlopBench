"""JSON report generation for SASTBench."""

from __future__ import annotations

from pathlib import Path


def _write(model, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Pydantic v2 models expose model_dump_json; fall back to json for plain dicts.
    if hasattr(model, "model_dump_json"):
        text = model.model_dump_json(indent=2)
    else:
        import json
        text = json.dumps(model, indent=2, default=str)
    path.write_text(text, encoding="utf-8")
    return path


def generate_json_report(report, path: Path | str) -> Path:
    """Write a MetricsReport to JSON."""
    return _write(report, path)


def generate_comparison_json(comparison, path: Path | str) -> Path:
    """Write a ComparisonReport to JSON."""
    return _write(comparison, path)


def generate_diff_json(diff_report, path: Path | str) -> Path:
    """Write a DiffReport to JSON."""
    return _write(diff_report, path)
