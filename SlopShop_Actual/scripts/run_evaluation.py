#!/usr/bin/env python
"""Run evaluation across all workspaces and agents, producing a summary.

Usage:
    python scripts/run_evaluation.py [--binary] [--no-cwe-match]

Auto-detects all workspaces in workspaces/ and all agent outputs
in output_agent_*/ directories within each workspace.
"""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACES = ROOT / "workspaces"
EVALUATOR_DATA = ROOT / "evaluator_data"

# Benchmarks that should use binary evaluation (no meaningful CWE labels)
BINARY_BENCHMARKS = {"primevul"}


def _find_workspaces() -> list[Path]:
    """Find workspaces that have evaluator data (new or legacy layout)."""
    found = []
    if not WORKSPACES.exists():
        return found
    for p in sorted(WORKSPACES.iterdir()):
        if not p.is_dir():
            continue
        # New layout: evaluator_data/<name>/
        has_eval = (EVALUATOR_DATA / p.name).exists() if EVALUATOR_DATA.exists() else False
        # Legacy layout: .sastbench/ inside workspace
        has_legacy = (p / ".sastbench").exists()
        if has_eval or has_legacy:
            found.append(p)
    return found


def run_evaluation(force_binary: bool = False, force_no_cwe: bool = False):
    ws_paths = _find_workspaces()

    if not ws_paths:
        print("No workspaces found. Run scripts/prepare_suites.py first.")
        return

    # Print exact agent prompts for each workspace
    print(f"\n{'='*60}")
    print("  Agent prompts — copy-paste these to launch runs:")
    print(f"{'='*60}")
    for ws in ws_paths:
        print(f"\n  SASTBench show-run-prompt {ws} --agent-name <name>")

    for ws in ws_paths:
        bench_name = ws.name
        is_binary = force_binary or bench_name in BINARY_BENCHMARKS

        cmd = [
            sys.executable, "-m", "sastbench.cli", "evaluate-all",
            str(ws),
            "--output-dir", str(ROOT / "reports" / bench_name),
        ]

        if is_binary:
            cmd.append("--binary")
        elif force_no_cwe:
            cmd.append("--no-cwe-match")

        print(f"\n{'='*60}")
        print(f"  Evaluating {bench_name} {'(binary)' if is_binary else '(file-level)'}")
        print(f"{'='*60}")

        subprocess.run(cmd, cwd=str(ROOT))

    print(f"\n{'='*60}")
    print(f"  Evaluation complete. Reports in {ROOT / 'reports'}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run evaluation across all workspaces")
    parser.add_argument("--binary", action="store_true", help="Force binary mode for all benchmarks")
    parser.add_argument("--no-cwe-match", action="store_true", help="Disable CWE matching")
    args = parser.parse_args()
    run_evaluation(force_binary=args.binary, force_no_cwe=args.no_cwe_match)
