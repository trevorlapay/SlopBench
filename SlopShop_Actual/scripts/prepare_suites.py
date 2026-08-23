#!/usr/bin/env python
"""Prepare all benchmark workspaces with consistent, reproducible settings.

Usage:
    python scripts/prepare_suites.py [--max-cases N] [--seed N] [--prompt-template NAME]

This regenerates all workspace directories under workspaces/ with:
- Shuffled file ordering (prevents systematic bias)
- Neutral filenames (no CWE hints)
- Hidden ground truth in evaluator_data/
- Saved prompt template for reproducible agent runs
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path

BENCHMARKS = {
    "bigvul": {"max_cases": 500, "description": "Real CVE functions from open-source C/C++"},
    "primevul": {"max_cases": 500, "description": "Paired vuln/safe C/C++ functions"},
    "castle": {"max_cases": 500, "description": "CWE-focused test cases"},
}

ROOT = Path(__file__).resolve().parent.parent
WORKSPACES = ROOT / "workspaces"


def prepare(
    max_cases_override: int | None = None,
    seed: int = 42,
    prompt_template: str = "selective",
):
    failures = []
    for name, cfg in BENCHMARKS.items():
        ws = WORKSPACES / name
        max_cases = max_cases_override or cfg["max_cases"]

        print(f"\n{'='*60}")
        print(f"  Preparing {name}: {cfg['description']}")
        print(f"  Max cases: {max_cases}, seed: {seed}, prompt: {prompt_template}")
        print(f"{'='*60}")

        # Clean existing workspace
        if ws.exists():
            shutil.rmtree(ws)
            print(f"  Cleaned old workspace: {ws}")

        cmd = [
            sys.executable, "-m", "sastbench.cli", "prepare",
            "-b", name,
            "-o", str(ws),
            "--max-cases", str(max_cases),
            "--seed", str(seed),
            "--prompt-template", prompt_template,
        ]
        result = subprocess.run(cmd, cwd=str(ROOT), capture_output=False)
        if result.returncode != 0:
            print(f"  ERROR: Failed to prepare {name}")
            failures.append(name)
            continue

    print(f"\n{'='*60}")
    if failures:
        print(f"  Failed benchmarks: {', '.join(failures)}")
    else:
        print(f"  All workspaces prepared in {WORKSPACES}")
        print(f"\n  Generate agent prompts with:")
        for name in BENCHMARKS:
            ws = WORKSPACES / name
            print(f"    SASTBench show-run-prompt {ws} --agent-name <name>")
    print(f"{'='*60}")
    return 1 if failures else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prepare all benchmark workspaces")
    parser.add_argument("--max-cases", type=int, help="Override max cases per benchmark")
    parser.add_argument("--seed", type=int, default=42, help="Shuffle seed (default: 42)")
    parser.add_argument(
        "--prompt-template",
        default="selective",
        help="Prompt template to save with each workspace (default: selective)",
    )
    args = parser.parse_args()
    sys.exit(prepare(
        max_cases_override=args.max_cases,
        seed=args.seed,
        prompt_template=args.prompt_template,
    ))
