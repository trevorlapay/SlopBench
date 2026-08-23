#!/usr/bin/env python
"""Verify workspace integrity after preparation.

Usage:
    python scripts/verify_workspaces.py [workspaces/bigvul workspaces/primevul ...]

Checks:
- File counts match config
- Ground truths have valid paths into code/
- No ordering bias (vuln/safe evenly distributed across file numbers)
- All agent output dirs exist
- No stale files from previous runs
- SECURITY: No .sastbench/ directory in workspace (GT leakage)
- SECURITY: No double-brace fingerprint in code files (safe corpus bug)
- SECURITY: No synthetic naming patterns in code files
"""
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKSPACES = ROOT / "workspaces"


def _find_evaluator_dir(ws_path: Path) -> Path | None:
    """Find evaluator data directory: evaluator_data/ sibling (preferred) or legacy .sastbench/."""
    evaluator_dir = ws_path.parent / "evaluator_data" / ws_path.name
    if evaluator_dir.exists():
        return evaluator_dir
    legacy_dir = ws_path / ".sastbench"
    if legacy_dir.exists():
        return legacy_dir
    return None


def verify(ws_path: Path) -> list[str]:
    """Verify a single workspace. Returns list of issues found."""
    issues = []
    name = ws_path.name

    # --- SECURITY: .sastbench/ must NOT exist in workspace ---
    if (ws_path / ".sastbench").is_dir():
        issues.append(
            f"[{name}] SECURITY: .sastbench/ directory exists in workspace — "
            "this leaks ground truth to agents. Delete it or re-prepare."
        )

    # Check essential files
    for required in ["AGENTS.md", "manifest.json", "output_schema.json"]:
        if not (ws_path / required).exists():
            issues.append(f"[{name}] Missing {required}")

    for required_dir in ["code", "output"]:
        if not (ws_path / required_dir).is_dir():
            issues.append(f"[{name}] Missing directory {required_dir}/")

    # Find evaluator data (new location or legacy)
    evaluator_dir = _find_evaluator_dir(ws_path)
    if evaluator_dir is None:
        issues.append(f"[{name}] No evaluator data found (checked evaluator_data/ and .sastbench/)")
        return issues

    config_path = evaluator_dir / "config.json"
    gt_path = evaluator_dir / "ground_truth.json"
    mapping_path = evaluator_dir / "file_mapping.json"

    if not config_path.exists():
        issues.append(f"[{name}] Missing config.json in {evaluator_dir}")
        return issues
    config = json.loads(config_path.read_text(encoding="utf-8"))

    if not gt_path.exists():
        issues.append(f"[{name}] Missing ground_truth.json in {evaluator_dir}")
        return issues
    gt = json.loads(gt_path.read_text(encoding="utf-8"))

    if not mapping_path.exists():
        issues.append(f"[{name}] Missing file_mapping.json in {evaluator_dir}")
        return issues
    mapping = json.loads(mapping_path.read_text(encoding="utf-8"))

    # Check file counts
    code_dir = ws_path / "code"
    code_files = list(code_dir.iterdir()) if code_dir.exists() else []
    expected = config["total_test_cases"]
    if len(code_files) != expected:
        issues.append(f"[{name}] Code files: {len(code_files)} (expected {expected})")

    if len(mapping) != expected:
        issues.append(f"[{name}] Mapping entries: {len(mapping)} (expected {expected})")

    # Check GT paths reference actual code files
    code_paths = {f"code/{f.name}" for f in code_files}
    gt_paths = {g["file_path"] for g in gt}
    unmapped = gt_paths - code_paths
    if unmapped:
        issues.append(f"[{name}] {len(unmapped)} GT paths not in code/: {list(unmapped)[:3]}")

    # --- SECURITY: Check for safe corpus fingerprints ---
    double_brace_files = []
    synthetic_name_files = []
    for f in code_files:
        content = f.read_text(encoding="utf-8", errors="replace")
        # Double-brace fingerprint (invalid C syntax from template bug)
        if "{{" in content or "}}" in content:
            double_brace_files.append(f.name)
        # Synthetic naming patterns (safe_*, util_*, helper_*)
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("void safe_") or stripped.startswith("void util_") or stripped.startswith("void helper_"):
                synthetic_name_files.append(f.name)
                break

    if double_brace_files:
        issues.append(
            f"[{name}] SECURITY: {len(double_brace_files)} files contain '{{{{' fingerprint "
            f"(safe corpus template bug): {double_brace_files[:3]}"
        )
    if synthetic_name_files:
        issues.append(
            f"[{name}] WARNING: {len(synthetic_name_files)} files have synthetic function names "
            f"(safe_*, util_*, helper_*): {synthetic_name_files[:3]}"
        )

    # Check ordering bias (for paired datasets)
    vuln_gts = [g for g in gt if g["is_vulnerable"]]
    safe_gts = [g for g in gt if not g["is_vulnerable"]]

    if vuln_gts and safe_gts:
        vuln_nums = []
        safe_nums = []
        for g in gt:
            try:
                num = int(g["file_path"].split("_")[1].split(".")[0])
                if g["is_vulnerable"]:
                    vuln_nums.append(num)
                else:
                    safe_nums.append(num)
            except (IndexError, ValueError):
                continue

        if vuln_nums and safe_nums:
            vuln_odd = sum(1 for n in vuln_nums if n % 2 == 1)
            vuln_even = sum(1 for n in vuln_nums if n % 2 == 0)
            ratio = vuln_odd / max(vuln_even, 1)
            if ratio > 3.0 or ratio < 0.33:
                issues.append(f"[{name}] Ordering bias: vuln odd/even = {vuln_odd}/{vuln_even} (ratio {ratio:.1f})")

    # CWE distribution
    cwes = Counter(g["cwe_id"] for g in gt if g.get("cwe_id"))

    # Summary
    total_lines = sum(len(f.read_text(encoding="utf-8", errors="replace").splitlines())
                      for f in code_files)

    status = "✅ PASS" if not issues else "❌ FAIL"
    eval_loc = "evaluator_data/" if (ws_path.parent / "evaluator_data" / ws_path.name).exists() else ".sastbench/ (LEGACY)"
    print(f"\n{status} {name}: {len(code_files)} files, {total_lines/1000:.1f} KLOC, "
          f"{len(gt)} GTs ({len(vuln_gts)} vuln, {len(safe_gts)} safe), {len(cwes)} CWEs "
          f"[GT: {eval_loc}]")
    for issue in issues:
        print(f"  ⚠ {issue}")

    return issues


def main():
    ws_paths = []
    if len(sys.argv) > 1:
        ws_paths = [Path(p) for p in sys.argv[1:]]
    else:
        if WORKSPACES.exists():
            # Find workspaces with evaluator_data/ or legacy .sastbench/
            for p in sorted(WORKSPACES.iterdir()):
                if not p.is_dir():
                    continue
                if (p / ".sastbench").exists():
                    ws_paths.append(p)
                elif (WORKSPACES.parent / "evaluator_data" / p.name).exists():
                    ws_paths.append(p)

    if not ws_paths:
        print("No workspaces found. Run scripts/prepare_suites.py first.")
        return 1

    all_issues = []
    for ws in ws_paths:
        all_issues.extend(verify(ws))

    print(f"\n{'='*60}")
    if all_issues:
        security_issues = [i for i in all_issues if "SECURITY" in i]
        print(f"  {len(all_issues)} issue(s) found ({len(security_issues)} security)")
        return 1
    else:
        print(f"  All workspaces verified ✅")
        return 0


if __name__ == "__main__":
    sys.exit(main())
