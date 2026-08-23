#!/usr/bin/env python3
"""Package the harvested verbatim corpus into a SASTBench `custom` bundle.

Reads ``corpus/manifest.jsonl`` (produced by ``harvest.py``) plus the verbatim
source files under ``corpus/`` and emits:

  * ``build/ground_truths.json`` -- the SASTBench custom-adapter bundle
    (``test_cases`` + ``ground_truths``), ready for
    ``sastbench prepare -b custom --benchmark-path build/ground_truths.json``.
  * ``build/vulnerability_key.json`` -- the full, auditable vulnerability key
    (every planted vuln with CVE, CWE, disclosure date, fix commit, upstream
    path, verbatim-file line range, and advisory links).
  * ``build/vulnerability_key.md`` -- a human-readable version of the key.

The bundle deliberately carries no hints inside the code: SASTBench neutralises
file names and isolates the ground truth outside the agent workspace at prepare
time.  This packager just formats what ``harvest.py`` already verified.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
MANIFEST = CORPUS / "manifest.jsonl"
BUILD = ROOT / "build"
WS_MAPPING = ROOT / "workspaces" / "evaluator_data" / "postcutoff" / "file_mapping.json"
CUTOFF = datetime(2025, 12, 1, 23, 59, 59, tzinfo=timezone.utc)  # strict: exclude all of Dec 1
CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
CWE_TOKEN_RE = re.compile(r"CWE-\d{1,6}", re.I)


def _redact(text: str) -> str:
    return CWE_TOKEN_RE.sub("WEAKNESSREF", CVE_RE.sub("ADVISORYREF", text))


def _neutral_paths() -> dict[str, str]:
    """cve -> neutral workspace path, from the built workspace's mapping."""
    if not WS_MAPPING.exists():
        return {}
    mp = json.loads(WS_MAPPING.read_text(encoding="utf-8"))
    return {info["cve"]: path for path, info in mp.items()}


def load_manifest() -> list[dict]:
    if not MANIFEST.exists():
        raise SystemExit("no corpus/manifest.jsonl -- run tools/harvest.py first")
    records = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def verify(records: list[dict]) -> list[str]:
    """Re-check the invariants before packaging; return a list of problems."""
    problems: list[str] = []
    seen: set[str] = set()
    for r in records:
        cve = r["cve"]
        if cve in seen:
            problems.append("duplicate entry: " + cve)
        seen.add(cve)
        dt = datetime.fromisoformat(r["published"])
        if dt <= CUTOFF:
            problems.append("{}: published {} is not after cutoff".format(cve, r["published"]))
        path = ROOT / r["local_path"]
        if not path.exists():
            problems.append("{}: missing corpus file {}".format(cve, r["local_path"]))
            continue
        nlines = path.read_text(encoding="utf-8", errors="replace").count("\n") + 1
        if not (1 <= r["start_line"] <= r["end_line"] <= nlines):
            problems.append("{}: line range {}-{} outside file (1..{})".format(
                cve, r["start_line"], r["end_line"], nlines))
    return problems


def build_bundle(records: list[dict]) -> dict:
    test_cases = []
    ground_truths = []
    for r in records:
        code = _redact((ROOT / r["local_path"]).read_text(encoding="utf-8", errors="replace"))
        rel = r["local_path"]
        test_cases.append({
            "original_id": r["cve"],
            "original_path": rel,
            "code": code,
            "language": r["language"],
            "metadata": {
                "cve": r["cve"],
                "ecosystem": r["ecosystem"],
                "package": r["package"],
            },
        })
        ground_truths.append({
            "file_path": rel,
            "cwe_id": r["primary_cwe"],
            "start_line": r["start_line"],
            "end_line": r["end_line"],
            "is_vulnerable": True,
            "metadata": {
                "cve": r["cve"],
                "published": r["published"],
                "fix_commit": r["fix_commit"],
                "repo": r["repo"],
                "all_cwes": r["cwe_ids"],
            },
        })
    return {"test_cases": test_cases, "ground_truths": ground_truths}


def write_key(records: list[dict]) -> None:
    neutral = _neutral_paths()
    for r in records:
        r["workspace_path"] = neutral.get(r["cve"], "(build workspace first)")
    cwe_counts = Counter(r["primary_cwe"] for r in records)
    lang_counts = Counter(r["language"] for r in records)
    eco_counts = Counter(r["ecosystem"] for r in records)
    key = {
        "generated_note": "All entries are real, publicly-disclosed vulnerabilities "
                          "published after 2025-12-01 (GPT-5.5 cutoff). Code is verbatim "
                          "from the affected project at the pre-fix commit.",
        "cutoff": "2025-12-01",
        "total_vulnerabilities": len(records),
        "distinct_cwes": len(cwe_counts),
        "by_cwe": dict(sorted(cwe_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_language": dict(sorted(lang_counts.items())),
        "by_ecosystem": dict(sorted(eco_counts.items())),
        "entries": sorted(records, key=lambda r: r["published"]),
    }
    (BUILD / "vulnerability_key.json").write_text(json.dumps(key, indent=2), encoding="utf-8")

    lines = [
        "# Helix / SASTBench Vulnerability Key",
        "",
        "Every entry below is a **real, publicly-disclosed vulnerability** whose advisory",
        "was **published after 2025-12-01** (the GPT-5.5 training cutoff). The code shipped",
        "in the benchmark workspace is the **verbatim upstream source at the pre-fix commit**.",
        "",
        "- Total vulnerabilities: **{}**".format(len(records)),
        "- Distinct CWEs: **{}**".format(len(cwe_counts)),
        "- Languages: {}".format(", ".join("{} ({})".format(k, v) for k, v in sorted(lang_counts.items()))),
        "- Ecosystems: {}".format(", ".join("{} ({})".format(k, v) for k, v in sorted(eco_counts.items()))),
        "",
        "The neutralised file name (`code/sample_NNNN.ext`) is assigned by "
        "`sastbench prepare` and printed by `sastbench verify`; map it back through "
        "`evaluator_data/<workspace>/file_mapping.json`.",
        "",
        "The **Workspace file** column is the neutral path the scanner sees; that is the "
        "answer sheet mapping each finding location back to its CVE.",
        "",
        "| # | CVE | CWE | Lines | Disclosed | Workspace file (scanner-facing) | Advisory |",
        "|---|-----|-----|-------|-----------|--------------------------------|----------|",
    ]
    for i, r in enumerate(sorted(records, key=lambda r: (r["workspace_path"])), 1):
        adv = r["repo"] + "/security/advisories/" + r["osv_id"] if r["osv_id"].startswith("GHSA") else \
            "https://nvd.nist.gov/vuln/detail/" + r["cve"]
        lines.append("| {} | {} | {} | {}-{} | {} | `{}` | [{}]({}) |".format(
            i, r["cve"], r["primary_cwe"], r["start_line"], r["end_line"],
            r["published"][:10], r["workspace_path"], r["osv_id"], adv))
    lines.append("")
    lines.append("## Provenance detail")
    lines.append("")
    for r in sorted(records, key=lambda r: r["workspace_path"]):
        lines.append("### {} — {} ({})".format(r["cve"], r["primary_cwe"], r["language"]))
        lines.append("")
        lines.append("- **Scanner-facing file:** `{}` lines **{}-{}**".format(
            r["workspace_path"], r["start_line"], r["end_line"]))
        lines.append("- **Summary:** {}".format(r["summary"] or "(see advisory)"))
        lines.append("- **Real package / project:** `{}` ({})".format(r["package"], r["ecosystem"]))
        lines.append("- **Disclosed:** {}".format(r["published"]))
        lines.append("- **Upstream repo:** {}".format(r["repo"]))
        lines.append("- **Fix commit:** `{}`  (vuln is the pre-fix state)".format(r["fix_commit"]))
        lines.append("- **Original upstream file:** `{}`".format(r["upstream_path"]))
        lines.append("- **All CWEs:** {}".format(", ".join(r["cwe_ids"])))
        lines.append("")
    (BUILD / "vulnerability_key.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="fail on any verification problem")
    ap.add_argument("--expect", type=int, default=None)
    args = ap.parse_args()

    BUILD.mkdir(parents=True, exist_ok=True)
    records = load_manifest()
    problems = verify(records)

    bundle = build_bundle(records)
    (BUILD / "ground_truths.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    write_key(records)

    cwe_counts = Counter(r["primary_cwe"] for r in records)
    print("vulnerabilities : {}".format(len(records)))
    print("distinct CWEs   : {}".format(len(cwe_counts)))
    print("languages       : {}".format(dict(sorted(Counter(r['language'] for r in records).items()))))
    print("ecosystems      : {}".format(dict(sorted(Counter(r['ecosystem'] for r in records).items()))))
    print("bundle          : {}".format(BUILD / "ground_truths.json"))
    print("key (json/md)   : {}".format(BUILD / "vulnerability_key.{json,md}"))
    if problems:
        print("\nVERIFICATION PROBLEMS ({}):".format(len(problems)))
        for p in problems:
            print("  - " + p)
        if args.strict:
            return 1
    else:
        print("verification    : OK")

    if args.expect is not None and len(records) != args.expect:
        print("EXPECTED {} entries, have {}".format(args.expect, len(records)))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
