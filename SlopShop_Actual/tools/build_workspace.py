#!/usr/bin/env python3
"""Assemble the scanner-facing workspace from the harvested corpus.

Two hard requirements drive this step:

  1. **Nothing may identify a vulnerability to the model under test.** No CVE or
     CWE token, no project name, no vuln title -- not in a path, a file name, or
     the file *contents*. The workspace is what the LLM SAST scanner reads; it
     must look like ordinary application code.
  2. **App-like layout.** Files are placed in a plausible polyglot
     "platform" monorepo (neutral service + module names), not a flat
     ``sample_NNNN`` dump.

The real, verbatim vulnerable code is preserved line-for-line; the only content
change is an in-place redaction of any ``CVE-xxxx-yyyy`` / ``CWE-nn`` token that
happens to appear in an upstream comment (redaction keeps the line count, so
ground-truth line numbers stay exact).

Ground truth (the answer key: neutral-path -> CVE/CWE/lines) is written to
``evaluator_data/<name>/`` **outside** the workspace, so the scanner cannot read
it.  ``sastbench evaluate`` scores against that.

Run: python tools/build_workspace.py --name postcutoff
"""

from __future__ import annotations

import argparse
import json
import random
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
MANIFEST = CORPUS / "manifest.jsonl"

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
CWE_RE = re.compile(r"CWE-\d{1,6}", re.I)
IDENT_SCAN = re.compile(r"CVE-\d|CWE-\d", re.I)

# Neutral polyglot "platform" layout: each language maps to plausible service
# directories.  Names are generic on purpose -- they encode nothing.
LANG_SERVICES: dict[str, list[str]] = {
    "go": ["edge-proxy", "scheduler", "fleet-controller", "object-gateway"],
    "typescript": ["web-console", "admin-portal"],
    "javascript": ["api-gateway"],
    "php": ["billing-service", "content-hub"],
    "python": ["analytics-engine", "ml-router"],
    "java": ["workflow-orchestrator"],
    "rust": ["crypto-core", "packfile-lib"],
    "ruby": ["notification-service"],
    "csharp": ["payments-adapter"],
    "c": ["sandbox-runtime"],
    "cpp": ["sandbox-runtime"],
}

LOWER_VOCAB = ["handler", "service", "client", "store", "router", "worker",
               "middleware", "gateway", "proxy", "cache", "queue", "codec",
               "parser", "engine", "provider", "resolver", "manager", "pipeline",
               "controller", "adapter"]
UPPER_VOCAB = ["Controller", "Service", "Repository", "Handler", "Provider",
               "Resolver", "Manager", "Client", "Filter", "Gateway", "Mapper",
               "Processor", "Validator", "Dispatcher"]


def redact(text: str) -> str:
    """Remove CVE/CWE tokens in place, preserving line count."""
    text = CVE_RE.sub("ADVISORYREF", text)
    text = CWE_RE.sub("WEAKNESSREF", text)
    return text


def load_manifest() -> list[dict]:
    return [json.loads(l) for l in MANIFEST.read_text(encoding="utf-8").splitlines() if l.strip()]


def opaque_corpus_names(records: list[dict]) -> None:
    """Rename corpus files so no filename on disk carries a CVE; update manifest."""
    ordered = sorted(records, key=lambda r: r["cve"])
    for i, r in enumerate(ordered, 1):
        ext = Path(r["local_path"]).suffix
        new_rel = "corpus/{}/vuln_{:04d}{}".format(r["language"], i, ext)
        old = ROOT / r["local_path"]
        new = ROOT / new_rel
        if old.resolve() != new.resolve():
            new.parent.mkdir(parents=True, exist_ok=True)
            if old.exists():
                shutil.move(str(old), str(new))
        r["local_path"] = new_rel
        r["opaque_id"] = "vuln_{:04d}".format(i)
    # remove any now-empty CVE-named leftovers
    with open(MANIFEST, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def java_pkg(service: str) -> str:
    return service.replace("-", "")


def neutral_path(record: dict, service: str, counter: int) -> str:
    lang = record["language"]
    ext = Path(record["local_path"]).suffix or {
        "go": ".go", "python": ".py", "php": ".php", "java": ".java",
        "javascript": ".js", "typescript": ".ts", "rust": ".rs",
        "ruby": ".rb", "csharp": ".cs", "c": ".c", "cpp": ".cpp",
    }.get(lang, ".txt")

    if lang == "java":
        name = UPPER_VOCAB[counter % len(UPPER_VOCAB)]
        return "code/services/{svc}/src/main/java/com/platform/{pkg}/{name}{n}.java".format(
            svc=service, pkg=java_pkg(service), name=name, n=counter)
    if lang == "csharp":
        name = UPPER_VOCAB[counter % len(UPPER_VOCAB)]
        return "code/services/{svc}/src/{name}{n}.cs".format(svc=service, name=name, n=counter)
    if lang == "php":
        name = UPPER_VOCAB[counter % len(UPPER_VOCAB)]
        return "code/services/{svc}/src/{name}{n}{ext}".format(svc=service, name=name, n=counter, ext=ext)
    if lang == "go":
        word = LOWER_VOCAB[counter % len(LOWER_VOCAB)]
        return "code/services/{svc}/internal/{word}{n}{ext}".format(svc=service, word=word, n=counter, ext=ext)
    if lang in ("javascript", "typescript"):
        word = LOWER_VOCAB[counter % len(LOWER_VOCAB)]
        return "code/services/{svc}/src/{word}{n}{ext}".format(svc=service, word=word, n=counter, ext=ext)
    if lang == "rust":
        word = LOWER_VOCAB[counter % len(LOWER_VOCAB)]
        return "code/services/{svc}/src/{word}{n}{ext}".format(svc=service, word=word, n=counter, ext=ext)
    if lang == "ruby":
        word = LOWER_VOCAB[counter % len(LOWER_VOCAB)]
        return "code/services/{svc}/app/{word}{n}{ext}".format(svc=service, word=word, n=counter, ext=ext)
    # c / cpp / fallback
    word = LOWER_VOCAB[counter % len(LOWER_VOCAB)]
    return "code/services/{svc}/src/{word}{n}{ext}".format(svc=service, word=word, n=counter, ext=ext)


AGENTS_MD = """# AGENTS.md — Input/Output Contract

You are analyzing the source tree under `code/` for security vulnerabilities.

## Reading Input
- Application source is under `code/` (a polyglot service monorepo).
- Analyze every file. Do not modify anything under `code/`.

## Writing Output
Write findings to `output/findings.json`:

```json
{
  "agent_name": "<your name>",
  "findings": [
    {
      "file_path": "code/services/<service>/.../<file>",
      "start_line": 123,
      "end_line": 123,
      "cwe_id": "CWE-<number>",
      "severity": "high",
      "message": "Short description"
    }
  ]
}
```

Required per finding: `file_path`, `start_line`, `cwe_id` (of the form `CWE-<number>`).
Optional: `end_line`, `severity`, `confidence`, `message`.

## Quality Expectations
- Report only genuinely exploitable vulnerabilities.
- Do not flag defensive patterns, style issues, or purely theoretical risks.
"""

OUTPUT_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["findings"],
    "properties": {
        "agent_name": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file_path", "start_line", "cwe_id"],
                "properties": {
                    "file_path": {"type": "string"},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                    "cwe_id": {"type": "string", "pattern": "^CWE-[0-9]+$"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "message": {"type": "string"},
                },
            },
        },
    },
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="postcutoff")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=ROOT / "workspaces")
    args = ap.parse_args()

    records = load_manifest()
    opaque_corpus_names(records)

    ws = args.out / args.name
    code = ws / "code"
    evald = args.out / "evaluator_data" / args.name
    for d in (code, evald):
        if d.exists():
            shutil.rmtree(d)
    code.mkdir(parents=True, exist_ok=True)
    evald.mkdir(parents=True, exist_ok=True)
    (ws / "output").mkdir(exist_ok=True)

    rng = random.Random(args.seed)
    shuffled = records[:]
    rng.shuffle(shuffled)

    lang_counter: dict[str, int] = {}
    ground_truth = []
    mapping = {}
    manifest_files = []
    problems: list[str] = []

    for rec in shuffled:
        lang = rec["language"]
        services = LANG_SERVICES.get(lang, ["core-service"])
        n = lang_counter.get(lang, 0)
        lang_counter[lang] = n + 1
        service = services[n % len(services)]
        rel = neutral_path(rec, service, n)
        # ensure uniqueness
        while (ws / rel).exists() or rel in mapping:
            n += 1
            lang_counter[lang] = n + 1
            service = services[n % len(services)]
            rel = neutral_path(rec, service, n)

        raw = (ROOT / rec["local_path"]).read_text(encoding="utf-8", errors="replace")
        clean = redact(raw)
        nlines = clean.count("\n") + 1
        start, end = rec["start_line"], min(rec["end_line"], nlines)

        target = ws / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(clean, encoding="utf-8")

        if IDENT_SCAN.search(clean) or IDENT_SCAN.search(rel):
            problems.append("identifier leak in " + rel)
        if not (1 <= start <= end <= nlines):
            problems.append("bad line range in {} ({}-{}/{})".format(rel, start, end, nlines))

        ground_truth.append({
            "file_path": rel,
            "start_line": start,
            "end_line": end,
            "function_name": None,
            "cwe_id": rec["primary_cwe"],
            "is_vulnerable": True,
            "benchmark_name": "postcutoff",
            "metadata": {"cve": rec["cve"], "all_cwes": rec["cwe_ids"],
                         "published": rec["published"], "repo": rec["repo"],
                         "fix_commit": rec["fix_commit"]},
        })
        mapping[rel] = {"cve": rec["cve"], "opaque_id": rec["opaque_id"],
                        "language": lang, "primary_cwe": rec["primary_cwe"]}
        manifest_files.append({"path": rel, "language": lang})

    # Workspace (agent-facing) files
    (ws / "AGENTS.md").write_text(AGENTS_MD, encoding="utf-8")
    (ws / "output_schema.json").write_text(json.dumps(OUTPUT_SCHEMA, indent=2), encoding="utf-8")
    rng.shuffle(manifest_files)
    (ws / "manifest.json").write_text(
        json.dumps({"files": manifest_files, "total_files": len(manifest_files)}, indent=2),
        encoding="utf-8")

    # Evaluator-only (outside workspace)
    (evald / "ground_truth.json").write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
    (evald / "file_mapping.json").write_text(json.dumps(mapping, indent=2), encoding="utf-8")
    (evald / "config.json").write_text(json.dumps({
        "benchmark": "postcutoff",
        "total_test_cases": len(records),
        "total_ground_truths": len(ground_truth),
        "workspace_path": str(ws),
        "prompt_template": "selective",
        "layout": "app-like-nested",
    }, indent=2), encoding="utf-8")

    # Final anti-leak sweep across every code file (name + content)
    leaks = 0
    for p in code.rglob("*"):
        if p.is_file():
            if IDENT_SCAN.search(p.name):
                leaks += 1
            if IDENT_SCAN.search(p.read_text(encoding="utf-8", errors="replace")):
                leaks += 1

    services_present = sorted(d.name for d in (code / "services").iterdir()) if (code / "services").exists() else []
    print("workspace       :", ws)
    print("code files      :", sum(1 for _ in code.rglob('*') if _.is_file()))
    print("services        :", services_present)
    print("ground truths   :", len(ground_truth))
    print("evaluator data  :", evald)
    print("CVE/CWE leaks    :", leaks)
    if problems:
        print("PROBLEMS:", len(problems))
        for pr in problems[:10]:
            print("  -", pr)
        return 1
    if leaks:
        print("LEAK CHECK FAILED")
        return 1
    print("leak check      : OK (no CVE/CWE token in any code path or content)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
