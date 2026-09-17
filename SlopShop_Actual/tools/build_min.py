#!/usr/bin/env python3
"""Build SlopShop_Actual_Minimum: a small, self-contained standalone variant.

SlopShop_Actual vendors each CVE's whole surrounding module (median 8 files,
~1200 files total), which overloads LLM scanners. This minimizer selects vulns
that are **findable in one file** — the fix touched only the sink file, so no
module context is needed — and caps files hard, targeting 100-200 total files
while keeping >=50 real post-cutoff vulns and broad CWE/language coverage.

Output is a bench directory inside the SlopBench suite: its `services/` tree is
an ordinary app to scan, its answer key lives in the suite `VulnerabilityKeys/`,
and it is scored by the suite `scoring/score.py --bench minimum`.

Reads SlopShop_Actual/corpus/enriched.jsonl + the vendored verbatim files.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent          # SlopShop_Actual/
ENRICHED = SRC / "corpus" / "enriched.jsonl"
CTX = SRC / "corpus" / "context"
SUITE_SCORER = SRC.parent / "scoring" / "score.py"

CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
CWE_RE = re.compile(r"CWE-\d{1,6}", re.I)
IDENT = re.compile(r"CVE-\d|CWE-\d", re.I)

SERVICE = {
    "python": "catalog-python", "go": "orders-go", "java": "search-java",
    "php": "backoffice-php", "javascript": "storefront-node", "typescript": "storefront-node",
    "csharp": "payments-csharp", "rust": "edge-rust", "ruby": "notifications-ruby",
    "c": "imaging-c", "cpp": "imaging-c",
}
SERVICE_DESC = {
    "catalog-python": ("Python", "Catalogue, search indexing, recommendations"),
    "orders-go": ("Go", "Order lifecycle, fulfilment, shipping"),
    "search-java": ("Java", "Full-text search and merchandising"),
    "backoffice-php": ("PHP", "Back-office reporting, imports, admin"),
    "storefront-node": ("JavaScript/TypeScript", "Public web surface, cart, checkout"),
    "payments-csharp": ("C#", "Charge authorisation, ledger, settlement"),
    "edge-rust": ("Rust", "Edge proxy, TLS termination, rate limiting"),
    "notifications-ruby": ("Ruby", "Email and webhook notifications"),
    "imaging-c": ("C/C++", "Thumbnailing and image processing"),
}
MANIFESTS = {
    "catalog-python": ("requirements.txt", "flask==3.0.3\nrequests==2.32.3\nsqlalchemy==2.0.36\npyyaml==6.0.2\n"),
    "orders-go": ("go.mod", "module github.com/slopshop/orders\n\ngo 1.23\n"),
    "search-java": ("pom.xml", "<project><modelVersion>4.0.0</modelVersion>\n  <groupId>com.slopshop</groupId>\n  <artifactId>search</artifactId>\n  <version>1.0.0</version>\n</project>\n"),
    "backoffice-php": ("composer.json", '{\n  "name": "slopshop/backoffice",\n  "require": {"php": ">=8.2"}\n}\n'),
    "storefront-node": ("package.json", '{\n  "name": "@slopshop/storefront",\n  "version": "1.0.0",\n  "private": true\n}\n'),
    "payments-csharp": ("Payments.csproj", "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>\n</Project>\n"),
    "edge-rust": ("Cargo.toml", "[package]\nname = \"slopshop-edge\"\nversion = \"1.0.0\"\nedition = \"2021\"\n"),
    "notifications-ruby": ("Gemfile", "source 'https://rubygems.org'\ngem 'sinatra'\n"),
    "imaging-c": ("Makefile", "CC=cc\nCFLAGS=-O2 -Wall\nall:\n\t$(CC) $(CFLAGS) -c $(wildcard */*.c)\n"),
}
CWE_CAT = {
    "CWE-89": "injection", "CWE-943": "injection", "CWE-77": "injection", "CWE-78": "injection",
    "CWE-94": "injection", "CWE-95": "injection", "CWE-917": "injection", "CWE-90": "injection",
    "CWE-79": "xss", "CWE-80": "xss", "CWE-116": "xss",
    "CWE-22": "path-traversal", "CWE-23": "path-traversal", "CWE-59": "path-traversal",
    "CWE-61": "path-traversal", "CWE-73": "path-traversal", "CWE-98": "path-traversal",
    "CWE-918": "ssrf", "CWE-601": "open-redirect", "CWE-502": "deserialization",
    "CWE-611": "xxe", "CWE-776": "xxe",
    "CWE-287": "authn", "CWE-306": "authn", "CWE-384": "authn", "CWE-620": "authn",
    "CWE-862": "authz", "CWE-863": "authz", "CWE-269": "authz", "CWE-732": "authz",
    "CWE-798": "secrets", "CWE-256": "secrets", "CWE-312": "secrets", "CWE-522": "secrets",
    "CWE-321": "secrets", "CWE-1391": "secrets",
    "CWE-327": "crypto", "CWE-328": "crypto", "CWE-916": "crypto", "CWE-338": "crypto",
    "CWE-347": "crypto", "CWE-759": "crypto",
    "CWE-362": "concurrency", "CWE-367": "concurrency",
    "CWE-400": "dos", "CWE-770": "dos", "CWE-1333": "dos", "CWE-248": "dos", "CWE-674": "dos",
    "CWE-125": "memory", "CWE-787": "memory", "CWE-416": "memory", "CWE-131": "memory",
    "CWE-200": "info-exposure", "CWE-209": "info-exposure", "CWE-532": "info-exposure",
    "CWE-829": "supply-chain", "CWE-471": "data-integrity", "CWE-913": "data-integrity",
}


def redact(t: str) -> str:
    return CWE_RE.sub("WEAKNESSREF", CVE_RE.sub("ADVISORYREF", t))


def sink_lines(r: dict) -> int:
    for c in r["context_files"]:
        if c["path"] == r["primary_file"]:
            return c["lines"]
    return 10 ** 9


def pkg_short(r: dict) -> str:
    pkg = r.get("package") or r["repo"].rsplit("/", 1)[-1]
    slug = re.sub(r"[^a-z0-9]+", "-", pkg.rsplit("/", 1)[-1].lower()).strip("-")
    return slug or "component"


def select(kept: list[dict], target: int, max_sink: int, file_budget: int, extra_cap: int):
    """Round-robin by CWE for diversity; prefer self-contained + small files."""
    cand = [r for r in kept if sink_lines(r) <= max_sink]
    # rank within a CWE: single-source first, then smaller sink file
    for r in cand:
        r["_files_planned"] = 1 + min(extra_cap, max(0, len(r.get("changed_source_files", [])) - 1))
        r["_score"] = (len(r.get("changed_source_files", [])), sink_lines(r))
    by_cwe = defaultdict(list)
    for r in sorted(cand, key=lambda x: x["_score"]):
        by_cwe[r["primary_cwe"]].append(r)
    order = sorted(by_cwe, key=lambda k: (min(x["_score"] for x in by_cwe[k]), k))
    queues = {k: iter(by_cwe[k]) for k in order}
    chosen, files = [], 0
    exhausted = set()
    while len(chosen) < target and len(exhausted) < len(queues) and files < file_budget:
        for k in order:
            if k in exhausted or len(chosen) >= target or files >= file_budget:
                continue
            try:
                r = next(queues[k])
            except StopIteration:
                exhausted.add(k); continue
            chosen.append(r)
            files += r["_files_planned"]
    return chosen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=SRC.parent / "SlopShop_Actual_Minimum")
    ap.add_argument("--target", type=int, default=80)
    ap.add_argument("--max-sink-lines", type=int, default=700)
    ap.add_argument("--file-budget", type=int, default=150)
    ap.add_argument("--extra-context", type=int, default=1,
                    help="max extra changed-source files to include for a multi-file fix")
    args = ap.parse_args()

    recs = [json.loads(l) for l in ENRICHED.read_text(encoding="utf-8").splitlines() if l.strip()]
    kept = [r for r in recs if not r.get("drop_reason")]
    chosen = select(kept, args.target, args.max_sink_lines, args.file_budget, args.extra_context)

    out = args.out
    if (out / "services").exists():
        shutil.rmtree(out / "services")
    (out / "services").mkdir(parents=True, exist_ok=True)

    used = defaultdict(int)
    findings, leaks = [], 0
    active = set()
    for i, rec in enumerate(sorted(chosen, key=lambda r: r["cve"]), 1):
        svc = SERVICE.get(rec["language"], "catalog-python"); active.add(svc)
        base = pkg_short(rec); used[base] += 1
        comp = base if used[base] == 1 else "{}-{}".format(base, used[base])
        # which files to include: sink + up to extra changed-source files present in context
        include = [rec["primary_file"]]
        for f in rec.get("changed_source_files", []):
            if f != rec["primary_file"] and any(c["path"] == f for c in rec["context_files"]):
                include.append(f)
            if len(include) >= 1 + args.extra_context:
                break
        sink_app = None
        for path in include:
            src_file = CTX / rec["cve"] / path
            if not src_file.exists():
                continue
            content = redact(src_file.read_text(encoding="utf-8", errors="replace"))
            dest = out / "services" / svc / comp / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            if IDENT.search(content) or IDENT.search(str(dest)):
                leaks += 1
            if path == rec["primary_file"]:
                sink_app = "services/{}/{}/{}".format(svc, comp, path)
        if sink_app is None:
            continue
        env_lo = rec.get("sink_env_start") or rec["sink_line"]
        env_hi = rec.get("sink_env_end") or rec["sink_line"]
        findings.append({
            "id": "VULN-{:04d}".format(i), "file": sink_app, "line": rec["sink_line"],
            "workspace_path": sink_app, "start_line": env_lo, "end_line": env_hi,
            "language": rec["language"], "category": CWE_CAT.get(rec["primary_cwe"], "other"),
            "cwe": rec["primary_cwe"], "primary_cwe": rec["primary_cwe"], "cwe_ids": rec["cwe_ids"],
            "cve": rec["cve"], "difficulty": "high", "description": rec.get("summary") or "(see advisory)",
            "_provenance": {"published": rec["published"], "repo": rec["repo"],
                            "fix_commit": rec["fix_commit"], "fix_commit_date": rec.get("fix_commit_date"),
                            "package": rec.get("package", ""), "upstream_path": rec["upstream_path"]},
        })

    _scaffold(out, sorted(active), findings)
    total_files = sum(1 for _ in out.rglob("*") if _.is_file())
    code_files = sum(1 for _ in (out / "services").rglob("*") if _.is_file())
    print("out           :", out)
    print("vulns         :", len(findings))
    print("code files    :", code_files)
    print("total files   :", total_files)
    print("distinct CWEs :", len({f["cwe"] for f in findings}))
    print("languages     :", dict(Counter(f["language"] for f in findings)))
    print("CVE/CWE leaks :", leaks)
    return 1 if leaks else 0


def _scaffold(out: Path, services: list[str], findings: list[dict]) -> None:
    # per-service manifest + README
    for svc in services:
        fname, body = MANIFESTS.get(svc, ("README.md", ""))
        (out / "services" / svc).mkdir(parents=True, exist_ok=True)
        if body:
            (out / "services" / svc / fname).write_text(body, encoding="utf-8")
        lang, resp = SERVICE_DESC.get(svc, ("", ""))
        (out / "services" / svc / "README.md").write_text(
            "# {}\n\n{} service. {}.\n".format(svc, lang, resp), encoding="utf-8")
    # app README
    rows = "\n".join("| `services/{}/` | {} | {} |".format(s, *SERVICE_DESC.get(s, ("", ""))) for s in services)
    (out / "README.md").write_text(
        "# SlopShop\n\nSlopShop is an online marketplace, split into polyglot services that talk\n"
        "over HTTP/JSON.\n\n## Services\n\n| Path | Language | Responsibility |\n|------|----------|----------------|\n"
        + rows + "\n\n## Layout\n\n    services/   one directory per service\n    infra/      container image and CI\n",
        encoding="utf-8")
    # infra + ci
    (out / "infra").mkdir(exist_ok=True)
    (out / "infra" / "Dockerfile").write_text(
        "FROM debian:bookworm-slim\nWORKDIR /app\nCOPY services/ /app/services/\nCMD [\"/bin/true\"]\n", encoding="utf-8")
    gh = out / ".github" / "workflows"; gh.mkdir(parents=True, exist_ok=True)
    (gh / "ci.yml").write_text("name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")
    # answer key -> suite VulnerabilityKeys/ (never inside a bench dir), matching
    # the sibling benches; scored by the suite scoring/score.py.
    keys = SRC.parent / "VulnerabilityKeys"; keys.mkdir(exist_ok=True)
    entries = [{"id": f["id"], "cve": f["cve"], "workspace_path": f["workspace_path"],
                "start_line": f["start_line"], "end_line": f["end_line"],
                "primary_cwe": f["primary_cwe"], "cwe_ids": f["cwe_ids"],
                "language": f["language"], "category": f["category"],
                "summary": f["description"], "sink_line": f["line"]} for f in findings]
    doc = {"benchmark": "SlopShop_Actual_Minimum",
           "description": "Minimal variant of SlopShop_Actual: real post-cutoff CVEs "
                          "(advisory + fix after 2025-12-01) selected to be findable in one file, "
                          "so the tree stays small for LLM scanners.",
           "cutoff": "2025-12-01", "total_findings": len(findings),
           "by_cwe": dict(Counter(f["cwe"] for f in findings).most_common()),
           "by_language": dict(Counter(f["language"] for f in findings).most_common()),
           "entries": entries, "findings": findings}
    (keys / "SlopShop_Actual_Minimum.vulnerability_key.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    md = ["# SlopShop_Actual_Minimum — Vulnerability Key", "",
          "{} real post-cutoff CVEs, each findable in one file.".format(len(findings)), "",
          "| ID | CVE | CWE | Cat | Lang | File : line |", "|----|-----|-----|-----|------|-------------|"]
    for f in findings:
        md.append("| {} | {} | {} | {} | {} | `{}:{}` |".format(
            f["id"], f["cve"], f["cwe"], f["category"], f["language"], f["file"], f["line"]))
    (keys / "SlopShop_Actual_Minimum.vulnerability_key.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (out / "BENCHMARK.md").write_text(
        "# SlopShop_Actual_Minimum (evaluator-only)\n\n"
        "> Remove `BENCHMARK.md` and `tools/` before pointing a scanner here. What remains —\n"
        "> `README.md`, `services/`, `infra/` — is an ordinary app. The answer key lives outside\n"
        "> this dir at `VulnerabilityKeys/SlopShop_Actual_Minimum.vulnerability_key.json`.\n\n"
        "{} real CVEs, advisories AND fix commits after 2025-12-01, each self-contained in one\n".format(len(findings)) +
        "file so an LLM scanner is not overloaded with module context or file count. Built by\n"
        "selecting single-file fixes from SlopShop_Actual (see `tools/build_min.py`).\n\n"
        "## Scoring (from the suite root)\n\n```\npython scoring/score.py --bench minimum --sarif your_run.sarif\n```\n",
        encoding="utf-8")
    # copy this builder in for transparency (evaluator-only)
    (out / "tools").mkdir(exist_ok=True)
    shutil.copy2(Path(__file__), out / "tools" / "build_min.py")


if __name__ == "__main__":
    raise SystemExit(main())
