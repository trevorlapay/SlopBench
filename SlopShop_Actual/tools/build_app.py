#!/usr/bin/env python3
"""Lay the enriched real-CVE corpus out as the installable SlopShop app.

Consumes ``corpus/enriched.jsonl`` (from enrich_context.py) and produces a tree
that matches the other SlopShop benches: a polyglot ``services/<domain>-<lang>/``
marketplace whose component code is the **verbatim, post-cutoff CVE source plus
its surrounding module** (so the vulnerability is actually reachable/findable by
an agent that reads across files), with CVE/CWE tokens redacted from everything
the scanner sees.

Outputs:
  * ``services/<service>/<component>/<orig-relpath>`` — real code (redacted)
  * per-service manifest + README, top-level README.md (neutral app) + BENCHMARK.md
  * ``../VulnerabilityKeys/SlopShop_Actual.vulnerability_key.json`` (+ .md) in the
    same schema as the sibling keys: {id, file, line, language, category, cwe, ...}

Dropped CVEs (no in-repo code sink) are excluded from the scored app and listed
in BENCHMARK.md as out-of-scope.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # SlopShop_Actual/
SUITE = ROOT.parent                                    # SlopBench/
ENRICHED = ROOT / "corpus" / "enriched.jsonl"
KEYS = SUITE / "VulnerabilityKeys"

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

# CWE -> coarse category, aligned with the sibling keys' vocabulary.
CWE_CAT = {
    "CWE-89": "injection", "CWE-564": "injection", "CWE-943": "injection",
    "CWE-77": "injection", "CWE-78": "injection", "CWE-88": "injection",
    "CWE-90": "injection", "CWE-91": "injection", "CWE-94": "injection", "CWE-95": "injection",
    "CWE-917": "injection", "CWE-1336": "injection", "CWE-74": "injection",
    "CWE-79": "xss", "CWE-80": "xss", "CWE-83": "xss", "CWE-116": "xss",
    "CWE-22": "path-traversal", "CWE-23": "path-traversal", "CWE-36": "path-traversal",
    "CWE-59": "path-traversal", "CWE-61": "path-traversal", "CWE-73": "path-traversal", "CWE-98": "path-traversal",
    "CWE-918": "ssrf", "CWE-601": "open-redirect",
    "CWE-502": "deserialization", "CWE-611": "xxe", "CWE-776": "xxe",
    "CWE-287": "authn", "CWE-306": "authn", "CWE-384": "authn", "CWE-307": "authn", "CWE-620": "authn",
    "CWE-862": "authz", "CWE-863": "authz", "CWE-269": "authz", "CWE-280": "authz", "CWE-732": "authz",
    "CWE-798": "secrets", "CWE-321": "secrets", "CWE-256": "secrets", "CWE-312": "secrets",
    "CWE-522": "secrets", "CWE-256": "secrets", "CWE-1391": "secrets",
    "CWE-327": "crypto", "CWE-328": "crypto", "CWE-326": "crypto", "CWE-916": "crypto",
    "CWE-330": "crypto", "CWE-338": "crypto", "CWE-347": "crypto", "CWE-759": "crypto", "CWE-1204": "crypto",
    "CWE-362": "concurrency", "CWE-367": "concurrency",
    "CWE-400": "dos", "CWE-770": "dos", "CWE-1333": "dos", "CWE-248": "dos", "CWE-674": "dos",
    "CWE-125": "memory", "CWE-787": "memory", "CWE-416": "memory", "CWE-415": "memory",
    "CWE-119": "memory", "CWE-131": "memory", "CWE-193": "memory", "CWE-121": "memory", "CWE-122": "memory",
    "CWE-200": "info-exposure", "CWE-209": "info-exposure", "CWE-532": "info-exposure",
    "CWE-829": "supply-chain", "CWE-494": "supply-chain", "CWE-471": "data-integrity", "CWE-913": "data-integrity",
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


def redact(text: str) -> str:
    return CWE_RE.sub("WEAKNESSREF", CVE_RE.sub("ADVISORYREF", text))


def load_enriched() -> list[dict]:
    if not ENRICHED.exists():
        raise SystemExit("run tools/enrich_context.py first")
    recs = [json.loads(l) for l in ENRICHED.read_text(encoding="utf-8").splitlines() if l.strip()]
    return recs


def pkg_short(rec: dict) -> str:
    pkg = rec.get("package") or rec["repo"].rsplit("/", 1)[-1]
    slug = pkg.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    slug = re.sub(r"[^a-z0-9]+", "-", slug.lower()).strip("-")
    return slug or "component"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args()

    recs = load_enriched()
    kept = [r for r in recs if not r.get("drop_reason")]
    dropped = [r for r in recs if r.get("drop_reason")]

    services_dir = ROOT / "services"
    if services_dir.exists():
        shutil.rmtree(services_dir)
    # remove the old neutral workspace layout entirely
    for stale in ("workspaces",):
        if (ROOT / stale).exists():
            shutil.rmtree(ROOT / stale)

    used_components: dict[str, int] = defaultdict(int)
    findings = []
    leaks = 0
    per_service_langs: dict[str, set] = defaultdict(set)

    for i, rec in enumerate(sorted(kept, key=lambda r: r["cve"]), 1):
        svc = SERVICE.get(rec["language"], "catalog-python")
        base_slug = pkg_short(rec)
        used_components[base_slug] += 1
        comp = base_slug if used_components[base_slug] == 1 else "{}-{}".format(base_slug, used_components[base_slug])
        comp_root = services_dir / svc / comp

        # write every context file (redacted), preserving internal relative structure
        sink_rel_in_app = None
        for cf in rec.get("context_files", []):
            content = redact((ROOT / "corpus" / "context" / rec["cve"] / cf["path"]).read_text(encoding="utf-8", errors="replace"))
            dest = comp_root / cf["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(content, encoding="utf-8")
            if IDENT.search(content) or IDENT.search(str(dest)):
                leaks += 1
            per_service_langs[svc].add(cf["language"])
            if cf["path"] == rec["primary_file"]:
                sink_rel_in_app = "services/{}/{}/{}".format(svc, comp, cf["path"])
        if sink_rel_in_app is None:
            # primary wasn't in context list (shouldn't happen) -> skip
            continue

        cat = CWE_CAT.get(rec["primary_cwe"], "other")
        env_lo = rec.get("sink_env_start") or rec["sink_line"]
        env_hi = rec.get("sink_env_end") or rec["sink_line"]
        findings.append({
            "id": "VULN-{:04d}".format(i),
            "file": sink_rel_in_app,
            "line": rec["sink_line"],
            # range fields for the actual-scorer (function/region-level matching)
            "workspace_path": sink_rel_in_app,
            "start_line": env_lo,
            "end_line": env_hi,
            "language": rec["language"],
            "category": cat,
            "cwe": rec["primary_cwe"],
            "primary_cwe": rec["primary_cwe"],
            "cwe_ids": rec["cwe_ids"],
            "cve": rec["cve"],
            "difficulty": "high",
            "description": rec.get("summary") or "(see advisory)",
            "_provenance": {
                "published": rec["published"], "repo": rec["repo"],
                "fix_commit": rec["fix_commit"], "package": rec.get("package", ""),
                "upstream_path": rec["upstream_path"],
                "context_files": [c["path"] for c in rec.get("context_files", [])],
            },
        })

    # per-service manifests + READMEs
    active_services = sorted({SERVICE.get(r["language"], "catalog-python") for r in kept})
    for svc in active_services:
        fname, body = MANIFESTS.get(svc, ("README.md", ""))
        (services_dir / svc / fname).parent.mkdir(parents=True, exist_ok=True)
        if body:
            (services_dir / svc / fname).write_text(body, encoding="utf-8")
        lang, resp = SERVICE_DESC.get(svc, ("", ""))
        (services_dir / svc / "README.md").write_text(
            "# {}\n\n{} service. {}.\n\nComponents live under this directory; each is an\nintegrated module of the SlopShop platform.\n".format(svc, lang, resp),
            encoding="utf-8")

    _write_app_readme(active_services)
    _write_benchmark_md(len(findings), dropped)
    _write_infra()
    _write_keys(findings)

    print("services      :", ", ".join(active_services))
    print("components    :", sum(used_components.values()))
    print("scored vulns  :", len(findings))
    _pre = sum(1 for d in dropped if str(d.get("drop_reason", "")).startswith("pre-cutoff"))
    print("dropped       :", len(dropped), "({} pre-cutoff-fix, {} no-code-sink/other)".format(_pre, len(dropped) - _pre))
    print("code files    :", sum(1 for _ in (ROOT / 'services').rglob('*') if _.is_file()))
    print("CVE/CWE leaks :", leaks)
    print("key           :", KEYS / "SlopShop_Actual.vulnerability_key.json")
    if leaks and args.strict:
        return 1
    return 0


def _write_app_readme(services: list[str]) -> None:
    rows = []
    for svc in services:
        lang, resp = SERVICE_DESC.get(svc, ("", ""))
        rows.append("| `services/{}/` | {} | {} |".format(svc, lang, resp))
    (ROOT / "README.md").write_text(
        "# SlopShop\n\n"
        "SlopShop is an online marketplace. Shoppers browse a catalogue, add items to a\n"
        "cart, check out, and pay; sellers list products and fulfil orders.\n\n"
        "The system is polyglot: each service is written in whichever language its team\n"
        "was most productive in, and the services talk to each other over HTTP/JSON.\n\n"
        "## Services\n\n"
        "| Path | Language | Responsibility |\n|------|----------|----------------|\n"
        + "\n".join(rows) + "\n\n"
        "## Layout\n\n    services/     one directory per service, split into components\n"
        "    infra/        container image and CI pipeline\n\n"
        "## Local development\n\nEach service builds with its own language toolchain "
        "(`pip`, `go build`, `mvn`, `dotnet build`, `cargo build`, `composer install`,\n"
        "`npm install`, `bundle`, `make`).\n",
        encoding="utf-8")


def _write_benchmark_md(n: int, dropped: list[dict]) -> None:
    lines = [
        "# SlopShop_Actual — real post-cutoff CVE bench (evaluator-only)",
        "",
        "> Evaluator-only. Remove `BENCHMARK.md`, `tools/`, `corpus/`, `provenance/`,",
        "> `build/` before pointing a scanner at this directory. What remains —",
        "> `README.md`, `services/`, `infra/` — is an ordinary polyglot app.",
        "",
        "The answer key is `VulnerabilityKeys/SlopShop_Actual.vulnerability_key.json`.",
        "",
        "Every finding is a **real, publicly-disclosed CVE** whose advisory was published",
        "**after 2025-12-01**. Each component under `services/*/` is the **verbatim upstream",
        "source at the pre-fix commit, together with its surrounding module** so the",
        "source->sink flow is present in-repo (an agent must read across files).",
        "",
        "- Scored findings: **{}**".format(n),
        "- Ground-truth line = the re-derived real sink line (not the fix commit's",
        "  incidental hunk line).",
        "",
        "## Out of scope (dropped)",
        "",
        "Dropped for one of two reasons: **pre-cutoff-fix-commit** (the fix landed on or",
        "before 2025-12-01 by committer date, so the vuln was public pre-cutoff despite a",
        "later OSV/CVE timestamp) or **no-code-sink** (the fix touched only config/imports,",
        "or the defect is purely out-of-repo). Not scored:",
        "",
    ]
    for d in dropped:
        lines.append("- {} ({}): {}".format(d["cve"], d.get("drop_reason"), d.get("summary", "")[:80]))
    (ROOT / "BENCHMARK.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_infra() -> None:
    d = ROOT / "infra"
    d.mkdir(exist_ok=True)
    (d / "Dockerfile").write_text(
        "# Multi-stage build for the SlopShop platform (illustrative).\n"
        "FROM debian:bookworm-slim\nWORKDIR /app\nCOPY services/ /app/services/\n"
        "CMD [\"/bin/true\"]\n", encoding="utf-8")
    gh = ROOT / ".github" / "workflows"
    gh.mkdir(parents=True, exist_ok=True)
    (gh / "ci.yml").write_text(
        "name: ci\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - uses: actions/checkout@v4\n      - run: echo build\n",
        encoding="utf-8")


def _write_keys(findings: list[dict]) -> None:
    KEYS.mkdir(parents=True, exist_ok=True)
    from collections import Counter
    # `entries` is the shape scoring/score.py::score_actual reads (workspace_path
    # + start_line/end_line range + cwe_ids); `findings` is the sibling-readable
    # shape. Both describe the same vulns.
    entries = [{
        "id": f["id"], "cve": f["cve"], "workspace_path": f["workspace_path"],
        "start_line": f["start_line"], "end_line": f["end_line"],
        "primary_cwe": f["primary_cwe"], "cwe_ids": f["cwe_ids"],
        "language": f["language"], "category": f["category"],
        "summary": f["description"], "sink_line": f["line"],
    } for f in findings]
    doc = {
        "benchmark": "SlopShop_Actual",
        "description": "Real, publicly-disclosed vulnerabilities (CVE/GHSA) with advisories "
                       "published after 2025-12-01, laid out as the SlopShop app with verbatim "
                       "upstream code plus surrounding module context. Ground-truth is the "
                       "re-derived real sink (line + enclosing region).",
        "cutoff": "2025-12-01",
        "total_findings": len(findings),
        "by_cwe": dict(Counter(f["cwe"] for f in findings).most_common()),
        "by_category": dict(Counter(f["category"] for f in findings).most_common()),
        "by_language": dict(Counter(f["language"] for f in findings).most_common()),
        "entries": entries,
        "findings": findings,
    }
    (KEYS / "SlopShop_Actual.vulnerability_key.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

    md = ["# SlopShop_Actual — Vulnerability Key",
          "",
          "Real post-cutoff CVEs ({} scored). Each row's `file`+`line` is the re-derived".format(len(findings)),
          "sink in the SlopShop app tree; full provenance follows.",
          "",
          "| ID | CVE | CWE | Cat | Lang | File : line |",
          "|----|-----|-----|-----|------|-------------|"]
    for f in findings:
        md.append("| {} | {} | {} | {} | {} | `{}:{}` |".format(
            f["id"], f["cve"], f["cwe"], f["category"], f["language"], f["file"], f["line"]))
    (KEYS / "SlopShop_Actual.vulnerability_key.md").write_text("\n".join(md) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
