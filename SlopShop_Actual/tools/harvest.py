#!/usr/bin/env python3
"""Harvest real, post-cutoff vulnerabilities into a verbatim source corpus.

Strategy (no invented code, nothing from recall):

  1. Download OSV's authoritative per-ecosystem data dumps (public GCS, no rate
     limit).  Each record is a real published advisory (GHSA/CVE) with a
     disclosure date, CWE ids, affected package, and references.
  2. Keep only records whose ``published`` date is strictly after the cutoff and
     that point at a concrete GitHub *fix commit* (via a GIT range or a
     ``/commit/<sha>`` reference).
  3. For each, fetch the fix commit with a shallow, blobless ``git fetch`` of the
     exact SHA (codeload, not the rate-limited REST API), read the patch to find
     the primary modified source file and its old-side (vulnerable) line range,
     and pull that file **verbatim** at the fix commit's parent
     (``<sha>^:<path>``) -- i.e. the real code as it was when vulnerable.
  4. Write the verbatim file to ``corpus/`` and append a provenance record to
     ``corpus/manifest.jsonl``.

Everything is auditable: every entry carries its advisory URL, disclosure date,
fix commit, and upstream path.  Nothing is included that cannot be re-fetched.

Run:  python tools/harvest.py --target 150
Resumable: already-accepted CVEs in manifest.jsonl are skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
PROVENANCE = ROOT / "provenance"
MANIFEST = CORPUS / "manifest.jsonl"

SCRATCH = Path(os.environ.get(
    "HELIX_SCRATCH",
    r"C:\Users\trevo\AppData\Local\Temp\claude\C--Users-trevo-Claude-SASTBenchTool\cab7a918-60b5-4172-b843-bab4686dc302\scratchpad",
))
OSV_CACHE = SCRATCH / "osv"
REPO_CACHE = SCRATCH / "repos"

CUTOFF = datetime(2025, 12, 1, 23, 59, 59, tzinfo=timezone.utc)  # strict: exclude all of Dec 1

# OSV ecosystem -> (SASTBench language, allowed source extensions)
ECOSYSTEMS: dict[str, tuple[str, tuple[str, ...]]] = {
    "npm": ("javascript", (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")),
    "PyPI": ("python", (".py",)),
    "Go": ("go", (".go",)),
    "Maven": ("java", (".java",)),
    "Packagist": ("php", (".php",)),
    "RubyGems": ("ruby", (".rb", ".c", ".cpp", ".cc")),
    "NuGet": ("csharp", (".cs",)),
    "crates.io": ("rust", (".rs",)),
}

# Extension -> SASTBench language key (overrides ecosystem default per file).
EXT_LANG: dict[str, str] = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".py": "python", ".go": "go", ".java": "java", ".php": "php",
    ".rb": "ruby", ".cs": "csharp", ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
}

COMMIT_RE = re.compile(r"github\.com/([^/\s]+/[^/\s]+?)(?:\.git)?/commit/([0-9a-f]{7,40})", re.I)
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

EXCLUDE_SUBSTR = (
    "test", "spec", "fixture", "/docs/", "example", "sample", "changelog",
    "vendor/", "node_modules/", ".min.", "/dist/", "generated", "snapshot",
    "third_party/", "/e2e/", "benchmark", "mock",
)


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# OSV dump handling
# --------------------------------------------------------------------------- #

def ensure_dump(ecosystem: str) -> Path:
    OSV_CACHE.mkdir(parents=True, exist_ok=True)
    safe = ecosystem.replace("/", "_")
    dest = OSV_CACHE / (safe + ".zip")
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    url = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip".format(ecosystem)
    log("  downloading OSV dump: {}".format(url))
    subprocess.run(["curl", "-sSL", "--max-time", "600", "-o", str(dest), url], check=True)
    return dest


def parse_date(rec: dict) -> datetime | None:
    raw = rec.get("published") or rec.get("modified")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def fix_commit(rec: dict) -> tuple[str, str] | None:
    """Return (github_repo_url, fix_sha) if discoverable, else None."""
    for aff in rec.get("affected") or []:
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT" and "github.com" in (rng.get("repo") or ""):
                for ev in rng.get("events") or []:
                    if ev.get("fixed"):
                        return rng["repo"].rstrip("/"), ev["fixed"]
    for ref in rec.get("references") or []:
        m = COMMIT_RE.search(ref.get("url", ""))
        if m:
            return "https://github.com/" + m.group(1), m.group(2)
    return None


def cwe_ids(rec: dict) -> list[str]:
    ds = rec.get("database_specific") or {}
    out = [c for c in (ds.get("cwe_ids") or []) if re.fullmatch(r"CWE-\d+", c)]
    return out


def primary_alias(rec: dict) -> str:
    for a in rec.get("aliases") or []:
        if a.startswith("CVE-"):
            return a
    return rec.get("id", "UNKNOWN")


def package_name(rec: dict) -> str:
    for aff in rec.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("name"):
            return pkg["name"]
    return ""


def collect_candidates(ecosystems: list[str]) -> list[dict]:
    candidates: list[dict] = []
    for eco in ecosystems:
        lang_default, exts = ECOSYSTEMS[eco]
        try:
            dump = ensure_dump(eco)
        except subprocess.CalledProcessError as exc:
            log("  ! could not download {}: {}".format(eco, exc))
            continue
        z = zipfile.ZipFile(dump)
        kept = 0
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            try:
                rec = json.loads(z.read(name))
            except json.JSONDecodeError:
                continue
            dt = parse_date(rec)
            if dt is None or dt <= CUTOFF:
                continue
            fc = fix_commit(rec)
            if fc is None:
                continue
            cwes = cwe_ids(rec)
            if not cwes:
                continue
            repo, sha = fc
            candidates.append({
                "osv_id": rec.get("id"),
                "cve": primary_alias(rec),
                "aliases": rec.get("aliases") or [],
                "published": dt.isoformat(),
                "ecosystem": eco,
                "lang_default": lang_default,
                "exts": exts,
                "package": package_name(rec),
                "cwe_ids": cwes,
                "primary_cwe": cwes[0],
                "summary": (rec.get("summary") or rec.get("details") or "")[:280],
                "severity": _severity(rec),
                "repo": repo,
                "fix_commit": sha,
                "references": [r.get("url") for r in (rec.get("references") or [])],
            })
            kept += 1
        log("  {}: {} qualifying candidates".format(eco, kept))
    return candidates


def _severity(rec: dict) -> str:
    sev = rec.get("severity") or []
    if sev:
        return str(sev[0].get("score", ""))[:24]
    ds = rec.get("database_specific") or {}
    return ds.get("severity", "") or ""


# --------------------------------------------------------------------------- #
# Verbatim extraction via git
# --------------------------------------------------------------------------- #

def repo_dir(repo_url: str) -> Path:
    key = hashlib.sha256(repo_url.encode()).hexdigest()[:16]
    return REPO_CACHE / key


def git(cwd: Path, *args: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True,
        timeout=timeout, encoding="utf-8", errors="replace",
    )


def ensure_commit(repo_url: str, sha: str) -> Path | None:
    d = repo_dir(repo_url)
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        git(d, "init", "-q")
        git(d, "remote", "add", "origin", repo_url)
    # Already have it?
    if git(d, "cat-file", "-e", sha).returncode == 0:
        return d
    fetched = git(d, "fetch", "--depth", "2", "--filter=blob:none", "-q", "origin", sha, timeout=240)
    if fetched.returncode != 0:
        return None
    return d if git(d, "cat-file", "-e", sha).returncode == 0 else None


def changed_source_files(d: Path, sha: str, exts: tuple[str, ...]) -> list[str]:
    res = git(d, "show", "--name-status", "--format=", sha)
    files: list[str] = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]
        if status.upper() != "M":  # only modified files have a pre-fix version
            continue
        low = path.lower()
        if any(sub in low for sub in EXCLUDE_SUBSTR):
            continue
        if Path(path).suffix.lower() not in exts:
            continue
        files.append(path)
    return files


def old_side_range(d: Path, sha: str, path: str) -> tuple[int, int, int] | None:
    res = git(d, "show", "--format=", "--unified=0", sha, "--", path)
    starts: list[int] = []
    ends: list[int] = []
    hunks = 0
    for line in res.stdout.splitlines():
        m = HUNK_RE.match(line)
        if not m:
            continue
        hunks += 1
        old_start = int(m.group(1))
        old_count = 1 if m.group(2) is None else int(m.group(2))
        if old_count == 0:  # pure insertion: anchor at the line the code was added after
            starts.append(max(1, old_start))
            ends.append(max(1, old_start))
        else:
            starts.append(old_start)
            ends.append(old_start + old_count - 1)
    if not starts:
        return None
    return min(starts), max(ends), hunks


def prefix_file(d: Path, sha: str, path: str) -> str | None:
    res = git(d, "cat-file", "-p", "{}^:{}".format(sha, path))
    if res.returncode != 0 or not res.stdout:
        return None
    return res.stdout


# --------------------------------------------------------------------------- #
# Selection for diversity
# --------------------------------------------------------------------------- #

def order_for_diversity(candidates: list[dict], seed: int = 1) -> list[dict]:
    """Round-robin by primary CWE (then interleave ecosystems) to maximise
    family and language spread before per-repo caps kick in."""
    for c in candidates:
        c["_rank"] = hashlib.sha256((c["osv_id"] or c["cve"]).encode()).hexdigest()
    by_cwe: dict[str, list[dict]] = defaultdict(list)
    for c in sorted(candidates, key=lambda x: x["_rank"]):
        by_cwe[c["primary_cwe"]].append(c)
    order = sorted(by_cwe, key=lambda k: (-len(by_cwe[k]), k))
    queues = {k: iter(by_cwe[k]) for k in order}
    out: list[dict] = []
    exhausted: set[str] = set()
    while len(exhausted) < len(queues):
        for k in order:
            if k in exhausted:
                continue
            try:
                out.append(next(queues[k]))
            except StopIteration:
                exhausted.add(k)
    return out


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def load_accepted() -> set[str]:
    if not MANIFEST.exists():
        return set()
    seen = set()
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.strip():
            seen.add(json.loads(line)["cve"])
    return seen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=150)
    ap.add_argument("--per-repo", type=int, default=3)
    ap.add_argument("--per-cwe", type=int, default=12)
    ap.add_argument("--max-span", type=int, default=80,
                    help="if the changed old-side range exceeds this, fall back to the first hunk")
    ap.add_argument("--ecosystems", nargs="*", default=list(ECOSYSTEMS))
    ap.add_argument("--attempt-cap", type=int, default=4000)
    args = ap.parse_args()

    CORPUS.mkdir(parents=True, exist_ok=True)
    PROVENANCE.mkdir(parents=True, exist_ok=True)
    REPO_CACHE.mkdir(parents=True, exist_ok=True)

    log("collecting candidates from OSV dumps ...")
    candidates = collect_candidates(args.ecosystems)
    log("total candidates: {}".format(len(candidates)))
    candidates = order_for_diversity(candidates)

    accepted = load_accepted()
    repo_counts: Counter = Counter()
    cwe_counts: Counter = Counter()
    for line in (MANIFEST.read_text(encoding="utf-8").splitlines() if MANIFEST.exists() else []):
        if line.strip():
            r = json.loads(line)
            repo_counts[r["repo"]] += 1
            cwe_counts[r["primary_cwe"]] += 1

    have = len(accepted)
    attempts = 0
    mf = open(MANIFEST, "a", encoding="utf-8")
    for cand in candidates:
        if have >= args.target:
            break
        if attempts >= args.attempt_cap:
            break
        if cand["cve"] in accepted:
            continue
        if repo_counts[cand["repo"]] >= args.per_repo:
            continue
        if cwe_counts[cand["primary_cwe"]] >= args.per_cwe:
            continue
        attempts += 1

        try:
            d = ensure_commit(cand["repo"], cand["fix_commit"])
        except subprocess.TimeoutExpired:
            log("  timeout  {} {}".format(cand["cve"], cand["repo"]))
            continue
        if d is None:
            continue
        files = changed_source_files(d, cand["fix_commit"], cand["exts"])
        if not files:
            continue

        chosen = None
        for path in files:
            rng = old_side_range(d, cand["fix_commit"], path)
            if rng is None:
                continue
            content = prefix_file(d, cand["fix_commit"], path)
            if content is None:
                continue
            nlines = content.count("\n") + 1
            start, end, hunks = rng
            if end > nlines or start < 1:
                continue
            if end - start > args.max_span:
                # localise to the first hunk to keep ground truth tight
                first = old_side_range_first(d, cand["fix_commit"], path)
                if first:
                    start, end = first
                    end = min(end, nlines)
            chosen = (path, content, start, end, hunks, nlines)
            break

        if chosen is None:
            continue
        path, content, start, end, hunks, nlines = chosen
        ext = Path(path).suffix.lower()
        language = EXT_LANG.get(ext, cand["lang_default"])
        local_rel = "{}/{}__{}".format(language, cand["cve"], Path(path).name)
        local_path = CORPUS / local_rel
        local_path.parent.mkdir(parents=True, exist_ok=True)
        local_path.write_text(content, encoding="utf-8")

        record = {
            "cve": cand["cve"],
            "osv_id": cand["osv_id"],
            "aliases": cand["aliases"],
            "published": cand["published"],
            "ecosystem": cand["ecosystem"],
            "package": cand["package"],
            "cwe_ids": cand["cwe_ids"],
            "primary_cwe": cand["primary_cwe"],
            "summary": cand["summary"],
            "severity": cand["severity"],
            "repo": cand["repo"],
            "fix_commit": cand["fix_commit"],
            "upstream_path": path,
            "language": language,
            "start_line": start,
            "end_line": end,
            "hunks": hunks,
            "file_lines": nlines,
            "local_path": "corpus/" + local_rel,
            "references": cand["references"],
        }
        mf.write(json.dumps(record) + "\n")
        mf.flush()
        (PROVENANCE / (cand["cve"] + ".json")).write_text(json.dumps(record, indent=2), encoding="utf-8")

        accepted.add(cand["cve"])
        repo_counts[cand["repo"]] += 1
        cwe_counts[cand["primary_cwe"]] += 1
        have += 1
        log("  [{:>3}/{}] {} {} {} L{}-{} ({})".format(
            have, args.target, cand["primary_cwe"], language, cand["cve"], start, end,
            cand["repo"].replace("https://github.com/", "")))

    mf.close()
    log("done: {} accepted ({} attempts), distinct CWEs so far: {}".format(
        have, attempts, len(cwe_counts)))
    return 0


def old_side_range_first(d: Path, sha: str, path: str) -> tuple[int, int] | None:
    res = git(d, "show", "--format=", "--unified=0", sha, "--", path)
    for line in res.stdout.splitlines():
        m = HUNK_RE.match(line)
        if m:
            old_start = int(m.group(1))
            old_count = 1 if m.group(2) is None else int(m.group(2))
            if old_count == 0:
                return max(1, old_start), max(1, old_start)
            return old_start, old_start + old_count - 1
    return None


if __name__ == "__main__":
    sys.exit(main())
