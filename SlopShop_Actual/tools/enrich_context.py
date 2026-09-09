#!/usr/bin/env python3
"""Enrich the single-file corpus into multi-file, function-located vuln bundles.

Problem this fixes (see the diagnosis): the original corpus shipped ONE file per
CVE with the ground-truth line taken from the fix commit's primary hunk.  For
real CVEs that (a) are inter-procedural / cross-file or (b) are "add a missing
check" fixes, that leaves the marked line on a blank / import / comment and
removes the caller/taint context an agent needs to actually find the bug.

For each CVE this pass:
  * re-fetches the fix commit (shallow, blobless git),
  * pulls the pre-fix (vulnerable) version of EVERY source file the fix touched
    plus the sibling files in the primary file's directory (module context), so
    the source->sink flow is present in-repo,
  * re-derives the real sink location as the **enclosing function** of the fix,
    using git's own hunk section heading (no fragile hand-written parsers) plus
    an anchor to the first real code line the fix changed,
  * flags CVEs with no in-repo code sink (config/doc-only fixes, purely
    out-of-repo issues) so the packager can drop them.

Output: ``corpus/enriched.jsonl`` and the vendored context tree under
``corpus/context/<CVE>/<original-relative-path>``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
MANIFEST = CORPUS / "manifest.jsonl"
CONTEXT = CORPUS / "context"
ENRICHED = CORPUS / "enriched.jsonl"

SCRATCH = Path(os.environ.get("SLOP_SCRATCH", os.environ.get(
    "HELIX_SCRATCH",
    str(ROOT / ".enrich-cache"))))
REPO_CACHE = SCRATCH / "repos"

SUPPORTED_EXT = {
    ".c", ".h", ".cpp", ".cc", ".hpp", ".java", ".py", ".js", ".jsx", ".mjs",
    ".cjs", ".ts", ".tsx", ".go", ".rs", ".rb", ".php", ".cs",
}
EXT_LANG = {
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".py": "python", ".go": "go",
    ".java": "java", ".php": "php", ".rb": "ruby", ".cs": "csharp", ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
}
EXCLUDE_SUBSTR = ("test", "spec", "fixture", "/docs/", "example", "changelog",
                  "vendor/", "node_modules/", ".min.", "/dist/", "snapshot",
                  "__mocks__", "/e2e/")

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$")
# extract an identifier that looks like a function/method name from a git section heading
NAME_IN_HEADING = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
# added lines that look like a security guard (helps pick the real sink hunk)
GUARD_RE = re.compile(
    r"\b(if|unless|throw|raise|return|abort|die|reject|deny|denied|forbid|forbidden|"
    r"validate|validation|saniti[sz]e|escape|encode|permission|author|authenticate|"
    r"verify|check|assert|bound|limit|clamp|filter|allowlist|whitelist|allowe?d|"
    r"csrf|token|secure|constant_time|compare_digest|strip|quote|param|bind)\b", re.I)


def _line_kind(t: str) -> str:
    t = t.strip()
    if not t:
        return "blank"
    if re.match(r"^(//|#|/\*|\*|\*/|--|<!--)", t):
        return "comment"
    if re.match(r"^(import |from |use |using |include |require|package |namespace )", t):
        return "import"
    if re.match(r"^[\}\)\];,{]+$", t):
        return "punct"
    return "code"


def git(cwd: Path, *args: str, timeout: int = 240) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(cwd), capture_output=True,
                          text=True, timeout=timeout, encoding="utf-8", errors="replace")


def repo_dir(repo_url: str) -> Path:
    import hashlib
    return REPO_CACHE / hashlib.sha256(repo_url.encode()).hexdigest()[:16]


def ensure_commit(repo_url: str, sha: str) -> Path | None:
    d = repo_dir(repo_url)
    if not d.exists():
        d.mkdir(parents=True, exist_ok=True)
        git(d, "init", "-q")
        git(d, "remote", "add", "origin", repo_url)
    if git(d, "cat-file", "-e", sha).returncode == 0:
        return d
    if git(d, "fetch", "--depth", "2", "--filter=blob:none", "-q", "origin", sha).returncode != 0:
        return None
    return d if git(d, "cat-file", "-e", sha).returncode == 0 else None


CUTOFF = "2025-12-01"  # fix commit must be strictly AFTER this to be post-cutoff


def fix_commit_date(d: Path, sha: str) -> str | None:
    """Committer date (YYYY-MM-DD) of the fix commit — the authoritative
    'when the vuln/fix became public' signal, unlike OSV's record timestamp."""
    res = git(d, "show", "-s", "--format=%ci", sha)
    return res.stdout.strip()[:10] if res.returncode == 0 and res.stdout.strip() else None


def modified_files(d: Path, sha: str) -> list[str]:
    res = git(d, "show", "--name-status", "--format=", sha)
    out = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].upper().startswith("M"):
            out.append(parts[-1])
    return out


def prefix_blob(d: Path, sha: str, path: str) -> str | None:
    res = git(d, "cat-file", "-p", "{}^:{}".format(sha, path))
    return res.stdout if res.returncode == 0 and res.stdout else None


def list_dir(d: Path, sha: str, directory: str) -> list[str]:
    """List files in `directory` at the pre-fix tree."""
    spec = "{}^:{}".format(sha, directory) if directory else "{}^".format(sha)
    res = git(d, "ls-tree", "--name-only", spec)
    if res.returncode != 0:
        return []
    prefix = (directory + "/") if directory else ""
    return [prefix + n for n in res.stdout.splitlines()]


def hunks_detailed(d: Path, sha: str, path: str):
    """Per-hunk {old_start, old_count, added:[str], heading} from a unified=0 diff."""
    res = git(d, "show", "--format=", "--unified=0", sha, "--", path)
    hunks = []
    cur = None
    for line in res.stdout.splitlines():
        m = HUNK_RE.match(line)
        if m:
            cur = {"old_start": int(m.group(1)),
                   "old_count": 1 if m.group(2) is None else int(m.group(2)),
                   "added": [], "heading": (m.group(5) or "").strip()}
            hunks.append(cur)
        elif cur is not None and line.startswith("+") and not line.startswith("+++"):
            cur["added"].append(line[1:])
    return hunks


def derive_sink(pre_lines: list[str], hunks: list[dict]):
    """Pick the real vulnerable code line + envelope from a file's hunks.

    Returns (sink_line, env_start, env_end, real_code_line_count, guard_score) or
    None when the file's changes touch no real code (pure import/comment/blank)."""
    n = len(pre_lines)

    def kind_at(ln: int) -> str:
        return _line_kind(pre_lines[ln - 1]) if 1 <= ln <= n else "blank"

    real_changed: list[int] = []
    guard_score = 0
    for h in hunks:
        guard_score += sum(1 for a in h["added"] if GUARD_RE.search(a))
        if h["old_count"] == 0:
            # pure insertion: the guarded code is right around the insertion point
            for cand in (h["old_start"], h["old_start"] + 1, h["old_start"] - 1):
                if kind_at(cand) == "code":
                    real_changed.append(cand)
                    break
        else:
            for ln in range(h["old_start"], h["old_start"] + h["old_count"]):
                if kind_at(ln) == "code":
                    real_changed.append(ln)
    real_changed = sorted(set(l for l in real_changed if 1 <= l <= n))
    if not real_changed:
        return None
    sink_line = real_changed[0]
    return sink_line, real_changed[0], real_changed[-1], len(real_changed), guard_score


def first_real_code_line(lines: list[str], near: int) -> int:
    """Return a 1-indexed line at/after `near` that is real code, not blank/comment/brace."""
    n = len(lines)
    for i in range(max(1, near), min(n, near + 25) + 1):
        t = lines[i - 1].strip()
        if not t:
            continue
        if re.match(r"^(//|#|/\*|\*|\*/|--|<!--|\})", t):
            continue
        if re.match(r"^(import |from |use |using |include |require|package |namespace )", t):
            continue
        return i
    return min(max(1, near), n)


def enclosing_function(lines: list[str], anchor: int, heading: str) -> tuple[str, int, int]:
    """Best-effort (name, start_line, end_line) of the function enclosing `anchor`."""
    n = len(lines)
    name = ""
    mh = NAME_IN_HEADING.search(heading or "")
    if mh:
        name = mh.group(1)

    start = None
    # Prefer locating the section-heading text itself in the file, above the anchor.
    if heading:
        needle = heading.strip()[:60]
        for i in range(min(anchor, n), 0, -1):
            if needle and needle in lines[i - 1]:
                start = i
                break
    if start is None:
        # Walk upward for a plausible function header.
        for i in range(min(anchor, n), 0, -1):
            if FUNC_HEADER.match(lines[i - 1]):
                start = i
                if not name:
                    m2 = NAME_IN_HEADING.search(lines[i - 1])
                    if m2:
                        name = m2.group(1)
                break
    if start is None:
        start = max(1, anchor - 3)

    indent = len(lines[start - 1]) - len(lines[start - 1].lstrip())
    end = n
    for i in range(start + 1, n + 1):
        line = lines[i - 1]
        if not line.strip():
            continue
        cur_indent = len(line) - len(line.lstrip())
        if cur_indent <= indent and FUNC_HEADER.match(line) and i > start + 1:
            end = i - 1
            break
        if i - start > 400:
            end = start + 400
            break
    return name or "(anonymous)", start, min(end, n)


def is_supported(path: str) -> bool:
    low = path.lower()
    if any(s in low for s in EXCLUDE_SUBSTR):
        return False
    return Path(path).suffix.lower() in SUPPORTED_EXT


def enrich_one(rec: dict, sibling_cap: int, total_line_cap: int) -> dict:
    out = dict(rec)
    out["context_files"] = []
    out["drop_reason"] = None
    d = ensure_commit(rec["repo"], rec["fix_commit"])
    if d is None:
        out["drop_reason"] = "fetch-failed"
        return out

    # Authoritative post-cutoff gate: the fix (which makes the vuln public) must
    # land AFTER the cutoff. OSV's `published` timestamp is unreliable (old CVEs
    # get re-imported later), so we trust the fix commit date instead.
    fdate = fix_commit_date(d, rec["fix_commit"])
    out["fix_commit_date"] = fdate
    if fdate is not None and fdate <= CUTOFF:
        out["drop_reason"] = "pre-cutoff-fix-commit ({})".format(fdate)
        return out

    changed = modified_files(d, rec["fix_commit"])
    changed_src = [f for f in changed if is_supported(f)]
    if not changed_src:
        out["drop_reason"] = "no-source-file-in-fix"
        return out

    # Choose the sink file: the changed source file with the most real-code
    # changed lines (tie -> more guard-like additions, then the advisory's file).
    best = None  # (real_count, guard_score, is_upstream, file, sink_line, env_start, env_end, pre, heading)
    for f in changed_src:
        pre_f = prefix_blob(d, rec["fix_commit"], f)
        if pre_f is None:
            continue
        hunks_f = hunks_detailed(d, rec["fix_commit"], f)
        if not hunks_f:
            continue
        derived = derive_sink(pre_f.split("\n"), hunks_f)
        if derived is None:
            continue
        sink_line, env_s, env_e, real_count, guard = derived
        heading = hunks_f[0]["heading"]
        key = (real_count, guard, 1 if f == rec["upstream_path"] else 0)
        if best is None or key > best[0]:
            best = (key, f, sink_line, env_s, env_e, pre_f, heading)
    if best is None:
        out["drop_reason"] = "no-code-sink (import/comment/config-only fix)"
        return out
    _, primary, sink_line, env_s, env_e, pre, heading = best
    lines = pre.split("\n")
    mh = NAME_IN_HEADING.search(heading or "")
    fname = mh.group(1) if mh else ""

    # Vendor: all changed source files + siblings of the primary file's dir.
    to_vendor: list[str] = []
    for f in changed_src:
        if f not in to_vendor:
            to_vendor.append(f)
    primary_dir = str(Path(primary).parent).replace("\\", "/")
    for sib in list_dir(d, rec["fix_commit"], primary_dir if primary_dir != "." else ""):
        if sib in to_vendor:
            continue
        if is_supported(sib):
            to_vendor.append(sib)
        if len(to_vendor) >= sibling_cap:
            break

    base = CONTEXT / rec["cve"]
    written = []
    total_lines = 0
    for f in to_vendor:
        content = prefix_blob(d, rec["fix_commit"], f)
        if content is None:
            continue
        fl = content.count("\n") + 1
        if total_lines + fl > total_line_cap and f != primary:
            continue
        total_lines += fl
        dest = base / f
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        written.append({"path": f, "lines": fl, "language": EXT_LANG.get(Path(f).suffix.lower(), "text"),
                        "is_primary": f == primary})

    out["context_files"] = written
    out["primary_file"] = primary
    out["sink_function"] = fname or "(unknown)"
    out["sink_line"] = sink_line
    out["sink_env_start"] = env_s
    out["sink_env_end"] = env_e
    out["changed_source_files"] = changed_src
    out["context_total_lines"] = total_lines
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", help="only these CVE ids (for testing)")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--sibling-cap", type=int, default=12)
    ap.add_argument("--total-line-cap", type=int, default=6000)
    ap.add_argument("--append", action="store_true", help="append to enriched.jsonl (resume)")
    args = ap.parse_args()

    REPO_CACHE.mkdir(parents=True, exist_ok=True)
    CONTEXT.mkdir(parents=True, exist_ok=True)

    records = [json.loads(l) for l in MANIFEST.read_text(encoding="utf-8").splitlines() if l.strip()]
    if args.only:
        records = [r for r in records if r["cve"] in set(args.only)]
    if args.limit:
        records = records[:args.limit]

    done = set()
    if args.append and ENRICHED.exists():
        for l in ENRICHED.read_text(encoding="utf-8").splitlines():
            if l.strip():
                done.add(json.loads(l)["cve"])

    mode = "a" if args.append else "w"
    kept = dropped = 0
    with open(ENRICHED, mode, encoding="utf-8") as out:
        for rec in records:
            if rec["cve"] in done:
                continue
            try:
                e = enrich_one(rec, args.sibling_cap, args.total_line_cap)
            except subprocess.TimeoutExpired:
                e = dict(rec); e["drop_reason"] = "timeout"; e["context_files"] = []
            out.write(json.dumps(e) + "\n")
            out.flush()
            if e["drop_reason"]:
                dropped += 1
                print("  DROP  {:12} {} ({})".format(e["drop_reason"], e["cve"], e["primary_cwe"]))
            else:
                kept += 1
                print("  keep  {:20} {} sink={} L{} env{}-{} ctx={}f".format(
                    e["cve"], e["primary_cwe"], Path(e["primary_file"]).name,
                    e["sink_line"], e["sink_env_start"], e["sink_env_end"], len(e["context_files"])))
    print("enriched: {} kept, {} dropped".format(kept, dropped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
