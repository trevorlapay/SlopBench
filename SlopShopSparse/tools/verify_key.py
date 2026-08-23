#!/usr/bin/env python3
"""Read-only sanity check for vulnerability_key.json against the source tree.

Confirms every finding still resolves to a real (non-blank) source line, that no two
findings in the same file fall within MIN_GAP lines of each other, and prints the
difficulty distribution plus the spacing statistics. Does NOT modify anything. The key
is the sole ground truth; the source contains no location hints.
"""
import json
import os
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(ROOT, "vulnerability_key.json")

# Sparsity contract for this variant: within one file, consecutive findings are at
# least this many lines apart. Findings in different files are independent.
MIN_GAP = 10

# The only finding whose sink legitimately IS a source comment.
COMMENT_SINKS = {"VULN-0012"}


def load_lines(path, cache):
    if path not in cache:
        try:
            cache[path] = open(path, encoding="utf-8").read().split("\n")
        except OSError:
            cache[path] = None
    return cache[path]


def check_resolution(findings, cache):
    """Every finding must land on a real, non-blank, non-comment source line."""
    problems = []
    for v in findings:
        path = os.path.join(ROOT, v["file"].replace("/", os.sep))
        lines = load_lines(path, cache)
        if lines is None:
            problems.append((v["id"], "file missing", v["file"]))
            continue
        ln = v["line"]
        if not (0 < ln <= len(lines)):
            problems.append((v["id"], "line out of range", "%s:%d" % (v["file"], ln)))
            continue
        text = lines[ln - 1].strip()
        if not text:
            problems.append((v["id"], "blank line", "%s:%d" % (v["file"], ln)))
        elif text.startswith(("#", "//", "/*", "*", "<!--")) and v["id"] not in COMMENT_SINKS:
            problems.append((v["id"], "comment line", "%s:%d" % (v["file"], ln)))
    return problems


def check_spacing(findings):
    """No two findings in one file may sit within MIN_GAP lines of each other."""
    problems = []
    gaps = []
    by_file = defaultdict(list)
    for v in findings:
        by_file[v["file"]].append(v)
    for path, entries in sorted(by_file.items()):
        entries.sort(key=lambda v: v["line"])
        for a, b in zip(entries, entries[1:]):
            gap = b["line"] - a["line"]
            gaps.append(gap)
            if gap < MIN_GAP:
                problems.append(
                    (b["id"], "gap %d < %d" % (gap, MIN_GAP),
                     "%s:%d after %s:%d" % (path, b["line"], a["id"], a["line"]))
                )
    return problems, gaps


def count_corpus_lines():
    """Total source lines in the tree, excluding the key and the README."""
    total = 0
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git")]
        for name in filenames:
            if name.endswith(".pyc"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/")
            if rel in ("vulnerability_key.json", "README.md", "BENCHMARK.md"):
                continue
            try:
                total += len(
                    open(os.path.join(dirpath, name), encoding="utf-8").read().split("\n")
                )
            except (OSError, UnicodeDecodeError):
                continue
    return total


def main():
    with open(KEY, encoding="utf-8") as f:
        key = json.load(f)
    findings = key["findings"]

    cache = {}
    problems = check_resolution(findings, cache)
    spacing_problems, gaps = check_spacing(findings)
    problems.extend(spacing_problems)

    mix = key["summary"]["by_difficulty"]
    corpus_lines = count_corpus_lines()
    print("findings:        %d" % len(findings))
    print("difficulty (graded, SCA exempt): high=%d medium=%d low=%d exempt=%d"
          % (mix["high"], mix["medium"], mix["low"], mix["exempt_sca"]))
    print("pct of graded:   %s" % mix["pct_of_graded"])
    print("corpus lines:    %d" % corpus_lines)
    if gaps:
        gaps.sort()
        print("spacing:         min=%d median=%d mean=%.1f max=%d (contract: >= %d)"
              % (gaps[0], gaps[len(gaps) // 2], sum(gaps) / len(gaps), gaps[-1], MIN_GAP))
        print("density:         1 finding per %.1f source lines"
              % (corpus_lines / float(len(findings))))
    print("problems:        %d" % len(problems))
    for p in problems:
        print("   ", p)


if __name__ == "__main__":
    main()
