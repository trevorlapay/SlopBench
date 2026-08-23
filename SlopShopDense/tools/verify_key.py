#!/usr/bin/env python3
"""Read-only sanity check for vulnerability_key.json against the source tree.

Confirms every finding still resolves to a real (non-blank) source line and prints
the difficulty distribution. Does NOT modify anything. The key is the sole ground
truth; the source contains no location hints.
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = os.path.join(ROOT, "vulnerability_key.json")

# The only finding whose sink legitimately IS a source comment.
COMMENT_SINKS = {"VULN-0012"}


def main():
    with open(KEY, encoding="utf-8") as f:
        key = json.load(f)
    findings = key["findings"]

    problems = []
    cache = {}
    for v in findings:
        path = os.path.join(ROOT, v["file"].replace("/", os.sep))
        if path not in cache:
            try:
                cache[path] = open(path, encoding="utf-8").read().split("\n")
            except OSError:
                cache[path] = None
        lines = cache[path]
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

    mix = key["summary"]["by_difficulty"]
    print("findings:        %d" % len(findings))
    print("difficulty (graded, SCA exempt): high=%d medium=%d low=%d exempt=%d"
          % (mix["high"], mix["medium"], mix["low"], mix["exempt_sca"]))
    print("pct of graded:   %s" % mix["pct_of_graded"])
    print("problems:        %d" % len(problems))
    for p in problems:
        print("   ", p)


if __name__ == "__main__":
    main()
