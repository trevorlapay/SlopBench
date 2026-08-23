#!/usr/bin/env python3
"""Score a SAST scanner's SARIF output against a SlopBench answer key.

    python scoring/score.py --bench dense  --sarif run.sarif
    python scoring/score.py --bench f      --sarif run.sarif
    python scoring/score.py --bench actual --sarif run.sarif
    python scoring/score.py --bench dense  --sarif r1.sarif r2.sarif r3.sarif   # variance

One SARIF in, precision/recall (and, per bench, lure-rate / noise / stealth /
difficulty breakdowns) out. Nothing here is bench-specific magic: the matcher is
file-suffix + line-tolerance + (optional) CWE-family, and every choice is a flag
so the scoring is auditable rather than a black box.

The keys live in ../VulnerabilityKeys/ relative to this file; a bench directory
handed to a scanner never contains its own answers.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
KEYS = os.path.join(ROOT, "VulnerabilityKeys")

BENCHES = {
    "dense":   {"kind": "vuln",    "key": "SlopShopDense.vulnerability_key.json"},
    "sparse":  {"kind": "vuln",    "key": "SlopShopSparse.vulnerability_key.json"},
    "f":       {"kind": "feint",   "key": "SlopShop_F.vulnerability_key.json"},
    "perfect": {"kind": "perfect", "key": "SlopShopPerfect.vulnerability_key.json"},
    "actual":  {"kind": "actual",  "key": "SlopShop_Actual.vulnerability_key.json"},
}

# Named safe look-alikes in Dense/Sparse: correct code that bait a false positive.
# Flagging one of these is a precision failure worth calling out on its own.
SAFE_LOOKALIKES = (
    "crypto_safe.py", "paths_safe.py", "repository.py", "repository_safe.js",
    "email_render.py", "validators.js", "validation.go", "catalog.go",
    "catalog.php", "ProductRepository.java", "geometry.c",
    "test_injection_defenses.py", "test_crypto_safe_and_paths.py",
)

# ---------------------------------------------------------------------------
# CWE-family matching. Scanners disagree on which CWE a bug "is" (89 vs 943,
# 22 vs 23, 78 vs 77). Exact-string matching therefore *undercounts* recall.
# `family` mode treats CWEs in the same group below as interchangeable. The
# groups are pragmatic, not the full MITRE hierarchy; a CWE in no group falls
# back to exact matching. Always report `off`/`family`/`exact` side by side so
# the spread is visible.
# ---------------------------------------------------------------------------
CWE_FAMILIES = [
    {"89", "564", "943", "566"},                                  # SQL / query injection
    {"77", "78", "88"},                                           # OS / argument / command injection
    {"79", "80", "83", "87", "116"},                              # XSS / output encoding
    {"94", "95", "96", "913", "917", "1336"},                     # code injection / eval / SSTI
    {"22", "23", "24", "25", "26", "27", "28", "29", "36",
     "40", "61", "73", "706", "59"},                              # path traversal / link following
    {"502", "915"},                                               # deserialization / mass-assignment
    {"918"},                                                      # SSRF
    {"611", "776", "827", "91", "776"},                           # XXE / XML
    {"326", "327", "328", "916", "780", "759", "760", "780"},     # weak crypto / hashing
    {"798", "259", "321", "320", "522", "312", "532", "200"},     # secrets / sensitive exposure
    {"287", "306", "862", "863", "285", "639", "640", "1220"},    # authn / authz / access control
    {"601"},                                                      # open redirect
    {"352"},                                                      # CSRF
    {"1321", "1325"},                                             # prototype pollution
    {"119", "120", "121", "122", "125", "787", "786", "788"},     # buffer bounds
    {"415", "416", "590", "761"},                                 # use-after-free / double-free
    {"190", "191", "680", "197"},                                 # integer overflow / wraparound
    {"476"},                                                      # null deref
    {"400", "405", "674", "770", "1333", "776"},                  # resource exhaustion / DoS
    {"250", "269", "271", "272", "732"},                          # privilege / permissions
    {"1104", "494", "506", "829", "1357", "427", "426"},          # supply chain / untrusted load
    {"345", "347", "295", "390", "354"},                          # integrity / signature / cert
    {"338", "330", "331", "335"},                                 # weak RNG
]
_CWE_TO_FAMILY = {}
for _i, _grp in enumerate(CWE_FAMILIES):
    for _c in _grp:
        _CWE_TO_FAMILY.setdefault(_c, set()).add(_i)

_CWE_RE = re.compile(r"CWE[\s_:-]?(\d{1,4})", re.IGNORECASE)


def cwe_nums(text):
    """Every CWE number mentioned in a string, normalized to the digits only."""
    return {m.group(1).lstrip("0") or "0" for m in _CWE_RE.finditer(text or "")}


def norm_cwe(c):
    return (c or "").upper().replace("CWE-", "").lstrip("0") or "0" if c else None


def cwe_matches(reported, keyed, mode):
    """reported: set of digit-strings; keyed: set of digit-strings."""
    if mode == "off":
        return True
    if not keyed:                      # key entry carries no CWE -> can't require one
        return True
    if not reported:                   # scanner gave no CWE -> only 'off' can credit it
        return False
    if reported & keyed:
        return True
    if mode == "exact":
        return False
    # family: shared family index between any reported and any keyed CWE
    rfam = set().union(*(_CWE_TO_FAMILY.get(c, set()) for c in reported)) if reported else set()
    kfam = set().union(*(_CWE_TO_FAMILY.get(c, set()) for c in keyed)) if keyed else set()
    return bool(rfam & kfam)


# ---------------------------------------------------------------------------
# SARIF parsing
# ---------------------------------------------------------------------------
def norm_path(p):
    if not p:
        return ""
    p = p.split("://", 1)[-1]                      # strip file:// etc.
    p = p.replace("\\", "/").lstrip("/")
    while p.startswith("./"):
        p = p[2:]
    return p


def path_suffix_match(a, b):
    """True if one normalized path is a trailing path-segment suffix of the other."""
    a, b = norm_path(a), norm_path(b)
    if not a or not b:
        return False
    if a == b:
        return True
    sa, sb = a.split("/"), b.split("/")
    short, long = (sa, sb) if len(sa) <= len(sb) else (sb, sa)
    return long[-len(short):] == short


def load_sarif(path):
    """Return list of findings: {path, line, cwes:set, rule, msg}."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    out = []
    for run in doc.get("runs", []):
        # rule_id -> set(cwe) from the tool's rule metadata / taxonomies
        rule_cwe = {}
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []) or []:
            rid = rule.get("id")
            blob = json.dumps(rule.get("properties", {})) + " " + (rule.get("name", "") or "")
            for rel in rule.get("relationships", []) or []:
                blob += " " + json.dumps(rel.get("target", {}))
            cw = cwe_nums(blob)
            if rid and cw:
                rule_cwe[rid] = cw
        for res in run.get("results", []):
            rid = res.get("ruleId", "")
            msg = (res.get("message", {}) or {}).get("text", "") or ""
            cwes = cwe_nums(rid) | cwe_nums(msg) | rule_cwe.get(rid, set())
            for tx in res.get("taxa", []) or []:
                cwes |= cwe_nums(tx.get("id", "")) | cwe_nums(json.dumps(tx))
            props = res.get("properties", {}) or {}
            cwes |= cwe_nums(json.dumps(props))
            locs = res.get("locations", []) or []
            if not locs:
                continue
            phys = (locs[0].get("physicalLocation", {}) or {})
            uri = (phys.get("artifactLocation", {}) or {}).get("uri", "")
            line = (phys.get("region", {}) or {}).get("startLine")
            if uri and line:
                out.append({"path": norm_path(uri), "line": int(line),
                            "cwes": cwes, "rule": rid, "msg": msg})
    return out


def dedup(findings):
    seen, out = set(), []
    for f in findings:
        k = (f["path"], f["line"], frozenset(f["cwes"]))
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


# ---------------------------------------------------------------------------
# Matching a finding to a keyed location
# ---------------------------------------------------------------------------
def line_ok(fl, lo, hi, tol):
    return (lo - tol) <= fl <= (hi + tol)


def pct(n, d):
    return 0.0 if not d else round(100.0 * n / d, 1)


def ci95(vals):
    n = len(vals)
    if n < 2:
        return None
    mean = sum(vals) / n
    sd = math.sqrt(sum((v - mean) ** 2 for v in vals) / (n - 1))
    half = 1.96 * sd / math.sqrt(n)
    return mean, sd, half


# ---------------------------------------------------------------------------
# Per-bench scorers -> dict of metrics
# ---------------------------------------------------------------------------
def score_vuln(key, findings, tol, cwe_mode):
    """Dense / Sparse."""
    graded = [f for f in key["findings"] if f.get("difficulty") != "exempt"]
    exempt = [f for f in key["findings"] if f.get("difficulty") == "exempt"]

    def matched(entries, mode):
        hit = set()
        for i, k in enumerate(entries):
            kc = cwe_nums(k.get("cwe", ""))
            for f in findings:
                if path_suffix_match(f["path"], k["file"]) and \
                   line_ok(f["line"], k["line"], k["line"], tol) and \
                   cwe_matches(f["cwes"], kc, mode):
                    hit.add(i)
                    break
        return hit

    hit_loc = matched(graded, "off")
    hit_fam = matched(graded, "family")
    hit_exa = matched(graded, "exact")

    # precision: which deduped findings land on ANY keyed line (location-only)?
    all_keyed = key["findings"]
    tp = 0
    fp_safe = 0
    for f in findings:
        on_key = any(path_suffix_match(f["path"], k["file"]) and
                     line_ok(f["line"], k["line"], k["line"], tol) for k in all_keyed)
        if on_key:
            tp += 1
        else:
            if any(f["path"].endswith(s) for s in SAFE_LOOKALIKES):
                fp_safe += 1
    fp = len(findings) - tp

    by_diff = {}
    for tier in ("high", "medium", "low"):
        idx = [i for i, k in enumerate(graded) if k.get("difficulty") == tier]
        by_diff[tier] = (len(hit_fam & set(idx)), len(idx))

    stealth_idx = [i for i, k in enumerate(graded) if k.get("stealth")]
    hard_idx = [i for i, k in enumerate(graded) if k.get("tag") == "stealthed_hard"]

    return {
        "graded_total": len(graded),
        "recall_location": (len(hit_loc), len(graded)),
        "recall_family": (len(hit_fam), len(graded)),
        "recall_exact": (len(hit_exa), len(graded)),
        "by_difficulty": by_diff,
        "stealth": (len(hit_fam & set(stealth_idx)), len(stealth_idx)),
        "stealthed_hard": (len(hit_fam & set(hard_idx)), len(hard_idx)),
        "sca_exempt_total": len(exempt),
        "findings_raw": None,
        "findings_dedup": len(findings),
        "true_positives": tp,
        "false_positives": fp,
        "fp_on_safe_lookalikes": fp_safe,
        "precision": pct(tp, tp + fp),
        "_headline": pct(len(hit_fam), len(graded)),   # recall(family) drives variance
    }


def score_feint(key, findings, tol):
    items = key["items"]
    hits = defaultdict(list)          # tier -> list of item ids hit
    matched_ids = set()
    for f in findings:
        for it in items:
            same = path_suffix_match(f["path"], it["file"]) and \
                   line_ok(f["line"], it["line"], it["line"], tol)
            construct_hit = it.get("construct", "")[:24].lower() in (f["msg"] or "").lower() \
                if it.get("construct") else False
            if same or (construct_hit and path_suffix_match(f["path"], it["file"])):
                if it["id"] not in matched_ids:
                    hits[it["tier"]].append(it["id"])
                    matched_ids.add(it["id"])
    tiers = {t: sum(1 for it in items if it["tier"] == t) for t in ("easy", "medium", "hard")}
    lure_total = len(matched_ids)
    noise = len(findings) - lure_total       # every finding here is a false positive
    return {
        "planted_feints": len(items),
        "lure_hits_total": (lure_total, len(items)),
        "lure_by_tier": {t: (len(hits[t]), tiers[t]) for t in ("easy", "medium", "hard")},
        "findings_total": len(findings),
        "noise_non_lure": noise,
        "_headline": float(lure_total),      # fewer is better
    }


def score_perfect(key, findings):
    by_lang = Counter(os.path.splitext(f["path"])[1] or "(none)" for f in findings)
    return {
        "expected": 0,
        "false_positives": len(findings),
        "by_extension": dict(by_lang.most_common()),
        "_headline": float(len(findings)),   # fewer is better
    }


def score_actual(key, findings, tol, cwe_mode):
    entries = key["entries"]

    def keypath(e):
        wp = e.get("workspace_path") or e.get("local_path") or e.get("upstream_path") or ""
        return wp[5:] if wp.startswith("code/") else wp

    def matched(mode):
        hit = set()
        for i, e in enumerate(entries):
            kp = keypath(e)
            kc = set(norm_cwe(c) for c in e.get("cwe_ids", []) if c) | cwe_nums(e.get("primary_cwe", ""))
            lo, hi = int(e.get("start_line", 1)), int(e.get("end_line", e.get("start_line", 1)))
            for f in findings:
                if path_suffix_match(f["path"], kp) and line_ok(f["line"], lo, hi, tol) \
                   and cwe_matches(f["cwes"], kc, mode):
                    hit.add(i)
                    break
        return hit

    hit_loc, hit_fam, hit_exa = matched("off"), matched("family"), matched("exact")
    by_lang = {}
    langs = sorted({e.get("language", "?") for e in entries})
    for lg in langs:
        idx = [i for i, e in enumerate(entries) if e.get("language") == lg]
        by_lang[lg] = (len(hit_fam & set(idx)), len(idx))
    # location-only TP for a rough precision floor (Actual labels one sink/CVE only)
    tp = sum(1 for f in findings if any(
        path_suffix_match(f["path"], keypath(e)) and
        line_ok(f["line"], int(e.get("start_line", 1)), int(e.get("end_line", e.get("start_line", 1))), tol)
        for e in entries))
    return {
        "cves_total": len(entries),
        "recall_location": (len(hit_loc), len(entries)),
        "recall_family": (len(hit_fam), len(entries)),
        "recall_exact": (len(hit_exa), len(entries)),
        "recall_by_language": by_lang,
        "findings_dedup": len(findings),
        "findings_on_a_sink": tp,
        "note": "Actual labels one primary sink per CVE; findings off those lines are "
                "not necessarily false positives, so no precision figure is reported.",
        "_headline": pct(len(hit_fam), len(entries)),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def frac(t):
    n, d = t
    return f"{n}/{d} ({pct(n, d)}%)"


def print_report(bench, kind, per_run, raw_counts, args):
    print(f"\n=== SlopBench score - {bench} ===")
    print(f"key:        VulnerabilityKeys/{BENCHES[bench]['key']}")
    print(f"sarif:      {', '.join(args.sarif)}")
    print(f"match:      line tolerance +/-{args.line_tol}, CWE mode '{args.cwe}', dedup on")
    m = per_run[0]

    if kind == "vuln":
        print(f"findings:   {raw_counts[0]} raw -> {m['findings_dedup']} deduped")
        print(f"recall (graded {m['graded_total']}, SCA-exempt {m['sca_exempt_total']} excluded):")
        print(f"   location-only : {frac(m['recall_location'])}")
        print(f"   CWE-family    : {frac(m['recall_family'])}")
        print(f"   CWE-exact     : {frac(m['recall_exact'])}")
        print(f"precision:  {m['precision']}%  (TP {m['true_positives']}, FP {m['false_positives']}; "
              f"{m['fp_on_safe_lookalikes']} FP landed on named safe look-alikes)")
        print("recall by difficulty (CWE-family):")
        for t in ("high", "medium", "low"):
            print(f"   {t:<7}: {frac(m['by_difficulty'][t])}")
        print(f"stealthed:        {frac(m['stealth'])}")
        print(f"stealthed_hard:   {frac(m['stealthed_hard'])}")
    elif kind == "feint":
        print(f"findings:   {m['findings_total']} (every finding here is a false positive)")
        print(f"lure hits:  {frac(m['lure_hits_total'])}  (lower is better)")
        for t in ("easy", "medium", "hard"):
            print(f"   {t:<6}: {frac(m['lure_by_tier'][t])}")
        print(f"other noise (non-lure FPs): {m['noise_non_lure']}")
    elif kind == "perfect":
        print(f"expected findings: 0")
        print(f"false positives:   {m['false_positives']}  (every finding is a FP; lower is better)")
        if m["by_extension"]:
            print("   by extension: " + ", ".join(f"{k} {v}" for k, v in m["by_extension"].items()))
    elif kind == "actual":
        print(f"findings:   {m['findings_dedup']} deduped")
        print(f"recall (of {m['cves_total']} CVEs):")
        print(f"   location-only : {frac(m['recall_location'])}")
        print(f"   CWE-family    : {frac(m['recall_family'])}")
        print(f"   CWE-exact     : {frac(m['recall_exact'])}")
        print(f"findings on a labelled sink: {m['findings_on_a_sink']}")
        print("recall by language (CWE-family):")
        for lg, t in sorted(m["recall_by_language"].items()):
            print(f"   {lg:<12}: {frac(t)}")
        print(f"note: {m['note']}")

    if len(per_run) > 1:
        vals = [r["_headline"] for r in per_run]
        label = {"vuln": "recall(family) %", "actual": "recall(family) %",
                 "feint": "lure hits", "perfect": "false positives"}[kind]
        stats = ci95(vals)
        print(f"\nvariance over {len(per_run)} runs - headline {label}:")
        print(f"   per run : {', '.join(str(round(v, 1)) for v in vals)}")
        if stats:
            mean, sd, half = stats
            print(f"   mean    : {round(mean,2)}  (sd {round(sd,2)}, 95% CI +/-{round(half,2)} "
                  f"-> [{round(mean-half,2)}, {round(mean+half,2)}])")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Score SARIF output against a SlopBench key.")
    ap.add_argument("--bench", required=True, choices=sorted(BENCHES))
    ap.add_argument("--sarif", required=True, nargs="+",
                    help="one SARIF file, or several runs of the same scanner for a variance report")
    ap.add_argument("--line-tol", type=int, default=3, help="line-number tolerance (default 3)")
    ap.add_argument("--cwe", choices=("off", "exact", "family"), default="family",
                    help="CWE matching strictness for the headline metric (default family)")
    ap.add_argument("--keys-dir", default=KEYS)
    ap.add_argument("--json", action="store_true", help="emit metrics as JSON instead of text")
    args = ap.parse_args(argv)

    cfg = BENCHES[args.bench]
    with open(os.path.join(args.keys_dir, cfg["key"]), encoding="utf-8") as fh:
        key = json.load(fh)

    per_run, raw_counts = [], []
    for path in args.sarif:
        raw = load_sarif(path)
        raw_counts.append(len(raw))
        f = dedup(raw)
        if cfg["kind"] == "vuln":
            per_run.append(score_vuln(key, f, args.line_tol, args.cwe))
        elif cfg["kind"] == "feint":
            per_run.append(score_feint(key, f, args.line_tol))
        elif cfg["kind"] == "perfect":
            per_run.append(score_perfect(key, f))
        elif cfg["kind"] == "actual":
            per_run.append(score_actual(key, f, args.line_tol, args.cwe))

    if args.json:
        print(json.dumps({"bench": args.bench, "kind": cfg["kind"],
                          "line_tol": args.line_tol, "cwe": args.cwe,
                          "sarif": args.sarif, "runs": per_run}, indent=2))
    else:
        print_report(args.bench, cfg["kind"], per_run, raw_counts, args)


if __name__ == "__main__":
    main()
