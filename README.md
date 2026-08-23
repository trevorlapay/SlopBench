# SlopBench — a SAST benchmark suite for LLM-based scanners

SlopBench is a family of related corpora for measuring how well a static-analysis
tool, especially an LLM-based one, finds real vulnerabilities **and** resists
crying wolf on code that only looks dangerous. The benches share one fictional
polyglot marketplace ("SlopShop") so that recall and precision can be compared on
the same application under different conditions.

_IF YOU READ NOTHING ELSE IN THIS DOCUMENT, READ THIS: DO NOT LET YOUR LLM ACCIDENTALLY SCAN THE VULNERABILTY KEY FILES. IT WILL RUIN WHATEVER IT IS YOU ARE TRYING TO DO, UNLESS WHAT YOU'RE TRYING TO DO IS WASTE TOKENS!_

Every bench is designed around one rule:

> **The tree handed to the scanner must read as an ordinary application.**
> No bench announces what it is. There are no `VULN-` markers, no "this is
> vulnerable / this is safe" comments, no give-away filenames, and no mention of
> benchmarks, findings, CWEs, or false positives anywhere in the code the scanner
> sees. Everything a grader needs — the answer key, the difficulty grades, the
> evasion catalogue — lives in **separate evaluator files that you remove before
> pointing a tool at the tree** (see *Using a bench*, below).

## The benches

| Directory | What it is | Ground truth | Measures |
|-----------|------------|--------------|----------|
| [`SlopShopDense/`](SlopShopDense/) | Deliberately vulnerable app, **dense** (a sink every few lines) | **411** planted vulns · 142 CWEs · 40 stealthed (20 hard) | Recall, and depth via difficulty tiers |
| [`SlopShopSparse/`](SlopShopSparse/) | The *same 411 vulns*, spread across ~2.4× as much clean code (no two findings within 10 lines) | 411 (same IDs as Dense) | Whether recall came from density or from reading the code |
| [`SlopShop_F/`](SlopShop_F/) | Clean app carrying **60 "feints"** — constructs that pattern-match a bug class but are correct | **0** real vulns · 60 planted false-positive lures (20 easy / 20 medium / 20 hard) | Specificity / lure susceptibility |
| [`SlopShopPerfect/`](SlopShopPerfect/) | The same app, correct, with **no vulns and no planted lures** | **0** of everything | Baseline false-positive floor on ordinary code |
| [`SlopShop_Actual/`](SlopShop_Actual/) | **150 real, post-cutoff CVEs** laid out as an app (built with SASTBench) | 150 real vulns · 147 CWEs · disclosed after 2025-12-01 | Recall on code that could not be in training data |

`Dense`, `Sparse`, `_F` and `Perfect` are one matched set: they are the same
application, so a scanner's four scores are directly comparable. Pairing them
separates the things a single number cannot:

- **Dense vs Sparse** — how much recall was locality (guessing that everything
  near a sink is a sink) versus actually reading the code.
- **Perfect vs _F** — baseline noise (Perfect: any finding is a false positive)
  versus lure susceptibility (_F: 60 specific traps, graded easy→hard).
- **Dense/Sparse vs _F/Perfect** — recall against precision on one codebase.

`SlopShop_Actual` is a different construction (real advisories, verbatim upstream
code, its own SASTBench harness and its own git history) and stands on its own; it
answers "does the scanner work on vulnerabilities it has never seen," which the
synthetic benches cannot. SlopShop_Actual may be the best actual verification tool we have for LLMs, as it is built on actual vulnerabilities discovered in the wild in 2026, well after GPT 5.5's curoff date. (This version is build for 5.5 because it is the frontier model being used with MDASH, as well as one commonly used as of this writing in Audust 2026).

## Using a bench

_IF YOU READ NOTHING ELSE IN THIS DOCUMENT, READ THIS PART._

Each bench keeps its scoring artifacts **in the repo** but they must be **removed
before the tree is scanned** — anything left in the tree can be read by the tool
under test and would both leak the answers and reveal that the tree is a benchmark.

**Dense / Sparse** — the evaluator files are `BENCHMARK.md` (the full spec),
`vulnerability_key.json` (the answer key) and `tools/` (a read-only key verifier).
Copy the tree, then strip them:

```bash
cp -r SlopShopDense /tmp/scan-target
cd /tmp/scan-target
rm BENCHMARK.md vulnerability_key.json && rm -rf tools
# what remains — README.md, services/, infra/, .github/ — is a plain application
```

**_F / Perfect** — the only evaluator file is `vulnerability_key.json`; the
in-tree `README.md` is already an innocuous application description.

```bash
cp -r SlopShopPerfect /tmp/scan-target
rm /tmp/scan-target/vulnerability_key.json
```

**SlopShop_Actual** — already isolates its ground truth: point the scanner at
`workspaces/postcutoff/code/` and the answer key lives outside that directory in
`workspaces/evaluator_data/`. See its own [`README.md`](SlopShop_Actual/README.md).

Then run your scanner over the stripped copy, collect its findings (file + line +
CWE), and score them against the key you set aside.

### Scoring

For **Dense / Sparse**, match each reported finding to a key entry by file + line
(± a couple of lines for manifest/multi-line-XML entries) + CWE:

- **Recall** = keyed vulns found ÷ 411. Filter by `difficulty` to see how deep the
  tool reaches; SCA/vulnerable-dependency entries are marked `exempt` (caught by a
  version lookup, not code analysis) and are usually scored separately.
- **Stealth** = of the 40 `stealth` findings (20 tagged `stealthed_hard`), how many
  survived the evasion payload. Each `stealth` entry records the `technique` and the
  decoded `payload`.
- The named safe look-alikes (e.g. `crypto_safe.py`, `repository.py`, `catalog.go`)
  are **not** in the key; flagging one is a false positive.

For **_F**, a finding that lands on one of the 60 items (by file + ~10 lines, or by
the `construct` string) is a lure hit; report the hit rate per tier (easy/medium/
hard). Findings elsewhere are ordinary noise. For **Perfect**, every finding is a
false positive — report the raw count and its per-language distribution; this is the
tool's floor before any bait exists.

### Verifying a key (evaluator side)

Dense and Sparse ship a read-only checker that confirms every finding still resolves
to a real source line (Sparse also enforces the 10-line spacing rule):

```bash
cd SlopShopDense && python tools/verify_key.py
cd SlopShopSparse && python tools/verify_key.py   # also prints spacing + density
```

Both currently report `problems: 0`.

## Caveats

- **Dependency drift.** The SCA entries and `_F`/`Perfect`'s pinned dependencies were
  accurate on the build date. A CVE published later can change what is true without any
  code change — re-run a dependency audit before each round.
- **In-code project identity.** `SlopShop_Actual` keeps upstream code verbatim, so real
  project namespaces and copyright headers remain. That is only a leak for a scanner
  with live web/tool access; see its README's threat model.
- These trees are **deliberately insecure** (except `Perfect`, which is deliberately
  correct). Do not deploy them, run them against real data, or copy the code. All
  secrets and keys are fake placeholders.

## Layout

```
SlopBench/
├── README.md            ← you are here (suite overview + how to score)
├── SlopShopDense/       dense vulnerable app   (README app-facing; BENCHMARK.md + key = evaluator-only)
├── SlopShopSparse/      sparse vulnerable app  (same 411 vulns, spread out)
├── SlopShop_F/          clean app + 60 feints  (README app-facing; key = evaluator-only)
├── SlopShopPerfect/     clean app, no bait     (README app-facing; key = evaluator-only)
└── SlopShop_Actual/     150 real post-cutoff CVEs (self-contained, own git + harness)
```
