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
| [`SlopShop_Actual/`](SlopShop_Actual/) | **164 real, post-cutoff CVEs** laid out as an app (built with SASTBench) | 164 real vulns · 140 CWEs · disclosed after 2025-12-01 | Recall on code that could not be in training data |

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

## Answer keys

**Every answer key lives in [`VulnerabilityKeys/`](VulnerabilityKeys/) at the suite
root — never inside a bench directory.** So copying a bench directory to a scan
target carries no answers, by construction:

| Key | Bench |
|-----|-------|
| `VulnerabilityKeys/SlopShopDense.vulnerability_key.json`   | Dense |
| `VulnerabilityKeys/SlopShopSparse.vulnerability_key.json`  | Sparse |
| `VulnerabilityKeys/SlopShop_F.vulnerability_key.json`      | _F (60 planted feints) |
| `VulnerabilityKeys/SlopShopPerfect.vulnerability_key.json` | Perfect (expected empty) |
| `VulnerabilityKeys/SlopShop_Actual.vulnerability_key.json` (+ `.md`) | Actual (164 CVEs) |

## Using a bench

Point the scanner at the bench directory, but first remove the couple of
**non-key** evaluator files that would still *announce* the tree is a benchmark
(the answer keys themselves already live outside every bench, in
`VulnerabilityKeys/`):

**Dense / Sparse** — strip `BENCHMARK.md` (the full spec) and `tools/` (the key
verifier). The key is already external, so nothing else has to be scrubbed:

```bash
cp -r SlopShopDense /tmp/scan-target
cd /tmp/scan-target
rm BENCHMARK.md && rm -rf tools
# what remains — README.md, services/, infra/, .github/ — is a plain application
```

**_F / Perfect** — nothing to strip: the key is external and the in-tree
`README.md` is already an innocuous application description. Point the scanner
straight at the directory.

**SlopShop_Actual** — point the scanner at `workspaces/postcutoff/code/`. Its own
in-tree ground truth stays isolated in `workspaces/evaluator_data/` (outside the
scanned `code/`), and the suite-level key is
`VulnerabilityKeys/SlopShop_Actual.vulnerability_key.json`. See its own
[`README.md`](SlopShop_Actual/README.md).

Then run your scanner over the target, collect its findings (file + line + CWE),
and score them against the matching key in `VulnerabilityKeys/`.

### Scoring

Have your scanner emit **SARIF** (the standard static-analysis result format;
CodeQL, Semgrep, and most tools can, and it is easy to coerce an LLM into it), then:

```bash
python scoring/score.py --bench dense --sarif run.sarif
```

`--bench` is one of `dense` / `sparse` / `f` / `perfect` / `actual`. The scorer
loads the matching key from `VulnerabilityKeys/`, matches each SARIF result to a
keyed location, and prints the metrics appropriate to that bench:

- **Dense / Sparse** — recall over the 378 graded findings (SCA-`exempt` shown
  separately), broken down by difficulty tier and by the stealth / `stealthed_hard`
  subsets; precision, with a separate count of false positives that landed on the
  named safe look-alikes.
- **_F** — lure hits per tier (easy/medium/hard); every finding here is a false
  positive, so it also reports total noise. Lower is better.
- **Perfect** — every finding is a false positive; reports the count and its
  distribution. The floor before any bait exists.
- **Actual** — recall over the 164 CVEs, broken down by language. (Only one sink is
  labelled per CVE, so no precision figure is reported.)

**Matching is explicit and tunable, not a black box** (`python scoring/score.py -h`):

- `--line-tol N` (default 3) — line-number tolerance. `_F`'s own guidance is ~10
  lines; pass `--line-tol 10` there if you want its looser convention.
- `--cwe {off,exact,family}` (default `family`) — how strict CWE matching is.
  Scanners disagree on which CWE a bug "is" (89 vs 943, 22 vs 23, 78 vs 77), so
  exact-string matching *undercounts* recall. `family` treats CWEs in the same
  pragmatic group as interchangeable; the groups are defined and commented at the
  top of `score.py`. The report always prints **location-only**, **CWE-family**, and
  **CWE-exact** recall side by side so the spread is visible — cite whichever you
  justify, but show all three.
- Paths are matched by trailing-segment suffix, so it does not matter whether the
  SARIF URIs are absolute, prefixed with the bench directory, or relative to it.
- Findings are de-duplicated on (path, line, CWE) before scoring, so a tool that
  reports the same line twice is not double-counted.

### Reporting results and handling variance

LLM-based scanners are **non-deterministic**: the same tool on the same file can
report a different set of findings run to run, and small prompt changes move the
numbers as much as real capability differences do
([Snyk VulnBench JS asks exactly this](https://arxiv.org/pdf/2606.15762);
[safety evaluators are not robust to artifacts](https://arxiv.org/pdf/2503.09347);
[small LLMs show low answer consistency across repetitions](https://arxiv.org/pdf/2509.09705)).
**A single run is an anecdote, not a score.** To report defensibly:

1. **Fix everything you can** and record it: model + version, temperature, the exact
   prompt/agent scaffold, tool version, and the scorer flags (`--line-tol`, `--cwe`).
   Hold the prompt identical across every system you compare — prompt wording is a
   confound, not a free variable.
2. **Run each bench N≥3 times** (5 is better) as independent runs, and report
   **mean ± standard deviation** or a **95% confidence interval** — the convention in
   recent code-LLM work (e.g. mean ± std over 3 seeds on a fixed test set). Pass all
   the runs to the scorer at once and it does this for you:

   ```bash
   python scoring/score.py --bench dense --sarif run1.sarif run2.sarif run3.sarif run4.sarif run5.sarif
   ```

   It prints the headline metric per run plus mean, sd, and a 95% CI.
3. **Two systems differ only if their confidence intervals do not overlap.** A 2-point
   gap inside overlapping CIs is noise. Report F1 alongside precision/recall when you
   need one number (the field's standard for this task).
4. **Choose an aggregation that matches your question, and name it:**
   - *mean-of-N* — expected behaviour of one run. The default for "how good is it."
   - *union / best-of-N* — the capability ceiling (did it *ever* find each vuln);
     analogous to pass@k. Good for "could it, with retries."
   - *majority-vote / self-consistency* across runs (optionally at mixed
     temperatures) — closer to a hardened deployment, and a known variance-reducer
     ([self-consistency sampling](https://arxiv.org/pdf/2401.16185)).
5. **Report at your deployment temperature.** Lower temperature reduces variance but
   can suppress recall; if you are characterising capability, report at both T≈0 and a
   higher T rather than cherry-picking. Note that LLM judges/evaluators are themselves
   inconsistent ([inconsistent and biased evaluators](https://arxiv.org/pdf/2405.01724)),
   which is why this suite scores against a fixed mechanical key, not an LLM grader.

Sources: [Snyk VulnBench JS](https://arxiv.org/pdf/2606.15762) ·
[Safer or Luckier?](https://arxiv.org/pdf/2503.09347) ·
[Non-Determinism of Small LLMs](https://arxiv.org/pdf/2509.09705) ·
[LLM4Vuln](https://arxiv.org/pdf/2401.16185) ·
[Inconsistent and Biased Evaluators](https://arxiv.org/pdf/2405.01724) ·
[SastBench (agentic SAST triage)](https://arxiv.org/pdf/2601.02941).

### Verifying a key (evaluator side)

Dense and Sparse ship a read-only checker that confirms every finding still resolves
to a real source line (Sparse also enforces the 10-line spacing rule):

```bash
cd SlopShopDense && python tools/verify_key.py
cd SlopShopSparse && python tools/verify_key.py   # also prints spacing + density
```

Both currently report `problems: 0`.

## Scope and caveats

- **Internal tool, not a public leaderboard.** SlopBench is built for internal use.
  The prompts and agent scaffolds you point at it may be proprietary, and its numbers
  are meant for your own iteration and relative comparison — not for cross-vendor
  "tool X scores Y%" claims. Treat scores as directional.
- **Keep the keys out of the scan target.** Every answer lives in `VulnerabilityKeys/`,
  but it sits in the *same repository* as the corpora. An agent given the repo root can
  read it trivially. Copy only the bench subdirectory into your scan target (see *Using
  a bench*); never run a scanner from the suite root.
- **Baselines are your job.** This repo ships no reference tool scores. Establish your
  own baseline (a config you trust, or an off-the-shelf scanner) so a new run has
  something to be compared against; an absolute number here means little on its own.
- **Feint calls can be arguable.** The 60 `_F` items are judged safe with a stated
  reason (`why_it_is_not`), but "correct here" sometimes rests on a guard one hop away
  that a cautious scanner may reasonably flag. Read the reason before counting a lure
  hit against a tool; some are genuinely debatable.
- **Difficulty tiers are author-assigned, not calibrated.** `high`/`medium`/`low` (and
  `easy`/`medium`/`hard` in `_F`) reflect the author's judgement, not measured tool
  performance. Use them to slice results, not as a validated hardness scale.
- **Dependency drift.** The SCA entries and `_F`/`Perfect`'s pinned dependencies were
  accurate on the build date. A CVE published later can change what is true without any
  code change — re-run a dependency audit before each round. The `--hash=sha256:` values
  in the `requirements.txt` files are correctly shaped placeholders, not real published
  hashes, so those trees are not `pip install`-able as written.
- **In-code project identity (Actual).** `SlopShop_Actual` keeps upstream code verbatim,
  so real project namespaces and copyright headers remain, and its files are other
  projects' code under their own licenses gathered under this repo's LICENSE. Verbatim
  identity is only a *leak* for a scanner with live web/tool access; see its README's
  threat model. Being real CVEs, the corpus also **decays** as models retrain past the
  cutoff — refresh it (`tools/harvest.py`) for a later model.
- **Language coverage in Actual is uneven** and it labels one primary sink per CVE;
  multi-file fixes record only that sink. See its README.
- These trees are **deliberately insecure** (except `Perfect`, which is deliberately
  correct). Do not deploy them, run them against real data, or copy the code. All
  secrets and keys are fake placeholders.

## Layout

```
SlopBench/
├── README.md            ← you are here (suite overview + how to score)
├── scoring/score.py     ← SARIF in, metrics out: python scoring/score.py --bench dense --sarif run.sarif
├── VulnerabilityKeys/   ← every answer key, one per bench (keep OUT of scan targets)
├── SlopShopDense/       dense vulnerable app   (README app-facing; BENCHMARK.md + tools/ = evaluator-only)
├── SlopShopSparse/      sparse vulnerable app  (same 411 vulns, spread out)
├── SlopShop_F/          clean app + 60 feints  (README app-facing, no in-tree evaluator files)
├── SlopShopPerfect/     clean app, no bait     (README app-facing, no in-tree evaluator files)
└── SlopShop_Actual/     164 real post-cutoff CVEs (harness + corpus; ground truth isolated)
```
