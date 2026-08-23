# Post-Cutoff SAST Benchmark

A SASTBench benchmark of **real, publicly-disclosed vulnerabilities** whose advisories were
**published after 2025-12-01** (the GPT-5.5 training cutoff), assembled into a neutral,
app-like monorepo so an LLM-based SAST scanner can be tested on code that could **not** have
been in its training data.

## Point your scanner here

```
workspaces/postcutoff/code/
```

164 real vulnerable files laid out as a plausible polyglot platform
(`code/services/<service>/...`). **Nothing in that tree identifies a vulnerability** — no CVE,
no CWE, no project name, no vuln title, in paths, file names, or file contents. The scanner
writes findings to `workspaces/postcutoff/output/findings.json` (see the workspace `AGENTS.md`).

The answer key (which neutral file is which CVE/CWE, and the vulnerable lines) lives **outside**
the workspace in `workspaces/evaluator_data/postcutoff/` so the scanner cannot read it.

## What makes this valid for testing a post-cutoff scanner

- **Real vulnerabilities, not invented.** Every entry is a CVE/GHSA with a live advisory.
  Nothing is authored from memory.
- **Verbatim upstream code.** Each file is the affected project's source *at the pre-fix
  commit* (`git cat-file -p <fix_commit>^:<path>`) — the exact code that was vulnerable.
- **Strictly post-cutoff.** Only advisories with disclosure date **after 2025-12-01** (earliest
  kept: 2025-12-02).
- **Not from vuln benchmarks.** Discovery uses the OSV database + affected-project repos —
  never Juliet/SARD/BigVul/PrimeVul/CVEfixes/CASTLE.
- **De-identified for the model under test.** No CVE/CWE token, neutral service/module names,
  ground truth isolated. (Caveat: verbatim code still contains the projects' *own* identifiers
  — namespaces, copyright headers. See "Threat model" below.)

## Layout

```
corpus/                          verbatim pre-fix source, opaque names (evaluator-side)
  <language>/vuln_NNNN.<ext>
  manifest.jsonl                 one provenance record per vulnerability (the answer key)
provenance/<CVE>.json            per-CVE provenance
tools/
  harvest.py                     OSV -> verified verbatim corpus (network)
  build_workspace.py             corpus -> app-like, de-identified scanner workspace
  build_corpus.py                corpus -> vulnerability key + (flat) SASTBench bundle
build/
  ground_truths.json             flat SASTBench custom-adapter bundle (secondary)
  (vulnerability_key.md / .json regenerate here; the checked-in copy is the suite key below)
../VulnerabilityKeys/
  SlopShop_Actual.vulnerability_key.json / .md   THE KEY: CVE <-> neutral path <-> CWE <-> lines <-> advisory
workspaces/
  postcutoff/code/               <-- point your scanner here
  evaluator_data/postcutoff/     isolated ground truth + neutral->CVE mapping
SASTBench/                       upstream SASTBench harness (unmodified)
```

## Rebuild from scratch

```bash
python tools/harvest.py --target 150        # 1. harvest real post-cutoff vulns (resumable)
python tools/build_workspace.py --name postcutoff   # 2. app-like, de-identified workspace
python tools/build_corpus.py --strict       # 3. vulnerability key (+ flat bundle)
```

## Score a scanner

```bash
cd SASTBench && pip install -e .   # once
# after your scanner writes workspaces/postcutoff/output/findings.json:
python -m sastbench.cli evaluate -w ../workspaces/postcutoff \
  --agent-output ../workspaces/postcutoff/output/findings.json \
  --agent-name "my-scanner" --granularity line --line-tolerance 3
```

`evaluate` scores findings against the isolated ground truth. (SASTBench's `verify` assumes a
flat `code/`, so it is not used with this nested app-like layout; `build_workspace.py` runs its
own integrity + leak checks instead.)

## Threat model / honest caveats

- **CVE/CWE labels, vuln locations, and ground truth are fully isolated** from the scanner —
  this is what stops a model from "reporting the answer."
- **The vulnerabilities are post-cutoff**, so a Dec-1-2025 model cannot have memorized them even
  if it recognizes the project. In-code project identity (namespaces, copyright) is therefore a
  weak signal for this use case. It only becomes a real leak if the scanner has **live web/tool
  access** to look up a project's recent CVEs — a different threat model. If you need that,
  `build_workspace.py` can be extended to strip project identity (at the cost of strict
  verbatimness).
- Ground truth marks **one primary file + line range per CVE** (the fixing commit's main hunk);
  multi-file fixes record only the primary sink.
```
