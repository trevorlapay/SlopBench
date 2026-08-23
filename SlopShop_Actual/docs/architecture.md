# sastbench Architecture

## What sastbench Does

sastbench answers a simple question: **how good is an AI agent at finding security vulnerabilities in code?**

It does this by giving agents code to analyze, collecting their findings, and comparing those findings against known answers. The result is a set of metrics — precision, recall, F1 — that tell you how accurate the agent is, what it misses, and where it hallucinates.

Security vulnerability detection is fundamentally an information retrieval problem. There is a set of real vulnerabilities in a codebase (the "relevant documents"), and an agent produces a set of suspected vulnerabilities (the "retrieved documents"). sastbench measures the overlap between these two sets with the same rigor that search engine benchmarks measure relevance.

The challenge specific to vulnerability detection is that "overlap" is fuzzy. Two tools might report the same buffer overflow at slightly different line numbers, or classify the same bug as CWE-120 (Buffer Copy without Checking Size) versus CWE-787 (Out-of-bounds Write). sastbench handles this through configurable matching tolerance and a weakness taxonomy hierarchy.

---

## How It Works (End to End)

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   1. PREPARE                                             │
│                                                          │
│   Download a benchmark dataset (real-world vulnerable    │
│   code from public databases). Extract the code and      │
│   the known vulnerability labels. Shuffle the files      │
│   randomly and rename them to neutral names so the       │
│   agent gets no hints about what to expect. Store the    │
│   answer key in a hidden folder the agent can't see.     │
│   Write a plain-english instruction file telling the     │
│   agent where to read code and where to write results.   │
│                                                          │
│   Input:  Benchmark name + configuration                 │
│   Output: A workspace folder ready for an agent          │
│                                                          │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   2. SCAN                                                │
│                                                          │
│   An AI agent (any model, any platform) receives the     │
│   workspace. It reads the instruction file, analyzes     │
│   every source code file, and writes a list of           │
│   suspected vulnerabilities — each with a file name,     │
│   line number, vulnerability type, and confidence.       │
│                                                          │
│   sastbench does not control how the agent works.        │
│   It only defines the input contract (where code lives)  │
│   and the output contract (where to write findings).     │
│                                                          │
│   Input:  Workspace folder                               │
│   Output: A findings file (JSON, SARIF, or CSV)          │
│                                                          │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   3. EVALUATE                                            │
│                                                          │
│   Compare the agent's findings against the hidden        │
│   answer key. For each finding, determine whether it     │
│   matches a known vulnerability (true positive),         │
│   flags clean code (false positive), or misses a         │
│   known vulnerability entirely (false negative).         │
│                                                          │
│   Matching can be strict (exact line number) or          │
│   lenient (same file, nearby line, related weakness      │
│   category). The matching strategy is configurable.      │
│                                                          │
│   Input:  Agent findings + hidden answer key             │
│   Output: Matched pairs, unmatched findings, missed      │
│           vulnerabilities                                │
│                                                          │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   4. MEASURE                                             │
│                                                          │
│   From the matching results, compute standard metrics:   │
│                                                          │
│   • Precision — of what the agent flagged, how much      │
│     was real?                                            │
│   • Recall — of the real vulnerabilities, how many       │
│     did the agent find?                                  │
│   • F1 — the balance between precision and recall        │
│   • Per-category breakdown — how does the agent          │
│     perform on buffer overflows vs injection vs          │
│     memory errors?                                       │
│   • Severity-weighted scores — are critical misses       │
│     penalized more than low-severity ones?               │
│                                                          │
│   Input:  Matching results                               │
│   Output: Metrics report                                 │
│                                                          │
└──────────────────────┬───────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   5. REPORT                                              │
│                                                          │
│   Present the results as:                                │
│   • A table in the terminal                              │
│   • A structured data file for programmatic access       │
│   • An interactive web dashboard with charts             │
│                                                          │
│   When multiple agents are evaluated on the same         │
│   benchmark, produce a side-by-side comparison           │
│   with rankings.                                         │
│                                                          │
│   Input:  Metrics report(s)                              │
│   Output: Human-readable and machine-readable reports    │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## Key Design Principles

### The Agent Sees No Answers

The workspace is deliberately constructed so the agent cannot cheat. Source files are renamed to meaningless sequential names. Folder structure carries no hints about vulnerability categories. The answer key is stored in a hidden directory that is excluded from version control. The only document the agent receives is a plain instruction file describing where to read code and where to write results — it says nothing about what kinds of vulnerabilities to look for.

This matters because many AI models have been trained on the same benchmark datasets we use for evaluation. If a file is named `CWE79_XSS_Reflected_01.c`, an LLM could match it to training data and "recall" the answer rather than genuinely analyzing the code. Neutral naming forces the agent to do actual static analysis rather than pattern-matching on metadata.

The instruction file (called AGENTS.md) is deliberately minimal. It specifies only three things: where source files live, what format to write findings in, and what fields each finding must contain. It never mentions security, vulnerabilities, CWE categories, or any domain-specific context. The agent's task is to figure out what to look for on its own.

### Any Agent, Any Platform

sastbench does not require agents to use a specific API, language, or framework. The contract is file-based: code goes in, findings come out. This means the same benchmark can evaluate a cloud-hosted coding agent, a local command-line tool, a Docker container, or a human analyst — all on equal footing.

To support orchestrated evaluation (where sastbench manages the entire lifecycle), platform adapters handle the mechanics of task submission, status monitoring, and result collection. Supported platforms include:

- **Manual mode** — sastbench prepares the workspace; the user runs any agent manually and points the evaluator at the output.
- **Docker containers** — sastbench mounts the workspace as a volume, starts a container, and collects results after the container exits. The agent inside the container reads the instruction file from its mount point.
- **GitHub Copilot Coding Agent** — sastbench pushes the workspace to a GitHub repository, creates an issue referencing the instruction file, and monitors for the agent to complete the task.
- **Local CLI agents** — sastbench spawns a local process (such as a Copilot CLI session) pointed at the workspace directory, waits for it to finish, and collects the output.

In all cases, the agent interacts with the same workspace structure and produces the same output format. Platform adapters only differ in how they deliver the workspace and collect results.

### Multiple Benchmarks, One Framework

Different vulnerability databases organize their data differently. Some provide individual functions, some provide whole files, some provide before-and-after patch pairs. sastbench includes an adapter for each database that translates its unique format into the common workspace structure. Adding a new benchmark means writing one adapter — the rest of the pipeline stays the same.

Each adapter knows how to:
1. **Download** its benchmark data from the canonical source (NIST website, GitHub, HuggingFace, Zenodo). Downloaded data is cached locally so subsequent runs don't re-download.
2. **Extract** source code and ground truth labels from the benchmark's native format (CSV, JSON, Parquet, directory trees with naming conventions).
3. **Normalize** the extracted data into a standard internal representation: a list of code samples and a list of known vulnerability labels.

The adapter layer absorbs all the complexity of each benchmark's quirks — column names, data types, file layouts, labeling conventions — so the evaluation pipeline downstream never has to think about it.

### Shuffled by Default

Some benchmark datasets have predictable ordering — for example, alternating vulnerable and safe versions of the same function. If agents process files sequentially and run out of budget partway through, this ordering can systematically bias which files get analyzed. sastbench shuffles files randomly (with a fixed seed for reproducibility) to eliminate this bias.

This was discovered during actual benchmarking. PrimeVul's paired test set alternates vulnerable and patched functions: file 1 is safe, file 2 is vulnerable, file 3 is safe, and so on. Two agents that processed files in order happened to analyze primarily odd-numbered (safe) files, producing near-zero recall. After shuffling, the same agents achieved 40-50% recall on the same dataset. The bias was entirely an artifact of file ordering, not model capability.

The shuffle uses a deterministic seed (default: 42) so results are reproducible. Running preparation twice with the same seed produces the identical workspace.

### One Finding, One Vulnerability

When an agent reports a finding that matches a known vulnerability, that finding is "consumed" — it cannot also satisfy a different known vulnerability. This prevents a single vague finding from inflating the score by claiming credit for multiple distinct bugs. The matching algorithm finds the optimal assignment that maximizes the total number of correct matches.

This is implemented as a maximum bipartite matching problem. Findings are on one side, known vulnerabilities on the other, and edges connect compatible pairs. The algorithm finds the largest set of edges where no finding and no vulnerability is used more than once. This is more accurate than a greedy first-match approach, which can produce suboptimal assignments when the same finding could match multiple vulnerabilities.

For example: suppose a file has two known vulnerabilities at lines 10 and 14, and the agent reports findings at lines 8 and 12. A greedy algorithm might match line 8 to the vulnerability at line 10 (within tolerance) and line 12 to nothing (too far from line 14). The optimal algorithm matches line 8 to line 10 and line 12 to line 14, producing two true positives instead of one.

---

## The Three Evaluation Modes

### Mode 1: Graded Evaluation (with answer key)

The standard mode. The agent's findings are compared against known vulnerability labels. Produces precision, recall, F1, and per-category breakdowns.

Best for: benchmarks with reliable labels (real CVE databases, curated test suites).

In this mode, a finding is a true positive only if it matches a known vulnerability at the correct location AND identifies the correct weakness category (e.g., CWE-79 for cross-site scripting). The weakness category requirement can be relaxed with a flag for benchmarks where the labels use broad or inconsistent categories.

This mode produces the richest output: overall metrics, per-CWE breakdowns showing which vulnerability types the agent excels at and which it struggles with, severity-weighted scores that penalize missing critical bugs more than missing minor ones, and the raw matching data for drill-down analysis.

### Mode 2: Binary Classification (vulnerable or safe?)

Some benchmarks include both vulnerable and clean code but don't label the specific weakness type. In this mode, the only question is: did the agent correctly identify which files are vulnerable and which are safe? No vulnerability category matching is performed.

Best for: paired datasets where the "safe" version is a patched copy of the vulnerable one.

This is the right evaluation mode when the ground truth lacks specific CWE labels (some datasets use generic placeholders like "Other" or "Unknown") or when the goal is to measure the agent's ability to discriminate between vulnerable and clean code rather than classify specific weakness types.

The metrics in binary mode are standard classification metrics: precision (of files the agent flagged, what fraction were truly vulnerable), recall (of truly vulnerable files, what fraction did the agent flag), accuracy (overall correct classification rate), and the confusion matrix (true positives, false positives, false negatives, true negatives).

A key subtlety: in binary mode, an agent that flags every file achieves 100% recall but only 50% precision on a balanced dataset. This makes precision the more discriminating metric — it measures whether the agent can tell the difference between vulnerable and patched code, which is the genuine skill being tested.

### Mode 3: Agent-to-Agent Comparison (no answer key)

When no ground truth is available, compare what different agents find. Measure how much they agree, what each finds exclusively, and how their confidence distributions differ. Useful for understanding relative strengths without needing labeled data.

Best for: proprietary codebases where no vulnerability labels exist.

This mode computes several agreement metrics:

- **Jaccard index** — the ratio of findings reported by both agents to findings reported by either agent. A value of 1.0 means perfect agreement; 0.0 means no overlap.
- **Agreement rate** — the fraction of unique findings that at least two agents agree on.
- **Cohen's kappa** — an agreement statistic that accounts for chance agreement. Higher values indicate more meaningful agreement beyond what you'd expect from random flagging.
- **Consensus findings** — for three or more agents, findings that a configurable majority agrees on. These high-consensus findings are more likely to be real vulnerabilities.
- **Per-agent unique findings** — what each agent finds that no other agent does. These are either genuine catches that other agents missed, or false positives that only one agent hallucinated.

Matching between agents uses the same tolerance-based approach as matching against ground truth. Two agents' findings are considered "the same" if they refer to the same file, a nearby line (within the tolerance window), and the same weakness category.

---

## How Matching Works

Matching is the most nuanced part of the system. It answers: does this agent finding correspond to this known vulnerability?

This is harder than it sounds. An agent might report a buffer overflow on line 42, while the ground truth labels it on line 44 (pointing to the vulnerable function call rather than the buffer declaration). Both are arguably correct — they describe the same bug. The matching system must be flexible enough to recognize this while still being strict enough to prevent spurious matches.

### Three Levels of Granularity

**File level:** The agent flagged the right file. This is the most lenient mode — if the agent says "there's a vulnerability in sample_0042.c" and the ground truth agrees, it's a match regardless of where in the file the agent points to. Best for benchmarks where each file contains one logical unit (a single function or a small self-contained program). Also appropriate when ground truth labels don't include line numbers.

**Function level:** The agent flagged the right file and the right function. This is useful for benchmarks like Juliet where a single file may contain both a vulnerable function and a safe function. It distinguishes between "the agent found the bug in the bad() function" and "the agent found something in the good() function" (which would be a false positive). Falls back to file level if either the finding or the ground truth doesn't include a function name.

**Line level:** The agent flagged the right file and a line number within a configurable tolerance window (e.g., ±5 lines) of the known vulnerability. The strictest mode, but accounts for the fact that different tools may point to slightly different lines for the same bug. The tolerance window is configurable because the appropriate tolerance depends on the benchmark: for benchmarks with precise line annotations (like CASTLE), a narrow window (±3 lines) makes sense. For benchmarks with approximate labels, a wider window (±10 lines) may be needed. Falls back to file level when line numbers are missing.

### Weakness Category Matching

By default, the agent must also identify the correct category of weakness (e.g., buffer overflow, SQL injection). sastbench uses the CWE (Common Weakness Enumeration) taxonomy — a standardized numbering system maintained by MITRE where each weakness type has a unique identifier.

CWE matching has several modes:

- **Strict matching (default):** The agent's CWE must exactly match the ground truth CWE after normalization. sastbench normalizes various formats ("CWE-79", "CWE79", "cwe_79", "79") to a canonical form before comparing.
- **No CWE matching:** Ignore the weakness category entirely. Match based on location only. Essential for benchmarks where the ground truth uses broad, outdated, or inconsistent CWE labels.
- **Hierarchical matching:** Give partial credit when the agent identifies a parent or child category. CWE is organized as a hierarchy — CWE-79 (Cross-Site Scripting) is a child of CWE-74 (Injection). An agent that reports CWE-74 for a ground truth labeled CWE-79 has the right family even if it's not specific enough. Hierarchical matching optionally accepts these parent-child relationships.

### Optimal Assignment

When a file contains multiple known vulnerabilities and multiple agent findings, the system computes the best possible one-to-one pairing. This ensures the highest number of correct matches without double-counting.

The problem is modeled as maximum bipartite matching: findings on one side, known vulnerabilities on the other, edges between compatible pairs. The algorithm considers all possible assignments and selects the one that produces the most true positives. This matters in practice for benchmarks like Juliet and CASTLE where a single file can contain 3-11 distinct vulnerabilities at different lines.

Without optimal matching, a greedy approach would process ground truths in order and greedily assign the first available matching finding. This can lead to suboptimal results — for example, assigning a finding to a nearby vulnerability when it would be a better match for a different vulnerability, leaving the second one unmatched.

### Path Normalization

Before any matching occurs, file paths from both the agent findings and the ground truth are normalized to a canonical form. This handles common inconsistencies:

- Backslash vs forward slash (`code\sample_001.c` vs `code/sample_001.c`)
- Leading `./` prefixes (`./code/sample_001.c` vs `code/sample_001.c`)
- Doubled slashes (`code//sample_001.c`)
- Relative path components (`code/subdir/../sample_001.c`)

This normalization is critical for cross-platform evaluation — an agent running on Windows might report backslash paths while the ground truth uses forward slashes.

---

## What Gets Measured

### Core Metrics

| Metric | Question It Answers | How It's Computed |
|--------|-------------------|-------------------|
| Precision | When the agent says "vulnerability here," how often is it right? | True positives ÷ (true positives + false positives) |
| Recall | Of all the real vulnerabilities, what fraction did the agent find? | True positives ÷ (true positives + false negatives) |
| F1 Score | How well does the agent balance finding things vs being accurate? | Harmonic mean of precision and recall |
| Accuracy | What fraction of all decisions (flag or don't flag) are correct? | (True positives + true negatives) ÷ total |
| False Positive Rate | How much noise does the agent generate? | False positives ÷ (false positives + true negatives) |

### Per-Category Breakdown

All core metrics are also computed per weakness category (per-CWE). This reveals the agent's strengths and weaknesses across different vulnerability types. An agent might have 95% recall on buffer overflows but only 20% recall on race conditions.

Two aggregation strategies are provided:
- **Micro-average** — pool all findings across categories, then compute metrics. Categories with more ground truths have proportionally more influence. Equivalent to the overall metrics.
- **Macro-average** — compute metrics independently per category, then average. Gives equal weight to every category regardless of how many examples it has. Better for assessing breadth of detection capability.

### Severity-Weighted Metrics

Not all vulnerabilities are equally important. A missed critical remote code execution matters more than a missed low-severity information disclosure. Severity-weighted metrics assign weights to each finding based on its severity level:

- Critical: weight 4
- High: weight 3
- Medium: weight 2
- Low: weight 1

Precision, recall, and F1 are then computed using weighted counts. This means a true positive on a critical vulnerability contributes 4× as much to recall as a true positive on a low-severity one. An agent that catches all the critical bugs but misses some low-severity ones will score higher on severity-weighted recall than one that catches the low-severity bugs but misses the critical ones.

### Agent-to-Agent Metrics (no ground truth)

| Metric | Question It Answers |
|--------|-------------------|
| Agreement Rate | What fraction of unique findings are reported by more than one agent? |
| Jaccard Index | How much do two agents' finding sets overlap? (intersection ÷ union) |
| Cohen's Kappa | Do the agents agree more than chance predicts? |
| Unique Findings | What does each agent exclusively find that no other agent reports? |
| CWE Distribution | Which weakness categories does each agent focus on? |
| Severity Distribution | How do agents differ in the severity levels they report? |
| Consensus Findings | For 3+ agents, which findings does a majority agree on? |

---

## Input and Output Formats

### What an Agent Receives

The workspace is a directory containing:

- **AGENTS.md** — a plain-text instruction file specifying where to read code and where to write findings. Contains no security-specific guidance.
- **code/** — a flat directory of source files with neutral sequential names (sample_0001.c, sample_0002.c, etc.).
- **manifest.json** — a machine-readable list of all files with their programming language. Contains no vulnerability information.
- **output/** — an empty directory where the agent should write its findings.
- **output_schema.json** — a JSON Schema document describing the expected structure of the findings file.

The workspace also contains a hidden directory (excluded from version control) that the agent should not access. This directory stores the ground truth labels and the mapping from neutral filenames back to original benchmark identifiers.

### What an Agent Produces

The agent writes a single findings file in one of three formats:

**JSON (recommended):** A JSON object with an array of findings, each containing at minimum a file path, line number, and CWE identifier. Optional fields include severity, confidence, end line, and a human-readable message.

**SARIF 2.1.0:** The industry-standard Static Analysis Results Interchange Format. sastbench parses the `runs[].results[]` array, extracting location, rule ID, severity level, and CWE identifiers from result properties and rule metadata. The parser is lenient — it handles non-standard SARIF produced by various tools without crashing on missing optional fields.

**CSV:** A simple columnar format with one row per finding. Column names map to finding fields. Useful for quick integration with tools that produce tabular output.

The parser layer auto-detects the format based on file extension and content. All three formats are normalized to the same internal representation before matching.

### What a Finding Contains

Each finding represents a single suspected vulnerability and carries these attributes:

| Field | Required | Description |
|-------|----------|-------------|
| File path | Yes | Which file the vulnerability is in (relative to workspace root) |
| Start line | Yes | The line number where the vulnerability occurs (1-indexed) |
| CWE identifier | Yes | The type of weakness (e.g., CWE-79 for cross-site scripting) |
| End line | No | The last line of the vulnerable code span |
| Severity | No | How serious the vulnerability is (critical, high, medium, low) |
| Confidence | No | How certain the agent is (0.0 to 1.0) |
| Message | No | Human-readable description of the vulnerability |

---

## Supported Benchmark Databases

### BigVul — Real-World CVE Functions

**Source:** GitHub (MSR 2020 dataset) — auto-downloaded
**Content:** ~370,000 C/C++ functions extracted from real open-source projects (Linux kernel, FFmpeg, OpenSSL, etc.), each linked to a CVE vulnerability report.
**Ground truth:** Every entry in the dataset corresponds to a function that was patched to fix a known vulnerability. The pre-patch version is the vulnerable code.
**Evaluation mode:** File-level matching with CWE matching disabled (the dataset uses broad CWE categories from the NVD that may not match what agents report).
**Difficulty:** Moderate. The code is real production code, but every file in the extracted set is vulnerable, so there are no true negatives. This makes recall trivially 100% for agents that flag everything — precision is the differentiating metric.
**Typical agent performance:** 60-94% F1 depending on the model.

### PrimeVul — Paired Vulnerable and Safe Functions

**Source:** HuggingFace (ASSERT-KTH/PrimeVul) — auto-downloaded
**Content:** ~7,000 vulnerable and ~229,000 benign C/C++ functions from real projects, curated with high label quality and careful train/test contamination prevention.
**Ground truth:** Each function is labeled as vulnerable or safe. The test set is paired: for each vulnerable function, there is a corresponding patched (safe) version. The two versions are often nearly identical — differing by just a few lines.
**Evaluation mode:** Binary classification (vulnerable vs safe). CWE labels are mostly "Other/Unknown" so category matching is not meaningful.
**Difficulty:** Very hard. This is the hardest benchmark because the agent must distinguish between code with a subtle bug and the same code with the bug fixed. The pairs are 80-90% similar. All tested models achieve below 55% F1, meaning they struggle to do much better than coin-flipping on this task.
**Typical agent performance:** 35-67% F1 (binary classification).

### CASTLE — CWE-Focused Test Cases

**Source:** GitHub (CASTLE-Benchmark) — auto-downloaded
**Content:** 250 purpose-built C test cases covering 25 CWE categories. Each test case is a small self-contained program designed to isolate one specific weakness type.
**Ground truth:** High-quality labels with exact vulnerable line numbers. Each test is labeled as vulnerable or non-vulnerable, with the specific CWE category and the precise lines where the vulnerability exists.
**Evaluation mode:** File-level matching with CWE matching disabled (the workspace uses neutral names, so CWE matching depends on the agent's classification accuracy). Can also use line-level matching for more precise evaluation.
**Difficulty:** Moderate to hard. The test cases are simpler than real-world code but cover a wide range of weakness types. The mix of vulnerable and non-vulnerable cases (roughly 60/40) tests discrimination ability.
**Typical agent performance:** 25-55% F1.

### Juliet — NIST Synthetic Test Suite

**Source:** NIST SARD website — auto-downloaded
**Content:** Thousands of synthetic C/C++ test cases covering 118 CWE categories. Each file contains both a vulnerable function and a safe function, with comments marking the vulnerable lines.
**Ground truth:** Comment-based annotations (lines marked with "POTENTIAL FLAW") provide line-level ground truth. Files are labeled by CWE category in the original directory structure, but this information is stripped during workspace preparation.
**Evaluation mode:** Line-level matching with tolerance ±5 lines and CWE matching enabled (the adapter extracts CWE from the original directory names and stores it in the hidden ground truth).
**Difficulty:** Variable by CWE category. Some categories (buffer overflows, null dereferences) are easy for modern models; others (race conditions, logic errors) are much harder. The synthetic nature of the code (formulaic function structure, explicit FLAW comments in the source) makes it less representative of real-world detection but useful for measuring breadth across CWE categories.
**Typical agent performance:** 50-90% F1 depending on matching granularity and the specific CWE mix.

### Adding New Benchmarks

The adapter interface is designed for extensibility. Adding a new benchmark requires implementing three operations:

1. **Download** — fetch the dataset from its source and store it in the local cache.
2. **Extract** — parse the dataset's native format and produce a list of code samples and a list of ground truth labels in the common internal representation.
3. **Register** — add the new adapter to the registry so the CLI discovers it.

A custom ground truth adapter is also available for one-off evaluations using user-provided JSON or CSV files containing vulnerability labels.

---

## Reproducibility

sastbench is designed so that any evaluation can be reproduced exactly:

- **Deterministic shuffle:** File ordering uses a fixed random seed (default: 42). Same seed + same benchmark + same max_cases = identical workspace every time.
- **Cached downloads:** Benchmark datasets are downloaded once and cached locally. The cache is keyed by benchmark name and validated for completeness before reuse.
- **Pinned evaluation parameters:** Every evaluation records its matching granularity, tolerance window, CWE matching mode, and other parameters in the output report. This makes it possible to re-run with identical settings.
- **Workspace verification:** A verification script checks that prepared workspaces have the expected file counts, that ground truth paths reference actual code files, that the vulnerability/safe distribution is not systematically biased, and that all essential files are present.

The full pipeline — from benchmark download through workspace preparation, agent execution, and evaluation — can be automated with three scripts that are part of the project. These scripts are designed for CI integration and return non-zero exit codes on failure.

---

## Known Limitations and Tradeoffs

### Ground truth quality varies

Real-world benchmark datasets have noisy labels. BigVul's CWE labels come from the National Vulnerability Database and may be broad or incorrect. PrimeVul's "Other" CWE label covers the majority of entries. CASTLE has the highest label quality but the smallest dataset. Evaluation results are only as good as the ground truth they're measured against.

### File-level granularity is generous

For benchmarks where each file contains one function, file-level matching effectively asks "did the agent identify that this function is vulnerable?" — not "did it find the specific line?" This can overcount true positives when the agent flags a file for the wrong reason. Line-level matching is more precise but requires ground truth with line annotations and tolerates some imprecision.

### Agents don't see project context

Each code file is presented in isolation, without the surrounding project context (header files, build configuration, call sites, data flow from other modules). Real-world vulnerability detection often depends on interprocedural analysis — tracing data flow across function boundaries. The benchmark measures per-file detection ability, which is a subset of full-project vulnerability hunting.

### Binary mode is a weak signal

On balanced datasets (50% vulnerable, 50% safe), an agent that flags everything achieves 50% precision and 100% recall (F1=66.7%). An agent that flags nothing achieves 0% recall. The useful range of F1 is narrow. Binary classification results should be interpreted with this baseline in mind — any F1 significantly above 66.7% would indicate genuine discrimination ability, which no tested model has yet achieved.

### LLM agents are non-deterministic

The same model may produce different findings on successive runs due to sampling temperature, token limits, and the order in which it processes files. sastbench evaluates a single run — it does not average across multiple runs. For production benchmarking, consider running each agent multiple times and reporting variance.

---

## Diagram: Information Flow

```
                    ┌─────────────┐
                    │  Benchmark  │
                    │  Database   │
                    │  (BigVul,   │
                    │  PrimeVul,  │
                    │  CASTLE...) │
                    └──────┬──────┘
                           │
                           │ download + extract
                           ▼
                    ┌─────────────┐
                    │  Workspace  │
                    │  Preparer   │
                    │             │
                    │  • shuffle  │
                    │  • rename   │
                    │  • hide GT  │
                    └──────┬──────┘
                           │
                           │ produces
                           ▼
          ┌────────────────────────────────┐
          │         WORKSPACE              │
          │                                │
          │  📄 instruction file           │
          │  📁 code/ (neutral filenames)  │
          │  📁 output/ (agent writes here)│
          │  🔒 .hidden/ (answer key)      │
          │                                │
          └───────┬───────────────┬────────┘
                  │               │
        agent reads code    agent writes findings
                  │               │
                  ▼               ▼
          ┌──────────────┐  ┌──────────────┐
          │   AI Agent   │  │   Findings   │
          │   (any model │  │   File       │
          │    or tool)  │  │              │
          └──────────────┘  └──────┬───────┘
                                   │
                                   │ parse + normalize
                                   ▼
                    ┌──────────────────────┐
                    │   Finding Normalizer │
                    │                      │
                    │   Accepts SARIF,     │
                    │   JSON, or CSV       │
                    └──────────┬───────────┘
                               │
                               │ normalized findings
                               ▼
          ┌──────────────────────────────────────┐
          │           Matching Engine             │
          │                                      │
          │   Pairs each finding with the best   │
          │   matching known vulnerability        │
          │   (file → function → line level)      │
          │                                      │
          │   findings + answer key → matches     │
          └──────────────────┬───────────────────┘
                             │
                             │ match results
                             ▼
          ┌──────────────────────────────────────┐
          │          Metrics Calculator           │
          │                                      │
          │   matches → precision, recall, F1,   │
          │   per-category breakdown,            │
          │   severity-weighted scores           │
          └──────────────────┬───────────────────┘
                             │
                             │ metrics
                             ▼
          ┌──────────────────────────────────────┐
          │          Report Generator             │
          │                                      │
          │   • Terminal table                    │
          │   • Structured data file             │
          │   • Interactive web dashboard        │
          │   • Multi-agent comparison           │
          └──────────────────────────────────────┘
```

---

## Diagram: Multi-Agent Comparison

```
     Agent A          Agent B          Agent C          Agent D
        │                │                │                │
        ▼                ▼                ▼                ▼
   ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
   │Findings │     │Findings │     │Findings │     │Findings │
   └────┬────┘     └────┬────┘     └────┬────┘     └────┬────┘
        │               │               │               │
        └───────┬───────┴───────┬───────┘               │
                │               │                       │
                ▼               ▼                       │
        ┌──────────────┐ ┌──────────────┐              │
        │  Evaluate    │ │  Evaluate    │              │
        │  vs Answer   │ │  vs Answer   │    ...       │
        │  Key         │ │  Key         │              │
        └──────┬───────┘ └──────┬───────┘              │
               │                │                       │
               ▼                ▼                       ▼
        ┌─────────────────────────────────────────────────┐
        │              Comparison Engine                    │
        │                                                  │
        │   • Rank agents on each metric                   │
        │   • Identify what each agent uniquely finds      │
        │   • Measure overlap between agents               │
        │   • Statistical significance of differences      │
        │                                                  │
        └─────────────────────┬────────────────────────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │  Comparison       │
                    │  Report           │
                    │                   │
                    │  Rankings,        │
                    │  overlap matrix,  │
                    │  unique finds     │
                    └───────────────────┘
```
