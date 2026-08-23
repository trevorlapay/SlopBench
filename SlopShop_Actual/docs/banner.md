```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                ║
║   ███████╗ █████╗ ███████╗████████╗██████╗ ███████╗███╗   ██╗ ██████╗██╗  ██╗ ║
║   ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔════╝████╗  ██║██╔════╝██║  ██║ ║
║   ███████╗███████║███████╗   ██║   ██████╔╝█████╗  ██╔██╗ ██║██║     ███████║ ║
║   ╚════██║██╔══██║╚════██║   ██║   ██╔══██╗██╔══╝  ██║╚██╗██║██║     ██╔══██║ ║
║   ███████║██║  ██║███████║   ██║   ██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║ ║
║   ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝ ║
║                                                                                ║
║           Benchmark Framework for Vulnerability-Hunting AI Agents              ║
║                                                                                ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║   PREPARE ──▶ RUN AGENTS ──▶ EVALUATE ──▶ COMPARE                             ║
║                                                                                ║
║   BENCHMARKS         METRICS            AGENTS             REPORTS            ║
║   ─────────────      ──────────────     ──────────────     ──────────────     ║
║   ▪ Juliet (NIST)    ▪ Precision        ▪ Claude Sonnet    ▪ Console         ║
║   ▪ BigVul           ▪ Recall           ▪ Claude Opus      ▪ JSON            ║
║   ▪ PrimeVul         ▪ F1 Score         ▪ GPT-5.4          ▪ HTML Dashboard  ║
║   ▪ CASTLE           ▪ Per-CWE Stats    ▪ Codex 5.3        ▪ Agent Diff      ║
║   ▪ CVEFixes / SARD  ▪ Cohen's Kappa    ▪ Any SARIF/JSON   ▪ Head-to-Head   ║
║   ▪ HumanEval        ▪ FPR / Accuracy   │  compatible       │                ║
║   ▪ Custom           ▪ GT Quality       │  agent            │                ║
║                                                                                ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║   KEY FEATURES                                                                 ║
║   ✓ Auto-download benchmarks         ✓ Neutral file naming (no CWE hints)     ║
║   ✓ Shuffled workspaces (no bias)    ✓ Ground truth isolated from agents      ║
║   ✓ SARIF / JSON / CSV parsing       ✓ File / function / line matching        ║
║   ✓ Binary vuln/safe classification  ✓ Optimal bipartite 1:1 matching         ║
║                                                                                ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║   ANTI-CHEATING MEASURES                                                       ║
║   ⛨ Ground truth stored OUTSIDE workspace (agents can't read it)              ║
║   ⛨ Files shuffled with deterministic seed (prevents ordering bias)           ║
║   ⛨ Neutral sample_NNNN naming (no CWE hints in filenames)                   ║
║   ⛨ Audit command detects GT leakage (CWE correlation, count matching)        ║
║   ⛨ Integrity clause in prompts (genuine analysis only)                       ║
║                                                                                ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```
