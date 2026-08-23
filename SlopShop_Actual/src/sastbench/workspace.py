"""Workspace preparer — transforms benchmark data into neutral agent workspaces.

This is the bridge between raw benchmark datasets and the AGENTS.md contract.
It creates TWO directories:
1. Workspace (agent-facing): neutrally-named source files, AGENTS.md, manifest
2. Evaluator data (hidden from agent): ground truth, file mappings, config

The evaluator data is stored OUTSIDE the workspace so agents cannot access it,
even if they have full filesystem access within the workspace directory.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from sastbench.models import GroundTruth, TestCase
from sastbench.prompt_templates import get_prompt_template
from sastbench.utils.normalize import normalize_path

logger = logging.getLogger(__name__)

DEFAULT_WORKSPACE_INSTRUCTIONS = """## Workspace Instructions

- The workspace root is the current working directory
- Read `AGENTS.md` in the workspace root for the I/O contract
- Source code files are in `code/` relative to the workspace root
- `manifest.json` lists all files with metadata
- Write your findings to `{output_path}`
- Set `agent_name` to `{agent_name}` in your output JSON
"""

AGENTS_MD_TEMPLATE = """# AGENTS.md — Input/Output Contract

## Reading Input
- Source code is in `code/` relative to this file
- `manifest.json` lists all files with metadata (language, relative path)
- Do not modify any files in `code/`

## Writing Output
Write findings to `output/findings.json` with this structure:

```json
{{
  "agent_name": "<your name>",
  "timestamp": "<ISO 8601>",
  "findings": [
    {{
      "file_path": "code/sample_001.c",
      "start_line": 15,
      "end_line": 15,
      "cwe_id": "CWE-79",
      "severity": "high",
      "confidence": 0.9,
      "message": "Description of finding"
    }}
  ]
}}
```

### Required Fields
| Field | Type | Description |
|-------|------|-------------|
| file_path | string | Relative path from workspace root |
| start_line | int | 1-indexed line number |
| cwe_id | string | CWE identifier, e.g. "CWE-79" |

### Optional Fields
| Field | Type | Description |
|-------|------|-------------|
| end_line | int | End line (defaults to start_line) |
| severity | string | "critical", "high", "medium", "low" |
| confidence | float | 0.0 to 1.0 |
| message | string | Description |

### Alternative Formats
- SARIF 2.1.0 → `output/findings.sarif`
- CSV → `output/findings.csv` (columns: file_path, start_line, end_line, cwe_id, severity, confidence, message)

## Quality Expectations
- Only report findings that represent genuinely exploitable vulnerabilities
- If a file contains no real vulnerabilities, do NOT report it
- Do not flag defensive coding patterns (null checks, bounds validation,
  error handling) as vulnerabilities — these are good practices, not bugs
- Do not flag style issues, theoretical risks, or issues that require
  unrealistic preconditions to exploit
- Quality matters more than quantity: 5 real findings are worth more
  than 50 false alarms

## Constraints
- Only write to `output/`
- Use standard CWE identifiers
- See `output_schema.json` for JSON Schema validation
"""

OUTPUT_SCHEMA: dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["findings"],
    "properties": {
        "agent_name": {"type": "string"},
        "timestamp": {"type": "string", "format": "date-time"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file_path", "start_line", "cwe_id"],
                "properties": {
                    "file_path": {"type": "string"},
                    "start_line": {"type": "integer", "minimum": 1},
                    "end_line": {"type": "integer", "minimum": 1},
                    "cwe_id": {"type": "string", "pattern": "^CWE-[0-9]+$"},
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                    },
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    "message": {"type": "string"},
                },
            },
        },
    },
}

COPILOT_INSTRUCTIONS = """# Copilot Instructions

Please follow the instructions in AGENTS.md in this repository.
Analyze all source code in the `code/` directory for security vulnerabilities
and write your findings to `output/findings.json`.
"""

LANGUAGE_EXTENSIONS: dict[str, str] = {
    "c": ".c",
    "cpp": ".cpp",
    "java": ".java",
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "go": ".go",
    "rust": ".rs",
    "ruby": ".rb",
    "php": ".php",
    "csharp": ".cs",
}


class WorkspacePreparer:
    """Transforms raw benchmark data into a neutral agent workspace."""

    def build(
        self,
        test_cases: list[TestCase],
        ground_truths: list[GroundTruth],
        output_dir: Path,
        benchmark_name: str,
        *,
        shuffle: bool = True,
        seed: int = 42,
        evaluator_dir: Path | None = None,
        safe_ratio: float = 0.0,
        prompt_template: str = "selective",
    ) -> Path:
        """Create the workspace directory with neutral naming.

        Args:
            test_cases: Code samples extracted by a benchmark adapter.
            ground_truths: Ground truth labels from the adapter.
            output_dir: Where to create the workspace (agent-facing).
            benchmark_name: Name of the source benchmark.
            shuffle: Randomize file order to prevent systematic bias.
            seed: Random seed for reproducible shuffling.
            evaluator_dir: Where to store ground truth and mappings.
                Defaults to output_dir.parent / "evaluator_data" / output_dir.name.
                This is stored OUTSIDE the workspace so agents cannot read it.
            safe_ratio: Ratio of safe files to inject (e.g. 1.0 = equal count).
                When > 0, generates safe C functions and mixes them in.
            prompt_template: Name of the prompt template to save alongside the
                workspace (default "selective").  The resolved text is written
                to evaluator_data so ``show-run-prompt`` can reconstruct the
                exact agent prompt without manual copy-paste.

        Returns:
            Path to the created workspace.
        """
        import random

        # Inject safe functions if requested
        if safe_ratio > 0:
            from sastbench.safe_corpus import generate_safe_functions

            safe_count = int(len(test_cases) * safe_ratio)
            if safe_count > 0:
                # Match the benchmark's language distribution to prevent
                # language-based gaming (e.g., all safe = .c, all vuln = .cpp)
                cpp_count = sum(1 for tc in test_cases if tc.language == "cpp")
                cpp_ratio = cpp_count / len(test_cases) if test_cases else 0.0
                ws_name = output_dir.name

                safe_cases = generate_safe_functions(
                    safe_count,
                    seed=seed,
                    cpp_ratio=cpp_ratio,
                    workspace_name=ws_name,
                )
                # Create corresponding ground truths for safe files
                safe_gts = [
                    GroundTruth(
                        file_path=sc.original_path,
                        is_vulnerable=False,
                        benchmark_name=benchmark_name,
                    )
                    for sc in safe_cases
                ]
                test_cases = list(test_cases) + safe_cases
                ground_truths = list(ground_truths) + safe_gts
                logger.info(
                    "Injected %d safe functions (ratio=%.2f, cpp_ratio=%.2f)",
                    safe_count,
                    safe_ratio,
                    cpp_ratio,
                )

        output_dir.mkdir(parents=True, exist_ok=True)

        # Evaluator data stored OUTSIDE workspace — agents cannot access it
        if evaluator_dir is None:
            evaluator_dir = output_dir.parent / "evaluator_data" / output_dir.name
        evaluator_dir.mkdir(parents=True, exist_ok=True)

        code_dir = output_dir / "code"
        old_SASTBench_dir = output_dir / ".sastbench"

        # Clean stale files from previous runs (don't touch output/)
        for d in (code_dir, old_SASTBench_dir):
            if d.exists():
                logger.warning("Cleaning stale directory: %s", d)
                shutil.rmtree(d)
        if evaluator_dir.exists():
            shutil.rmtree(evaluator_dir)
            evaluator_dir.mkdir(parents=True, exist_ok=True)

        code_dir.mkdir(exist_ok=True)
        output_subdir = output_dir / "output"
        output_subdir.mkdir(exist_ok=True)
        github_dir = output_dir / ".github"
        github_dir.mkdir(exist_ok=True)

        # Shuffle test cases to prevent systematic ordering bias
        if shuffle and len(test_cases) > 1:
            indices = list(range(len(test_cases)))
            random.Random(seed).shuffle(indices)
            test_cases = [test_cases[i] for i in indices]
            # (ground truths reference original_path which we'll remap below)

        # Build file mapping: neutral name → original
        file_mapping: dict[str, dict[str, str]] = {}
        manifest_files: list[dict[str, str]] = []
        # Track how ground truths map to neutral paths
        original_to_neutral: dict[str, str] = {}

        for i, tc in enumerate(test_cases, 1):
            ext = LANGUAGE_EXTENSIONS.get(tc.language, ".txt")
            neutral_name = f"sample_{i:04d}{ext}"
            neutral_path = f"code/{neutral_name}"

            # Write the code file
            (code_dir / neutral_name).write_text(tc.code, encoding="utf-8")

            # Record mapping (use opaque ID to prevent index-based gaming)
            import hashlib
            opaque_id = hashlib.sha256(
                f"{benchmark_name}:{tc.original_id}:{tc.original_path}".encode()
            ).hexdigest()[:16]
            file_mapping[neutral_path] = {
                "original_id": tc.original_id,
                "opaque_id": opaque_id,
                "benchmark": benchmark_name,
                "language": tc.language,
            }
            original_to_neutral[tc.original_path] = neutral_path

        # Build manifest (agent-visible, no CWE info)
        manifest_files = [
            {"path": neutral_path, "language": info["language"]}
            for neutral_path, info in file_mapping.items()
        ]
        manifest = {
            "files": manifest_files,
            "total_files": len(manifest_files),
        }

        # Rewrite ground truths with neutral file paths
        # Build a normalized lookup for robust matching
        normalized_to_neutral: dict[str, str] = {
            normalize_path(k): v for k, v in original_to_neutral.items()
        }

        neutral_ground_truths = []
        for gt in ground_truths:
            neutral_path = original_to_neutral.get(gt.file_path)
            if neutral_path is None:
                # Try normalized comparison as fallback
                neutral_path = normalized_to_neutral.get(normalize_path(gt.file_path))
            if neutral_path is None:
                logger.warning(
                    "Ground truth file_path %r could not be remapped to a neutral "
                    "path — no matching TestCase.original_path found. This GT will "
                    "likely cause false negatives.",
                    gt.file_path,
                )
                neutral_path = gt.file_path
            neutral_gt = gt.model_copy(update={"file_path": neutral_path})
            neutral_ground_truths.append(neutral_gt)

        # Write all files
        (output_dir / "AGENTS.md").write_text(AGENTS_MD_TEMPLATE, encoding="utf-8")
        (output_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        (output_dir / "output_schema.json").write_text(
            json.dumps(OUTPUT_SCHEMA, indent=2), encoding="utf-8"
        )
        (output_subdir / ".gitkeep").write_text("", encoding="utf-8")

        # GitHub Copilot instructions (agent-facing, not secret)
        (github_dir / "copilot-instructions.md").write_text(
            COPILOT_INSTRUCTIONS, encoding="utf-8"
        )

        # Evaluator-only data (OUTSIDE workspace — agents cannot access)
        (evaluator_dir / "ground_truth.json").write_text(
            json.dumps(
                [gt.model_dump(mode="json") for gt in neutral_ground_truths],
                indent=2,
            ),
            encoding="utf-8",
        )
        (evaluator_dir / "file_mapping.json").write_text(
            json.dumps(file_mapping, indent=2), encoding="utf-8"
        )

        # Save the prompt template text so show-run-prompt can reconstruct it
        prompt_text = get_prompt_template(prompt_template)
        (evaluator_dir / "prompt.txt").write_text(prompt_text, encoding="utf-8")

        (evaluator_dir / "config.json").write_text(
            json.dumps(
                {
                    "benchmark": benchmark_name,
                    "total_test_cases": len(test_cases),
                    "total_ground_truths": len(ground_truths),
                    "workspace_path": str(output_dir),
                    "prompt_template": prompt_template,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        logger.info(
            "Workspace created at %s (evaluator data at %s): %d files, %d ground truths",
            output_dir,
            evaluator_dir,
            len(test_cases),
            len(ground_truths),
        )

        # Post-prep assertion: .sastbench/ must NOT exist in workspace
        # (it would leak ground truth to agents)
        SASTBench_dir = output_dir / ".sastbench"
        if SASTBench_dir.exists():
            shutil.rmtree(SASTBench_dir)
            logger.warning(
                "Removed stale .sastbench/ from workspace %s — "
                "ground truth must only exist in evaluator_data/",
                output_dir,
            )
        assert not SASTBench_dir.exists(), (
            f"SECURITY: .sastbench/ directory exists in workspace {output_dir}. "
            "This leaks ground truth to agents. Remove it or re-prepare the workspace."
        )

        return output_dir


def _find_evaluator_dir(workspace_path: Path) -> Path:
    """Find the evaluator data directory for a workspace.

    Checks (in order):
    1. Sibling: workspace_path.parent / "evaluator_data" / workspace_path.name
    2. Legacy: workspace_path / ".sastbench" (backward compatibility)
    """
    # New location: evaluator_data sibling directory
    evaluator_dir = workspace_path.parent / "evaluator_data" / workspace_path.name
    if evaluator_dir.exists():
        return evaluator_dir
    # Legacy fallback: .SASTBench inside workspace
    legacy_dir = workspace_path / ".sastbench"
    if legacy_dir.exists():
        return legacy_dir
    raise FileNotFoundError(
        f"No evaluator data found for workspace {workspace_path}. "
        f"Checked: {evaluator_dir} and {legacy_dir}. "
        "Run 'SASTBench prepare' first."
    )


def load_workspace_ground_truth(workspace_path: Path) -> list[GroundTruth]:
    """Load ground truths from the evaluator data directory (outside workspace)."""
    evaluator_dir = _find_evaluator_dir(workspace_path)
    gt_path = evaluator_dir / "ground_truth.json"
    if not gt_path.exists():
        raise FileNotFoundError(f"No ground truth found at {gt_path}")
    data = json.loads(gt_path.read_text(encoding="utf-8"))
    return [GroundTruth.model_validate(item) for item in data]


def load_workspace_config(workspace_path: Path) -> dict:
    """Load workspace configuration from the evaluator data directory."""
    evaluator_dir = _find_evaluator_dir(workspace_path)
    config_path = evaluator_dir / "config.json"
    if not config_path.exists():
        raise FileNotFoundError(f"No config found at {config_path}")
    return json.loads(config_path.read_text(encoding="utf-8"))


def build_run_prompt(
    workspace_path: Path,
    agent_name: str = "Agent",
    output_dir: str | None = None,
    prompt_template: str | None = None,
) -> str:
    """Build the complete prompt to send to an agent for a workspace.

    Combines the analysis prompt template, workspace instructions, and
    output path into a single copy-pasteable string.

    Args:
        workspace_path: Path to the prepared workspace.
        agent_name: Name for the agent (used in output JSON and dir name).
        output_dir: Output subdirectory name (e.g. "output_sonnet46").
            Defaults to "output_<agent_name_slug>".
        prompt_template: Override the prompt template saved during prepare.
            If None, reads the template stored in evaluator_data/prompt.txt.

    Returns:
        The complete prompt text ready to paste into an agent session.
    """
    workspace_path = Path(workspace_path).resolve()
    evaluator_dir = _find_evaluator_dir(workspace_path)

    # Resolve analysis prompt text
    if prompt_template is not None:
        analysis_prompt = get_prompt_template(prompt_template)
    else:
        saved_prompt = evaluator_dir / "prompt.txt"
        if saved_prompt.exists():
            analysis_prompt = saved_prompt.read_text(encoding="utf-8")
        else:
            analysis_prompt = get_prompt_template("selective")

    # Build output path
    if output_dir is None:
        slug = agent_name.lower().replace(" ", "_").replace(".", "")
        output_dir = f"output_{slug}"
    findings_path = f"{workspace_path}/{output_dir}/findings.json"

    # Assemble workspace instructions
    instructions = DEFAULT_WORKSPACE_INSTRUCTIONS.format(
        workspace_path=workspace_path,
        output_path=findings_path,
        agent_name=agent_name,
    )

    return (
        f"{analysis_prompt.rstrip()}\n\n"
        f"{instructions.rstrip()}\n"
    )
