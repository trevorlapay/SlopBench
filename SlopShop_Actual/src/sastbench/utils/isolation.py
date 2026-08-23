"""Workspace isolation utilities.

Provides functions to copy a workspace to a neutral temporary directory
before running agents, preventing path-based information leakage
(e.g., benchmark names in directory paths) and parent directory traversal
to reach evaluator_data/.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


def create_isolated_workspace(
    workspace_path: Path,
    *,
    base_dir: Path | None = None,
) -> Path:
    """Copy a workspace to a neutral temporary directory for isolated agent execution.

    The isolated workspace:
    - Has a UUID-based name (no benchmark hints)
    - Contains only the agent-facing files (code/, AGENTS.md, manifest.json, etc.)
    - Does NOT contain .sastbench/ or evaluator_data/
    - Is in a location where ``../`` traversal cannot reach ground truth

    Args:
        workspace_path: Path to the original prepared workspace.
        base_dir: Parent directory for the isolated copy. Defaults to
            the system temp directory.

    Returns:
        Path to the isolated workspace copy. Caller is responsible
        for cleanup (use :func:`cleanup_isolated_workspace`).
    """
    workspace_path = Path(workspace_path).resolve()
    if not workspace_path.is_dir():
        raise FileNotFoundError(f"Workspace not found: {workspace_path}")

    if base_dir is None:
        base_dir = Path(tempfile.gettempdir())
    base_dir.mkdir(parents=True, exist_ok=True)

    isolated_name = f"workspace_{uuid.uuid4().hex[:12]}"
    isolated_path = base_dir / isolated_name
    isolated_path.mkdir()

    # Copy only agent-facing contents (skip .sastbench/ and any output)
    agent_facing = ["AGENTS.md", "manifest.json", "output_schema.json", ".github"]
    for item in agent_facing:
        src = workspace_path / item
        dst = isolated_path / item
        if src.is_dir():
            shutil.copytree(src, dst)
        elif src.is_file():
            shutil.copy2(src, dst)

    # Copy code directory
    code_src = workspace_path / "code"
    if code_src.is_dir():
        shutil.copytree(code_src, isolated_path / "code")

    # Create empty output directory
    (isolated_path / "output").mkdir(exist_ok=True)

    # Verify no GT leaked into isolated workspace
    assert not (isolated_path / ".sastbench").exists(), \
        "SECURITY: .sastbench/ leaked into isolated workspace"
    for f in isolated_path.rglob("ground_truth*"):
        raise AssertionError(f"SECURITY: Ground truth file in isolated workspace: {f}")

    logger.info(
        "Created isolated workspace: %s -> %s",
        workspace_path.name,
        isolated_path,
    )
    return isolated_path


def cleanup_isolated_workspace(isolated_path: Path) -> None:
    """Remove an isolated workspace created by :func:`create_isolated_workspace`."""
    if isolated_path.exists():
        shutil.rmtree(isolated_path)
        logger.info("Cleaned up isolated workspace: %s", isolated_path)


def copy_results_back(
    isolated_path: Path,
    original_workspace: Path,
    *,
    output_subdir: str = "output",
) -> None:
    """Copy agent output from isolated workspace back to the original.

    Args:
        isolated_path: Path to the isolated workspace.
        original_workspace: Path to the original workspace.
        output_subdir: Name of the output subdirectory (default "output").
    """
    src = isolated_path / output_subdir
    dst = original_workspace / output_subdir

    if not src.exists():
        logger.warning("No output directory in isolated workspace: %s", src)
        return

    dst.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        dest_item = dst / item.name
        if item.is_dir():
            if dest_item.exists():
                shutil.rmtree(dest_item)
            shutil.copytree(item, dest_item)
        else:
            shutil.copy2(item, dest_item)

    logger.info("Copied results from %s to %s", src, dst)
