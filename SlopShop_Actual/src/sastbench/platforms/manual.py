"""Manual/generic platform — just prepares workspace, user handles agent execution."""

from __future__ import annotations

from pathlib import Path

from sastbench.models import AgentTask, TaskStatus
from sastbench.platforms.base import AgentPlatform


class ManualPlatform(AgentPlatform):
    """No-op platform: workspace is prepared, user runs agent manually."""

    name = "manual"

    async def submit_task(self, workspace_path: str, task: AgentTask) -> str:
        return "manual"

    async def check_status(self, task_id: str) -> TaskStatus:
        # Check if output directory has findings
        wp = Path(task_id) if task_id != "manual" else None
        return TaskStatus.COMPLETED

    async def collect_results(self, task_id: str, workspace_path: str) -> Path | None:
        output_dir = Path(workspace_path) / "output"
        for ext in ["findings.json", "findings.sarif", "findings.csv"]:
            p = output_dir / ext
            if p.exists():
                return p
        return None
