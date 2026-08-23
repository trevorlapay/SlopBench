"""Abstract base class for agent platform adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sastbench.models import AgentTask, TaskStatus


class AgentPlatform(ABC):
    """Interface for submitting tasks to autonomous agent platforms."""

    name: str = ""

    @abstractmethod
    async def submit_task(self, workspace_path: str, task: AgentTask) -> str:
        """Submit a vulnerability scanning task. Returns task/run ID."""

    @abstractmethod
    async def check_status(self, task_id: str) -> TaskStatus:
        """Check if the agent has completed the task."""

    @abstractmethod
    async def collect_results(self, task_id: str, workspace_path: str) -> Path | None:
        """Collect the agent's output file(s). Returns path to findings file or None."""
