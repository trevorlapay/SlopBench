"""GitHub Copilot Coding Agent platform adapter."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from sastbench.models import AgentTask, TaskStatus
from sastbench.platforms.base import AgentPlatform

logger = logging.getLogger(__name__)


class CopilotPlatform(AgentPlatform):
    """Submit tasks to GitHub Copilot Coding Agent via GitHub Issues."""

    name = "copilot"

    def __init__(self, github_repo: str, token_env: str = "GITHUB_TOKEN"):
        self.github_repo = github_repo
        self.token_env = token_env

    async def submit_task(self, workspace_path: str, task: AgentTask) -> str:
        try:
            from github import Github
        except ImportError:
            raise ImportError("PyGithub required: pip install SASTBench[github]")

        token = os.environ.get(self.token_env)
        if not token:
            raise ValueError(f"GitHub token not found in env var '{self.token_env}'")

        g = Github(token)
        repo = g.get_repo(self.github_repo)

        # Create issue with task instructions
        issue = repo.create_issue(
            title="[SASTBench] Vulnerability Analysis Task",
            body=task.task_instructions,
            labels=["sastbench", "security-scan"],
        )

        logger.info("Created issue #%d on %s", issue.number, self.github_repo)
        return str(issue.number)

    async def check_status(self, task_id: str) -> TaskStatus:
        try:
            from github import Github
        except ImportError:
            return TaskStatus.FAILED

        token = os.environ.get(self.token_env)
        if not token:
            return TaskStatus.FAILED

        g = Github(token)
        repo = g.get_repo(self.github_repo)
        issue = repo.get_issue(int(task_id))

        if issue.state == "closed":
            return TaskStatus.COMPLETED
        return TaskStatus.RUNNING

    async def collect_results(self, task_id: str, workspace_path: str) -> Path | None:
        output_dir = Path(workspace_path) / "output"
        for name in ["findings.json", "findings.sarif", "findings.csv"]:
            p = output_dir / name
            if p.exists():
                return p
        return None
