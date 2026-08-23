"""Docker container agent platform adapter."""

from __future__ import annotations

import logging
from pathlib import Path

from sastbench.models import AgentTask, TaskStatus
from sastbench.platforms.base import AgentPlatform

logger = logging.getLogger(__name__)


class DockerAgentPlatform(AgentPlatform):
    """Run agent inside a Docker container with workspace mounted as a volume."""

    name = "docker"

    def __init__(
        self,
        image: str,
        mount_path: str = "/workspace",
        command: str | None = None,
    ):
        self.image = image
        self.mount_path = mount_path
        self.command = command

    async def submit_task(self, workspace_path: str, task: AgentTask) -> str:
        if not self.mount_path.replace("/", "").replace("_", "").replace("-", "").isalnum():
            raise ValueError(f"Invalid mount path: {self.mount_path}")

        try:
            import docker
        except ImportError:
            raise ImportError("Docker SDK required: pip install SASTBench[docker]")

        client = docker.from_env()
        volumes = {str(Path(workspace_path).resolve()): {"bind": self.mount_path, "mode": "rw"}}

        cmd = self.command.split() if self.command else ["cat", f"{self.mount_path}/AGENTS.md"]
        logger.info("Starting Docker container %s with workspace at %s", self.image, self.mount_path)

        container = client.containers.run(
            self.image,
            command=cmd,
            volumes=volumes,
            detach=True,
        )
        return container.id

    async def check_status(self, task_id: str) -> TaskStatus:
        try:
            import docker
        except ImportError:
            return TaskStatus.FAILED

        client = docker.from_env()
        try:
            container = client.containers.get(task_id)
            status = container.status
            if status == "exited":
                exit_code = container.attrs["State"]["ExitCode"]
                return TaskStatus.COMPLETED if exit_code == 0 else TaskStatus.FAILED
            elif status == "running":
                return TaskStatus.RUNNING
            return TaskStatus.PENDING
        except Exception:
            return TaskStatus.FAILED

    async def collect_results(self, task_id: str, workspace_path: str) -> Path | None:
        output_dir = Path(workspace_path) / "output"
        for name in ["findings.json", "findings.sarif", "findings.csv"]:
            p = output_dir / name
            if p.exists():
                return p
        return None
