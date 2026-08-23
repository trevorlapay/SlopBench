"""Agent platform adapters for orchestrated evaluation."""

from sastbench.platforms.base import AgentPlatform
from sastbench.platforms.copilot import CopilotPlatform
from sastbench.platforms.docker_agent import DockerAgentPlatform
from sastbench.platforms.local_copilot import LocalCopilotPlatform
from sastbench.platforms.manual import ManualPlatform

PLATFORMS: dict[str, type[AgentPlatform]] = {
    "manual": ManualPlatform,
    "docker": DockerAgentPlatform,
    "copilot": CopilotPlatform,
    "local_copilot": LocalCopilotPlatform,
}

__all__ = [
    "AgentPlatform",
    "CopilotPlatform",
    "DockerAgentPlatform",
    "LocalCopilotPlatform",
    "ManualPlatform",
    "PLATFORMS",
]
