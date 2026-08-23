"""Local Copilot CLI platform adapter.

Runs the GitHub Copilot CLI agent locally against a prepared workspace.
The adapter spawns a `copilot-cli` (or `gh copilot`) subprocess, points it
at the workspace, and instructs it to follow AGENTS.md. It then polls the
output directory for results.

Supports multiple invocation modes:
  - ghcs (GitHub Copilot CLI standalone)
  - gh copilot (via GitHub CLI extension)
  - Custom command (any local agent CLI that accepts a task prompt)
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
from pathlib import Path

from sastbench.models import AgentTask, TaskStatus
from sastbench.platforms.base import AgentPlatform

logger = logging.getLogger(__name__)

# Workspace instructions appended to any analysis prompt template.
# Tells the agent where to find code and how to write output.
# NOTE: Do NOT include the absolute workspace path — it may leak
# benchmark names (e.g., "bigvul", "primevul") to the agent.
DEFAULT_WORKSPACE_INSTRUCTIONS = (
    "\n\nYou are working in the current directory. "
    "Read the file AGENTS.md for instructions on input/output format. "
    "Follow those instructions exactly: analyse the code in the code/ "
    "directory and write your findings to the output/ directory in the "
    "format described in AGENTS.md."
)


class LocalCopilotPlatform(AgentPlatform):
    """Run the Copilot CLI agent locally against a workspace.

    Invocation modes (tried in order unless ``command`` is set):
      1. ``gh copilot agent`` — GitHub CLI Copilot extension
      2. ``copilot-cli`` — standalone Copilot CLI binary
      3. Falls back to the explicit ``command`` if neither is found

    The task prompt combines two parts:
    1. An analysis prompt template (how to think about vulnerabilities)
    2. Workspace instructions (where to read code, where to write findings)
    """

    name = "local_copilot"

    def __init__(
        self,
        command: str | None = None,
        task_prompt: str | None = None,
        prompt_template: str = "default",
        timeout_seconds: int = 3600,
        poll_interval: int = 5,
        env: dict[str, str] | None = None,
    ):
        """
        Args:
            command: Explicit CLI command template. Use ``{workspace}`` and
                     ``{prompt}`` placeholders.
            task_prompt: Full override for the task prompt. If set, skips
                         template loading entirely.
            prompt_template: Built-in template name ("default", "thorough",
                     "minimal") or path to a custom .txt file. Ignored if
                     task_prompt is provided.
            timeout_seconds: Maximum wall-clock time to wait for the agent.
            poll_interval: Seconds between output-directory polls.
            env: Extra environment variables passed to the subprocess.
        """
        self.command = command
        if task_prompt:
            self.task_prompt = task_prompt
        else:
            from sastbench.prompt_templates import get_prompt_template
            analysis_prompt = get_prompt_template(prompt_template)
            self.task_prompt = analysis_prompt + DEFAULT_WORKSPACE_INSTRUCTIONS
        self.prompt_template_name = prompt_template
        self.timeout_seconds = timeout_seconds
        self.poll_interval = poll_interval
        self.extra_env = env or {}
        # Runtime state
        self._process: asyncio.subprocess.Process | None = None
        self._start_time: float = 0

    # ------------------------------------------------------------------
    # AgentPlatform interface
    # ------------------------------------------------------------------

    async def submit_task(self, workspace_path: str, task: AgentTask) -> str:
        ws = Path(workspace_path).resolve()
        if not (ws / "AGENTS.md").exists():
            raise FileNotFoundError(
                f"AGENTS.md not found in {ws}. Is this a SASTBench workspace?"
            )

        prompt = self.task_prompt
        cmd_parts = self._build_command(ws, prompt)

        logger.info("Starting local Copilot agent: %s", " ".join(cmd_parts))

        import os
        env = {**os.environ, **self.extra_env}

        self._process = await asyncio.create_subprocess_exec(
            *cmd_parts,
            cwd=str(ws),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        self._start_time = time.monotonic()
        return str(self._process.pid)

    async def check_status(self, task_id: str) -> TaskStatus:
        if self._process is None:
            return TaskStatus.FAILED

        # Check if process is still alive
        if self._process.returncode is not None:
            if self._process.returncode == 0:
                return TaskStatus.COMPLETED
            logger.warning(
                "Local agent exited with code %d", self._process.returncode
            )
            return TaskStatus.FAILED

        # Check timeout
        elapsed = time.monotonic() - self._start_time
        if elapsed > self.timeout_seconds:
            logger.warning("Local agent timed out after %ds", self.timeout_seconds)
            self._process.terminate()
            return TaskStatus.TIMED_OUT

        return TaskStatus.RUNNING

    async def collect_results(self, task_id: str, workspace_path: str) -> Path | None:
        output_dir = Path(workspace_path) / "output"
        for name in ["findings.json", "findings.sarif", "findings.csv"]:
            p = output_dir / name
            if p.exists() and p.stat().st_size > 0:
                logger.info("Found agent output: %s", p)
                return p

        # If process finished, capture its stdout as a fallback log
        if self._process and self._process.returncode is not None:
            stdout, stderr = await self._process.communicate()
            if stdout:
                log_path = output_dir / "agent_stdout.log"
                log_path.write_bytes(stdout)
                logger.info("Agent stdout saved to %s", log_path)
            if stderr:
                log_path = output_dir / "agent_stderr.log"
                log_path.write_bytes(stderr)
                logger.info("Agent stderr saved to %s", log_path)

        return None

    # ------------------------------------------------------------------
    # Orchestration helper — run the full lifecycle
    # ------------------------------------------------------------------

    async def run_and_wait(
        self, workspace_path: str, task: AgentTask
    ) -> Path | None:
        """Submit, poll until done, and collect results.

        Convenience method for callers that want a single awaitable.
        """
        task_id = await self.submit_task(workspace_path, task)
        logger.info("Agent started (PID %s), polling for results...", task_id)

        while True:
            status = await self.check_status(task_id)
            if status in (
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.TIMED_OUT,
            ):
                break
            await asyncio.sleep(self.poll_interval)

        if status != TaskStatus.COMPLETED:
            logger.error("Agent finished with status: %s", status.value)

        return await self.collect_results(task_id, workspace_path)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_command(self, workspace: Path, prompt: str) -> list[str]:
        """Build the subprocess command list."""
        import shlex

        if self.command:
            # User-provided command template
            full = self.command.format(workspace=shlex.quote(str(workspace)), prompt=shlex.quote(prompt))
            return shlex.split(full)

        # Auto-detect available CLI tools
        if shutil.which("gh"):
            return [
                "gh", "copilot", "agent",
                "--cwd", str(workspace),
                prompt,
            ]

        copilot_bin = shutil.which("copilot-cli") or shutil.which("ghcs")
        if copilot_bin:
            return [copilot_bin, "--cwd", str(workspace), prompt]

        raise RuntimeError(
            "No Copilot CLI found. Install one of:\n"
            "  - GitHub CLI + Copilot extension: gh extension install github/gh-copilot\n"
            "  - Copilot CLI standalone: npm install -g @githubnext/github-copilot-cli\n"
            "Or pass a custom command= to LocalCopilotPlatform."
        )
