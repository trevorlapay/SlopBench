"""Tests for the local Copilot CLI platform adapter."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from sastbench.models import AgentConfig, AgentTask, TaskStatus
from sastbench.platforms.local_copilot import LocalCopilotPlatform, DEFAULT_WORKSPACE_INSTRUCTIONS
from sastbench.workspace import WorkspacePreparer
from sastbench.models import GroundTruth, TestCase


@pytest.fixture
def workspace(tmp_path) -> Path:
    """Create a minimal SASTBench workspace."""
    preparer = WorkspacePreparer()
    test_cases = [
        TestCase(original_id="tc1", original_path="a.c", code="int x;", language="c"),
    ]
    ground_truths = [
        GroundTruth(file_path="a.c", cwe_id="CWE-79", benchmark_name="test"),
    ]
    return preparer.build(test_cases, ground_truths, tmp_path / "workspace", "test")


class TestLocalCopilotPlatformInit:
    def test_defaults(self):
        p = LocalCopilotPlatform()
        assert p.name == "local_copilot"
        assert p.timeout_seconds == 3600
        assert p.poll_interval == 5
        assert p.command is None

    def test_custom_command(self):
        p = LocalCopilotPlatform(command="my-agent --dir {workspace} --task {prompt}")
        assert "my-agent" in p.command

    def test_custom_prompt(self):
        p = LocalCopilotPlatform(task_prompt="Do the thing in {workspace}")
        assert "Do the thing" in p.task_prompt


class TestBuildCommand:
    def test_custom_command_template(self, workspace):
        p = LocalCopilotPlatform(command="my-tool --cwd {workspace} {prompt}")
        cmd = p._build_command(workspace, "scan the code")
        assert cmd[0] == "my-tool"
        assert "--cwd" in cmd
        assert str(workspace) in " ".join(cmd)

    def test_no_cli_found_raises(self, workspace):
        p = LocalCopilotPlatform()
        with patch("shutil.which", return_value=None):
            with pytest.raises(RuntimeError, match="No Copilot CLI found"):
                p._build_command(workspace, "scan")

    def test_gh_detected(self, workspace):
        p = LocalCopilotPlatform()
        with patch("shutil.which", side_effect=lambda x: "/usr/bin/gh" if x == "gh" else None):
            cmd = p._build_command(workspace, "scan")
            assert cmd[0] == "gh"
            assert "copilot" in cmd

    def test_copilot_cli_detected(self, workspace):
        p = LocalCopilotPlatform()
        def mock_which(x):
            if x == "gh":
                return None
            if x == "copilot-cli":
                return "/usr/bin/copilot-cli"
            return None
        with patch("shutil.which", side_effect=mock_which):
            cmd = p._build_command(workspace, "scan")
            assert cmd[0] == "/usr/bin/copilot-cli"


class TestSubmitTask:
    @pytest.mark.asyncio
    async def test_missing_agents_md(self, tmp_path):
        p = LocalCopilotPlatform(command="echo test")
        task = AgentTask(workspace_path=str(tmp_path), task_instructions="test")
        with pytest.raises(FileNotFoundError, match="AGENTS.md"):
            await p.submit_task(str(tmp_path), task)

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.platform == "win32", reason="Subprocess creation differs on Windows")
    async def test_submit_starts_process(self, workspace):
        p = LocalCopilotPlatform(command=f"{sys.executable} -c pass")
        task = AgentTask(workspace_path=str(workspace), task_instructions="test")
        task_id = await p.submit_task(str(workspace), task)
        assert task_id.isdigit()  # PID
        # Clean up
        if p._process:
            try:
                p._process.terminate()
                await p._process.wait()
            except ProcessLookupError:
                pass


class TestCheckStatus:
    @pytest.mark.asyncio
    async def test_no_process(self):
        p = LocalCopilotPlatform()
        status = await p.check_status("0")
        assert status == TaskStatus.FAILED

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.platform == "win32", reason="Subprocess creation differs on Windows")
    async def test_completed_process(self, workspace):
        # Start a quick process that exits immediately
        p = LocalCopilotPlatform(command=f"{sys.executable} -c pass")
        task = AgentTask(workspace_path=str(workspace), task_instructions="test")
        await p.submit_task(str(workspace), task)
        await p._process.wait()
        status = await p.check_status("0")
        assert status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    @pytest.mark.skipif(sys.platform == "win32", reason="Subprocess creation differs on Windows")
    async def test_timeout(self, workspace):
        # Start a process, then set a very short timeout
        p = LocalCopilotPlatform(
            command=f"{sys.executable} -c \"import time; time.sleep(60)\"",
            timeout_seconds=0,
        )
        task = AgentTask(workspace_path=str(workspace), task_instructions="test")
        await p.submit_task(str(workspace), task)
        status = await p.check_status("0")
        assert status == TaskStatus.TIMED_OUT
        # Clean up
        try:
            await p._process.wait()
        except Exception:
            pass


class TestCollectResults:
    @pytest.mark.asyncio
    async def test_finds_json(self, workspace):
        # Write a findings file
        output_dir = workspace / "output"
        findings = {"findings": [{"file_path": "code/sample_0001.c", "start_line": 1, "cwe_id": "CWE-79"}]}
        (output_dir / "findings.json").write_text(json.dumps(findings))

        p = LocalCopilotPlatform()
        result = await p.collect_results("0", str(workspace))
        assert result is not None
        assert result.name == "findings.json"

    @pytest.mark.asyncio
    async def test_finds_sarif(self, workspace):
        output_dir = workspace / "output"
        (output_dir / "findings.sarif").write_text('{"version": "2.1.0"}')

        p = LocalCopilotPlatform()
        result = await p.collect_results("0", str(workspace))
        assert result is not None
        assert result.name == "findings.sarif"

    @pytest.mark.asyncio
    async def test_no_output(self, workspace):
        p = LocalCopilotPlatform()
        result = await p.collect_results("0", str(workspace))
        assert result is None


class TestAgentConfig:
    def test_local_copilot_config(self):
        ac = AgentConfig(
            name="Local Copilot",
            platform="local_copilot",
            copilot_command="gh copilot agent --cwd {workspace} {prompt}",
            timeout_minutes=30,
        )
        assert ac.platform == "local_copilot"
        assert "gh copilot" in ac.copilot_command

    def test_local_copilot_yaml_roundtrip(self):
        """Verify config can be serialized/deserialized (for YAML config files)."""
        ac = AgentConfig(
            name="Local Copilot",
            platform="local_copilot",
            copilot_task_prompt="Scan {workspace} following AGENTS.md",
        )
        data = ac.model_dump()
        ac2 = AgentConfig.model_validate(data)
        assert ac2.copilot_task_prompt == ac.copilot_task_prompt


class TestPlatformRegistry:
    def test_local_copilot_in_registry(self):
        from sastbench.platforms import PLATFORMS
        assert "local_copilot" in PLATFORMS
        assert PLATFORMS["local_copilot"] is LocalCopilotPlatform
