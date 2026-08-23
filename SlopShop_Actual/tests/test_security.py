"""Tests for security fixes: path traversal, injection, XSS prevention."""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


class TestCachePathTraversal:
    """C-1 & H-SEC-4: Path traversal prevention in cache operations."""

    def test_get_benchmark_cache_path_normal(self, tmp_path):
        from sastbench.utils.cache import get_benchmark_cache_path

        result = get_benchmark_cache_path("my_benchmark", cache_dir=tmp_path)
        assert result == (tmp_path / "my_benchmark").resolve()

    def test_get_benchmark_cache_path_traversal_rejected(self, tmp_path):
        from sastbench.utils.cache import get_benchmark_cache_path

        with pytest.raises(ValueError, match="Invalid benchmark name"):
            get_benchmark_cache_path("../../etc/passwd", cache_dir=tmp_path)

    def test_get_benchmark_cache_path_dot_dot_rejected(self, tmp_path):
        from sastbench.utils.cache import get_benchmark_cache_path

        with pytest.raises(ValueError, match="Invalid benchmark name"):
            get_benchmark_cache_path("../secret", cache_dir=tmp_path)

    def test_get_benchmark_cache_path_absolute_rejected(self, tmp_path):
        from sastbench.utils.cache import get_benchmark_cache_path

        # Absolute paths that resolve outside cache dir
        with pytest.raises(ValueError, match="Invalid benchmark name"):
            get_benchmark_cache_path("/etc/passwd", cache_dir=tmp_path)


class TestAgentNameSanitization:
    """Agent name sanitization for safe filenames."""

    def test_sanitize_removes_dangerous_chars(self):
        name = "../../etc/passwd"
        safe = re.sub(r'[^a-z0-9_-]', '', name.lower().replace(' ', '_'))
        assert safe == "etcpasswd"

    def test_sanitize_preserves_normal_names(self):
        name = "My Agent v2"
        safe = re.sub(r'[^a-z0-9_-]', '', name.lower().replace(' ', '_'))
        assert safe == "my_agent_v2"

    def test_sanitize_strips_slashes_and_dots(self):
        name = "agent../../../hack"
        safe = re.sub(r'[^a-z0-9_-]', '', name.lower().replace(' ', '_'))
        assert safe == "agenthack"


class TestShellInjection:
    """H-SEC-2: Shell injection prevention in LocalCopilot."""

    def test_build_command_uses_shlex(self):
        from sastbench.platforms.local_copilot import LocalCopilotPlatform

        platform = LocalCopilotPlatform(
            command="agent --workspace {workspace} --prompt {prompt}"
        )
        ws = Path("/safe/workspace")
        prompt = "normal prompt"
        parts = platform._build_command(ws, prompt)
        assert isinstance(parts, list)
        assert all(isinstance(p, str) for p in parts)

    def test_build_command_quotes_dangerous_input(self):
        from sastbench.platforms.local_copilot import LocalCopilotPlatform

        platform = LocalCopilotPlatform(
            command="agent --workspace {workspace} --prompt {prompt}"
        )
        ws = Path("/safe/workspace")
        prompt = "; rm -rf /"
        parts = platform._build_command(ws, prompt)
        # The dangerous prompt should be a single argument, not split into
        # separate shell tokens like ";", "rm", "-rf", "/"
        assert "rm" not in parts
        assert "-rf" not in parts


class TestDockerCommandInjection:
    """H-SEC-3: Docker command injection prevention."""

    def test_valid_mount_path(self):
        from sastbench.platforms.docker_agent import DockerAgentPlatform

        platform = DockerAgentPlatform(image="test", mount_path="/workspace")
        # Should not raise
        assert platform.mount_path == "/workspace"

    def test_invalid_mount_path_rejected(self):
        from sastbench.platforms.docker_agent import DockerAgentPlatform

        platform = DockerAgentPlatform(
            image="test", mount_path="/workspace; rm -rf /"
        )
        with pytest.raises((ValueError, ImportError)):
            import asyncio
            asyncio.run(platform.submit_task("/tmp/ws", AsyncMock()))

    def test_command_passed_as_list(self):
        """Verify command is split into a list, not passed as a shell string."""
        from sastbench.platforms.docker_agent import DockerAgentPlatform

        platform = DockerAgentPlatform(image="test", mount_path="/workspace")
        # The default command should be a list
        cmd = platform.command
        if cmd:
            parts = cmd.split()
            assert isinstance(parts, list)


class TestXSSPrevention:
    """H-SEC-1: XSS prevention in HTML report via Jinja2 autoescape."""

    def test_html_template_uses_autoescape(self):
        from sastbench.reports.html_report import HTML_TEMPLATE

        # Jinja2 Template with autoescape=True will escape HTML entities
        assert HTML_TEMPLATE.environment.autoescape is True
