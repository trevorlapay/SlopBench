"""Shared pytest fixtures."""

import pytest

from sastbench.models import Finding, GroundTruth, Severity


@pytest.fixture
def sample_finding() -> Finding:
    return Finding(
        file_path="code/sample_001.c",
        start_line=15,
        end_line=15,
        cwe_id="CWE-79",
        severity=Severity.HIGH,
        confidence=0.9,
        message="XSS vulnerability",
        tool_name="test-agent",
    )


@pytest.fixture
def sample_ground_truth() -> GroundTruth:
    return GroundTruth(
        file_path="code/sample_001.c",
        start_line=15,
        end_line=15,
        cwe_id="CWE-79",
        is_vulnerable=True,
        benchmark_name="juliet",
    )


@pytest.fixture
def sample_findings() -> list[Finding]:
    return [
        Finding(file_path="code/sample_001.c", start_line=15, cwe_id="CWE-79", severity=Severity.HIGH),
        Finding(file_path="code/sample_002.c", start_line=30, cwe_id="CWE-89", severity=Severity.CRITICAL),
        Finding(file_path="code/sample_003.c", start_line=10, cwe_id="CWE-120", severity=Severity.MEDIUM),
    ]


@pytest.fixture
def sample_ground_truths() -> list[GroundTruth]:
    return [
        GroundTruth(file_path="code/sample_001.c", start_line=15, cwe_id="CWE-79", benchmark_name="juliet"),
        GroundTruth(file_path="code/sample_002.c", start_line=30, cwe_id="CWE-89", benchmark_name="juliet"),
        GroundTruth(file_path="code/sample_004.c", start_line=5, cwe_id="CWE-416", benchmark_name="juliet"),
    ]
