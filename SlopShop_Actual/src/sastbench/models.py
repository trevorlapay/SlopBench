"""Core data models for sastbench.

Data flow:
  Agent output → Parser → List[Finding]
  Benchmark    → Adapter → List[TestCase], List[GroundTruth]
  Finding + GroundTruth → MatchingEngine → MatchResult
  MatchResult → MetricsCalculator → MetricsReport
  Multiple MetricsReports → Comparison → ComparisonReport
  Multiple Findings (no GT) → Diff → DiffReport
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MatchGranularity(str, Enum):
    FILE = "file"
    FUNCTION = "function"
    LINE = "line"


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


# ---------------------------------------------------------------------------
# Agent output (normalized)
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single vulnerability finding reported by an agent."""
    file_path: str = Field(..., min_length=1, description="Relative path from workspace root")
    start_line: int | None = Field(None, ge=1, description="1-indexed start line")
    end_line: int | None = Field(None, ge=1)
    function_name: str | None = None
    cwe_id: str | None = Field(None, pattern=r"^CWE-\d+$")
    severity: Severity | None = None
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    message: str | None = None
    rule_id: str | None = None
    tool_name: str | None = None

    @model_validator(mode='after')
    def _check_line_range(self):
        if self.start_line is not None and self.end_line is not None:
            if self.end_line < self.start_line:
                raise ValueError("end_line must be >= start_line")
        return self


# ---------------------------------------------------------------------------
# Ground truth (from benchmarks)
# ---------------------------------------------------------------------------

class GroundTruth(BaseModel):
    """A known vulnerability (or known-safe) label from a benchmark."""
    file_path: str = Field(..., min_length=1)
    start_line: int | None = Field(None, ge=1)
    end_line: int | None = Field(None, ge=1)
    function_name: str | None = None
    cwe_id: str | None = Field(None, pattern=r"^CWE-\d+$")
    is_vulnerable: bool = True
    benchmark_name: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode='after')
    def _check_line_range(self):
        if self.start_line is not None and self.end_line is not None:
            if self.end_line < self.start_line:
                raise ValueError("end_line must be >= start_line")
        return self


# ---------------------------------------------------------------------------
# Test case (intermediate between adapter and workspace)
# ---------------------------------------------------------------------------

class TestCase(BaseModel):
    """One code sample extracted by a benchmark adapter."""
    __test__ = False  # prevent pytest collection
    original_id: str
    original_path: str
    code: str
    language: str
    metadata: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

class MatchingConfig(BaseModel):
    granularity: MatchGranularity = MatchGranularity.FILE
    line_tolerance: int = Field(3, ge=0, description="±N lines for line-level matching")
    require_cwe_match: bool = True
    allow_parent_cwe: bool = Field(
        False,
        description="When True, a reported CWE that is a parent/child of the expected CWE is accepted as a match.",
    )
    require_line_number: bool = Field(
        False,
        description="When True, findings without a start_line are never matched (counted as FP). "
        "Also requires that the reported line falls within line_tolerance of the GT location "
        "when the GT has line info.",
    )


class MatchedPair(BaseModel):
    finding: Finding
    ground_truth: GroundTruth


class MatchResult(BaseModel):
    """Result of matching agent findings against ground truth."""
    true_positives: list[MatchedPair] = Field(default_factory=list)
    false_positives: list[Finding] = Field(default_factory=list)
    false_negatives: list[GroundTruth] = Field(default_factory=list)
    true_negatives: int = 0
    config: MatchingConfig = Field(default_factory=MatchingConfig)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class StandardMetrics(BaseModel):
    precision: float = Field(0.0, ge=0.0, le=1.0)
    recall: float = Field(0.0, ge=0.0, le=1.0)
    f1: float = Field(0.0, ge=0.0, le=1.0)
    accuracy: float = Field(0.0, ge=0.0, le=1.0)
    false_positive_rate: float = Field(0.0, ge=0.0, le=1.0)
    false_negative_rate: float = Field(0.0, ge=0.0, le=1.0)
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0


class MetricsReport(BaseModel):
    """Full evaluation result for one agent on one benchmark."""
    agent_name: str
    benchmark_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    matching_granularity: MatchGranularity
    overall: StandardMetrics
    per_cwe: dict[str, StandardMetrics] = Field(default_factory=dict)
    severity_weighted: StandardMetrics | None = None
    total_findings: int = 0
    total_ground_truths: int = 0
    match_result: MatchResult | None = None


# ---------------------------------------------------------------------------
# Comparison (with ground truth)
# ---------------------------------------------------------------------------

class AgentRanking(BaseModel):
    agent_name: str
    value: float
    rank: int


class ComparisonReport(BaseModel):
    """Side-by-side comparison of multiple agents (requires ground truth)."""
    agents: list[str]
    benchmark_name: str
    rankings: dict[str, list[AgentRanking]] = Field(default_factory=dict)
    overlap_matrix: dict[str, Any] = Field(default_factory=dict)
    unique_finds: dict[str, list[Finding]] = Field(default_factory=dict)
    statistical_tests: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Diff (agent-vs-agent, no ground truth)
# ---------------------------------------------------------------------------

class AgentDiffStats(BaseModel):
    total_findings: int = 0
    cwe_distribution: dict[str, int] = Field(default_factory=dict)
    severity_distribution: dict[str, int] = Field(default_factory=dict)
    files_flagged: int = 0


class MatchedFinding(BaseModel):
    """A finding reported by multiple agents at the same location."""
    file_path: str
    start_line: int | None = None
    cwe_id: str | None = None
    agents: list[str] = Field(default_factory=list)


class ConsensusFinding(BaseModel):
    """A finding reported by at least N agents."""
    finding: MatchedFinding
    agent_count: int
    total_agents: int

    @model_validator(mode='after')
    def _check_agent_counts(self):
        if self.total_agents <= 0:
            raise ValueError("total_agents must be > 0")
        if self.agent_count <= 0 or self.agent_count > self.total_agents:
            raise ValueError("agent_count must satisfy 0 < agent_count <= total_agents")
        return self


class DiffReport(BaseModel):
    """Agent-vs-agent comparison without ground truth."""
    agents: list[str]
    match_tolerance: int = 3
    agreement_rate: float = 0.0
    jaccard_index: float = 0.0
    cohens_kappa: float = 0.0
    per_agent: dict[str, AgentDiffStats] = Field(default_factory=dict)
    agreed_findings: list[MatchedFinding] = Field(default_factory=list)
    unique_findings: dict[str, list[Finding]] = Field(default_factory=dict)
    cwe_distribution: dict[str, dict[str, int]] = Field(default_factory=dict)
    severity_distribution: dict[str, dict[str, int]] = Field(default_factory=dict)
    consensus_findings: list[ConsensusFinding] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent platform configuration
# ---------------------------------------------------------------------------

class AgentConfig(BaseModel):
    """Configuration for an agent platform."""
    name: str
    platform: str = Field(..., pattern=r"^(copilot|local_copilot|docker|api|local_llm|manual)$")
    # GitHub Copilot Coding Agent
    github_repo: str | None = None
    github_token_env: str | None = None
    # Docker container agent
    docker_image: str | None = None
    docker_mount_path: str = "/workspace"
    docker_command: str | None = None
    # API-based agent
    api_url: str | None = None
    api_key_env: str | None = None
    # Local LLM loop
    model: str | None = None
    provider: str | None = None
    llm_api_key_env: str | None = None
    # Local Copilot CLI
    copilot_command: str | None = None
    copilot_task_prompt: str | None = None
    prompt_template: str = "default"  # "default", "thorough", "minimal", or path to .txt
    # Common
    timeout_minutes: int = Field(60, ge=1)
    max_concurrent: int = Field(5, ge=1)


class AgentTask(BaseModel):
    """A task to submit to an autonomous agent platform."""
    workspace_path: str
    task_instructions: str
    output_schema: dict[str, Any] = Field(default_factory=dict)
    timeout_minutes: int = 60
    benchmark_name: str = ""
    test_case_count: int = 0
