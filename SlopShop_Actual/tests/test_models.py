"""Tests for core data models."""

import pytest
from pydantic import ValidationError

from sastbench.models import (
    AgentConfig,
    ConsensusFinding,
    DiffReport,
    Finding,
    GroundTruth,
    MatchedFinding,
    MatchedPair,
    MatchGranularity,
    MatchingConfig,
    MatchResult,
    MetricsReport,
    Severity,
    StandardMetrics,
    TestCase,
)


class TestFinding:
    def test_minimal_finding(self):
        f = Finding(file_path="code/sample_001.c")
        assert f.file_path == "code/sample_001.c"
        assert f.start_line is None
        assert f.cwe_id is None

    def test_full_finding(self):
        f = Finding(
            file_path="code/sample_001.c",
            start_line=15,
            end_line=20,
            function_name="bad_func",
            cwe_id="CWE-79",
            severity=Severity.HIGH,
            confidence=0.95,
            message="XSS found",
            rule_id="xss-001",
            tool_name="agent-a",
        )
        assert f.severity == Severity.HIGH
        assert f.confidence == 0.95

    def test_invalid_cwe_format(self):
        with pytest.raises(ValidationError):
            Finding(file_path="x.c", cwe_id="not-a-cwe")

    def test_invalid_confidence(self):
        with pytest.raises(ValidationError):
            Finding(file_path="x.c", confidence=1.5)

    def test_invalid_line(self):
        with pytest.raises(ValidationError):
            Finding(file_path="x.c", start_line=0)

    def test_end_line_before_start_line(self):
        with pytest.raises(ValidationError):
            Finding(file_path="x.c", start_line=10, end_line=5)

    def test_empty_file_path(self):
        with pytest.raises(ValidationError):
            Finding(file_path="")

    def test_serialization_roundtrip(self):
        f = Finding(file_path="code/a.c", cwe_id="CWE-89", start_line=10)
        data = f.model_dump()
        f2 = Finding.model_validate(data)
        assert f == f2


class TestGroundTruth:
    def test_minimal(self):
        gt = GroundTruth(file_path="code/x.c", cwe_id="CWE-79")
        assert gt.is_vulnerable is True
        assert gt.benchmark_name == ""

    def test_known_safe(self):
        gt = GroundTruth(file_path="code/x.c", cwe_id="CWE-79", is_vulnerable=False)
        assert gt.is_vulnerable is False

    def test_with_metadata(self):
        gt = GroundTruth(
            file_path="code/x.c",
            cwe_id="CWE-89",
            benchmark_name="juliet",
            metadata={"test_case_id": "CWE89_01"},
        )
        assert gt.metadata["test_case_id"] == "CWE89_01"

    def test_end_line_before_start_line(self):
        with pytest.raises(ValidationError):
            GroundTruth(file_path="code/x.c", cwe_id="CWE-79", start_line=10, end_line=5)

    def test_empty_file_path(self):
        with pytest.raises(ValidationError):
            GroundTruth(file_path="", cwe_id="CWE-79")


class TestTestCase:
    def test_creation(self):
        tc = TestCase(
            original_id="CWE79_XSS_01",
            original_path="testcases/CWE79/CWE79_XSS_01.c",
            code='void bad() { printf("%s", user_input); }',
            language="c",
        )
        assert tc.language == "c"
        assert tc.metadata == {}


class TestMatchResult:
    def test_empty(self):
        mr = MatchResult()
        assert len(mr.true_positives) == 0
        assert mr.true_negatives == 0

    def test_with_pairs(self, sample_finding, sample_ground_truth):
        mr = MatchResult(
            true_positives=[MatchedPair(finding=sample_finding, ground_truth=sample_ground_truth)],
            false_positives=[],
            false_negatives=[],
            true_negatives=10,
        )
        assert len(mr.true_positives) == 1
        assert mr.true_negatives == 10


class TestMatchingConfig:
    def test_defaults(self):
        mc = MatchingConfig()
        assert mc.granularity == MatchGranularity.FILE
        assert mc.line_tolerance == 3
        assert mc.require_cwe_match is True

    def test_custom(self):
        mc = MatchingConfig(
            granularity=MatchGranularity.LINE,
            line_tolerance=5,
            require_cwe_match=False,
        )
        assert mc.line_tolerance == 5


class TestStandardMetrics:
    def test_defaults(self):
        sm = StandardMetrics()
        assert sm.precision == 0.0
        assert sm.recall == 0.0

    def test_out_of_range_precision(self):
        with pytest.raises(ValidationError):
            StandardMetrics(precision=1.5)

    def test_negative_recall(self):
        with pytest.raises(ValidationError):
            StandardMetrics(recall=-0.1)


class TestMetricsReport:
    def test_creation(self):
        mr = MetricsReport(
            agent_name="test-agent",
            benchmark_name="juliet",
            matching_granularity=MatchGranularity.FILE,
            overall=StandardMetrics(precision=0.8, recall=0.7, f1=0.74),
        )
        assert mr.agent_name == "test-agent"
        assert mr.overall.precision == 0.8


class TestDiffReport:
    def test_creation(self):
        dr = DiffReport(
            agents=["agent_a", "agent_b"],
            agreement_rate=0.75,
            jaccard_index=0.60,
        )
        assert len(dr.agents) == 2
        assert dr.cohens_kappa == 0.0


class TestAgentConfig:
    def test_copilot_config(self):
        ac = AgentConfig(
            name="Copilot Agent",
            platform="copilot",
            github_repo="myorg/workspace",
            github_token_env="GITHUB_TOKEN",
        )
        assert ac.platform == "copilot"
        assert ac.timeout_minutes == 60

    def test_docker_config(self):
        ac = AgentConfig(
            name="Docker Agent",
            platform="docker",
            docker_image="scanner:latest",
        )
        assert ac.docker_mount_path == "/workspace"

    def test_invalid_platform(self):
        with pytest.raises(ValidationError):
            AgentConfig(name="Bad", platform="unknown")

    def test_invalid_timeout(self):
        with pytest.raises(ValidationError):
            AgentConfig(name="Bad", platform="docker", timeout_minutes=0)

    def test_invalid_max_concurrent(self):
        with pytest.raises(ValidationError):
            AgentConfig(name="Bad", platform="docker", max_concurrent=0)


class TestConsensusFinding:
    def test_valid(self):
        mf = MatchedFinding(file_path="a.c", agents=["a", "b"])
        cf = ConsensusFinding(finding=mf, agent_count=2, total_agents=3)
        assert cf.agent_count == 2

    def test_agent_count_exceeds_total(self):
        mf = MatchedFinding(file_path="a.c")
        with pytest.raises(ValidationError):
            ConsensusFinding(finding=mf, agent_count=5, total_agents=3)

    def test_zero_agent_count(self):
        mf = MatchedFinding(file_path="a.c")
        with pytest.raises(ValidationError):
            ConsensusFinding(finding=mf, agent_count=0, total_agents=3)

    def test_zero_total_agents(self):
        mf = MatchedFinding(file_path="a.c")
        with pytest.raises(ValidationError):
            ConsensusFinding(finding=mf, agent_count=1, total_agents=0)
