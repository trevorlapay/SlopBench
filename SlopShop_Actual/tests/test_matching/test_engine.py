"""Integration tests for the MatchingEngine."""

import pytest

from sastbench.models import (
    Finding,
    GroundTruth,
    MatchGranularity,
    MatchingConfig,
)
from sastbench.matching.engine import MatchingEngine


def _finding(
    path: str = "src/app.py",
    cwe: str | None = "CWE-79",
    line: int | None = 10,
    func: str | None = None,
) -> Finding:
    return Finding(file_path=path, cwe_id=cwe, start_line=line, function_name=func)


def _gt(
    path: str = "src/app.py",
    cwe: str = "CWE-79",
    line: int | None = 10,
    func: str | None = None,
    vuln: bool = True,
) -> GroundTruth:
    return GroundTruth(
        file_path=path, cwe_id=cwe, start_line=line, function_name=func, is_vulnerable=vuln,
    )


class TestEngineFileGranularity:
    def setup_method(self):
        self.engine = MatchingEngine(MatchingConfig(granularity=MatchGranularity.FILE))

    def test_perfect_match(self):
        findings = [_finding()]
        gts = [_gt()]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 1
        assert len(result.false_positives) == 0
        assert len(result.false_negatives) == 0

    def test_all_false_positives(self):
        findings = [_finding(), _finding(path="other.py")]
        gts: list[GroundTruth] = []
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 0
        assert len(result.false_positives) == 2

    def test_all_false_negatives(self):
        findings: list[Finding] = []
        gts = [_gt(), _gt(path="other.py", cwe="CWE-89")]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 0
        assert len(result.false_negatives) == 2

    def test_mixed_results(self):
        findings = [_finding(), _finding(path="extra.py")]
        gts = [_gt(), _gt(path="missed.py", cwe="CWE-89")]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 1
        assert len(result.false_positives) == 1
        assert len(result.false_negatives) == 1

    def test_duplicate_findings_same_gt(self):
        """Multiple findings matching the same GT should produce one TP."""
        findings = [_finding(), _finding()]
        gts = [_gt()]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 1
        # The second finding that also matches is not a FP since it was consumed
        # The first matching finding is used for the TP, second goes to FP
        assert len(result.false_positives) == 1

    def test_empty_inputs(self):
        result = self.engine.match([], [])
        assert len(result.true_positives) == 0
        assert len(result.false_positives) == 0
        assert len(result.false_negatives) == 0
        assert result.true_negatives == 0

    def test_non_vulnerable_gt_counts_as_tn(self):
        findings: list[Finding] = []
        gts = [_gt(vuln=False)]
        result = self.engine.match(findings, gts)
        assert result.true_negatives == 1
        assert len(result.false_negatives) == 0

    def test_non_vulnerable_gt_flagged_not_tn(self):
        """A non-vulnerable GT flagged by a finding should NOT be a TN."""
        findings = [_finding()]
        gts = [_gt(vuln=False)]
        result = self.engine.match(findings, gts)
        assert result.true_negatives == 0

    def test_one_finding_cannot_match_multiple_gts(self):
        """A single finding must not satisfy two different GTs (1:1 matching)."""
        findings = [_finding(path="src/app.py", cwe="CWE-79")]
        gts = [
            _gt(path="src/app.py", cwe="CWE-79", line=10),
            _gt(path="src/app.py", cwe="CWE-79", line=20),
        ]
        result = self.engine.match(findings, gts)
        # Only one GT can be matched — the other must be a FN
        assert len(result.true_positives) == 1
        assert len(result.false_negatives) == 1
        assert len(result.false_positives) == 0

    def test_one_to_one_with_enough_findings(self):
        """Two findings should match two GTs 1:1, not have one finding match both."""
        findings = [
            _finding(path="src/app.py", cwe="CWE-79"),
            _finding(path="src/app.py", cwe="CWE-79"),
        ]
        gts = [
            _gt(path="src/app.py", cwe="CWE-79", line=10),
            _gt(path="src/app.py", cwe="CWE-79", line=20),
        ]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 2
        assert len(result.false_negatives) == 0
        assert len(result.false_positives) == 0

    def test_one_to_one_partial_match(self):
        """Three GTs but only two findings — one GT must be a FN."""
        findings = [
            _finding(path="a.py", cwe="CWE-79"),
            _finding(path="b.py", cwe="CWE-89"),
        ]
        gts = [
            _gt(path="a.py", cwe="CWE-79"),
            _gt(path="b.py", cwe="CWE-89"),
            _gt(path="a.py", cwe="CWE-79", line=50),
        ]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 2
        assert len(result.false_negatives) == 1
        assert len(result.false_positives) == 0

    def test_cwe_mismatch(self):
        findings = [_finding(cwe="CWE-89")]
        gts = [_gt(cwe="CWE-79")]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 0
        assert len(result.false_positives) == 1
        assert len(result.false_negatives) == 1

    def test_path_normalization(self):
        findings = [_finding(path="src\\app.py")]
        gts = [_gt(path="./src/app.py")]
        result = self.engine.match(findings, gts)
        assert len(result.true_positives) == 1


class TestEngineLineGranularity:
    def setup_method(self):
        self.engine = MatchingEngine(
            MatchingConfig(granularity=MatchGranularity.LINE, line_tolerance=3)
        )

    def test_exact_line_match(self):
        result = self.engine.match([_finding(line=10)], [_gt(line=10)])
        assert len(result.true_positives) == 1

    def test_within_tolerance(self):
        result = self.engine.match([_finding(line=12)], [_gt(line=10)])
        assert len(result.true_positives) == 1

    def test_outside_tolerance(self):
        result = self.engine.match([_finding(line=14)], [_gt(line=10)])
        assert len(result.true_positives) == 0
        assert len(result.false_positives) == 1
        assert len(result.false_negatives) == 1


class TestEngineFunctionGranularity:
    def setup_method(self):
        self.engine = MatchingEngine(
            MatchingConfig(granularity=MatchGranularity.FUNCTION)
        )

    def test_same_function(self):
        result = self.engine.match(
            [_finding(func="handle")], [_gt(func="handle")]
        )
        assert len(result.true_positives) == 1

    def test_different_function(self):
        result = self.engine.match(
            [_finding(func="handle")], [_gt(func="process")]
        )
        assert len(result.true_positives) == 0

    def test_fallback_no_function(self):
        result = self.engine.match(
            [_finding(func=None)], [_gt(func="handle")]
        )
        assert len(result.true_positives) == 1


class TestEngineDefaultConfig:
    def test_default_config(self):
        engine = MatchingEngine()
        assert engine.config.granularity == MatchGranularity.FILE
        assert engine.config.require_cwe_match is True
        assert engine.config.line_tolerance == 3

    def test_config_stored_in_result(self):
        cfg = MatchingConfig(granularity=MatchGranularity.LINE, line_tolerance=5)
        engine = MatchingEngine(cfg)
        result = engine.match([], [])
        assert result.config == cfg
